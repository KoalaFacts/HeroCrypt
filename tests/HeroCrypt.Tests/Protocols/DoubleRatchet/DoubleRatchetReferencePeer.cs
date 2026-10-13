using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using BcCipher = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace HeroCrypt.Tests.Protocols.DoubleRatchet;

// Test oracle for the documented classical Double Ratchet profile. It deliberately
// uses no HeroCrypt KDF, curve, cipher, state or wire encoder. Fixture keys/nonces
// are reproducible and public; this is not a production session implementation.
internal sealed class DoubleRatchetReferencePeer
{
    private readonly byte[] context;
    private readonly int seed;
    private readonly Dictionary<(string Key, uint Number), byte[]> skipped = [];
    private byte[] root;
    private byte[] local;
    private byte[]? remote;
    private byte[]? sending;
    private byte[]? receiving;
    private uint sent;
    private uint received;
    private uint previous;
    private int keyCounter;
    private int nonceCounter;

    internal DoubleRatchetReferencePeer(byte[] shared, byte[] responderPrivate, byte[] context,
        int seed, bool initiator)
    {
        this.context = context.ToArray();
        this.seed = seed;
        root = shared.ToArray();
        local = initiator ? NextPrivateKey() : responderPrivate.ToArray();
        if (initiator)
        {
            remote = PublicKey(responderPrivate);
            sending = DeriveRoot(remote);
        }
    }

    internal static byte[] PublicKey(byte[] privateKey)
    {
        var result = new byte[32];
        BcX25519.GeneratePublicKey(privateKey, 0, result, 0);
        return result;
    }

    internal byte[] Encrypt(byte[] plaintext, byte[] metadata)
    {
        Assert.NotNull(sending);
        var key = Advance(ref sending);
        var header = new byte[53];
        header[0] = 1;
        PublicKey(local).CopyTo(header, 1);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(33, 4), previous);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(37, 4), sent++);
        var nonce = SHA256.HashData(Encoding.UTF8.GetBytes($"reference nonce {seed} {nonceCounter++}"))[..12];
        nonce.CopyTo(header, 41);
        return [.. header, .. Cipher(true, key, nonce, AssociatedData(header, metadata), plaintext)];
    }

    internal byte[] Decrypt(byte[] wire, byte[] metadata)
    {
        Assert.Equal(1, wire[0]);
        var publicKey = wire.AsSpan(1, 32).ToArray();
        var pn = BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(33, 4));
        var number = BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(37, 4));
        var id = (Convert.ToHexString(publicKey), number);
        byte[] key;
        if (skipped.Remove(id, out var cached))
        {
            key = cached;
        }
        else
        {
            if (remote == null || !publicKey.SequenceEqual(remote))
            {
                Skip(pn);
                previous = sent;
                sent = received = 0;
                remote = publicKey;
                receiving = DeriveRoot(remote);
                local = NextPrivateKey();
                sending = DeriveRoot(remote);
            }
            Assert.True(number >= received, "Reference peer received a replay.");
            Skip(number);
            key = Advance(ref receiving);
            received++;
        }
        return Cipher(false, key, wire.AsSpan(41, 12).ToArray(),
            AssociatedData(wire.AsSpan(0, 53).ToArray(), metadata), wire.AsSpan(53).ToArray());
    }

    private void Skip(uint until)
    {
        if (receiving == null)
        {
            Assert.Equal(0u, until);
            return;
        }
        Assert.True(until >= received);
        while (received < until)
            skipped.Add((Convert.ToHexString(remote!), received++), Advance(ref receiving));
    }

    private byte[] DeriveRoot(byte[] publicKey)
    {
        var dh = new byte[32];
        Assert.True(BcX25519.CalculateAgreement(local, 0, publicKey, 0, dh, 0));
        var generator = new HkdfBytesGenerator(new Sha256Digest());
        generator.Init(new HkdfParameters(dh, root, Encoding.ASCII.GetBytes("HeroCrypt.DoubleRatchet.Root.v1")));
        var output = new byte[64];
        generator.GenerateBytes(output, 0, output.Length);
        root = output[..32];
        return output[32..];
    }

    private byte[] NextPrivateKey() =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"reference private {seed} {keyCounter++}"));

    private static byte[] Advance(ref byte[]? chain)
    {
        Assert.NotNull(chain);
        var message = Mac(chain, 1);
        chain = Mac(chain, 2);
        return message;
    }

    private static byte[] Mac(byte[] key, byte discriminator)
    {
        var mac = new HMac(new Sha256Digest());
        mac.Init(new KeyParameter(key));
        mac.Update(discriminator);
        var output = new byte[32];
        mac.DoFinal(output, 0);
        return output;
    }

    private byte[] AssociatedData(byte[] header, byte[] metadata)
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("HeroCrypt.DoubleRatchet.v1"));
        var length = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)context.Length);
        stream.Write(length);
        stream.Write(context);
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)metadata.Length);
        stream.Write(length);
        stream.Write(metadata);
        stream.Write(header);
        return stream.ToArray();
    }

    private static byte[] Cipher(bool encrypt, byte[] key, byte[] nonce, byte[] ad, byte[] input)
    {
        var cipher = new BcCipher();
        cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, nonce, ad));
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        length += cipher.DoFinal(output, length);
        Assert.Equal(output.Length, length);
        return output;
    }
}
