using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;
using BcCipher = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace HeroCrypt.Tests.Protocols.X3dh;

internal static class X3dhReference
{
    internal static byte[] DecryptInitial(byte[] wire, byte[] responderPrivate, byte[] signedPrivate, byte[]? oneTimePrivate,
        byte[] applicationContext, byte[] metadata)
    {
        var initiator = wire.AsSpan(5, 32).ToArray(); var ephemeral = wire.AsSpan(37, 32).ToArray();
        var responder = Public(responderPrivate); var signed = Public(signedPrivate); var opk = wire[73] == 1;
        var input = new List<byte>(Enumerable.Repeat((byte)255, 32));
        input.AddRange(Dh(signedPrivate, initiator)); input.AddRange(Dh(responderPrivate, ephemeral)); input.AddRange(Dh(signedPrivate, ephemeral));
        if (opk) input.AddRange(Dh(oneTimePrivate!, ephemeral));
        var sk = Hkdf(input.ToArray(), new byte[32], "HeroCrypt.X3DH.v1"u8.ToArray(), 32);
        using var transcript = new MemoryStream(); transcript.Write("HeroCrypt.X3DH.DoubleRatchet.v1"u8);
        WriteLength(transcript, applicationContext.Length); transcript.Write(applicationContext);
        foreach (var key in new[] { initiator, responder, ephemeral, signed }) { transcript.WriteByte(5); transcript.Write(key); }
        transcript.Write(wire.AsSpan(69, 4)); transcript.WriteByte(wire[73]);
        if (opk) { transcript.Write(wire.AsSpan(74, 4)); transcript.WriteByte(5); transcript.Write(Public(oneTimePrivate!)); }
        var context = SHA256.HashData(transcript.ToArray());
        var headerOffset = opk ? 82 : 78; var header = wire.AsSpan(headerOffset, 53).ToArray();
        var root = Hkdf(Dh(signedPrivate, header.AsSpan(1, 32).ToArray()), sk, "HeroCrypt.DoubleRatchet.Root.v1"u8.ToArray(), 64);
        using var hmac = new HMACSHA256(root.AsSpan(32).ToArray()); var keyMaterial = hmac.ComputeHash([1]);
        using var firstAd = new MemoryStream(); firstAd.WriteByte(5); firstAd.Write(initiator); firstAd.WriteByte(5); firstAd.Write(responder);
        WriteLength(firstAd, metadata.Length); firstAd.Write(metadata);
        using var ad = new MemoryStream(); ad.Write("HeroCrypt.DoubleRatchet.v1"u8);
        WriteLength(ad, context.Length); ad.Write(context); WriteLength(ad, (int)firstAd.Length); ad.Write(firstAd.ToArray()); ad.Write(header);
        var cipher = new BcCipher(); cipher.Init(false, new AeadParameters(new KeyParameter(keyMaterial), 128, header.AsSpan(41, 12).ToArray(), ad.ToArray()));
        var ciphertext = wire.AsSpan(headerOffset + 53).ToArray(); var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
        var length = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0); length += cipher.DoFinal(output, length);
        Assert.Equal(output.Length, length); return output;
    }

    private static void WriteLength(Stream output, int length)
    {
        var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)length); output.Write(bytes);
    }

    private static byte[] Hkdf(byte[] input, byte[] salt, byte[] info, int length)
    {
        var generator = new HkdfBytesGenerator(new Sha256Digest()); generator.Init(new HkdfParameters(input, salt, info));
        var output = new byte[length]; generator.GenerateBytes(output, 0, output.Length); return output;
    }
    internal static byte[] Key(string name) => SHA256.HashData(Encoding.UTF8.GetBytes("profile " + name));
    internal static byte[] Public(byte[] key)
    {
        var output = new byte[32]; BcX25519.GeneratePublicKey(key, 0, output, 0); return output;
    }
    internal static byte[] Dh(byte[] key, byte[] other)
    {
        var output = new byte[32]; Assert.True(BcX25519.CalculateAgreement(key, 0, other, 0, output, 0)); return output;
    }
    internal static byte[] Secret(bool opk)
    {
        var a = Key("Alice identity"); var e = Key("Alice ephemeral");
        var input = new List<byte>(Enumerable.Repeat((byte)255, 32));
        input.AddRange(Dh(a, Public(Key("signed prekey"))));
        input.AddRange(Dh(e, Public(Key("Bob identity")))); input.AddRange(Dh(e, Public(Key("signed prekey"))));
        if (opk) input.AddRange(Dh(e, Public(Key("one time"))));
        var generator = new HkdfBytesGenerator(new Sha256Digest());
        generator.Init(new HkdfParameters(input.ToArray(), new byte[32], "HeroCrypt.X3DH.v1"u8.ToArray()));
        var result = new byte[32]; generator.GenerateBytes(result, 0, 32); return result;
    }
}
