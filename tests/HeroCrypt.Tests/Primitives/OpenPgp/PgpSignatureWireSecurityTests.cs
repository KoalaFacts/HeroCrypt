using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpSignatureWireSecurityTests
{
    private static readonly byte[] Data = "Signed packet bytes must remain authenticated"u8.ToArray();

    [Theory]
    [InlineData(4, false)]
    [InlineData(6, false)]
    [InlineData(4, true)]
    [InlineData(6, true)]
    public void Verify_FiveOctetSubpacketEncoding_AuthenticatesOriginalBytes(byte version, bool signedOriginalEncoding)
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        var key = PgpPublicKeyPacket.CreateRsa(version, DateTimeOffset.FromUnixTimeSeconds(1700000000),
            new BigInteger(parameters.Modulus!, true, true), new BigInteger(parameters.Exponent!, true, true));
        // The same creation-time subpacket encoded with two different legal length forms.
        byte[] shortEncoding = [5, 2, 0x65, 0x53, 0xF1, 0];
        byte[] longEncoding = [255, 0, 0, 0, 5, 2, 0x65, 0x53, 0xF1, 0];
        byte[] salt = version == 6 ? Enumerable.Range(1, 16).Select(x => (byte)x).ToArray() : [];
        var header = Header(version, signedOriginalEncoding ? longEncoding : shortEncoding);
        var trailer = new byte[] { version, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)header.Length);
        var hash = SHA256.HashData(salt.Concat(Data).Concat(header).Concat(trailer).ToArray());
        var raw = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var mpi = new byte[Mpi.GetEncodedLength(raw)];
        Mpi.Write(raw, mpi);
        // The transmitted packet always uses the long form; in the negative case no re-signing occurs.
        using var wire = new MemoryStream();
        wire.Write(Header(version, longEncoding));
        wire.Write(new byte[version == 4 ? 2 : 4]);
        wire.Write(hash, 0, 2);
        if (version == 6) { wire.WriteByte((byte)salt.Length); wire.Write(salt); }
        wire.Write(mpi);
        var packetBytes = wire.ToArray();
        if (version == 4)
        {
            using var keyStream = new MemoryStream();
            using (var writer = new PgpPacketWriter(keyStream, leaveOpen: true))
                writer.WritePacket(PgpPacketTag.PublicKey, key.ToArray());
            var bcKey = new Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyRing(keyStream.ToArray()).GetPublicKey();
            using var signatureStream = new MemoryStream();
            using (var writer = new PgpPacketWriter(signatureStream, leaveOpen: true))
                writer.WritePacket(PgpPacketTag.Signature, packetBytes);
            var factory = new Org.BouncyCastle.Bcpg.OpenPgp.PgpObjectFactory(signatureStream.ToArray());
            var bcSignature = Assert.IsType<Org.BouncyCastle.Bcpg.OpenPgp.PgpSignatureList>(factory.NextPgpObject())[0];
            bcSignature.InitVerify(bcKey);
            bcSignature.Update(Data);
            Assert.Equal(signedOriginalEncoding, bcSignature.Verify());
        }
        var packet = PgpSignaturePacket.Read(packetBytes);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.Equal(signedOriginalEncoding, verifier.Verify(Data, packet).IsValid);
        Assert.Equal(packetBytes, packet.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(191)]
    [InlineData(192)]
    [InlineData(9000)]
    public void Subpacket_ReadWrite_PreservesFiveOctetLength(int dataLength)
    {
        var encoded = new byte[6 + dataLength];
        encoded[0] = 255;
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(1), (uint)(1 + dataLength));
        encoded[5] = 100;
        Assert.Equal(encoded, PgpSignatureSubpacket.Read(encoded).ToArray());
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Packet_ReadWrite_PreservesUnhashedEncoding(byte version)
    {
        byte[] salt = version == 6 ? new byte[16] : [];
        using var wire = new MemoryStream();
        wire.Write(Header(version, []));
        var length = new byte[version == 4 ? 2 : 4];
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(length, 6);
        else BinaryPrimitives.WriteUInt32BigEndian(length, 6);
        wire.Write(length);
        wire.Write([255, 0, 0, 0, 1, 100]);
        wire.Write(new byte[2]);
        if (version == 6) { wire.WriteByte(16); wire.Write(salt); }
        wire.Write([0, 1, 1]);
        var body = wire.ToArray();
        Assert.Equal(body, PgpSignaturePacket.Read(body).ToArray());
    }

    private static byte[] Header(byte version, byte[] hashedSubpackets)
    {
        int overhead = version == 4 ? 6 : 8;
        var result = new byte[overhead + hashedSubpackets.Length];
        result[0] = version;
        result[1] = 0;
        result[2] = 1;
        result[3] = 8;
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)hashedSubpackets.Length);
        else BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), (uint)hashedSubpackets.Length);
        hashedSubpackets.CopyTo(result, overhead);
        return result;
    }
}
