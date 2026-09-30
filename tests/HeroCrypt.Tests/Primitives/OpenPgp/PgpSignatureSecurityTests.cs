using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpSignatureSecurityTests
{
    private static readonly byte[] Data = "OpenPGP verification boundary"u8.ToArray();

    [Fact]
    public void Verify_UnknownCriticalHashedSubpacket_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [new((PgpSignatureSubpacketType)100, true, new byte[] { 1 })]);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Fact]
    public void Verify_UnsupportedCriticalNotation_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [PgpSignatureSubpacket.CreateNotationData("required@example.invalid", "enforce", true, true)]);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Fact]
    public void Verify_FalseHashedIssuerFingerprint_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [PgpSignatureSubpacket.CreateIssuerFingerprint(4, new byte[20])]);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Fact]
    public void Verify_NoIssuerHints_ReportsActualVerificationKey()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [], []);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        var result = verifier.Verify(Data, signature);
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal(key.GetKeyId(), result.SignerKeyId);
        Assert.Equal(key.ComputeFingerprint(), result.SignerFingerprint);
    }

    [Fact]
    public void Verify_FingerprintOnly_FindsActualKey()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [PgpSignatureSubpacket.CreateIssuerFingerprint(4, key.ComputeFingerprint())], []);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.True(verifier.Verify(Data, signature).IsValid);
    }

    [Theory]
    [InlineData(PgpSignatureType.Standalone)]
    [InlineData(PgpSignatureType.KeyRevocation)]
    [InlineData((PgpSignatureType)0x7F)]
    public void Verify_NonDocumentSignatureType_Rejects(PgpSignatureType type)
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [], type: type);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Fact]
    public void Verify_SignatureAlgorithmDoesNotMatchKey_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [], algorithm: (byte)PgpPublicKeyAlgorithm.Ed25519);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Fact]
    public void Verify_RsaSignatureWithTrailingData_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, []);
        signature = Copy(signature, signature.SignatureData.ToArray().Concat(new byte[] { 0 }).ToArray());
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Fact]
    public void Verify_NoncanonicalRsaMpiBitCount_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, []);
        var encoded = signature.SignatureData.ToArray();
        var bitCount = BinaryPrimitives.ReadUInt16BigEndian(encoded);
        BinaryPrimitives.WriteUInt16BigEndian(encoded, (ushort)(bitCount % 8 == 1 ? bitCount + 1 : bitCount - 1));
        signature = Copy(signature, encoded);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void WeakSignatureHash_RejectsInSignerAndVerifier(byte hashAlgorithm)
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [], hashAlgorithm: hashAlgorithm);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(Data, signature).IsValid);
        using var signer = PgpSignatureSigner.Create();
        Assert.Throws<ArgumentException>(() => signer.WithHashAlgorithm((PgpHashAlgorithmId)hashAlgorithm));
    }

    [Fact]
    public void Verify_OnePassMetadataMismatch_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, []);
        var ops = PgpOnePassSignaturePacket.CreateV3(PgpSignatureType.BinaryDocument,
            (byte)PgpHashAlgorithmId.Sha512, (byte)key.Algorithm, key.GetKeyId(), true);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.False(verifier.Verify(new PgpSignedMessage(Data, signature, ops)).IsValid);
    }

    [Fact]
    public void Read_DuplicateLiteralData_Rejects()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var message = new PgpSignedMessage(Data, Sign(rsa, key, []));
        Assert.False(PgpSignedMessage.TryRead(message.ToArray().Concat(message.ToArray()).ToArray(), out _, out _));
    }

    [Fact]
    public void TryRead_TruncatedPacket_ReturnsFalse()
    {
        Assert.False(PgpSignedMessage.TryRead([0xCB, 8, 1], out _, out _));
    }

    [Fact]
    public void TryRead_EmptyV6Salt_ReturnsFalse()
    {
        using var stream = new MemoryStream();
        using (var writer = new PgpPacketWriter(stream, leaveOpen: true))
        {
            new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, "", DateTimeOffset.UnixEpoch, Data).WriteTo(writer);
            // Complete V6 framing with empty subpacket areas, hash prefix and salt.
            writer.WritePacket(PgpPacketTag.Signature, [6, 0, 27, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        Assert.False(PgpSignedMessage.TryRead(stream.ToArray(), out _, out _));
    }

    [Fact]
    public void Verify_ValidBinaryMessage_ReportsVerificationKey()
    {
        var pair = GenerateKey();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        var message = PgpSignedMessage.Read(signer.Sign(Data).ToArray());
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(pair.MasterPublicKey);
        var result = verifier.Verify(message);
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal(pair.Fingerprint, result.SignerFingerprint);
        Assert.Equal(pair.KeyId, result.SignerKeyId);
        Assert.False(verifier.Verify(Data.Concat(new byte[] { 0 }).ToArray(), message.Signature).IsValid);
    }

    [Fact]
    public void Verify_UnknownNoncriticalHashedSubpacket_Accepts()
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var signature = Sign(rsa, key, [new((PgpSignatureSubpacketType)100, false, new byte[] { 1 })]);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        Assert.True(verifier.Verify(Data, signature).IsValid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Verify_KeyAndCertificationSignatures_RejectSpoofedIssuer(bool certification)
    {
        var pair = GenerateKey();
        using var certifier = PgpKeyCertifier.Create().WithCertifyingKey(pair.MasterSecretKey)
            .WithTargetKey(pair.MasterPublicKey).WithUserId(new PgpUserIdPacket("audit@example.invalid"));
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(pair.MasterSecretKey);
        var signature = certification ? certifier.Certify() : revoker.RevokeKey();
        using var verifier = PgpSignatureVerifier.Create();
        PgpSignatureResult Verify(PgpSignaturePacket value) => certification
            ? verifier.VerifyCertification(value, pair.MasterPublicKey, pair.MasterPublicKey, new PgpUserIdPacket("audit@example.invalid"))
            : verifier.VerifyKeyRevocation(value, pair.MasterPublicKey);
        var result = Verify(signature);
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal(pair.Fingerprint, result.SignerFingerprint);
        var spoofed = new PgpSignaturePacket(signature.Version, signature.SignatureType,
            signature.PublicKeyAlgorithm, signature.HashAlgorithm, signature.HashedSubpackets,
            [PgpSignatureSubpacket.CreateIssuerKeyId(new byte[8])], signature.HashPrefix, signature.SignatureData, signature.Salt);
        Assert.False(Verify(spoofed).IsValid);
    }

    [Fact]
    public void Verify_V6InlineMessage_UsesMatchingOnePassSaltAndKey()
    {
        var generator = PgpKeyGenerator.Create().WithUserId("audit@example.invalid");
        var pair = generator.GenerateEd25519();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        var message = signer.Sign(Data);
        Assert.Equal(6, message.Signature.Version);
        Assert.Equal(16, message.Signature.Salt.Length);
        Assert.Equal(message.Signature.Salt.ToArray(), message.OnePassSignature!.Value.Salt.ToArray());
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(pair.MasterPublicKey);
        var result = verifier.Verify(PgpSignedMessage.Read(message.ToArray()));
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal(pair.Fingerprint, result.SignerFingerprint);
    }

    [Theory]
    [InlineData(8, 16)]
    [InlineData(9, 24)]
    [InlineData(10, 32)]
    [InlineData(11, 16)]
    [InlineData(12, 16)]
    [InlineData(14, 32)]
    public void V6SaltLength_MatchesRfc9580Table23(byte hash, int size)
    {
        Assert.Equal(size, PgpSignaturePacket.GetExpectedSaltLength(hash));
    }

    [Fact]
    public void Sign_V6RequestedWithV4Key_RejectsBothConfigurationOrders()
    {
        var pair = GenerateKey();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        Assert.Throws<InvalidOperationException>(signer.WithVersion6);
        using var reverse = PgpSignatureSigner.Create().WithVersion6();
        Assert.Throws<ArgumentException>(() => reverse.WithSecretKey(pair.MasterSecretKey));
    }

    [Theory]
    [InlineData(PgpSignatureType.Standalone)]
    [InlineData(PgpSignatureType.KeyRevocation)]
    [InlineData((PgpSignatureType)0x7F)]
    public void Sign_NonDocumentSignatureType_Rejects(PgpSignatureType type)
    {
        using var signer = PgpSignatureSigner.Create();
        Assert.Throws<ArgumentException>(() => signer.WithSignatureType(type));
    }

    [Fact]
    public void Verify_DefaultSignature_FailsClosed()
    {
        using var rsa = RSA.Create(2048);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(PublicKey(rsa));
        Assert.False(verifier.Verify(Data, default).IsValid);
    }

    [Fact]
    public void Verify_V6WrongSaltLength_Rejects()
    {
        var pair = PgpKeyGenerator.Create().WithUserId("audit@example.invalid").GenerateEd25519();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        var signature = signer.Sign(Data).Signature;
        var malformed = new PgpSignaturePacket(signature.Version, signature.SignatureType,
            signature.PublicKeyAlgorithm, signature.HashAlgorithm, signature.HashedSubpackets,
            signature.UnhashedSubpackets, signature.HashPrefix, signature.SignatureData, new byte[32]);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(pair.MasterPublicKey);
        Assert.False(verifier.Verify(Data, malformed).IsValid);
    }

    [Theory]
    [InlineData(35, false)]
    [InlineData(60, true)]
    public void Read_UnknownPacket_EnforcesCriticality(byte tag, bool accepted)
    {
        using var rsa = RSA.Create(2048);
        var key = PublicKey(rsa);
        var message = new PgpSignedMessage(Data, Sign(rsa, key, []));
        using var stream = new MemoryStream();
        using (var writer = new PgpPacketWriter(stream, leaveOpen: true)) writer.WritePacket((PgpPacketTag)tag, [1]);
        var serialized = stream.ToArray().Concat(message.ToArray()).ToArray();
        Assert.Equal(accepted, PgpSignedMessage.TryRead(serialized, out _, out _));
    }

    private static PgpKeyGeneratorResult GenerateKey()
    {
        var generator = PgpKeyGenerator.Create().WithUserId("audit@example.invalid");
        return generator.GenerateRsa();
    }

    private static PgpPublicKeyPacket PublicKey(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        return PgpPublicKeyPacket.CreateRsa(4, DateTimeOffset.FromUnixTimeSeconds(1700000000),
            new BigInteger(p.Modulus!, true, true), new BigInteger(p.Exponent!, true, true));
    }

    // Construct standard V4 framing independently to exercise validation boundaries.
    private static PgpSignaturePacket Sign(RSA rsa, PgpPublicKeyPacket key,
        IReadOnlyList<PgpSignatureSubpacket> hashed, IReadOnlyList<PgpSignatureSubpacket>? unhashed = null,
        PgpSignatureType type = PgpSignatureType.BinaryDocument, byte algorithm = 1, byte hashAlgorithm = 8)
    {
        var subpackets = PgpSignatureSubpacket.WriteAll(hashed);
        var header = new byte[6 + subpackets.Length];
        header[0] = 4;
        header[1] = (byte)type;
        header[2] = algorithm;
        header[3] = hashAlgorithm;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)subpackets.Length));
        subpackets.CopyTo(header, 6);
        var trailer = new byte[] { 4, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)header.Length);
        var signed = Data.Concat(header).Concat(trailer).ToArray();
        var hash = hashAlgorithm switch { 1 => MD5.HashData(signed), 2 => SHA1.HashData(signed), _ => SHA256.HashData(signed) };
        var hashName = hashAlgorithm switch { 1 => HashAlgorithmName.MD5, 2 => HashAlgorithmName.SHA1, _ => HashAlgorithmName.SHA256 };
        var raw = rsa.SignHash(hash, hashName, RSASignaturePadding.Pkcs1);
        var mpi = new byte[Mpi.GetEncodedLength(raw)];
        Mpi.Write(raw, mpi);
        return PgpSignaturePacket.CreateV4(type, algorithm, hashAlgorithm,
            hashed, unhashed ?? [PgpSignatureSubpacket.CreateIssuerKeyId(key.GetKeyId())],
            BinaryPrimitives.ReadUInt16BigEndian(hash), mpi);
    }

    private static PgpSignaturePacket Copy(PgpSignaturePacket signature, byte[] raw) => new(
        signature.Version, signature.SignatureType, signature.PublicKeyAlgorithm, signature.HashAlgorithm,
        signature.HashedSubpackets, signature.UnhashedSubpackets, signature.HashPrefix, raw, signature.Salt);
}
