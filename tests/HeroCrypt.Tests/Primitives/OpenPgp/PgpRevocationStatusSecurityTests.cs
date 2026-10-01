using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpRevocationStatusSecurityTests
{
    private static readonly DateTimeOffset Created = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(32, true)]
    [InlineData(255, true)]
    public void KeyReasonClassification_OnlyKnownSoftReasonsAreSoft(byte code, bool hard)
    {
        Assert.Equal(hard, ((PgpRevocationReason)code).IsHardRevocation());
    }

    [Theory]
    [InlineData(4, 0, false)]
    [InlineData(4, 1, true)]
    [InlineData(4, 2, true)]
    [InlineData(6, 0, true)]
    [InlineData(6, 1, false)]
    [InlineData(6, 2, true)]
    public void InvalidOnlyEvidence_ThrowsInsteadOfClaimingStatus(int version, int kind, bool reimport)
    {
        var owner = Generate(version);
        var fake = Invalid(owner, kind);
        var (pub, secret) = Rings(owner, [fake], reimport);
        using var verifier = PgpSignatureVerifier.Create();
        Assert.False(verifier.VerifyKeyRevocation(fake, owner.MasterPublicKey).IsValid);
        Assert.Single(pub.GetRevocationSignatures());
        Assert.Single(secret.GetRevocationSignatures());
        Assert.Throws<InvalidOperationException>(() => pub.IsRevoked);
        Assert.Throws<InvalidOperationException>(() => pub.GetRevocationReason());
        Assert.Throws<InvalidOperationException>(() => secret.IsKeyRevoked);
        Assert.Throws<InvalidOperationException>(() => secret.GetRevocationReason());
        var result = Validate(pub);
        Assert.Contains(result.Errors, x => x.Code == PgpValidationCode.InvalidRevocationSignature);
        Assert.DoesNotContain(result.Warnings, x => x.Code == PgpValidationCode.KeyRevoked);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void MixedEvidence_PreservesAuthenticatedReason(int version, bool fakeFirst)
    {
        var owner = Generate(version);
        var fake = Invalid(owner, 1);
        var real = Revoke(owner, PgpRevocationReason.KeyCompromised, "Confirmed compromise");
        var (pub, secret) = Rings(owner, fakeFirst ? [fake, real] : [real, fake], true);
        AssertStatus(pub, secret, PgpRevocationReason.KeyCompromised, "Confirmed compromise");
        var result = Validate(pub);
        Assert.Contains(result.Errors, x => x.Code == PgpValidationCode.InvalidRevocationSignature);
        Assert.Contains("Confirmed compromise", Assert.Single(result.Warnings, x => x.Code == PgpValidationCode.KeyRevoked).Message);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void GenuineEvidence_AuthenticatesAcrossKeyAlgorithms(int version, bool ed25519)
    {
        var owner = Generate(version, ed25519);
        var real = Revoke(owner, PgpRevocationReason.KeyRetired, "Retired");
        using var verifier = PgpSignatureVerifier.Create();
        Assert.True(verifier.VerifyKeyRevocation(real, owner.MasterPublicKey).IsValid);
        var (pub, secret) = Rings(owner, [real], true);
        AssertStatus(pub, secret, PgpRevocationReason.KeyRetired, "Retired");
        Assert.True(Validate(pub).IsValid);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompromiseReason_CannotBeHiddenByPacketOrder(bool reversed)
    {
        var owner = Generate(6, true);
        var soft = Revoke(owner, PgpRevocationReason.KeyRetired, "Retired");
        var hard = Revoke(owner, PgpRevocationReason.KeyCompromised, "Compromised");
        var (pub, secret) = Rings(owner, reversed ? [hard, soft] : [soft, hard], true);
        AssertStatus(pub, secret, PgpRevocationReason.KeyCompromised, "Compromised");
        Assert.Contains("Compromised", Assert.Single(Validate(pub).Warnings, x => x.Code == PgpValidationCode.KeyRevoked).Message);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ConflictingReasons_ProduceOrderIndependentConservativeResult(bool sameCode, bool reversed)
    {
        var owner = Generate(6, true);
        var first = Revoke(owner, PgpRevocationReason.KeyRetired, "First");
        var second = Revoke(owner, sameCode ? PgpRevocationReason.KeyRetired : PgpRevocationReason.KeySuperseded, "Second");
        var (pub, secret) = Rings(owner, reversed ? [second, first] : [first, second], true);
        AssertStatus(pub, secret, sameCode ? PgpRevocationReason.KeyRetired : PgpRevocationReason.NoReason, null);
        Assert.True(Validate(pub).IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void AuthenticatedMalformedOrUnsupportedReason_DoesNotLoseRevocation(int kind)
    {
        var owner = Generate(4);
        PgpSignatureSubpacket[] reasons = kind switch
        {
            0 => [],
            1 => [new(PgpSignatureSubpacketType.ReasonForRevocation, false, ReadOnlyMemory<byte>.Empty)],
            2 => [PgpSignatureSubpacket.CreateReasonForRevocation((PgpRevocationReason)255, "Unknown")],
            3 => [PgpSignatureSubpacket.CreateReasonForRevocation(PgpRevocationReason.UserIdNoLongerValid, "Wrong context")],
            _ => [PgpSignatureSubpacket.CreateReasonForRevocation(PgpRevocationReason.KeyRetired, "Soft"),
                  PgpSignatureSubpacket.CreateReasonForRevocation(PgpRevocationReason.KeyCompromised, "Hard")]
        };
        var real = Sign(owner, reasons);
        var (pub, secret) = Rings(owner, [real], true);
        AssertStatus(pub, secret, PgpRevocationReason.NoReason, null);
        Assert.Single(Validate(pub).Warnings, x => x.Code == PgpValidationCode.KeyRevoked);
    }

    [Fact]
    public void UnsupportedCriticalEvidence_ThrowsInsteadOfClaimingStatus()
    {
        var owner = Generate(4);
        var signature = Sign(owner, [new PgpSignatureSubpacket((PgpSignatureSubpacketType)100, true, new byte[] { 1 })], false);
        var (pub, secret) = Rings(owner, [signature], true);
        Assert.Throws<InvalidOperationException>(() => pub.GetRevocationReason());
        Assert.Throws<InvalidOperationException>(() => secret.IsKeyRevoked);
        Assert.Contains(Validate(pub).Errors, x => x.Code == PgpValidationCode.InvalidRevocationSignature);
    }

    [Fact]
    public void UnhashedReason_CannotOverrideSignedReason()
    {
        var owner = Generate(4);
        var real = Sign(owner, [], unhashed: [PgpSignatureSubpacket.CreateReasonForRevocation(PgpRevocationReason.KeyRetired, "Unsigned")]);
        var (pub, secret) = Rings(owner, [real], true);
        AssertStatus(pub, secret, PgpRevocationReason.NoReason, null);
    }

    [Fact]
    public void EncryptedSecretKey_StatusRequiresNoDecryption()
    {
        var owner = Generate(6, true);
        var real = Revoke(owner, PgpRevocationReason.KeyCompromised, "Confirmed");
        var encrypted = PgpSecretKeyPacket.CreateEncrypted(owner.MasterPublicKey, PgpS2KUsage.Sha1Hash, 9,
            PgpS2KSpecifier.CreateIterated(8, new byte[8], 96), new byte[16], new byte[32]);
        var secret = new PgpSecretKeyRing(encrypted, [], owner.SecretKeyRing.UserIds, [], [real]);
        Assert.True(secret.MasterKey.IsEncrypted);
        AssertStatus(secret.ExtractPublicKeyRing(), secret, PgpRevocationReason.KeyCompromised, "Confirmed");
    }

    [Fact]
    public void NoPrimaryRevocation_ReturnsNoEvidence()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519WithX25519Subkey();
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(owner.MasterSecretKey).WithSubkey(owner.PublicKeyRing.Subkeys[0]);
        var (pub, secret) = Rings(owner, [revoker.RevokeSubkey()], true);
        Assert.False(pub.IsRevoked);
        Assert.False(secret.IsKeyRevoked);
        Assert.Null(pub.GetRevocationReason());
        Assert.Null(secret.GetRevocationReason());
    }

    private static PgpKeyGeneratorResult Generate(int version, bool ed25519 = false)
    {
        var generator = PgpKeyGenerator.Create().WithVersion((byte)version).WithCreationTime(Created).WithUserId("owner@example.invalid").WithKeySize(2048);
        return ed25519 ? generator.GenerateEd25519() : generator.GenerateRsa();
    }

    private static PgpSignaturePacket Revoke(PgpKeyGeneratorResult owner, PgpRevocationReason reason, string text)
    {
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(owner.MasterSecretKey).WithReason(reason, text).WithRevocationTime(Created.AddHours(1));
        return revoker.RevokeKey();
    }

    private static PgpSignaturePacket Invalid(PgpKeyGeneratorResult owner, int kind)
    {
        if (kind == 0) return PgpSignaturePacket.CreateV4(PgpSignatureType.KeyRevocation, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(Created)], [], 0, new byte[] { 0 });
        if (kind == 1) return Revoke(Generate(owner.MasterPublicKey.Version), PgpRevocationReason.KeyRetired, "Untrusted");
        var real = Revoke(owner, PgpRevocationReason.KeyCompromised, "Original");
        var hashed = real.HashedSubpackets.Where(x => x.Type != PgpSignatureSubpacketType.ReasonForRevocation)
            .Append(PgpSignatureSubpacket.CreateReasonForRevocation(PgpRevocationReason.KeyRetired, "Tampered")).ToArray();
        return real.Version == 4
            ? PgpSignaturePacket.CreateV4(real.SignatureType, real.PublicKeyAlgorithm, real.HashAlgorithm, hashed, real.UnhashedSubpackets, real.HashPrefix, real.SignatureData)
            : PgpSignaturePacket.CreateV6(real.SignatureType, real.PublicKeyAlgorithm, real.HashAlgorithm, hashed, real.UnhashedSubpackets, real.HashPrefix, real.Salt, real.SignatureData);
    }

    private static (PgpPublicKeyRing Public, PgpSecretKeyRing Secret) Rings(PgpKeyGeneratorResult owner, PgpSignaturePacket[] candidates, bool reimport)
    {
        var signatures = owner.PublicKeyRing.Signatures.Concat(candidates).ToArray();
        var pub = new PgpPublicKeyRing(owner.MasterPublicKey, owner.PublicKeyRing.Subkeys, owner.PublicKeyRing.UserIds, owner.PublicKeyRing.UserAttributes, signatures);
        var secret = new PgpSecretKeyRing(owner.MasterSecretKey, owner.SecretKeyRing.Subkeys, owner.SecretKeyRing.UserIds, owner.SecretKeyRing.UserAttributes, signatures);
        return reimport ? (PgpPublicKeyRing.Read(pub.ToArray()), PgpSecretKeyRing.Read(secret.ToArray())) : (pub, secret);
    }

    private static void AssertStatus(PgpPublicKeyRing pub, PgpSecretKeyRing secret, PgpRevocationReason reason, string? text)
    {
        Assert.True(pub.IsRevoked);
        Assert.True(secret.IsKeyRevoked);
        Assert.Equal((reason, text), pub.GetRevocationReason());
        Assert.Equal((reason, text), secret.GetRevocationReason());
    }

    private static PgpKeyValidationResult Validate(PgpPublicKeyRing ring)
    {
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).CheckRevocation();
        return validator.Validate();
    }

    // Construct RFC V4 key-revocation bytes and sign with platform RSA, independently of PgpKeyRevoker.
    private static PgpSignaturePacket Sign(PgpKeyGeneratorResult owner, PgpSignatureSubpacket[] reasons,
        bool expectSupported = true, PgpSignatureSubpacket[]? unhashed = null)
    {
        var packets = new[] { PgpSignatureSubpacket.CreateSignatureCreationTime(Created.AddHours(1)) }.Concat(reasons).ToArray();
        var hashed = PgpSignatureSubpacket.WriteAll(packets);
        var key = owner.MasterPublicKey.ToArray();
        var keyPrefix = new byte[] { 0x99, 0, 0 };
        BinaryPrimitives.WriteUInt16BigEndian(keyPrefix.AsSpan(1), checked((ushort)key.Length));
        var header = new byte[] { 4, 0x20, 1, 8, 0, 0 };
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)hashed.Length));
        var trailer = new byte[] { 4, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)(header.Length + hashed.Length));
        var digest = SHA256.HashData(keyPrefix.Concat(key).Concat(header).Concat(hashed).Concat(trailer).ToArray());
        var (d, p, q, _) = owner.MasterSecretKey.ReadRsaSecretKey();
        var (n, e) = owner.MasterPublicKey.ReadRsaKey();
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RsaCore().ToRsaParameters(new RsaPrivateKey(n, d, p, q, e)));
        var raw = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(rsa.VerifyHash(digest, raw, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var mpi = new byte[Mpi.GetEncodedLength(raw)];
        Mpi.Write(raw, mpi);
        var signature = PgpSignaturePacket.CreateV4(PgpSignatureType.KeyRevocation, 1, 8, packets, unhashed ?? [], BinaryPrimitives.ReadUInt16BigEndian(digest), mpi);
        using var verifier = PgpSignatureVerifier.Create();
        Assert.Equal(expectSupported, verifier.VerifyKeyRevocation(signature, owner.MasterPublicKey).IsValid);
        return signature;
    }
}
