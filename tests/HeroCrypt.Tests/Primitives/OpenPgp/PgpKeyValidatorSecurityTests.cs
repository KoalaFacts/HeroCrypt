using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpKeyValidatorSecurityTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Validate_UnboundInjectedSubkey_ReturnsError(bool fullValidation)
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519();
        var attacker = PgpKeyGenerator.Create().WithUserId("attacker@example.invalid").GenerateEd25519WithX25519Subkey();
        var ring = Replace(owner.PublicKeyRing, attacker.PublicKeyRing.Subkeys, owner.PublicKeyRing.Signatures);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring);
        if (fullValidation) { validator.FullValidation(); } else { validator.VerifySubkeyBindings(); }

        var result = validator.Validate();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, x => x.Code == PgpValidationCode.MissingSubkeyBinding);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Validate_BindingForAnotherSubkeyOrPrimary_ReturnsError(bool wrongPrimary)
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519WithX25519Subkey();
        var attacker = PgpKeyGenerator.Create().WithUserId("attacker@example.invalid").GenerateEd25519WithX25519Subkey();
        var signatures = wrongPrimary
            ? owner.PublicKeyRing.Signatures.Where(x => x.SignatureType != PgpSignatureType.SubkeyBinding)
                .Concat(attacker.PublicKeyRing.Signatures.Where(x => x.SignatureType == PgpSignatureType.SubkeyBinding)).ToArray()
            : owner.PublicKeyRing.Signatures;
        var ring = Replace(owner.PublicKeyRing, attacker.PublicKeyRing.Subkeys, signatures);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).FullValidation();

        var result = validator.Validate();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, x => x.Code == PgpValidationCode.InvalidSubkeyBinding);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Validate_GenuineBinding_DoesNotReportMissingBinding(byte version)
    {
        var generated = PgpKeyGenerator.Create().WithUserId("owner@example.invalid")
            .WithKeySize(2048).WithVersion(version).WithEncryptionSubkey().GenerateRsa();
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(generated.PublicKeyRing).FullValidation();

        var result = validator.Validate();

        Assert.True(result.IsValid);
        Assert.DoesNotContain(result.Issues, x => x.Code == PgpValidationCode.MissingSubkeyBinding);
    }

    [Fact]
    public void ValidateStructureOnly_UnboundSubkey_DoesNotClaimCryptographicValidation()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519WithX25519Subkey();
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.Subkeys,
            owner.PublicKeyRing.Signatures.Where(x => x.SignatureType != PgpSignatureType.SubkeyBinding).ToArray());
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).FullValidation();

        var result = validator.ValidateStructureOnly();

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, x => x.Code == PgpValidationCode.MissingSubkeyBinding);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Validate_UnsignedKeyRevocation_DoesNotReportAuthenticatedStatus(bool fullValidation)
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").WithKeySize(2048).GenerateRsa();
        var fake = PgpSignaturePacket.CreateV4(PgpSignatureType.KeyRevocation, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.FromUnixTimeSeconds(1700000000))], [], 0, new byte[] { 0 });
        var ring = owner.PublicKeyRing.AddRevocationSignature(fake);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring);
        if (fullValidation) { validator.FullValidation(); } else { validator.CheckRevocation(); }

        var result = validator.Validate();

        Assert.False(result.IsValid);
        Assert.DoesNotContain(result.Warnings, x => x.Code == PgpValidationCode.KeyRevoked);
    }

    [Fact]
    public void Validate_KeyRevocationSignedByAnotherPrimary_ReturnsError()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519();
        var attacker = PgpKeyGenerator.Create().WithUserId("attacker@example.invalid").GenerateEd25519();
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(attacker.MasterSecretKey);
        var ring = owner.PublicKeyRing.AddRevocationSignature(revoker.RevokeKey());
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).FullValidation();

        var result = validator.Validate();

        Assert.False(result.IsValid);
        Assert.DoesNotContain(result.Warnings, x => x.Code == PgpValidationCode.KeyRevoked);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Validate_GenuineKeyRevocation_RemainsWarning(bool fullValidation)
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519();
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(owner.MasterSecretKey)
            .WithReason(PgpRevocationReason.KeyCompromised, "Confirmed compromise");
        var ring = owner.PublicKeyRing.AddRevocationSignature(revoker.RevokeKey());
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring);
        if (fullValidation) { validator.FullValidation(); } else { validator.CheckRevocation(); }

        var result = validator.Validate();

        Assert.True(result.IsValid);
        var warning = Assert.Single(result.Warnings, x => x.Code == PgpValidationCode.KeyRevoked);
        Assert.Contains("Confirmed compromise", warning.Message);
    }

    [Fact]
    public void Validate_SubkeyRevocation_ReportsOnlyTheCryptographicTarget()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519WithX25519Subkey();
        var other = PgpKeyGenerator.Create().WithUserId("other@example.invalid").GenerateEd25519WithX25519Subkey();
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(owner.MasterSecretKey).WithSubkey(owner.PublicKeyRing.Subkeys[0]);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.Subkeys.Concat(other.PublicKeyRing.Subkeys).ToArray(),
            owner.PublicKeyRing.Signatures.Append(revoker.RevokeSubkey()).ToArray());
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).CheckRevocation();

        var result = validator.Validate();

        Assert.True(result.IsValid);
        var warning = Assert.Single(result.Warnings, x => x.Code == PgpValidationCode.SubkeyRevoked);
        Assert.Contains(Convert.ToHexString(owner.PublicKeyRing.Subkeys[0].GetKeyId()), warning.Message);
    }

    [Fact]
    public void Validate_SubkeyRevocationSignedByAnotherPrimary_ReturnsError()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519WithX25519Subkey();
        var attacker = PgpKeyGenerator.Create().WithUserId("attacker@example.invalid").GenerateEd25519();
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(attacker.MasterSecretKey).WithSubkey(owner.PublicKeyRing.Subkeys[0]);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.Subkeys,
            owner.PublicKeyRing.Signatures.Append(revoker.RevokeSubkey()).ToArray());
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).FullValidation();

        var result = validator.Validate();

        Assert.False(result.IsValid);
        Assert.DoesNotContain(result.Warnings, x => x.Code == PgpValidationCode.SubkeyRevoked);
    }

    [Fact]
    public void Validate_InvalidAndValidRevocations_PreservesVerifiedReason()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").GenerateEd25519();
        var attacker = PgpKeyGenerator.Create().WithUserId("attacker@example.invalid").GenerateEd25519();
        using var fakeRevoker = PgpKeyRevoker.Create().WithSecretKey(attacker.MasterSecretKey).WithReason(PgpRevocationReason.KeyRetired, "Untrusted reason");
        using var realRevoker = PgpKeyRevoker.Create().WithSecretKey(owner.MasterSecretKey).WithReason(PgpRevocationReason.KeyCompromised, "Trusted reason");
        var ring = owner.PublicKeyRing.AddRevocationSignature(fakeRevoker.RevokeKey()).AddRevocationSignature(realRevoker.RevokeKey());
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).FullValidation();

        var result = validator.Validate();

        Assert.False(result.IsValid);
        var warning = Assert.Single(result.Warnings, x => x.Code == PgpValidationCode.KeyRevoked);
        Assert.Contains("Trusted reason", warning.Message);
        Assert.DoesNotContain("Untrusted reason", warning.Message);
    }

    private static PgpPublicKeyRing Replace(PgpPublicKeyRing ring, IReadOnlyList<PgpPublicKeyPacket> subkeys,
        IReadOnlyList<PgpSignaturePacket> signatures) =>
        new(ring.MasterKey, subkeys, ring.UserIds, ring.UserAttributes, signatures);
}
