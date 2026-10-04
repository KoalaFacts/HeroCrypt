using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpEncryptionKeyPolicySecurityTests
{
    private static readonly DateTimeOffset Created = DateTimeOffset.FromUnixTimeSeconds(1700000000);
    private static readonly byte[] Document = "recipient policy regression"u8.ToArray();

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Encrypt_UnboundAttackerSubkey_CannotBecomeRecipient(int version)
    {
        var owner = Generate(version, encryptionSubkey: false);
        var attacker = Generate(version, encryptionSubkey: false);
        var injectedSubkey = PgpPublicKeyPacket.Read(attacker.MasterPublicKey.ToArray(), isSubkey: true);
        var ring = new PgpPublicKeyRing(owner.MasterPublicKey, subkeys: [injectedSubkey],
            userIds: owner.PublicKeyRing.UserIds, signatures: owner.PublicKeyRing.Signatures);

        // The trusted primary fingerprint is unchanged. No owner signature binds
        // the attacker-controlled subkey, and the primary permits only signing.
        Assert.Equal(owner.PublicKeyRing.MasterFingerprint, ring.MasterFingerprint);
        Assert.Throws<InvalidOperationException>(() => Encrypt(ring));
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void Encrypt_AuthenticatedPrimaryOrSubkeyRevocation_Rejects(int version, bool subkey)
    {
        var owner = Generate(version);
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(owner.MasterSecretKey)
            .WithRevocationTime(Created.AddHours(1));
        var revocation = subkey
            ? revoker.WithSubkey(owner.PublicKeyRing.Subkeys[0]).RevokeSubkey()
            : revoker.RevokeKey();
        using var verifier = PgpSignatureVerifier.Create();
        var evidence = subkey
            ? verifier.VerifySubkeyRevocation(revocation, owner.MasterPublicKey, owner.PublicKeyRing.Subkeys[0])
            : verifier.VerifyKeyRevocation(revocation, owner.MasterPublicKey);
        Assert.True(evidence.IsValid, evidence.ErrorMessage);

        Assert.Throws<InvalidOperationException>(() => Encrypt(owner.PublicKeyRing.AddSignature(revocation)));
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void Encrypt_ExpiredPrimaryOrSubkey_Rejects(int version, bool subkey)
    {
        var generator = Generator(version).WithEncryptionSubkey();
        if (subkey) generator.WithSubkeyExpiration(TimeSpan.FromSeconds(1));
        else generator.WithExpiration(TimeSpan.FromSeconds(1));
        var owner = generator.GenerateRsa();

        Assert.Throws<InvalidOperationException>(() => Encrypt(owner.PublicKeyRing));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Encrypt_SigningOnlyPrimary_CannotBeEncryptionFallback(int version)
    {
        var owner = Generate(version, encryptionSubkey: false);
        Assert.Throws<InvalidOperationException>(() => Encrypt(owner.PublicKeyRing));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Encrypt_CurrentAuthenticatedEncryptionSubkey_RoundTrips(int version)
    {
        var owner = Generate(version);
        var encrypted = Encrypt(PgpPublicKeyRing.Read(owner.PublicKeyRing.ToArray()));
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKeyRing(owner.SecretKeyRing);
        Assert.Equal(Document, decryptor.Decrypt(encrypted).Data.ToArray());
        Assert.Equal(owner.PublicKeyRing.Subkeys[0].GetKeyId(), encrypted.Recipients[0].KeyId.ToArray());
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Encrypt_ExplicitRawKey_RemainsCallerManaged(int version)
    {
        var owner = Generate(version, encryptionSubkey: false);
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(owner.MasterPublicKey);
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(owner.MasterSecretKey);
        Assert.Equal(Document, decryptor.Decrypt(encryptor.Encrypt(Document)).Data.ToArray());
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void Encrypt_RawKeyCannotBypassConfiguredRingPolicy(int version, bool rawFirst)
    {
        // Ring selection succeeds for its valid encryption subkey; the separately
        // configured signing-only primary must still be vetoed in either order.
        var owner = Generate(version);
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var encryptor = PgpMessageEncryptor.Create();
            if (rawFirst) encryptor.AddRecipient(owner.MasterPublicKey);
            encryptor.AddRecipient(owner.PublicKeyRing);
            if (!rawFirst) encryptor.AddRecipient(owner.MasterPublicKey);
            encryptor.Encrypt(Document);
        });
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Encrypt_CurrentAuthenticatedPrimaryEncryptionPermission_RoundTrips(int version)
    {
        var owner = Generator(version).WithKeyFlags(PgpKeyCapabilities.Certify |
            PgpKeyCapabilities.EncryptCommunications).GenerateRsa();
        var encrypted = Encrypt(owner.PublicKeyRing);
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(owner.MasterSecretKey);
        Assert.Equal(Document, decryptor.Decrypt(encrypted).Data.ToArray());
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Encrypt_NewerBindingRemovesPermission_DoesNotRestoreOlderEncryptionUsage(int version)
    {
        var owner = Generate(version);
        var subkey = owner.PublicKeyRing.Subkeys[0];
        PgpSignatureSubpacket[] fields = [
            PgpSignatureSubpacket.CreateSignatureCreationTime(Created.AddHours(1)),
            PgpSignatureSubpacket.CreateIssuerFingerprint((byte)version, owner.MasterPublicKey.ComputeFingerprint()),
            PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.Authentication)
        ];
        byte[] salt = version == 6 ? new byte[16] : [];
        var digest = PgpSignatureHashHelper.ComputeKeySignatureHash(owner.MasterPublicKey, subkey,
            (byte)version, (byte)PgpSignatureType.SubkeyBinding, 1, 8,
            PgpSignatureSubpacket.WriteAll(fields), salt);
        var (n, e) = owner.MasterPublicKey.ReadRsaKey();
        var (d, p, q, _) = owner.MasterSecretKey.ReadRsaSecretKey();
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RsaCore().ToRsaParameters(new RsaPrivateKey(n, d, p, q, e)));
        var rawSignature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var binding = new PgpSignaturePacket((byte)version, PgpSignatureType.SubkeyBinding, 1, 8,
            fields, [], BinaryPrimitives.ReadUInt16BigEndian(digest), Mpi.Encode(rawSignature), salt);
        using var verifier = PgpSignatureVerifier.Create();
        Assert.True(verifier.VerifySubkeyBinding(binding, owner.MasterPublicKey, subkey).IsValid);

        Assert.Throws<InvalidOperationException>(() => Encrypt(owner.PublicKeyRing.AddSignature(binding)));
    }

    private static PgpEncryptedMessage Encrypt(PgpPublicKeyRing ring)
    {
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(ring);
        return encryptor.Encrypt(Document);
    }

    private static PgpKeyGeneratorResult Generate(int version, bool encryptionSubkey = true)
    {
        var generator = Generator(version);
        if (encryptionSubkey) generator.WithEncryptionSubkey();
        return generator.GenerateRsa();
    }

    private static PgpKeyGenerator Generator(int version) => PgpKeyGenerator.Create()
        .WithVersion((byte)version).WithCreationTime(Created).WithKeySize(2048)
        .WithKeyFlags(PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign)
        .WithUserId("owner@example.invalid");
}
