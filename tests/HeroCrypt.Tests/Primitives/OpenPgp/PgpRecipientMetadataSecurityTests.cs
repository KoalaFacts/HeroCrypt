using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpRecipientMetadataSecurityTests
{
    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void RecipientMetadata_MatchesActualPkeskAndKeyVersion(int keyVersion, bool aead)
    {
        var pair = PgpKeyGenerator.Create().WithVersion((byte)keyVersion).WithKeySize(2048)
            .WithUserId("recipient-metadata@example.invalid").GenerateRsa();
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(pair.MasterPublicKey);
        if (aead) encryptor.WithAead();
        var encrypted = encryptor.Encrypt("recipient metadata"u8);
        var imported = PgpEncryptedMessage.Read(encrypted.Data.Span);
        var recipient = encrypted.Recipients[0];

        Assert.Equal(aead ? 6 : 3, recipient.Version);
        Assert.Equal(aead ? keyVersion : 0, recipient.KeyVersion);
        Assert.Equal(pair.MasterPublicKey.GetKeyId(), recipient.KeyId.ToArray());
        Assert.Equal(aead ? pair.MasterPublicKey.ComputeFingerprint() : [], recipient.Fingerprint.ToArray());
        Assert.True(recipient.MatchesKey(pair.MasterPublicKey));
        Assert.True(imported.Recipients[0].MatchesKey(pair.MasterPublicKey));
        Assert.Equal(recipient, imported.Recipients[0]);
    }
}
