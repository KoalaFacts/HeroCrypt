using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpEncryptionCipherSecurityTests
{
    private static readonly Lazy<PgpKeyGeneratorResult> Recipient = new(() => PgpKeyGenerator.Create()
        .WithVersion(4).WithKeySize(2048).WithUserId("cipher-fixture@example.invalid").GenerateRsa());

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Twofish)]
    [InlineData(SymmetricCipherAlgorithm.Camellia128)]
    [InlineData(SymmetricCipherAlgorithm.Camellia192)]
    [InlineData(SymmetricCipherAlgorithm.Camellia256)]
    public void Encrypt_UnsupportedDataCipher_RejectsBeforeProducingMislabeledCiphertext(SymmetricCipherAlgorithm cipher)
    {
        Assert.Throws<NotSupportedException>(() =>
        {
            using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.MasterPublicKey)
                .WithSymmetricAlgorithm(cipher);
            encryptor.Encrypt("cipher-label regression"u8);
        });
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void Encrypt_SupportedAesCipher_RoundTripsWithMatchingAlgorithm(SymmetricCipherAlgorithm cipher)
    {
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.MasterPublicKey)
            .WithSymmetricAlgorithm(cipher);
        var encrypted = encryptor.Encrypt("cipher-label regression"u8);
        Assert.Equal(cipher, encrypted.SymmetricAlgorithm);
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(Recipient.Value.MasterSecretKey);
        Assert.Equal("cipher-label regression"u8.ToArray(), decryptor.Decrypt(encrypted).Data.ToArray());
    }
}
