using System.Text;
using HeroCrypt.Encryption;
using HeroCrypt.KeyManagement;

namespace HeroCrypt.Tests;

public class PgpCryptographyServiceTests
{
    private readonly PgpCryptographyService service;

    // Lazy initialization to avoid key generation when tests are filtered out
    private static readonly Lazy<Task<KeyPair>> lazyTestKeyPair = new(() =>
        new PgpCryptographyService().GenerateKeyPairAsync(512, TestContext.Current.CancellationToken));

    private static readonly Lazy<Task<KeyPair>> lazyTestKeyPair1024 = new(() =>
        new PgpCryptographyService().GenerateKeyPairAsync(1024, TestContext.Current.CancellationToken));

    private static Task<KeyPair> GetSmallKeyPairAsync() => lazyTestKeyPair.Value;
    private static Task<KeyPair> GetLargeKeyPairAsync() => lazyTestKeyPair1024.Value; // Reuse 1024-bit key to save time

    public PgpCryptographyServiceTests()
    {
        service = new PgpCryptographyService();
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task GenerateKeyPairAsyncReturnsValidKeyPair()
    {
        var keyPair = await GetSmallKeyPairAsync();

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKey);
        Assert.NotNull(keyPair.PrivateKey);
        Assert.Contains("BEGIN PGP PUBLIC KEY", keyPair.PublicKey);
        Assert.Contains("BEGIN PGP PRIVATE KEY", keyPair.PrivateKey);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task GenerateKeyPairAsyncWithIdentityIncludesIdentityInKeys()
    {
        var identity = "test@example.com";

        var keyPair = await service.GenerateKeyPairAsync(identity, "", 1024, TestContext.Current.CancellationToken);

        Assert.Contains(identity, keyPair.PublicKey);
        Assert.Contains(identity, keyPair.PrivateKey);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    [Trait("Category", TestCategories.INTEGRATION)]
    public async Task EncryptDecryptTextWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalText = "This is a secret message!";

        var encrypted = await service.EncryptTextAsync(originalText, keyPair.PublicKey, TestContext.Current.CancellationToken);
        var decrypted = await service.DecryptTextAsync(encrypted, keyPair.PrivateKey, TestContext.Current.CancellationToken);

        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    [Trait("Category", TestCategories.INTEGRATION)]
    public async Task EncryptDecryptBytesWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalData = Encoding.UTF8.GetBytes("This is binary data!");

        var encrypted = await service.EncryptAsync(originalData, keyPair.PublicKey, TestContext.Current.CancellationToken);
        var decrypted = await service.DecryptAsync(encrypted, keyPair.PrivateKey, TestContext.Current.CancellationToken);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task EncryptProducesDifferentOutputForSameInput()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalText = "Same message";

        var encrypted1 = await service.EncryptTextAsync(originalText, keyPair.PublicKey, TestContext.Current.CancellationToken);
        var encrypted2 = await service.EncryptTextAsync(originalText, keyPair.PublicKey, TestContext.Current.CancellationToken);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task EncryptedMessageHasPgpFormat()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalText = "Test message";

        var encrypted = await service.EncryptTextAsync(originalText, keyPair.PublicKey, TestContext.Current.CancellationToken);

        Assert.Contains("BEGIN PGP MESSAGE", encrypted);
        Assert.Contains("END PGP MESSAGE", encrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task DecryptWithWrongKeyThrowsException()
    {
        var keyPair1 = await GetSmallKeyPairAsync();
        var keyPair2 = await service.GenerateKeyPairAsync(512, TestContext.Current.CancellationToken); // Generate small key for this test
        var originalText = "Secret";

        var encrypted = await service.EncryptTextAsync(originalText, keyPair1.PublicKey, TestContext.Current.CancellationToken);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await service.DecryptTextAsync(encrypted, keyPair2.PrivateKey, TestContext.Current.CancellationToken));
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task GenerateKeyPairAsyncDifferentKeySizesWorkCorrectly()
    {
        // Test with pre-generated keys to avoid slow generation
        var smallKeyPair = await GetSmallKeyPairAsync();
        var largeKeyPair = await GetLargeKeyPairAsync();

        var testCases = new[]
        {
            (512, smallKeyPair),
            (1024, largeKeyPair)
        };

        foreach (var (size, keyPair) in testCases)
        {
            var message = "Test message for key size " + size;

            var encrypted = await service.EncryptTextAsync(message, keyPair.PublicKey, TestContext.Current.CancellationToken);
            var decrypted = await service.DecryptTextAsync(encrypted, keyPair.PrivateKey, TestContext.Current.CancellationToken);

            Assert.Equal(message, decrypted);
        }
    }


    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    [Trait("Category", TestCategories.INTEGRATION)]
    public async Task EncryptDecryptLargeDataWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var largeText = new string('A', 1000);

        var encrypted = await service.EncryptTextAsync(largeText, keyPair.PublicKey, TestContext.Current.CancellationToken);
        var decrypted = await service.DecryptTextAsync(encrypted, keyPair.PrivateKey, TestContext.Current.CancellationToken);

        Assert.Equal(largeText, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task EncryptDecryptSpecialCharactersWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var specialText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~\n\t\r";

        var encrypted = await service.EncryptTextAsync(specialText, keyPair.PublicKey, TestContext.Current.CancellationToken);
        var decrypted = await service.DecryptTextAsync(encrypted, keyPair.PrivateKey, TestContext.Current.CancellationToken);

        Assert.Equal(specialText, decrypted);
    }
    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task EncryptDecryptTextWithPassphraseProtectedKeyWorks()
    {
        var passphrase = "strong-passphrase";
        var keyPair = await service.GenerateKeyPairAsync("secure@example.com", passphrase, 512, TestContext.Current.CancellationToken);
        var originalText = "Message protected by passphrase";

        var encrypted = await service.EncryptTextAsync(originalText, keyPair.PublicKey, TestContext.Current.CancellationToken);
        var decrypted = await service.DecryptTextAsync(encrypted, keyPair.PrivateKey, passphrase, TestContext.Current.CancellationToken);

        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task DecryptingPassphraseProtectedKeyWithoutPassphraseThrows()
    {
        var passphrase = "another-passphrase";
        var keyPair = await service.GenerateKeyPairAsync("nopass@example.com", passphrase, 512, TestContext.Current.CancellationToken);
        var encrypted = await service.EncryptTextAsync("protected", keyPair.PublicKey, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.DecryptTextAsync(encrypted, keyPair.PrivateKey, TestContext.Current.CancellationToken));
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    public async Task DecryptingWithWrongPassphraseThrows()
    {
        var keyPair = await service.GenerateKeyPairAsync("wrong@example.com", "correct-passphrase", 512, TestContext.Current.CancellationToken);
        var encrypted = await service.EncryptTextAsync("protected", keyPair.PublicKey, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.DecryptTextAsync(encrypted, keyPair.PrivateKey, "incorrect-passphrase", TestContext.Current.CancellationToken));
    }

    [Fact]
    [Trait("Category", TestCategories.SLOW)]
    [Trait("Category", TestCategories.INTEGRATION)]
    public async Task SenderCanEncryptAndRecipientCanReply()
    {
        var senderPassphrase = "sender-secret";
        var recipientPassphrase = "recipient-secret";

        var sender = await service.GenerateKeyPairAsync("alice@example.com", senderPassphrase, 512, TestContext.Current.CancellationToken);
        var recipient = await service.GenerateKeyPairAsync("bob@example.com", recipientPassphrase, 512, TestContext.Current.CancellationToken);

        var outgoingMessage = "Hello Bob, this is Alice.";
        var encryptedForRecipient = await service.EncryptTextAsync(outgoingMessage, recipient.PublicKey, TestContext.Current.CancellationToken);
        var decryptedByRecipient = await service.DecryptTextAsync(encryptedForRecipient, recipient.PrivateKey, recipientPassphrase, TestContext.Current.CancellationToken);

        Assert.Equal(outgoingMessage, decryptedByRecipient);

        var replyMessage = "Hi Alice, message received.";
        var encryptedReply = await service.EncryptTextAsync(replyMessage, sender.PublicKey, TestContext.Current.CancellationToken);
        var decryptedBySender = await service.DecryptTextAsync(encryptedReply, sender.PrivateKey, senderPassphrase, TestContext.Current.CancellationToken);

        Assert.Equal(replyMessage, decryptedBySender);
    }
}









