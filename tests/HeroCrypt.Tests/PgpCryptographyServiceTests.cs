using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using System.Text;

namespace HeroCrypt.Tests;

public class PgpCryptographyServiceTests
{
    private readonly PgpCryptographyService _service;

    // Lazy initialization to avoid key generation when tests are filtered out
    private static readonly Lazy<Task<KeyPair>> _lazyTestKeyPair = new(() =>
        new PgpCryptographyService().GenerateKeyPairAsync(512));

    private static readonly Lazy<Task<KeyPair>> _lazyTestKeyPair1024 = new(() =>
        new PgpCryptographyService().GenerateKeyPairAsync(1024));

    private static Task<KeyPair> GetSmallKeyPairAsync() => _lazyTestKeyPair.Value;
    private static Task<KeyPair> GetLargeKeyPairAsync() => _lazyTestKeyPair1024.Value; // Reuse 1024-bit key to save time

    public PgpCryptographyServiceTests()
    {
        _service = new PgpCryptographyService();
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
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
    [Trait("Category", TestCategories.Slow)]
    public async Task GenerateKeyPairAsyncWithIdentityIncludesIdentityInKeys()
    {
        var identity = "test@example.com";

        var keyPair = await _service.GenerateKeyPairAsync(identity, "", 1024, CancellationToken.None);

        Assert.Contains(identity, keyPair.PublicKey);
        Assert.Contains(identity, keyPair.PrivateKey);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    [Trait("Category", TestCategories.Integration)]
    public async Task EncryptDecryptTextWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalText = "This is a secret message!";

        var encrypted = await _service.EncryptTextAsync(originalText, keyPair.PublicKey, CancellationToken.None);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, CancellationToken.None);

        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    [Trait("Category", TestCategories.Integration)]
    public async Task EncryptDecryptBytesWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalData = Encoding.UTF8.GetBytes("This is binary data!");

        var encrypted = await _service.EncryptAsync(originalData, keyPair.PublicKey, CancellationToken.None);
        var decrypted = await _service.DecryptAsync(encrypted, keyPair.PrivateKey, CancellationToken.None);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task EncryptProducesDifferentOutputForSameInput()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalText = "Same message";

        var encrypted1 = await _service.EncryptTextAsync(originalText, keyPair.PublicKey, CancellationToken.None);
        var encrypted2 = await _service.EncryptTextAsync(originalText, keyPair.PublicKey, CancellationToken.None);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task EncryptedMessageHasPgpFormat()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var originalText = "Test message";

        var encrypted = await _service.EncryptTextAsync(originalText, keyPair.PublicKey, CancellationToken.None);

        Assert.Contains("BEGIN PGP MESSAGE", encrypted);
        Assert.Contains("END PGP MESSAGE", encrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task DecryptWithWrongKeyThrowsException()
    {
        var keyPair1 = await GetSmallKeyPairAsync();
        var keyPair2 = await _service.GenerateKeyPairAsync(512, CancellationToken.None); // Generate small key for this test
        var originalText = "Secret";

        var encrypted = await _service.EncryptTextAsync(originalText, keyPair1.PublicKey, CancellationToken.None);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _service.DecryptTextAsync(encrypted, keyPair2.PrivateKey, CancellationToken.None));
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
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

            var encrypted = await _service.EncryptTextAsync(message, keyPair.PublicKey, CancellationToken.None);
            var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, CancellationToken.None);

            Assert.Equal(message, decrypted);
        }
    }


    [Fact]
    [Trait("Category", TestCategories.Slow)]
    [Trait("Category", TestCategories.Integration)]
    public async Task EncryptDecryptLargeDataWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var largeText = new string('A', 1000);

        var encrypted = await _service.EncryptTextAsync(largeText, keyPair.PublicKey, CancellationToken.None);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, CancellationToken.None);

        Assert.Equal(largeText, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task EncryptDecryptSpecialCharactersWorksCorrectly()
    {
        var keyPair = await GetSmallKeyPairAsync();
        var specialText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~\n\t\r";

        var encrypted = await _service.EncryptTextAsync(specialText, keyPair.PublicKey, CancellationToken.None);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, CancellationToken.None);

        Assert.Equal(specialText, decrypted);
    }
    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task EncryptDecryptTextWithPassphraseProtectedKeyWorks()
    {
        var passphrase = "strong-passphrase";
        var keyPair = await _service.GenerateKeyPairAsync("secure@example.com", passphrase, 512, CancellationToken.None);
        var originalText = "Message protected by passphrase";

        var encrypted = await _service.EncryptTextAsync(originalText, keyPair.PublicKey, CancellationToken.None);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, passphrase, CancellationToken.None);

        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task DecryptingPassphraseProtectedKeyWithoutPassphraseThrows()
    {
        var passphrase = "another-passphrase";
        var keyPair = await _service.GenerateKeyPairAsync("nopass@example.com", passphrase, 512, CancellationToken.None);
        var encrypted = await _service.EncryptTextAsync("protected", keyPair.PublicKey, CancellationToken.None);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, CancellationToken.None));
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    public async Task DecryptingWithWrongPassphraseThrows()
    {
        var keyPair = await _service.GenerateKeyPairAsync("wrong@example.com", "correct-passphrase", 512, CancellationToken.None);
        var encrypted = await _service.EncryptTextAsync("protected", keyPair.PublicKey, CancellationToken.None);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.DecryptTextAsync(encrypted, keyPair.PrivateKey, "incorrect-passphrase", CancellationToken.None));
    }

    [Fact]
    [Trait("Category", TestCategories.Slow)]
    [Trait("Category", TestCategories.Integration)]
    public async Task SenderCanEncryptAndRecipientCanReply()
    {
        var senderPassphrase = "sender-secret";
        var recipientPassphrase = "recipient-secret";

        var sender = await _service.GenerateKeyPairAsync("alice@example.com", senderPassphrase, 512, CancellationToken.None);
        var recipient = await _service.GenerateKeyPairAsync("bob@example.com", recipientPassphrase, 512, CancellationToken.None);

        var outgoingMessage = "Hello Bob, this is Alice.";
        var encryptedForRecipient = await _service.EncryptTextAsync(outgoingMessage, recipient.PublicKey, CancellationToken.None);
        var decryptedByRecipient = await _service.DecryptTextAsync(encryptedForRecipient, recipient.PrivateKey, recipientPassphrase, CancellationToken.None);

        Assert.Equal(outgoingMessage, decryptedByRecipient);

        var replyMessage = "Hi Alice, message received.";
        var encryptedReply = await _service.EncryptTextAsync(replyMessage, sender.PublicKey, CancellationToken.None);
        var decryptedBySender = await _service.DecryptTextAsync(encryptedReply, sender.PrivateKey, senderPassphrase, CancellationToken.None);

        Assert.Equal(replyMessage, decryptedBySender);
    }
}









