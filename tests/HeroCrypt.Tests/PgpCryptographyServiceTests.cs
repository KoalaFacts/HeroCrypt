using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
}

