using HeroCrypt.Services;
using System.Text;

namespace HeroCrypt.Tests;

public class PgpCryptographyServiceTests
{
    private readonly PgpCryptographyService _service;

    public PgpCryptographyServiceTests()
    {
        _service = new PgpCryptographyService();
    }

    [Fact]
    public async Task GenerateKeyPairAsync_ReturnsValidKeyPair()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        
        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKey);
        Assert.NotNull(keyPair.PrivateKey);
        Assert.Contains("BEGIN PGP PUBLIC KEY", keyPair.PublicKey);
        Assert.Contains("BEGIN PGP PRIVATE KEY", keyPair.PrivateKey);
    }

    [Fact]
    public async Task GenerateKeyPairAsync_WithIdentity_IncludesIdentityInKeys()
    {
        var identity = "test@example.com";
        
        var keyPair = await _service.GenerateKeyPairAsync(identity, "", 1024);
        
        Assert.Contains(identity, keyPair.PublicKey);
        Assert.Contains(identity, keyPair.PrivateKey);
    }

    [Fact]
    public async Task EncryptDecrypt_Text_WorksCorrectly()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        var originalText = "This is a secret message!";
        
        var encrypted = await _service.EncryptTextAsync(originalText, keyPair.PublicKey);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey);
        
        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_Bytes_WorksCorrectly()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        var originalData = Encoding.UTF8.GetBytes("This is binary data!");
        
        var encrypted = await _service.EncryptAsync(originalData, keyPair.PublicKey);
        var decrypted = await _service.DecryptAsync(encrypted, keyPair.PrivateKey);
        
        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    public async Task Encrypt_ProducesDifferentOutputForSameInput()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        var originalText = "Same message";
        
        var encrypted1 = await _service.EncryptTextAsync(originalText, keyPair.PublicKey);
        var encrypted2 = await _service.EncryptTextAsync(originalText, keyPair.PublicKey);
        
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public async Task EncryptedMessage_HasPgpFormat()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        var originalText = "Test message";
        
        var encrypted = await _service.EncryptTextAsync(originalText, keyPair.PublicKey);
        
        Assert.Contains("BEGIN PGP MESSAGE", encrypted);
        Assert.Contains("END PGP MESSAGE", encrypted);
    }

    [Fact]
    public async Task Decrypt_WithWrongKey_ThrowsException()
    {
        var keyPair1 = await _service.GenerateKeyPairAsync(1024);
        var keyPair2 = await _service.GenerateKeyPairAsync(1024);
        var originalText = "Secret";
        
        var encrypted = await _service.EncryptTextAsync(originalText, keyPair1.PublicKey);
        
        await Assert.ThrowsAnyAsync<Exception>(async () => 
            await _service.DecryptTextAsync(encrypted, keyPair2.PrivateKey));
    }

    [Fact]
    public async Task GenerateKeyPairAsync_DifferentKeySizes_WorkCorrectly()
    {
        var sizes = new[] { 512, 1024, 2048 };
        
        foreach (var size in sizes)
        {
            var keyPair = await _service.GenerateKeyPairAsync(size);
            var message = "Test message for key size " + size;
            
            var encrypted = await _service.EncryptTextAsync(message, keyPair.PublicKey);
            var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey);
            
            Assert.Equal(message, decrypted);
        }
    }

    [Fact]
    public async Task EncryptDecrypt_LargeData_WorksCorrectly()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        var largeText = new string('A', 1000);
        
        var encrypted = await _service.EncryptTextAsync(largeText, keyPair.PublicKey);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey);
        
        Assert.Equal(largeText, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_SpecialCharacters_WorksCorrectly()
    {
        var keyPair = await _service.GenerateKeyPairAsync(1024);
        var specialText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~\n\t\r";
        
        var encrypted = await _service.EncryptTextAsync(specialText, keyPair.PublicKey);
        var decrypted = await _service.DecryptTextAsync(encrypted, keyPair.PrivateKey);
        
        Assert.Equal(specialText, decrypted);
    }
}