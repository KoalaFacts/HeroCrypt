using HeroCrypt.Abstractions;
using HeroCrypt.Services;

namespace HeroCrypt.Tests;


/// <summary>
/// Unit tests for Cryptographic Key Generation Service functionality
/// </summary>
public class CryptographicKeyGenerationServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Constructor_InitializesCorrectly()
    {
        var service = new CryptographicKeyGenerationService();

        Assert.NotNull(service);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRandomBytes_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var bytes = service.GenerateRandomBytes(32);

        Assert.Equal(32, bytes.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRandomBytes_WithZeroLength_ReturnsEmptyArray()
    {
        var service = new CryptographicKeyGenerationService();

        var result = service.GenerateRandomBytes(0);
        Assert.Empty(result);
        Assert.Equal(0, result.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRandomBytes_WithNegativeLength_ThrowsException()
    {
        var service = new CryptographicKeyGenerationService();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateRandomBytes(-5));
        Assert.Contains("Length cannot be negative", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRandomBytes_ProducesUniqueValues()
    {
        var service = new CryptographicKeyGenerationService();

        var bytes1 = service.GenerateRandomBytes(32);
        var bytes2 = service.GenerateRandomBytes(32);

        Assert.NotEqual(bytes1, bytes2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public async Task GenerateRandomBytesAsync_WorksCorrectly()
    {
        var service = new CryptographicKeyGenerationService();

        var bytes = await service.GenerateRandomBytesAsync(16);

        Assert.Equal(16, bytes.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public async Task GenerateRandomBytesAsync_WithCancellation_ThrowsWhenCancelled()
    {
        var service = new CryptographicKeyGenerationService();
        var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.GenerateRandomBytesAsync(32, cts.Token));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSymmetricKey_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateSymmetricKey(32);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSymmetricKey_Aes128_Returns16Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.Aes128);

        Assert.Equal(16, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSymmetricKey_Aes192_Returns24Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.Aes192);

        Assert.Equal(24, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSymmetricKey_Aes256_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.Aes256);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSymmetricKey_ChaCha20_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.ChaCha20);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSymmetricKey_ChaCha20Poly1305_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.ChaCha20Poly1305);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateIV_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var iv = service.GenerateIV(16);

        Assert.Equal(16, iv.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateIV_Aes128_Returns16Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var iv = service.GenerateIV(CryptographicAlgorithm.Aes128);

        Assert.Equal(16, iv.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateIV_ChaCha20_Returns12Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var iv = service.GenerateIV(CryptographicAlgorithm.ChaCha20);

        Assert.Equal(12, iv.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSalt_DefaultLength_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var salt = service.GenerateSalt();

        Assert.Equal(32, salt.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSalt_CustomLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var salt = service.GenerateSalt(64);

        Assert.Equal(64, salt.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateNonce_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var nonce = service.GenerateNonce(12);

        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateNonce_ChaCha20_Returns12Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var nonce = service.GenerateNonce(NonceAlgorithm.ChaCha20);

        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateNonce_AesGcm_Returns12Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var nonce = service.GenerateNonce(NonceAlgorithm.AesGcm);

        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRsaKeyPair_DefaultSize_ReturnsValidKeyPair()
    {
        var service = new CryptographicKeyGenerationService();

        var (privateKey, publicKey) = service.GenerateRsaKeyPair();

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
        Assert.NotEqual(privateKey, publicKey);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRsaKeyPair_1024Bits_ReturnsValidKeyPair()
    {
        var service = new CryptographicKeyGenerationService();

        var (privateKey, publicKey) = service.GenerateRsaKeyPair(1024);

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRsaKeyPair_InvalidKeySize_ThrowsException()
    {
        var service = new CryptographicKeyGenerationService();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateRsaKeyPair(512));
        Assert.Contains("RSA key size must be at least 1024 bits", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateRsaKeyPair_NonMultipleOf8_ThrowsException()
    {
        var service = new CryptographicKeyGenerationService();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateRsaKeyPair(2049));
        Assert.Contains("must be a multiple of 8", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public async Task GenerateRsaKeyPairAsync_WorksCorrectly()
    {
        var service = new CryptographicKeyGenerationService();

        var (privateKey, publicKey) = await service.GenerateRsaKeyPairAsync(1024);

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateHmacKey_SHA256_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateHmacKey(HeroCrypt.Abstractions.HashAlgorithmName.SHA256);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateHmacKey_SHA384_Returns48Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateHmacKey(HeroCrypt.Abstractions.HashAlgorithmName.SHA384);

        Assert.Equal(48, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateHmacKey_SHA512_Returns64Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateHmacKey(HeroCrypt.Abstractions.HashAlgorithmName.SHA512);

        Assert.Equal(64, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateHmacKey_Blake2b_Returns64Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var key = service.GenerateHmacKey(HeroCrypt.Abstractions.HashAlgorithmName.Blake2b);

        Assert.Equal(64, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateKeyDerivationMaterial_DefaultLength_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerationService();

        var material = service.GenerateKeyDerivationMaterial();

        Assert.Equal(32, material.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateKeyDerivationMaterial_CustomLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var material = service.GenerateKeyDerivationMaterial(64);

        Assert.Equal(64, material.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void ValidateKeyMaterial_ValidAesKey_ReturnsTrue()
    {
        var service = new CryptographicKeyGenerationService();
        var key = service.GenerateSymmetricKey(32);

        var isValid = service.ValidateKeyMaterial(key, "AES256");

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void ValidateKeyMaterial_TooShortKey_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerationService();
        var key = service.GenerateSymmetricKey(8); // Too short for AES

        var isValid = service.ValidateKeyMaterial(key, "AES128");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void ValidateKeyMaterial_AllZeroKey_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerationService();
        var key = new byte[32]; // All zeros

        var isValid = service.ValidateKeyMaterial(key, "AES256");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void ValidateKeyMaterial_NullKey_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerationService();

        var isValid = service.ValidateKeyMaterial(null!, "AES256");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void ValidateKeyMaterial_EmptyAlgorithm_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerationService();
        var key = service.GenerateSymmetricKey(32);

        var isValid = service.ValidateKeyMaterial(key, "");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_DefaultLength_Returns32Characters()
    {
        var service = new CryptographicKeyGenerationService();

        var password = service.GenerateSecurePassword();

        Assert.Equal(32, password.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_CustomLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerationService();

        var password = service.GenerateSecurePassword(16);

        Assert.Equal(16, password.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_WithSymbols_ContainsSymbols()
    {
        var service = new CryptographicKeyGenerationService();

        var password = service.GenerateSecurePassword(50, includeSymbols: true);

        var symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        Assert.True(password.Any(c => symbols.Contains(c)));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_WithNumbers_ContainsNumbers()
    {
        var service = new CryptographicKeyGenerationService();

        var password = service.GenerateSecurePassword(50, includeNumbers: true);

        Assert.True(password.Any(char.IsDigit));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_WithUppercase_ContainsUppercase()
    {
        var service = new CryptographicKeyGenerationService();

        var password = service.GenerateSecurePassword(50, includeUppercase: true);

        Assert.True(password.Any(char.IsUpper));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_WithLowercase_ContainsLowercase()
    {
        var service = new CryptographicKeyGenerationService();

        var password = service.GenerateSecurePassword(50, includeLowercase: true);

        Assert.True(password.Any(char.IsLower));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_AllCharacterSetsDisabled_ThrowsException()
    {
        var service = new CryptographicKeyGenerationService();

        var ex = Assert.Throws<ArgumentException>(() =>
            service.GenerateSecurePassword(32, false, false, false, false));
        Assert.Contains("At least one character set must be included", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_ZeroLength_ThrowsException()
    {
        var service = new CryptographicKeyGenerationService();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateSecurePassword(0));
        Assert.Contains("Password length must be positive", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateSecurePassword_ProducesUniquePasswords()
    {
        var service = new CryptographicKeyGenerationService();

        var password1 = service.GenerateSecurePassword(32);
        var password2 = service.GenerateSecurePassword(32);

        Assert.NotEqual(password1, password2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void MultipleGenerations_ProduceUniqueResults()
    {
        var service = new CryptographicKeyGenerationService();

        var key1 = service.GenerateSymmetricKey(32);
        var key2 = service.GenerateSymmetricKey(32);
        var salt1 = service.GenerateSalt();
        var salt2 = service.GenerateSalt();
        var nonce1 = service.GenerateNonce(12);
        var nonce2 = service.GenerateNonce(12);

        Assert.NotEqual(key1, key2);
        Assert.NotEqual(salt1, salt2);
        Assert.NotEqual(nonce1, nonce2);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void KeyGeneration_ProducesHighEntropyKeys()
    {
        var service = new CryptographicKeyGenerationService();

        // Generate multiple keys and check they're all different
        var keys = new byte[10][];
        for (var i = 0; i < 10; i++)
        {
            keys[i] = service.GenerateSymmetricKey(32);
        }

        // All keys should be different
        for (var i = 0; i < keys.Length; i++)
        {
            for (var j = i + 1; j < keys.Length; j++)
            {
                Assert.NotEqual(keys[i], keys[j]);
            }
        }
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_HandlesLargeKeyGeneration()
    {
        var service = new CryptographicKeyGenerationService();

        // Generate a large key (1KB)
        var largeKey = service.GenerateSymmetricKey(1024);

        Assert.Equal(1024, largeKey.Length);

        // Ensure it's not all zeros
        Assert.True(largeKey.Any(b => b != 0));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_ThreadSafety_MultipleThreadsCanGenerate()
    {
        var service = new CryptographicKeyGenerationService();
        var tasks = new Task<byte[]>[10];

        // Generate keys on multiple threads
        for (var i = 0; i < tasks.Length; i++)
        {
            tasks[i] = Task.Run(() => service.GenerateSymmetricKey(32));
        }

        Task.WaitAll(tasks);

        // All tasks should complete successfully and produce unique results
        for (var i = 0; i < tasks.Length; i++)
        {
            Assert.Equal(32, tasks[i].Result.Length);
            for (var j = i + 1; j < tasks.Length; j++)
            {
                Assert.NotEqual(tasks[i].Result, tasks[j].Result);
            }
        }
    }
}


