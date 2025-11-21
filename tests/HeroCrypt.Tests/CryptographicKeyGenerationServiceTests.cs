using HeroCrypt.KeyManagement;

namespace HeroCrypt.Tests;

/// <summary>
/// Unit tests for Cryptographic Key Generation Service functionality
/// </summary>
public class CryptographicKeyGenerationServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Constructor_InitializesCorrectly()
    {
        var service = new CryptographicKeyGenerator();

        Assert.NotNull(service);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRandomBytes_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var bytes = service.GenerateRandomBytes(32);

        Assert.Equal(32, bytes.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRandomBytes_WithZeroLength_ReturnsEmptyArray()
    {
        var service = new CryptographicKeyGenerator();

        var result = service.GenerateRandomBytes(0);
        Assert.Empty(result);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRandomBytes_WithNegativeLength_ThrowsException()
    {
        var service = new CryptographicKeyGenerator();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateRandomBytes(-5));
        Assert.Contains("Length cannot be negative", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRandomBytes_ProducesUniqueValues()
    {
        var service = new CryptographicKeyGenerator();

        var bytes1 = service.GenerateRandomBytes(32);
        var bytes2 = service.GenerateRandomBytes(32);

        Assert.NotEqual(bytes1, bytes2);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public async Task GenerateRandomBytesAsync_WorksCorrectly()
    {
        var service = new CryptographicKeyGenerator();

        var bytes = await service.GenerateRandomBytesAsync(16, TestContext.Current.CancellationToken);

        Assert.Equal(16, bytes.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public async Task GenerateRandomBytesAsync_WithCancellation_ThrowsWhenCancelled()
    {
        var service = new CryptographicKeyGenerator();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.GenerateRandomBytesAsync(32, cts.Token));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSymmetricKey_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateSymmetricKey(32);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSymmetricKey_Aes128_Returns16Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.Aes128);

        Assert.Equal(16, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSymmetricKey_Aes192_Returns24Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.Aes192);

        Assert.Equal(24, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSymmetricKey_Aes256_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.Aes256);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSymmetricKey_ChaCha20_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.ChaCha20);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSymmetricKey_ChaCha20Poly1305_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateSymmetricKey(CryptographicAlgorithm.ChaCha20Poly1305);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateIV_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var iv = service.GenerateIV(16);

        Assert.Equal(16, iv.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateIV_Aes128_Returns16Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var iv = service.GenerateIV(CryptographicAlgorithm.Aes128);

        Assert.Equal(16, iv.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateIV_ChaCha20_Returns12Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var iv = service.GenerateIV(CryptographicAlgorithm.ChaCha20);

        Assert.Equal(12, iv.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSalt_DefaultLength_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var salt = service.GenerateSalt();

        Assert.Equal(32, salt.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSalt_CustomLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var salt = service.GenerateSalt(64);

        Assert.Equal(64, salt.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateNonce_WithValidLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var nonce = service.GenerateNonce(12);

        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateNonce_ChaCha20_Returns12Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var nonce = service.GenerateNonce(NonceAlgorithm.ChaCha20);

        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateNonce_AesGcm_Returns12Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var nonce = service.GenerateNonce(NonceAlgorithm.AesGcm);

        Assert.Equal(12, nonce.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRsaKeyPair_DefaultSize_ReturnsValidKeyPair()
    {
        var service = new CryptographicKeyGenerator();

        var (privateKey, publicKey) = service.GenerateRsaKeyPair();

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
        Assert.NotEqual(privateKey, publicKey);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRsaKeyPair_2048Bits_ReturnsValidKeyPair()
    {
        var service = new CryptographicKeyGenerator();

        var (privateKey, publicKey) = service.GenerateRsaKeyPair(2048);

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRsaKeyPair_InvalidKeySize_ThrowsException()
    {
        var service = new CryptographicKeyGenerator();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateRsaKeyPair(1024));
        Assert.Contains("RSA key size must be at least 2048 bits", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateRsaKeyPair_NonMultipleOf8_ThrowsException()
    {
        var service = new CryptographicKeyGenerator();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateRsaKeyPair(2049));
        Assert.Contains("must be a multiple of 8", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public async Task GenerateRsaKeyPairAsync_WorksCorrectly()
    {
        var service = new CryptographicKeyGenerator();

        var (privateKey, publicKey) = await service.GenerateRsaKeyPairAsync(2048, TestContext.Current.CancellationToken);

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateHmacKey_SHA256_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateHmacKey(HashAlgorithmName.SHA256);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateHmacKey_SHA384_Returns48Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateHmacKey(HashAlgorithmName.SHA384);

        Assert.Equal(48, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateHmacKey_SHA512_Returns64Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateHmacKey(HashAlgorithmName.SHA512);

        Assert.Equal(64, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateHmacKey_Blake2b_Returns64Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var key = service.GenerateHmacKey(HashAlgorithmName.Blake2b);

        Assert.Equal(64, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateKeyDerivationMaterial_DefaultLength_Returns32Bytes()
    {
        var service = new CryptographicKeyGenerator();

        var material = service.GenerateKeyDerivationMaterial();

        Assert.Equal(32, material.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateKeyDerivationMaterial_CustomLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var material = service.GenerateKeyDerivationMaterial(64);

        Assert.Equal(64, material.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ValidateKeyMaterial_ValidAesKey_ReturnsTrue()
    {
        var service = new CryptographicKeyGenerator();
        var key = service.GenerateSymmetricKey(32);

        var isValid = service.ValidateKeyMaterial(key, "AES256");

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ValidateKeyMaterial_TooShortKey_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerator();
        var key = service.GenerateSymmetricKey(8); // Too short for AES

        var isValid = service.ValidateKeyMaterial(key, "AES128");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ValidateKeyMaterial_AllZeroKey_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerator();
        var key = new byte[32]; // All zeros

        var isValid = service.ValidateKeyMaterial(key, "AES256");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ValidateKeyMaterial_NullKey_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerator();

        var isValid = service.ValidateKeyMaterial(null!, "AES256");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ValidateKeyMaterial_EmptyAlgorithm_ReturnsFalse()
    {
        var service = new CryptographicKeyGenerator();
        var key = service.GenerateSymmetricKey(32);

        var isValid = service.ValidateKeyMaterial(key, "");

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_DefaultLength_Returns32Characters()
    {
        var service = new CryptographicKeyGenerator();

        var password = service.GenerateSecurePassword();

        Assert.Equal(32, password.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_CustomLength_ReturnsCorrectLength()
    {
        var service = new CryptographicKeyGenerator();

        var password = service.GenerateSecurePassword(16);

        Assert.Equal(16, password.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_WithSymbols_ContainsSymbols()
    {
        var service = new CryptographicKeyGenerator();

        var password = service.GenerateSecurePassword(50, includeSymbols: true);

        var symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        Assert.Contains(password, symbols.Contains);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_WithNumbers_ContainsNumbers()
    {
        var service = new CryptographicKeyGenerator();

        var password = service.GenerateSecurePassword(50, includeNumbers: true);

        Assert.Contains(password, char.IsDigit);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_WithUppercase_ContainsUppercase()
    {
        var service = new CryptographicKeyGenerator();

        var password = service.GenerateSecurePassword(50, includeUppercase: true);

        Assert.Contains(password, char.IsUpper);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_WithLowercase_ContainsLowercase()
    {
        var service = new CryptographicKeyGenerator();

        var password = service.GenerateSecurePassword(50, includeLowercase: true);

        Assert.Contains(password, char.IsLower);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_AllCharacterSetsDisabled_ThrowsException()
    {
        var service = new CryptographicKeyGenerator();

        var ex = Assert.Throws<ArgumentException>(() =>
            service.GenerateSecurePassword(32, false, false, false, false));
        Assert.Contains("At least one character set must be included", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_ZeroLength_ThrowsException()
    {
        var service = new CryptographicKeyGenerator();

        var ex = Assert.Throws<ArgumentException>(() => service.GenerateSecurePassword(0));
        Assert.Contains("Password length must be positive", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateSecurePassword_ProducesUniquePasswords()
    {
        var service = new CryptographicKeyGenerator();

        var password1 = service.GenerateSecurePassword(32);
        var password2 = service.GenerateSecurePassword(32);

        Assert.NotEqual(password1, password2);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void MultipleGenerations_ProduceUniqueResults()
    {
        var service = new CryptographicKeyGenerator();

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
    [Trait("Category", TestCategories.COMPLIANCE)]
    public void KeyGeneration_ProducesHighEntropyKeys()
    {
        var service = new CryptographicKeyGenerator();

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
    [Trait("Category", TestCategories.UNIT)]
    public void Service_HandlesLargeKeyGeneration()
    {
        var service = new CryptographicKeyGenerator();

        // Generate a large key (1KB)
        var largeKey = service.GenerateSymmetricKey(1024);

        Assert.Equal(1024, largeKey.Length);

        // Ensure it's not all zeros
        Assert.Contains(largeKey, b => b != 0);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public async Task Service_ThreadSafety_MultipleThreadsCanGenerate()
    {
        var service = new CryptographicKeyGenerator();
        var tasks = Enumerable.Range(0, 10)
            .Select(_ => Task.Run(() => service.GenerateSymmetricKey(32), TestContext.Current.CancellationToken))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        // All tasks should complete successfully and produce unique results
        for (var i = 0; i < results.Length; i++)
        {
            Assert.Equal(32, results[i].Length);
            for (var j = i + 1; j < results.Length; j++)
            {
                Assert.NotEqual(results[i], results[j]);
            }
        }
    }
}

