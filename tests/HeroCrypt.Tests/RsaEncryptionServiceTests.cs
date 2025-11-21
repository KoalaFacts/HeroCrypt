using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Signature.Rsa;
using HeroCrypt.Encryption;

namespace HeroCrypt.Tests;

/// <summary>
/// Unit tests for RSA Encryption Service functionality
/// </summary>
public class RsaEncryptionServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Constructor_WithValidKeySize_InitializesCorrectly()
    {
        var service = new RsaEncryptionService(2048);

        Assert.Equal("RSA-2048", service.AlgorithmName);
        Assert.Equal(2048, service.KeySizeBits);
        Assert.True(service.MaxMessageSize > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Constructor_WithInvalidKeySize_ThrowsException()
    {
        var ex = Assert.Throws<ArgumentException>(() => new RsaEncryptionService(1024));
        Assert.Contains("RSA key size must be at least 2048 bits", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Constructor_WithNonMultipleOf8_ThrowsException()
    {
        var ex = Assert.Throws<ArgumentException>(() => new RsaEncryptionService(2049));
        Assert.Contains("must be a multiple of 8", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateKeyPair_ReturnsValidKeyPair()
    {
        var service = new RsaEncryptionService(2048);

        var (privateKey, publicKey) = service.GenerateKeyPair();

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
        Assert.NotEqual(privateKey, publicKey);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void DerivePublicKey_FromPrivateKey_ReturnsConsistentResult()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, originalPublicKey) = service.GenerateKeyPair();

        var derivedPublicKey = service.DerivePublicKey(privateKey);

        Assert.Equal(originalPublicKey, derivedPublicKey);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void DerivePublicKey_WithNullPrivateKey_ThrowsException()
    {
        var service = new RsaEncryptionService();

        var ex = Assert.Throws<ArgumentNullException>(() => service.DerivePublicKey(null!));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithValidInputs_ReturnsEncryptedData()
    {
        var service = new RsaEncryptionService(2048);
        var (_, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message for encryption");

        var encrypted = service.Encrypt(data, publicKey);

        Assert.NotNull(encrypted);
        Assert.True(encrypted.Length > 0);
        Assert.NotEqual(data, encrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithPkcs1Padding_Works()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Pkcs1);
        var (_, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message");

        var encrypted = service.Encrypt(data, publicKey, RsaPaddingMode.Pkcs1);

        Assert.NotNull(encrypted);
        Assert.True(encrypted.Length > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithOaepPadding_Works()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Oaep);
        var (_, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message");

        var encrypted = service.Encrypt(data, publicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);

        Assert.NotNull(encrypted);
        Assert.True(encrypted.Length > 0);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithNullData_ThrowsException()
    {
        var service = new RsaEncryptionService();
        var (_, publicKey) = service.GenerateKeyPair();

        var ex = Assert.Throws<ArgumentNullException>(() => service.Encrypt(null!, publicKey));
        Assert.Equal("data", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithNullPublicKey_ThrowsException()
    {
        var service = new RsaEncryptionService();
        var data = Encoding.UTF8.GetBytes("test");

        var ex = Assert.Throws<ArgumentNullException>(() => service.Encrypt(data, null!));
        Assert.Equal("publicKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Decrypt_WithValidInputs_ReturnsOriginalData()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var originalData = Encoding.UTF8.GetBytes("Test message for decryption");

        var encrypted = service.Encrypt(originalData, publicKey);
        var decrypted = service.Decrypt(encrypted, privateKey);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Decrypt_WithPkcs1Padding_Works()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Pkcs1);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var originalData = Encoding.UTF8.GetBytes("Test message");

        var encrypted = service.Encrypt(originalData, publicKey, RsaPaddingMode.Pkcs1);
        var decrypted = service.Decrypt(encrypted, privateKey, RsaPaddingMode.Pkcs1);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Decrypt_WithOaepPadding_Works()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Oaep);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var originalData = Encoding.UTF8.GetBytes("Test message");

        var encrypted = service.Encrypt(originalData, publicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);
        var decrypted = service.Decrypt(encrypted, privateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);

        Assert.Equal(originalData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Decrypt_WithNullEncryptedData_ThrowsException()
    {
        var service = new RsaEncryptionService();
        var (privateKey, _) = service.GenerateKeyPair();

        var ex = Assert.Throws<ArgumentNullException>(() => service.Decrypt(null!, privateKey));
        Assert.Equal("encryptedData", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Decrypt_WithNullPrivateKey_ThrowsException()
    {
        var service = new RsaEncryptionService();
        var encrypted = new byte[256];

        var ex = Assert.Throws<ArgumentNullException>(() => service.Decrypt(encrypted, null!));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void EncryptDecrypt_RoundTrip_PreservesData()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var testData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        var encrypted = service.Encrypt(testData, publicKey);
        var decrypted = service.Decrypt(encrypted, privateKey);

        Assert.Equal(testData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void EncryptDecrypt_WithDifferentPaddings_Works()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var testData = Encoding.UTF8.GetBytes("Test message");

        // Test PKCS#1
        var encryptedPkcs1 = service.Encrypt(testData, publicKey, RsaPaddingMode.Pkcs1);
        var decryptedPkcs1 = service.Decrypt(encryptedPkcs1, privateKey, RsaPaddingMode.Pkcs1);
        Assert.Equal(testData, decryptedPkcs1);

        // Test OAEP
        var encryptedOaep = service.Encrypt(testData, publicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);
        var decryptedOaep = service.Decrypt(encryptedOaep, privateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);
        Assert.Equal(testData, decryptedOaep);

        // Verify different ciphertexts
        Assert.NotEqual(encryptedPkcs1, encryptedOaep);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithWrongPaddingOnDecrypt_Fails()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var testData = Encoding.UTF8.GetBytes("Test message");

        var encrypted = service.Encrypt(testData, publicKey, RsaPaddingMode.Pkcs1);

        // Should fail when trying to decrypt with wrong padding
        Assert.ThrowsAny<CryptographicException>(() =>
            service.Decrypt(encrypted, privateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_WithWrongPrivateKey_FailsDecryption()
    {
        var service = new RsaEncryptionService(2048);
        var (_, publicKey1) = service.GenerateKeyPair();
        var (privateKey2, _) = service.GenerateKeyPair();
        var testData = Encoding.UTF8.GetBytes("Test message");

        var encrypted = service.Encrypt(testData, publicKey1);

        // Should fail when trying to decrypt with wrong private key
        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted, privateKey2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void KeyPairGeneration_ProducesUniqueKeys()
    {
        var service = new RsaEncryptionService(2048);

        var (privateKey1, publicKey1) = service.GenerateKeyPair();
        var (privateKey2, publicKey2) = service.GenerateKeyPair();

        Assert.NotEqual(privateKey1, privateKey2);
        Assert.NotEqual(publicKey1, publicKey2);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_SameDataTwice_ProducesDifferentCiphertexts()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Oaep);
        var (_, publicKey) = service.GenerateKeyPair();
        var testData = Encoding.UTF8.GetBytes("Same message");

        var encrypted1 = service.Encrypt(testData, publicKey);
        var encrypted2 = service.Encrypt(testData, publicKey);

        // OAEP uses randomization, so ciphertexts should differ
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void MaxMessageSize_ReturnsCorrectValue()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Oaep);
        var maxSize = service.MaxMessageSize;

        // For 2048-bit RSA with OAEP-SHA256:
        // 2048 bits = 256 bytes
        // SHA256 = 32 bytes
        // Max message = 256 - 2*32 - 2 = 190 bytes
        Assert.Equal(190, maxSize);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_ExceedsMaxMessageSize_ThrowsException()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Oaep);
        var (_, publicKey) = service.GenerateKeyPair();

        // Create data larger than max message size
        var largeData = new byte[service.MaxMessageSize + 10];

        var ex = Assert.Throws<ArgumentException>(() => service.Encrypt(largeData, publicKey));
        Assert.Contains("exceeds maximum message size", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Encrypt_AtMaxMessageSize_Works()
    {
        var service = new RsaEncryptionService(2048, RsaPaddingMode.Oaep);
        var (privateKey, publicKey) = service.GenerateKeyPair();

        // Create data exactly at max message size
        var maxData = new byte[service.MaxMessageSize];
        new Random(42).NextBytes(maxData);

        var encrypted = service.Encrypt(maxData, publicKey);
        var decrypted = service.Decrypt(encrypted, privateKey);

        Assert.Equal(maxData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public async Task EncryptAsync_WorksCorrectly()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Async encryption test");

        var encrypted = await service.EncryptAsync(data, publicKey);
        var decrypted = service.Decrypt(encrypted, privateKey);

        Assert.Equal(data, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public async Task DecryptAsync_WorksCorrectly()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Async decryption test");

        var encrypted = service.Encrypt(data, publicKey);
        var decrypted = await service.DecryptAsync(encrypted, privateKey);

        Assert.Equal(data, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public async Task AsyncOperations_ProduceSameResultsAsSyncOperations()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Sync vs Async test");

        var syncEncrypted = service.Encrypt(data, publicKey, RsaPaddingMode.Pkcs1);
        var asyncEncrypted = await service.EncryptAsync(data, publicKey, RsaPaddingMode.Pkcs1);

        // PKCS1 is deterministic (unlike OAEP), so results should match
        // Note: Actually PKCS1 has randomization too, so just verify both decrypt correctly
        var syncDecrypted = service.Decrypt(syncEncrypted, privateKey, RsaPaddingMode.Pkcs1);
        var asyncDecrypted = await service.DecryptAsync(asyncEncrypted, privateKey, RsaPaddingMode.Pkcs1);

        Assert.Equal(data, syncDecrypted);
        Assert.Equal(data, asyncDecrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Service_HandlesEmptyData_ThrowsException()
    {
        var service = new RsaEncryptionService(2048);
        var (_, publicKey) = service.GenerateKeyPair();
        var emptyData = Array.Empty<byte>();

        // Empty data should not be allowed for encryption
        Assert.Throws<ArgumentException>(() => service.Encrypt(emptyData, publicKey));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Service_HandlesBinaryData()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();

        // Create random binary data
        var binaryData = new byte[100];
        new Random(42).NextBytes(binaryData);

        var encrypted = service.Encrypt(binaryData, publicKey);
        var decrypted = service.Decrypt(encrypted, privateKey);

        Assert.Equal(binaryData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Service_HandlesUnicodeText()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var unicodeText = "Hello 世界 🌍 Привет مرحبا";
        var data = Encoding.UTF8.GetBytes(unicodeText);

        var encrypted = service.Encrypt(data, publicKey);
        var decrypted = service.Decrypt(encrypted, privateKey);
        var result = Encoding.UTF8.GetString(decrypted);

        Assert.Equal(unicodeText, result);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Service_MultipleKeySizes_Work()
    {
        var keySizes = new[] { 2048, 3072, 4096 };

        foreach (var keySize in keySizes)
        {
            var service = new RsaEncryptionService(keySize);
            var (privateKey, publicKey) = service.GenerateKeyPair();
            var data = Encoding.UTF8.GetBytes($"Test with {keySize}-bit key");

            var encrypted = service.Encrypt(data, publicKey);
            var decrypted = service.Decrypt(encrypted, privateKey);

            Assert.Equal(data, decrypted);
        }
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Service_SecurityTest_TamperedCiphertext_FailsDecryption()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Security test message");

        var encrypted = service.Encrypt(data, publicKey);
        encrypted[0] ^= 0xFF; // Tamper with the ciphertext

        // Should fail due to tampering
        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted, privateKey));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Service_PerformanceTest_MultipleOperations()
    {
        var service = new RsaEncryptionService(2048);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Performance test message");

        // Perform multiple encrypt/decrypt operations
        for (var i = 0; i < 5; i++)
        {
            var encrypted = service.Encrypt(data, publicKey);
            var decrypted = service.Decrypt(encrypted, privateKey);
            Assert.Equal(data, decrypted);
        }
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void AlgorithmName_ReflectsKeySize()
    {
        var service2048 = new RsaEncryptionService(2048);
        var service4096 = new RsaEncryptionService(4096);

        Assert.Equal("RSA-2048", service2048.AlgorithmName);
        Assert.Equal("RSA-4096", service4096.AlgorithmName);
    }

    #region PKCS#8 and X.509 Key Format Tests

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ExportPkcs8PrivateKey_WithValidKey_ReturnsValidPkcs8()
    {
        // Arrange
        var service = new RsaEncryptionService(2048);
        var (privateKey, _) = service.GenerateKeyPair();

        // Act
        var pkcs8Bytes = service.ExportPkcs8PrivateKey(privateKey);

        // Assert
        Assert.NotNull(pkcs8Bytes);
        Assert.True(pkcs8Bytes.Length > 0);

        // Verify it's valid PKCS#8 by trying to import it
        using var rsa = RSA.Create();
        var exception = Record.Exception(() => rsa.ImportPkcs8PrivateKey(pkcs8Bytes, out _));
        Assert.Null(exception);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ImportPkcs8PrivateKey_WithValidPkcs8_ImportsSuccessfully()
    {
        // Arrange - Generate a standard PKCS#8 key
        using var rsa = RSA.Create(2048);
        var pkcs8Bytes = rsa.ExportPkcs8PrivateKey();

        var service = new RsaEncryptionService(2048);

        // Act
        var importedKey = service.ImportPkcs8PrivateKey(pkcs8Bytes);

        // Assert
        Assert.NotNull(importedKey);
        Assert.True(importedKey.Length > 0);

        // Verify it works by encrypting/decrypting
        var (_, publicKey) = service.GenerateKeyPair();
        var publicKeyFromImported = service.DerivePublicKey(importedKey);

        var testData = Encoding.UTF8.GetBytes("Test encryption with imported key");
        var encrypted = service.Encrypt(testData, publicKeyFromImported);
        var decrypted = service.Decrypt(encrypted, importedKey);

        Assert.Equal(testData, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Pkcs8_ExportImportRoundtrip_PreservesKey()
    {
        // Arrange
        var service = new RsaEncryptionService(2048);
        var (originalPrivateKey, publicKey) = service.GenerateKeyPair();

        // Act - Export to PKCS#8 and import back
        var pkcs8Bytes = service.ExportPkcs8PrivateKey(originalPrivateKey);
        var importedPrivateKey = service.ImportPkcs8PrivateKey(pkcs8Bytes);

        // Assert - Both keys should produce the same results
        var testData = Encoding.UTF8.GetBytes("Test roundtrip");
        var encrypted = service.Encrypt(testData, publicKey);

        var decrypted1 = service.Decrypt(encrypted, originalPrivateKey);
        var decrypted2 = service.Decrypt(encrypted, importedPrivateKey);

        Assert.Equal(testData, decrypted1);
        Assert.Equal(testData, decrypted2);
        Assert.Equal(decrypted1, decrypted2);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ImportPkcs8PrivateKey_WithWeakKey_ThrowsException()
    {
        // Arrange - Generate a weak 1024-bit PKCS#8 key
        using var rsa = RSA.Create(1024);
        var pkcs8Bytes = rsa.ExportPkcs8PrivateKey();

        var service = new RsaEncryptionService(2048);

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => service.ImportPkcs8PrivateKey(pkcs8Bytes));
        Assert.Contains("too small", ex.Message);
        Assert.Contains("2048", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ExportSubjectPublicKeyInfo_WithValidKey_ReturnsValidX509()
    {
        // Arrange
        var service = new RsaEncryptionService(2048);
        var (_, publicKey) = service.GenerateKeyPair();

        // Act
        var spkiBytes = service.ExportSubjectPublicKeyInfo(publicKey);

        // Assert
        Assert.NotNull(spkiBytes);
        Assert.True(spkiBytes.Length > 0);

        // Verify it's valid X.509 SubjectPublicKeyInfo by trying to import it
        using var rsa = RSA.Create();
        var exception = Record.Exception(() => rsa.ImportSubjectPublicKeyInfo(spkiBytes, out _));
        Assert.Null(exception);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ImportSubjectPublicKeyInfo_WithValidX509_ImportsSuccessfully()
    {
        // Arrange - Generate a standard X.509 public key
        using var rsa = RSA.Create(2048);
        var spkiBytes = rsa.ExportSubjectPublicKeyInfo();

        var service = new RsaEncryptionService(2048);

        // Act
        var importedPublicKey = service.ImportSubjectPublicKeyInfo(spkiBytes);

        // Assert
        Assert.NotNull(importedPublicKey);
        Assert.True(importedPublicKey.Length > 0);

        // Verify it works by encrypting with imported public key
        var (privateKey, _) = service.GenerateKeyPair();
        var testData = Encoding.UTF8.GetBytes("Test encryption with imported public key");

        var encrypted = service.Encrypt(testData, importedPublicKey);

        // Should be able to encrypt without errors
        Assert.NotNull(encrypted);
        Assert.True(encrypted.Length > 0);
        Assert.NotEqual(testData, encrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void SubjectPublicKeyInfo_ExportImportRoundtrip_PreservesKey()
    {
        // Arrange
        var service = new RsaEncryptionService(2048);
        var (privateKey, originalPublicKey) = service.GenerateKeyPair();

        // Act - Export to X.509 and import back
        var spkiBytes = service.ExportSubjectPublicKeyInfo(originalPublicKey);
        var importedPublicKey = service.ImportSubjectPublicKeyInfo(spkiBytes);

        // Assert - Both public keys should work with the same private key
        var testData = Encoding.UTF8.GetBytes("Test roundtrip");

        var encrypted1 = service.Encrypt(testData, originalPublicKey);
        var encrypted2 = service.Encrypt(testData, importedPublicKey);

        // Both should decrypt to the same plaintext
        var decrypted1 = service.Decrypt(encrypted1, privateKey);
        var decrypted2 = service.Decrypt(encrypted2, privateKey);

        Assert.Equal(testData, decrypted1);
        Assert.Equal(testData, decrypted2);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Pkcs8AndX509_InteroperabilityTest()
    {
        // Arrange - Generate key pair with standard .NET RSA
        using var rsa = RSA.Create(2048);
        var pkcs8PrivateKey = rsa.ExportPkcs8PrivateKey();
        var spkiPublicKey = rsa.ExportSubjectPublicKeyInfo();

        var service = new RsaEncryptionService(2048);

        // Act - Import both keys
        var importedPrivateKey = service.ImportPkcs8PrivateKey(pkcs8PrivateKey);
        var importedPublicKey = service.ImportSubjectPublicKeyInfo(spkiPublicKey);

        // Assert - Keys should work together
        var testData = Encoding.UTF8.GetBytes("Interoperability test");
        var encrypted = service.Encrypt(testData, importedPublicKey);
        var decrypted = service.Decrypt(encrypted, importedPrivateKey);

        Assert.Equal(testData, decrypted);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    [Trait("Category", TestCategories.UNIT)]
    public void Pkcs8Export_WithDifferentKeySizes_WorksCorrectly(int keySize)
    {
        // Arrange
        var service = new RsaEncryptionService(keySize);
        var (privateKey, _) = service.GenerateKeyPair();

        // Act
        var pkcs8Bytes = service.ExportPkcs8PrivateKey(privateKey);

        // Assert
        Assert.NotNull(pkcs8Bytes);

        // Verify key size is preserved
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8Bytes, out _);
        Assert.Equal(keySize, rsa.KeySize);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ExportPkcs8PrivateKey_WithNullKey_ThrowsException()
    {
        var service = new RsaEncryptionService();

        var ex = Assert.Throws<ArgumentNullException>(() => service.ExportPkcs8PrivateKey(null!));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ImportPkcs8PrivateKey_WithNullData_ThrowsException()
    {
        var service = new RsaEncryptionService();

        var ex = Assert.Throws<ArgumentNullException>(() => service.ImportPkcs8PrivateKey(null!));
        Assert.Equal("pkcs8Data", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ExportSubjectPublicKeyInfo_WithNullKey_ThrowsException()
    {
        var service = new RsaEncryptionService();

        var ex = Assert.Throws<ArgumentNullException>(() => service.ExportSubjectPublicKeyInfo(null!));
        Assert.Equal("publicKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ImportSubjectPublicKeyInfo_WithNullData_ThrowsException()
    {
        var service = new RsaEncryptionService();

        var ex = Assert.Throws<ArgumentNullException>(() => service.ImportSubjectPublicKeyInfo(null!));
        Assert.Equal("subjectPublicKeyInfo", ex.ParamName);
    }

    #endregion
}
