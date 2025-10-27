using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Symmetric.AesCcm;
using HeroCrypt.Services;
using System.Text;

namespace HeroCrypt.Tests;


/// <summary>
/// Tests for AES-CCM (Counter with CBC-MAC) implementation
/// Includes RFC 3610 test vectors for compliance verification
/// </summary>
public class AesCcmTests
{
    private readonly AeadService _aeadService;

    public AesCcmTests()
    {
        _aeadService = new AeadService();
    }

    #region RFC 3610 Test Vectors

    /// <summary>
    /// RFC 3610 Test Vector #1
    /// Packet Vector #1 - AES-128, 8-byte auth tag, 13-byte nonce
    /// </summary>
    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Rfc3610_TestVector1_Success()
    {
        // Arrange - From RFC 3610 Appendix A, Packet Vector #1
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000003020100A0A1A2A3A4A5");
        var plaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        var associatedData = Convert.FromHexString("0001020304050607");

        // Expected ciphertext + 8-byte tag
        var expectedCiphertext = Convert.FromHexString("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0");

        // Act
        var ciphertext = new byte[plaintext.Length + 8];
        var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData, tagSize: 8);

        // Assert
        Assert.Equal(plaintext.Length + 8, actualLength);
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 3610 Test Vector #1 - Decryption
    /// </summary>
    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Rfc3610_TestVector1_Decrypt_Success()
    {
        // Arrange
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000003020100A0A1A2A3A4A5");
        var expectedPlaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        var associatedData = Convert.FromHexString("0001020304050607");
        var ciphertext = Convert.FromHexString("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0");

        // Act
        var plaintext = new byte[expectedPlaintext.Length];
        var actualLength = AesCcmCore.Decrypt(plaintext, ciphertext, key, nonce, associatedData, tagSize: 8);

        // Assert
        Assert.Equal(expectedPlaintext.Length, actualLength);
        Assert.Equal(expectedPlaintext, plaintext);
    }

    /// <summary>
    /// RFC 3610 Test Vector #2
    /// Packet Vector #2 - Shorter plaintext, different nonce
    /// </summary>
    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Rfc3610_TestVector2_Success()
    {
        // Arrange - From RFC 3610 Appendix A, Packet Vector #2
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000004030201A0A1A2A3A4A5");
        var plaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        var associatedData = Convert.FromHexString("0001020304050607");

        var expectedCiphertext = Convert.FromHexString("72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916");

        // Act
        var ciphertext = new byte[plaintext.Length + 8];
        var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData, tagSize: 8);

        // Assert
        Assert.Equal(plaintext.Length + 8, actualLength);
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 3610 Test Vector #3
    /// Packet Vector #3 - 25-byte plaintext, 8-byte AD
    /// </summary>
    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Rfc3610_TestVector3_Success()
    {
        // Arrange - From RFC 3610 Appendix A, Packet Vector #3
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000005040302A0A1A2A3A4A5");
        var plaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
        var associatedData = Convert.FromHexString("0001020304050607"); // 8 bytes, not 12!

        var expectedCiphertext = Convert.FromHexString("51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0C5");

        // Act
        var ciphertext = new byte[plaintext.Length + 8];
        var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData, tagSize: 8);

        // Assert
        Assert.Equal(plaintext.Length + 8, actualLength);
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    #endregion

    #region Basic Functionality Tests

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm128_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Hello, AES-CCM! This is a test message.");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);
        var associatedData = Encoding.UTF8.GetBytes("metadata");

        // Act - Encrypt
        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Act - Decrypt
        var decrypted = _aeadService.DecryptAsync(ciphertext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm256_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Testing AES-256-CCM with a longer key.");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes256Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes256Ccm);
        var associatedData = Encoding.UTF8.GetBytes("additional data");

        // Act - Encrypt
        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, associatedData, AeadAlgorithm.Aes256Ccm)
            .GetAwaiter().GetResult();

        // Act - Decrypt
        var decrypted = _aeadService.DecryptAsync(ciphertext, key, nonce, associatedData, AeadAlgorithm.Aes256Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_WithoutAssociatedData_Success()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("No associated data");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);

        // Act
        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, algorithm: AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();
        var decrypted = _aeadService.DecryptAsync(ciphertext, key, nonce, algorithm: AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_EmptyPlaintext_Success()
    {
        // Arrange
        var plaintext = Array.Empty<byte>();
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);
        var associatedData = Encoding.UTF8.GetBytes("metadata only");

        // Act
        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();
        var decrypted = _aeadService.DecryptAsync(ciphertext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.True(ciphertext.Length > 0); // Should contain tag
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_LargeData_Success()
    {
        // Arrange - 60 KB of data (within AES-CCM limit of 65,535 bytes for 13-byte nonce)
        // AES-CCM max plaintext = 2^(8*L) - 1 where L = 15 - nonceSize
        // For 13-byte nonce: L=2, max = 2^16 - 1 = 65,535 bytes
        var plaintext = new byte[60 * 1024]; // 61,440 bytes
        new Random(42).NextBytes(plaintext);
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes256Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes256Ccm);

        // Act
        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, algorithm: AeadAlgorithm.Aes256Ccm)
            .GetAwaiter().GetResult();
        var decrypted = _aeadService.DecryptAsync(ciphertext, key, nonce, algorithm: AeadAlgorithm.Aes256Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    #endregion

    #region Authentication Tests

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_TamperedCiphertext_FailsAuthentication()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Authenticated message");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);
        var associatedData = Encoding.UTF8.GetBytes("metadata");

        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Act - Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _aeadService.DecryptAsync(ciphertext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
                .GetAwaiter().GetResult());
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_WrongKey_FailsAuthentication()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Secret message");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var wrongKey = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);

        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, algorithm: AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _aeadService.DecryptAsync(ciphertext, wrongKey, nonce, algorithm: AeadAlgorithm.Aes128Ccm)
                .GetAwaiter().GetResult());
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_WrongNonce_FailsAuthentication()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("Nonce test");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);
        var wrongNonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);

        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, algorithm: AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _aeadService.DecryptAsync(ciphertext, key, wrongNonce, algorithm: AeadAlgorithm.Aes128Ccm)
                .GetAwaiter().GetResult());
    }

    [Fact]
    [Trait("Category", TestCategories.Fast)]
    public void AesCcm_WrongAssociatedData_FailsAuthentication()
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes("AAD test");
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);
        var associatedData = Encoding.UTF8.GetBytes("correct AAD");
        var wrongAssociatedData = Encoding.UTF8.GetBytes("wrong AAD");

        var ciphertext = _aeadService.EncryptAsync(plaintext, key, nonce, associatedData, AeadAlgorithm.Aes128Ccm)
            .GetAwaiter().GetResult();

        // Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _aeadService.DecryptAsync(ciphertext, key, nonce, wrongAssociatedData, AeadAlgorithm.Aes128Ccm)
                .GetAwaiter().GetResult());
    }

    #endregion

    #region Parameter Validation Tests

    [Fact]
    public void AesCcm_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[12]; // Should be 16 or 32
        var nonce = new byte[13];
        var plaintext = new byte[10];
        var ciphertext = new byte[26];

        // Assert
        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, invalidKey, nonce, Array.Empty<byte>()));
    }

    [Fact]
    public void AesCcm_NonceTooShort_ThrowsException()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[6]; // Minimum is 7
        var plaintext = new byte[10];
        var ciphertext = new byte[26];

        // Assert
        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, Array.Empty<byte>()));
    }

    [Fact]
    public void AesCcm_NonceTooLong_ThrowsException()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[14]; // Maximum is 13
        var plaintext = new byte[10];
        var ciphertext = new byte[26];

        // Assert
        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, Array.Empty<byte>()));
    }

    [Fact]
    public void AesCcm_InvalidTagSize_ThrowsException()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[13];
        var plaintext = new byte[10];
        var ciphertext = new byte[20];

        // Assert - Odd tag size
        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, Array.Empty<byte>(), tagSize: 7));

        // Assert - Tag too small
        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, Array.Empty<byte>(), tagSize: 2));

        // Assert - Tag too large
        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, Array.Empty<byte>(), tagSize: 18));
    }

    [Fact]
    public void AesCcm_GetMaxPlaintextLength_ReturnsCorrectValues()
    {
        // Act & Assert
        Assert.Equal((1L << 16) - 1, AesCcmCore.GetMaxPlaintextLength(13)); // L=2
        Assert.Equal((1L << 24) - 1, AesCcmCore.GetMaxPlaintextLength(12)); // L=3
        Assert.Equal((1L << 32) - 1, AesCcmCore.GetMaxPlaintextLength(11)); // L=4
    }

    #endregion

    #region Key and Nonce Generation Tests

    [Fact]
    public void GenerateKey_Aes128Ccm_Returns16Bytes()
    {
        // Act
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);

        // Assert
        Assert.Equal(16, key.Length);
    }

    [Fact]
    public void GenerateKey_Aes256Ccm_Returns32Bytes()
    {
        // Act
        var key = _aeadService.GenerateKey(AeadAlgorithm.Aes256Ccm);

        // Assert
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void GenerateNonce_AesCcm_Returns13Bytes()
    {
        // Act
        var nonce = _aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);

        // Assert
        Assert.Equal(13, nonce.Length);
    }

    [Fact]
    public void GetKeySize_ReturnsCorrectSizes()
    {
        // Assert
        Assert.Equal(16, _aeadService.GetKeySize(AeadAlgorithm.Aes128Ccm));
        Assert.Equal(32, _aeadService.GetKeySize(AeadAlgorithm.Aes256Ccm));
    }

    [Fact]
    public void GetNonceSize_Returns13Bytes()
    {
        // Assert
        Assert.Equal(13, _aeadService.GetNonceSize(AeadAlgorithm.Aes128Ccm));
        Assert.Equal(13, _aeadService.GetNonceSize(AeadAlgorithm.Aes256Ccm));
    }

    [Fact]
    public void GetTagSize_Returns16Bytes()
    {
        // Assert
        Assert.Equal(16, _aeadService.GetTagSize(AeadAlgorithm.Aes128Ccm));
        Assert.Equal(16, _aeadService.GetTagSize(AeadAlgorithm.Aes256Ccm));
    }

    #endregion

    #region Variable Tag Size Tests

    [Fact]
    public void AesCcm_VariableTagSizes_Work()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[13];
        var plaintext = Encoding.UTF8.GetBytes("Tag size test");
        var tagSizes = new[] { 4, 6, 8, 10, 12, 14, 16 };

        foreach (var tagSize in tagSizes)
        {
            // Act
            var ciphertext = new byte[plaintext.Length + tagSize];
            var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, Array.Empty<byte>(), tagSize);

            var decrypted = new byte[plaintext.Length];
            var decryptedLength = AesCcmCore.Decrypt(decrypted, ciphertext, key, nonce, Array.Empty<byte>(), tagSize);

            // Assert
            Assert.Equal(plaintext.Length + tagSize, actualLength);
            Assert.Equal(plaintext.Length, decryptedLength);
            Assert.Equal(plaintext, decrypted);
        }
    }

    #endregion
}


