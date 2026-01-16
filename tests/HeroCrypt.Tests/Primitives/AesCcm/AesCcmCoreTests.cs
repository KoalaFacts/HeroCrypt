using System.Security.Cryptography;
using HeroCrypt.Primitives.AesCcm;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.AesCcm;

/// <summary>
/// Comprehensive tests for AES-CCM implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class AesCcmCoreTests
{
    private const int KEY_SIZE = 16;
    private const int NONCE_SIZE = 13; // Standard nonce size for CCM
    private const int DEFAULT_TAG_SIZE = 16;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            // Act
            var result = AesCcmCore.Encrypt(plaintext, key, nonce, associatedData, DEFAULT_TAG_SIZE);
            var decrypted = AesCcmCore.Decrypt(result.Ciphertext, key, result.Nonce, associatedData, DEFAULT_TAG_SIZE);

            // Assert
            Assert.Equal(plaintext.Length + DEFAULT_TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_WithoutAssociatedData_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var result = AesCcmCore.Encrypt(plaintext, key, nonce);
            var decrypted = AesCcmCore.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Fact]
        public void Encrypt_EmptyPlaintext_ReturnsTagOnly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = Array.Empty<byte>();

            // Act
            var result = AesCcmCore.Encrypt(plaintext, key, nonce);

            // Assert
            Assert.Equal(DEFAULT_TAG_SIZE, result.Ciphertext.Length);
            Assert.False(TestHelpers.AllZeros(result.Ciphertext));
        }

        [Fact]
        public void Encrypt_VariableTagSizes_Supported()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var tagSizes = new[] { 4, 6, 8, 10, 12, 14, 16 };

            foreach (var tagSize in tagSizes)
            {
                var result = AesCcmCore.Encrypt(plaintext, key, nonce, default, tagSize);
                var decrypted = AesCcmCore.Decrypt(result.Ciphertext, key, result.Nonce, default, tagSize);

                Assert.Equal(plaintext.Length + tagSize, result.Ciphertext.Length);
                CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
            }
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        [Fact]
        public void Decrypt_ModifiedCiphertext_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = AesCcmCore.Encrypt(plaintext, key, nonce);

            // Act - Tamper with ciphertext (part of the encrypted message)
            var tamperedCiphertext = TestHelpers.TamperFirst(result.Ciphertext);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                AesCcmCore.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedTag_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = AesCcmCore.Encrypt(plaintext, key, nonce);

            // Act - Tamper with tag (at the end)
            var tamperedCiphertext = TestHelpers.TamperLast(result.Ciphertext);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                AesCcmCore.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedAssociatedData_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            var result = AesCcmCore.Encrypt(plaintext, key, nonce, associatedData, DEFAULT_TAG_SIZE);

            // Act - Tamper with AD
            var tamperedAD = TestHelpers.TamperFirst(associatedData);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                AesCcmCore.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAD, DEFAULT_TAG_SIZE));
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        [Fact]
        public void Encrypt_InvalidKeySize_ThrowsArgumentException()
        {
            var invalidKey = new byte[12];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesCcmCore.Encrypt(plaintext, invalidKey, nonce),
                "Key must be");
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var invalidNonce = new byte[6]; // Too short
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesCcmCore.Encrypt(plaintext, key, invalidNonce),
                "Nonce");
        }

        [Fact]
        public void Encrypt_InvalidTagSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];

            // Odd sizes validation
            Assert.Throws<ArgumentException>(() =>
                AesCcmCore.Encrypt(plaintext, key, nonce, default, tagSize: 7));

            // Too small validation
            Assert.Throws<ArgumentException>(() =>
                AesCcmCore.Encrypt(plaintext, key, nonce, default, tagSize: 2));

            // Too large validation
            Assert.Throws<ArgumentException>(() =>
                AesCcmCore.Encrypt(plaintext, key, nonce, default, tagSize: 18));
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 3610 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc3610_TestVector1()
        {
            var key = TestHelpers.HexToBytes("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
            var nonce = TestHelpers.HexToBytes("00000003020100A0A1A2A3A4A5");
            var plaintext = TestHelpers.HexToBytes("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
            var associatedData = TestHelpers.HexToBytes("0001020304050607");
            var expectedCiphertext = TestHelpers.HexToBytes("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0");

            var result = AesCcmCore.Encrypt(plaintext, key, nonce, associatedData, tagSize: 8);

            Assert.Equal(plaintext.Length + 8, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(expectedCiphertext, result.Ciphertext);
        }
    }
}
