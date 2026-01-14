using HeroCrypt.Cryptography.Primitives.Cipher.Aead;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// Comprehensive tests for AES-OCB (Offset Codebook Mode) implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class AesOcbCoreTests
{
    // OCB uses 16, 24, or 32 byte keys (AES-128/192/256)
    // Nonce size 1-15 bytes
    private const int KEY_SIZE_128 = 16;
    private const int KEY_SIZE_192 = 24;
    private const int KEY_SIZE_256 = 32;
    private const int DEFAULT_NONCE_SIZE = 12;
    private const int TAG_SIZE = 16;

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
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            var len = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            Assert.Equal(plaintext.Length, len);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_WithAssociatedData_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData);
            var len = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, associatedData);

            // Assert
            Assert.Equal(plaintext.Length, len);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_VariableKeySizes_Success()
        {
            var keySizes = new[] { KEY_SIZE_128, KEY_SIZE_192, KEY_SIZE_256 };
            foreach (var size in keySizes)
            {
                var key = TestHelpers.RandomBytes(size);
                var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
                var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
                var ciphertext = new byte[plaintext.Length + TAG_SIZE];
                var decrypted = new byte[plaintext.Length];

                AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
                AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

                CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
            }
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
        public void Encrypt_EmptyPlaintext_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = Array.Empty<byte>();
            var ciphertext = new byte[TAG_SIZE];
            var decrypted = Array.Empty<byte>(); // Correct implementation should handle this

            // Act
            var encryptedLen = AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            // Decrypt typically returns length, but if input buffer is 0 length, behaviour depends on impl.
            // AesOcbCore.Decrypt signature: int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ...)
            // We pass empty span for plaintext.
            var decryptedLen = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            Assert.Equal(TAG_SIZE, encryptedLen);
            Assert.Equal(0, decryptedLen);
        }

        [Fact]
        public void Encrypt_PartialBlock_Success()
        {
            // Arrange - length not multiple of block size (16)
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(17);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_VariableNonceSizes_Success()
        {
            // RFC 7253 allows 1-15 bytes
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);

            for (int i = 1; i <= 15; i++)
            {
                var nonce = TestHelpers.RandomBytes(i);
                var ciphertext = new byte[plaintext.Length + TAG_SIZE];
                var decrypted = new byte[plaintext.Length];

                AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
                AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

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
        public void Decrypt_ModifiedCiphertext_ReturnsFailureAndClearsPlaintext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);

            // Act - Tamper with ciphertext
            ciphertext[0] ^= 0xFF;
            var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            CryptoAssertions.AssertDecryptionFailed(result, decrypted);
        }

        [Fact]
        public void Decrypt_ModifiedTag_ReturnsFailure()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);

            // Act - Tamper with tag
            ciphertext[ciphertext.Length - 1] ^= 0xFF;
            var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            CryptoAssertions.AssertDecryptionFailed(result, decrypted);
        }

        [Fact]
        public void Decrypt_ModifiedAssociatedData_ReturnsFailure()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData);

            // Act - Tamper with AD
            var tamperedAD = TestHelpers.TamperFirst(associatedData);
            var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, tamperedAD);

            // Assert
            CryptoAssertions.AssertDecryptionFailed(result, decrypted);
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
            var invalidKey = new byte[15]; // Not 16, 24, 32
            var nonce = new byte[DEFAULT_NONCE_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[26];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesOcbCore.Encrypt(ciphertext, plaintext, invalidKey, nonce, []),
                "16, 24, or 32 bytes");
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE_128];
            var invalidNonce = new byte[16]; // Max is 15
            var plaintext = new byte[10];
            var ciphertext = new byte[26];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesOcbCore.Encrypt(ciphertext, plaintext, key, invalidNonce, []),
                "between 1 and 15");
        }
    }
}
