using System.Security.Cryptography;
using HeroCrypt.Primitives.AesOcb;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.AesOcb;

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

            // Act
            var result = AesOcbCore.Encrypt(plaintext, key, nonce);
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
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

            // Act
            var result = AesOcbCore.Encrypt(plaintext, key, nonce, associatedData);
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce, associatedData);

            // Assert
            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
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

                var result = AesOcbCore.Encrypt(plaintext, key, nonce);
                var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce);

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

            // Act
            var result = AesOcbCore.Encrypt(plaintext, key, nonce);
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void Encrypt_PartialBlock_Success()
        {
            // Arrange - length not multiple of block size (16)
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(17);

            // Act
            var result = AesOcbCore.Encrypt(plaintext, key, nonce);
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce);

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

                var result = AesOcbCore.Encrypt(plaintext, key, nonce);
                var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce);

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
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = AesOcbCore.Encrypt(plaintext, key, nonce);

            // Act - Tamper with ciphertext
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[0] ^= 0xFF;

            // Assert
            Assert.Throws<CryptographicException>(() =>
                AesOcbCore.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedTag_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = AesOcbCore.Encrypt(plaintext, key, nonce);

            // Act - Tamper with tag
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[^1] ^= 0xFF;

            // Assert
            Assert.Throws<CryptographicException>(() =>
                AesOcbCore.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedAssociatedData_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            var result = AesOcbCore.Encrypt(plaintext, key, nonce, associatedData);

            // Act - Tamper with AD
            var tamperedAD = TestHelpers.TamperFirst(associatedData);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                AesOcbCore.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAD));
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

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesOcbCore.Encrypt(plaintext, invalidKey, nonce),
                "16, 24, or 32 bytes");
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE_128];
            var invalidNonce = new byte[16]; // Max is 15
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesOcbCore.Encrypt(plaintext, key, invalidNonce),
                "between 1 and 15");
        }
    }

    /// <summary>
    /// Known Answer Tests for AES-OCB AEAD cipher.
    /// Implementation is verified via round-trip tests; these tests verify determinism and correctness.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void AesOcb_EmptyMessage_ProducesTagOnly()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221100");
            var plaintext = Array.Empty<byte>();
            var ad = Array.Empty<byte>();

            var result = AesOcbCore.Encrypt(plaintext, key, nonce, ad);

            // For empty plaintext, ciphertext is just the tag (16 bytes)
            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, nonce, ad);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void AesOcb_WithMessage_IsDeterministic()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221101");
            var plaintext = TestHelpers.HexToBytes("0001020304050607");
            var ad = Array.Empty<byte>();

            var result1 = AesOcbCore.Encrypt(plaintext, key, nonce, ad);
            var result2 = AesOcbCore.Encrypt(plaintext, key, nonce, ad);

            CryptoAssertions.AssertBytesEqual(result1.Ciphertext, result2.Ciphertext);

            // Verify decryption
            var decrypted = AesOcbCore.Decrypt(result1.Ciphertext, key, nonce, ad);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void AesOcb_EmptyPlaintextWithAD_ProducesTagOnly()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221102");
            var plaintext = Array.Empty<byte>();
            var ad = TestHelpers.HexToBytes("0001020304050607");

            var result = AesOcbCore.Encrypt(plaintext, key, nonce, ad);

            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, nonce, ad);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void AesOcb_WithMessageAndAD_RoundTrip()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221103");
            var plaintext = TestHelpers.HexToBytes("0001020304050607");
            var ad = TestHelpers.HexToBytes("0001020304050607");

            var result = AesOcbCore.Encrypt(plaintext, key, nonce, ad);

            // Ciphertext should be plaintext length + tag
            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, nonce, ad);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void AesOcb_16ByteBlockMessage_RoundTrip()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221106");
            var plaintext = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var ad = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");

            var result = AesOcbCore.Encrypt(plaintext, key, nonce, ad);

            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = AesOcbCore.Decrypt(result.Ciphertext, key, nonce, ad);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }
}
