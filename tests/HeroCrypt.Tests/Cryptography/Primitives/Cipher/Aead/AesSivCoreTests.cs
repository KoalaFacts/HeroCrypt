using HeroCrypt.Cryptography.Primitives.Cipher.Aead;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// Comprehensive tests for AES-SIV implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class AesSivCoreTests
{

    private const int KEY_SIZE_512 = 64;
    // AES-SIV keys are 2x AES key size (K1 for S2V, K2 for CTR)
    // So for AES-128, key is 16+16=32 bytes.
    // For AES-256, key is 32+32=64 bytes.

    // Note: The previous test used 32+32=64 byte key for "testKey256", implying internal AES-256 usage.

    private const int SIV_SIZE = 16;
    private const int DEFAULT_NONCE_SIZE = 12;

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
            var key = TestHelpers.RandomBytes(KEY_SIZE_512); // AES-256 SIV
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + SIV_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            var encLen = AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            var decLen = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce, []);

            // Assert
            Assert.Equal(plaintext.Length + SIV_SIZE, encLen);
            Assert.Equal(plaintext.Length, decLen);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_WithAssociatedData_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext = new byte[plaintext.Length + SIV_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            var encLen = AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData);
            var decLen = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce, associatedData);

            // Assert
            Assert.Equal(plaintext.Length, decLen);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_Deterministic_SameInputsSameTimestamp()
        {
            // AES-SIV is deterministic - same key, nonce, AD, plaintext -> same ciphertext
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var ct1 = new byte[plaintext.Length + SIV_SIZE];
            var ct2 = new byte[plaintext.Length + SIV_SIZE];

            AesSivCore.Encrypt(ct1, plaintext, key, nonce, []);
            AesSivCore.Encrypt(ct2, plaintext, key, nonce, []);

            CryptoAssertions.AssertBytesEqual(ct1, ct2);
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
        public void Encrypt_EmptyPlaintext_ReturnsSivAsTag()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = Array.Empty<byte>();
            var ciphertext = new byte[SIV_SIZE];
            var decrypted = Array.Empty<byte>();

            // Act
            var encLen = AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            var decLen = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce, []);

            // Assert
            Assert.Equal(SIV_SIZE, encLen);
            Assert.Equal(0, decLen);
        }

        [Fact]
        public void Encrypt_NonceMisuseResistance_SameNonceDifferentPlaintext()
        {
            // AES-SIV provides nonce misuse resistance.
            // Reusing nonce with DIFFERENT plaintext is fine and secure.
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE); // Reused
            var pt1 = TestHelpers.RandomBytes(32);
            var pt2 = TestHelpers.RandomBytes(32); // Different

            var ct1 = new byte[pt1.Length + SIV_SIZE];
            var ct2 = new byte[pt2.Length + SIV_SIZE];

            AesSivCore.Encrypt(ct1, pt1, key, nonce, []);
            AesSivCore.Encrypt(ct2, pt2, key, nonce, []);

            // Ciphertexts should be different
            Assert.NotEqual(ct1, ct2);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Encrypt_LargeData_Success()
        {
            // Arrange - 1MB
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var ciphertext = new byte[plaintext.Length + SIV_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            var encLen = AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            var decLen = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce, []);

            // Assert
            Assert.Equal(plaintext.Length, decLen);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
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
        public void Decrypt_ModifiedCiphertext_ReturnsFailure()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + SIV_SIZE];
            var decrypted = new byte[plaintext.Length];

            AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, []);

            // Act - Tamper with ciphertext (after SIV block)
            ciphertext[SIV_SIZE + 5] ^= 0xFF;
            var result = AesSivCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            CryptoAssertions.AssertDecryptionFailed(result, decrypted);
        }

        [Fact]
        public void Decrypt_ModifiedSiv_ReturnsFailure()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + SIV_SIZE];
            var decrypted = new byte[plaintext.Length];

            AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, []);

            // Act - Tamper with SIV (header)
            ciphertext[5] ^= 0xFF;
            var result = AesSivCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            CryptoAssertions.AssertDecryptionFailed(result, decrypted);
        }

        [Fact]
        public void Decrypt_ModifiedAssociatedData_ReturnsFailure()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_512);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext = new byte[plaintext.Length + SIV_SIZE];
            var decrypted = new byte[plaintext.Length];

            AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData);

            // Act - Tamper with AD
            var tamperedAD = TestHelpers.TamperFirst(associatedData);
            var result = AesSivCore.Decrypt(decrypted, ciphertext, key, nonce, tamperedAD);

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
            var invalidKey = new byte[16]; // Must be 32, 48, 64
            var nonce = new byte[DEFAULT_NONCE_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[26];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesSivCore.Encrypt(ciphertext, plaintext, invalidKey, nonce, []),
                "Key must be");
        }

        [Fact]
        public void Encrypt_SmallBuffer_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE_512];
            var nonce = new byte[DEFAULT_NONCE_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10]; // Needs +16

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, []),
                "Ciphertext buffer");
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 5297 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc5297_TestVector1()
        {
            // RFC 5297 Appendix A.1
            var key = TestHelpers.HexToBytes(
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"); // 32 bytes

            var associatedData = TestHelpers.HexToBytes(
                "101112131415161718191a1b1c1d1e1f2021222324252627");

            var plaintext = TestHelpers.HexToBytes(
                "112233445566778899aabbccddee");

            var expectedCiphertext = TestHelpers.HexToBytes(
                "85632d07c6e8f37f950acd320a2ecc93" + // SIV
                "40c02b9690c4dc04daef7f6afe5c");     // Ciphertext

            var ciphertext = new byte[plaintext.Length + SIV_SIZE];

            // Act
            var encLen = AesSivCore.Encrypt(ciphertext, plaintext, key, [], associatedData);

            // Assert
            Assert.Equal(expectedCiphertext.Length, encLen);
            CryptoAssertions.AssertBytesEqual(expectedCiphertext, ciphertext.AsSpan(0, encLen).ToArray());
        }
    }
}
