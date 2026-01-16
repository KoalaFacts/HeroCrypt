using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.ChaCha20Poly1305;

/// <summary>
/// Comprehensive tests for ChaCha20-Poly1305 Core implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class ChaCha20Poly1305CoreTests
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 12;
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
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, associatedData);
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce, associatedData);

            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_CiphertextDifferentFromPlaintext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            // Ciphertext part should not equal plaintext
            Assert.False(plaintext.AsSpan().SequenceEqual(result.Ciphertext.AsSpan(0, plaintext.Length)));
        }

        [Fact]
        public void Decrypt_InvalidTag_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            // Corrupt tag (last 16 bytes)
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[^1] ^= 0xFF;

            Assert.Throws<CryptographicException>(() =>
                ChaCha20Poly1305Core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_InvalidAssociatedData_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);
            var ad = TestHelpers.RandomBytes(16);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, ad);

            var tamperedAd = TestHelpers.TamperFirst(ad);

            Assert.Throws<CryptographicException>(() =>
                ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAd));
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
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = Array.Empty<byte>();

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void Encrypt_SingleByte_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[] { 0x42 };

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            Assert.Equal(1 + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_ExactBlockSize_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64); // ChaCha20 block size

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Encrypt_LargeData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_EmptyAssociatedData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var emptyAd = Array.Empty<byte>();

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, emptyAd);
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce, emptyAd);

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
        public void Decrypt_ModifiedCiphertext_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[0] ^= 0xFF;

            Assert.Throws<CryptographicException>(() =>
                ChaCha20Poly1305Core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_WrongKey_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var wrongKey = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            Assert.Throws<CryptographicException>(() =>
                ChaCha20Poly1305Core.Decrypt(result.Ciphertext, wrongKey, result.Nonce));
        }

        [Fact]
        public void Decrypt_WrongNonce_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var wrongNonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            Assert.Throws<CryptographicException>(() =>
                ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, wrongNonce));
        }

        [Fact]
        public void Encrypt_SameInputDifferentNonce_ProducesDifferentCiphertext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result1 = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce1);
            var result2 = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce2);

            Assert.NotEqual(result1.Ciphertext, result2.Ciphertext);
        }

        [Fact]
        public void Encrypt_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            var ciphertextOnly = result.Ciphertext.AsSpan(0, plaintext.Length).ToArray();
            CryptoAssertions.AssertAppearsRandom(ciphertextOnly);
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
            var key = new byte[KEY_SIZE - 1];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];

            Assert.Throws<ArgumentException>(() => ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce));
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE - 1]; // Only 12 allowed
            var plaintext = new byte[10];

            Assert.Throws<ArgumentException>(() => ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce));
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 8439 vector.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc8439_TestVector()
        {
            // RFC 8439 Section 2.8.2
            var key = TestHelpers.HexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
            var nonce = TestHelpers.HexToBytes("070000004041424344454647");
            var ad = TestHelpers.HexToBytes("50515253c0c1c2c3c4c5c6c7");
            var plaintext = Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

            var expectedTag = TestHelpers.HexToBytes("1ae10b594f09e26a7e902ecbd0600691");

            var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, ad);

            var actualTag = result.Ciphertext.AsSpan().Slice(plaintext.Length, TAG_SIZE).ToArray();

            CryptoAssertions.AssertBytesEqual(expectedTag, actualTag);

            // Decrypt as well
            var decrypted = ChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, nonce, ad);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }
}
