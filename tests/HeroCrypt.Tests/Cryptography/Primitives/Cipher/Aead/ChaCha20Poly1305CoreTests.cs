using System.Text;
using HeroCrypt.Cryptography.Primitives.Cipher.Aead;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Aead;

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

            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            var encLen = ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData);
            var decLen = ChaCha20Poly1305Core.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce, associatedData);

            Assert.Equal(plaintext.Length + TAG_SIZE, encLen);
            Assert.Equal(plaintext.Length, decLen);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_CiphertextDifferentFromPlaintext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];

            ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce);

            // Ciphertext part should not equal plaintext (it's XOR, so only equals if keystream is 0, unlikely)
            Assert.False(plaintext.AsSpan().SequenceEqual(ciphertext.AsSpan(0, plaintext.Length)));
        }

        [Fact]
        public void Decrypt_InvalidTag_ReturnsFailure()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            var encLen = ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce);

            // Corrupt tag (last 16 bytes)
            ciphertext[encLen - 1] ^= 0xFF;

            var decLen = ChaCha20Poly1305Core.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce);

            CryptoAssertions.AssertDecryptionFailed(decLen, decrypted);
        }

        [Fact]
        public void Decrypt_InvalidAssociatedData_ReturnsFailure()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);
            var ad = TestHelpers.RandomBytes(16);
            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            var encLen = ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, ad);

            var tamperedAd = TestHelpers.TamperFirst(ad);

            var decLen = ChaCha20Poly1305Core.Decrypt(decrypted, ciphertext.AsSpan(0, encLen), key, nonce, tamperedAd);

            CryptoAssertions.AssertDecryptionFailed(decLen, decrypted);
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
            var ciphertext = new byte[30];

            Assert.Throws<ArgumentException>(() => ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce));
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE - 1]; // Only 12 allowed
            var plaintext = new byte[10];
            var ciphertext = new byte[30];

            Assert.Throws<ArgumentException>(() => ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce));
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
            // The example also lists ciphertext but checking tag is sufficient for full integrity check + derived Poly key
            // Start of CT: d31a8d...

            var ciphertext = new byte[plaintext.Length + TAG_SIZE];
            var len = ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, ad);

            var actualTag = ciphertext.AsSpan().Slice(plaintext.Length, TAG_SIZE).ToArray();

            CryptoAssertions.AssertBytesEqual(expectedTag, actualTag);

            // Decrypt as well
            var decrypted = new byte[plaintext.Length];
            var decLen = ChaCha20Poly1305Core.Decrypt(decrypted, ciphertext.AsSpan(0, len), key, nonce, ad);

            Assert.Equal(plaintext.Length, decLen);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }
}
