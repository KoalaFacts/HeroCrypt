using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.XChaCha20Poly1305;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.XChaCha20Poly1305;

/// <summary>
/// Comprehensive tests for XChaCha20-Poly1305 Core implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class XChaCha20Poly1305CoreTests
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 24;
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

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, associatedData);
            var decrypted = XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce, associatedData);

            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_CiphertextDifferentFromPlaintext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            Assert.False(plaintext.AsSpan().SequenceEqual(result.Ciphertext.AsSpan(0, plaintext.Length)));
        }

        [Fact]
        public void Decrypt_InvalidTag_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            // Corrupt tag
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[^1] ^= 0xFF;

            Assert.Throws<CryptographicException>(() =>
                XChaCha20Poly1305Core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_InvalidAssociatedData_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);
            var ad = TestHelpers.RandomBytes(16);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, ad);

            var tamperedAd = TestHelpers.TamperFirst(ad);

            Assert.Throws<CryptographicException>(() =>
                XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAd));
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

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void Encrypt_SingleByte_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[] { 0x42 };

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            Assert.Equal(1 + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_ExactBlockSize_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Encrypt_LargeData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
            var decrypted = XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, result.Nonce);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void LongNonce_ReducesCollisionRisk()
        {
            // XChaCha20's 24-byte nonce reduces collision risk
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var outputs = new HashSet<string>();

            for (int i = 0; i < 100; i++)
            {
                var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
                var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);
                outputs.Add(Convert.ToHexString(result.Ciphertext));
            }

            Assert.Equal(100, outputs.Count);
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

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[0] ^= 0xFF;

            Assert.Throws<CryptographicException>(() =>
                XChaCha20Poly1305Core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_WrongKey_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var wrongKey = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            Assert.Throws<CryptographicException>(() =>
                XChaCha20Poly1305Core.Decrypt(result.Ciphertext, wrongKey, result.Nonce));
        }

        [Fact]
        public void Decrypt_WrongNonce_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var wrongNonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

            Assert.Throws<CryptographicException>(() =>
                XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, wrongNonce));
        }

        [Fact]
        public void Encrypt_SameInputDifferentNonce_ProducesDifferentCiphertext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result1 = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce1);
            var result2 = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce2);

            Assert.NotEqual(result1.Ciphertext, result2.Ciphertext);
        }

        [Fact]
        public void Encrypt_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce);

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

            Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce));
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE - 1]; // Only 24 allowed
            var plaintext = new byte[10];

            Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce));
        }
    }

    /// <summary>
    /// Known Answer Tests using draft-arciszewski-xchacha-03 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void XChaCha20Poly1305_TestVector()
        {
            // draft-irtf-cfrg-xchacha-03 Section A.3.1
            var key = TestHelpers.HexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
            var nonce = TestHelpers.HexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657");
            var ad = TestHelpers.HexToBytes("50515253c0c1c2c3c4c5c6c7");
            var plaintext = Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

            // Expected ciphertext from draft
            var expectedCiphertext = TestHelpers.HexToBytes(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
                "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
                "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
                "21f9664c97637da9768812f615c68b13b52e");
            var expectedTag = TestHelpers.HexToBytes("c0875924c1c7987947deafd8780acf49");

            var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, ad);

            var actualCiphertext = result.Ciphertext.AsSpan(0, plaintext.Length).ToArray();
            var actualTag = result.Ciphertext.AsSpan().Slice(plaintext.Length, TAG_SIZE).ToArray();

            CryptoAssertions.AssertBytesEqual(expectedCiphertext, actualCiphertext);
            CryptoAssertions.AssertBytesEqual(expectedTag, actualTag);

            // Decrypt
            var decrypted = XChaCha20Poly1305Core.Decrypt(result.Ciphertext, key, nonce, ad);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }
}
