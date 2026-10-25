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
        private readonly ChaCha20Poly1305Core core = new();

        [Fact]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            var result = core.Encrypt(plaintext, key, nonce, associatedData);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce, associatedData);

            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_CiphertextDifferentFromPlaintext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            // Ciphertext part should not equal plaintext
            Assert.False(plaintext.AsSpan().SequenceEqual(result.Ciphertext.AsSpan(0, plaintext.Length)));
        }

        [Fact]
        public void Decrypt_InvalidTag_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);

            var result = core.Encrypt(plaintext, key, nonce);

            // Corrupt tag (last 16 bytes)
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[^1] ^= 0xFF;

            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_InvalidAssociatedData_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(32);
            var ad = TestHelpers.RandomBytes(16);

            var result = core.Encrypt(plaintext, key, nonce, ad);

            var tamperedAd = TestHelpers.TamperFirst(ad);

            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAd));
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly ChaCha20Poly1305Core core = new();

        [Fact]
        public void Encrypt_EmptyPlaintext_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = Array.Empty<byte>();

            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void Encrypt_SingleByte_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[] { 0x42 };

            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            Assert.Equal(1 + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_ExactBlockSize_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64); // ChaCha20 block size

            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Encrypt_LargeData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);

            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_EmptyAssociatedData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var emptyAd = Array.Empty<byte>();

            var result = core.Encrypt(plaintext, key, nonce, emptyAd);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce, emptyAd);

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
        private readonly ChaCha20Poly1305Core core = new();

        [Fact]
        public void Decrypt_ModifiedCiphertext_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[0] ^= 0xFF;

            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_WrongKey_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var wrongKey = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(result.Ciphertext, wrongKey, result.Nonce));
        }

        [Fact]
        public void Decrypt_WrongNonce_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var wrongNonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(result.Ciphertext, key, wrongNonce));
        }

        [Fact]
        public void Encrypt_SameInputDifferentNonce_ProducesDifferentCiphertext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result1 = core.Encrypt(plaintext, key, nonce1);
            var result2 = core.Encrypt(plaintext, key, nonce2);

            Assert.NotEqual(result1.Ciphertext, result2.Ciphertext);
        }

        [Fact]
        public void Encrypt_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

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
        private readonly ChaCha20Poly1305Core core = new();

        [Fact]
        public void Encrypt_InvalidKeySize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE - 1];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];

            Assert.Throws<ArgumentException>(() => core.Encrypt(plaintext, key, nonce));
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE - 1]; // Only 12 allowed
            var plaintext = new byte[10];

            Assert.Throws<ArgumentException>(() => core.Encrypt(plaintext, key, nonce));
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
        private readonly ChaCha20Poly1305Core core = new();

        [Fact]
        public void Rfc8439_TestVector()
        {
            // RFC 8439 Section 2.8.2
            var key = TestHelpers.HexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
            var nonce = TestHelpers.HexToBytes("070000004041424344454647");
            var ad = TestHelpers.HexToBytes("50515253c0c1c2c3c4c5c6c7");
            var plaintext = Encoding.UTF8.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

            // RFC 8439 §2.8.2: independently specified complete ciphertext, not only its tag.
            var expectedCiphertext = TestHelpers.HexToBytes(
                "d31a8d34648e60db7b86afbc53ef7ec2" +
                "a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b" +
                "1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58" +
                "fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b" +
                "6116");

            var expectedTag = TestHelpers.HexToBytes("1ae10b594f09e26a7e902ecbd0600691");

            var result = core.Encrypt(plaintext, key, nonce, ad);

            var actualTag = result.Ciphertext.AsSpan().Slice(plaintext.Length, TAG_SIZE).ToArray();

            CryptoAssertions.AssertBytesEqual(expectedCiphertext,
                result.Ciphertext.AsSpan(0, plaintext.Length).ToArray());
            CryptoAssertions.AssertBytesEqual(expectedTag, actualTag);

            // Decrypt as well
            var decrypted = core.Decrypt(result.Ciphertext, key, nonce, ad);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }

        [Theory]
        [InlineData(0, 0)]
        [InlineData(0, 19)]
        [InlineData(1, 0)]
        [InlineData(63, 17)]
        [InlineData(64, 32)]
        [InlineData(65, 1)]
        [InlineData(256, 71)]
        public void DotNetBcl_EncryptAndDecrypt_AgreeAcrossLengths(int plaintextLength, int associatedDataLength)
        {
            // The published RFC vector above remains unconditional across all platforms.
            // The .NET BCL implementation is an independent interoperability oracle when available.
            if (!System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
            {
                return;
            }

            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(plaintextLength);
            var associatedData = TestHelpers.RandomBytes(associatedDataLength);
            var bclCiphertext = new byte[plaintextLength];
            var bclTag = new byte[TAG_SIZE];

            using var bcl = new System.Security.Cryptography.ChaCha20Poly1305(key);
            bcl.Encrypt(nonce, plaintext, bclCiphertext, bclTag, associatedData);

            var encrypted = core.Encrypt(plaintext, key, nonce, associatedData);
            CryptoAssertions.AssertBytesEqual(bclCiphertext,
                encrypted.Ciphertext.AsSpan(0, plaintextLength).ToArray());
            CryptoAssertions.AssertBytesEqual(bclTag,
                encrypted.Ciphertext.AsSpan(plaintextLength, TAG_SIZE).ToArray());

            // Test that our decryptor accepts an independent BCL-produced ciphertext + tag.
            var bclCombined = new byte[plaintextLength + TAG_SIZE];
            bclCiphertext.CopyTo(bclCombined, 0);
            bclTag.CopyTo(bclCombined, plaintextLength);
            CryptoAssertions.AssertBytesEqual(plaintext, core.Decrypt(bclCombined, key, nonce, associatedData));

            // Test the opposite direction: BCL must accept our encrypted output.
            var bclPlaintext = new byte[plaintextLength];
            bcl.Decrypt(nonce,
                encrypted.Ciphertext.AsSpan(0, plaintextLength),
                encrypted.Ciphertext.AsSpan(plaintextLength, TAG_SIZE),
                bclPlaintext, associatedData);
            CryptoAssertions.AssertBytesEqual(plaintext, bclPlaintext);

            // Reject forged authentication data even when the plaintext is empty.
            bclCombined[^1] ^= 1;
            Assert.Throws<CryptographicException>(() => core.Decrypt(bclCombined, key, nonce, associatedData));
            bclCombined[^1] ^= 1;
            var alteredNonce = (byte[])nonce.Clone();
            alteredNonce[0] ^= 1;
            Assert.Throws<CryptographicException>(() => core.Decrypt(bclCombined, key, alteredNonce, associatedData));
        }

}
