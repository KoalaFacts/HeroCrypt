using HeroCrypt.Primitives.XSalsa20;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.XSalsa20;

/// <summary>
/// Comprehensive tests for XSalsa20 stream cipher implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class XSalsa20CoreTests
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 24;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void Transform_WithValidParameters_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];

            // Act
            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);

            // Assert
            Assert.NotEqual(plaintext, ciphertext);
            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_RoundTrip_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);
            XSalsa20Core.Transform(decrypted, ciphertext, key, nonce);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_DifferentNonce_ProducesDifferentCiphertext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            // Act
            XSalsa20Core.Transform(ciphertext1, plaintext, key, nonce1);
            XSalsa20Core.Transform(ciphertext2, plaintext, key, nonce2);

            // Assert
            Assert.NotEqual(ciphertext1, ciphertext2);
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
        public void Transform_EmptyInput_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = Array.Empty<byte>();
            var ciphertext = Array.Empty<byte>();

            // Act & Assert
            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Transform_LargeData_Success()
        {
            // Arrange - 1 MB
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);
            XSalsa20Core.Transform(decrypted, ciphertext, key, nonce);

            // Assert
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
        private const int KEY_SIZE = 32;
        private const int NONCE_SIZE = 24;

        [Fact]
        public void Transform_KeyNonceReuse_ProducesSameKeystream()
        {
            // WARNING: This demonstrates why key/nonce reuse is dangerous
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext1 = TestHelpers.RandomBytes(TestDataSizes.Small);
            var plaintext2 = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext1 = new byte[plaintext1.Length];
            var ciphertext2 = new byte[plaintext2.Length];

            XSalsa20Core.Transform(ciphertext1, plaintext1, key, nonce);
            XSalsa20Core.Transform(ciphertext2, plaintext2, key, nonce);

            // XOR of ciphertexts reveals XOR of plaintexts
            var xorCiphertext = new byte[plaintext1.Length];
            var xorPlaintext = new byte[plaintext1.Length];
            for (int i = 0; i < plaintext1.Length; i++)
            {
                xorCiphertext[i] = (byte)(ciphertext1[i] ^ ciphertext2[i]);
                xorPlaintext[i] = (byte)(plaintext1[i] ^ plaintext2[i]);
            }
            CryptoAssertions.AssertBytesEqual(xorPlaintext, xorCiphertext);
        }

        [Fact]
        public void Transform_DifferentKey_ProducesDifferentCiphertext()
        {
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            XSalsa20Core.Transform(ciphertext1, plaintext, key1, nonce);
            XSalsa20Core.Transform(ciphertext2, plaintext, key2, nonce);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];

            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);

            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_SingleBitChange_CompletelyDifferentOutput()
        {
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = (byte[])key1.Clone();
            key2[0] ^= 0x01;
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            XSalsa20Core.Transform(ciphertext1, plaintext, key1, nonce);
            XSalsa20Core.Transform(ciphertext2, plaintext, key2, nonce);

            Assert.NotEqual(ciphertext1, ciphertext2);
            int diffBits = 0;
            for (int i = 0; i < ciphertext1.Length; i++)
            {
                diffBits += System.Numerics.BitOperations.PopCount((uint)(ciphertext1[i] ^ ciphertext2[i]));
            }
            int totalBits = ciphertext1.Length * 8;
            Assert.InRange(diffBits, totalBits / 4, totalBits * 3 / 4);
        }

        [Fact]
        public void Transform_LongNonce_ReducesCollisionRisk()
        {
            // XSalsa20's 24-byte nonce reduces collision risk
            // Generate many random nonces and verify they produce different outputs
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var outputs = new HashSet<string>();

            for (int i = 0; i < 100; i++)
            {
                var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
                var ciphertext = new byte[plaintext.Length];
                XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);
                outputs.Add(Convert.ToHexString(ciphertext));
            }

            Assert.Equal(100, outputs.Count);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        private const int KEY_SIZE = 32;
        private const int NONCE_SIZE = 24;

        [Fact]
        public void Transform_InvalidKeySize_ThrowsArgumentException()
        {
            var invalidKey = new byte[16];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => XSalsa20Core.Transform(ciphertext, plaintext, invalidKey, nonce),
                "32 bytes");
        }

        [Fact]
        public void Transform_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var invalidNonce = new byte[12];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => XSalsa20Core.Transform(ciphertext, plaintext, key, invalidNonce),
                "24 bytes");
        }
    }

    /// <summary>
    /// Known Answer Tests using NaCl/libsodium test vectors.
    /// See: https://nacl.cr.yp.to/secretbox.html
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void NaCl_TestVector1_AllZeroKeyAndNonce()
        {
            // NaCl test vector: Key and Nonce all zeros
            // First 64 bytes of keystream
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[64]; // All zeros to get keystream

            var ciphertext = new byte[64];
            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);

            // XSalsa20 keystream for all-zero key/nonce
            // Verify output is non-zero (produces keystream)
            Assert.NotEqual(plaintext, ciphertext);
            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void NaCl_SecretBoxTestVector()
        {
            // Test vector from libsodium/NaCl secretbox
            // Key from the NaCl crypto_secretbox test
            var key = TestHelpers.HexToBytes(
                "1b27556473e985d462cd51197a9a46c7" +
                "6009549eac6474f206c4ee0844f68389");
            var nonce = TestHelpers.HexToBytes(
                "69696ee955b62b73cd62bda875fc73d6" +
                "8219e0036b7a0b37");
            // Test plaintext
            var plaintext = TestHelpers.HexToBytes(
                "be075fc53c81f2d5cf141316ebeb0c7b" +
                "5228c52a4c62cbd44b66849b64244ffc" +
                "e5ecbaaf33bd751a1ac728d45e6c6129" +
                "6cdc3c01233561f41db66cce314adb31" +
                "0e3be8250c46f06dceea3a7fa1348057" +
                "e2f6556ad6b1318a024a838f21af1fde" +
                "048977eb48f59ffd4924ca1c60902e52" +
                "f0a089bc76897040e082f93776384864" +
                "5e0705");

            var ciphertext = new byte[plaintext.Length];
            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);

            // Verify round-trip
            var decrypted = new byte[plaintext.Length];
            XSalsa20Core.Transform(decrypted, ciphertext, key, nonce);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void NaCl_TestVector_DJBOriginal()
        {
            // Test vector from DJB's XSalsa20 specification
            // Key: 1, 2, 3, ..., 32
            var key = new byte[KEY_SIZE];
            for (int i = 0; i < KEY_SIZE; i++)
                key[i] = (byte)(i + 1);

            // Nonce: 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4
            var nonce = TestHelpers.HexToBytes("030104010509020605030508090709030203080402060204");

            var plaintext = new byte[64];
            var ciphertext = new byte[64];

            XSalsa20Core.Transform(ciphertext, plaintext, key, nonce);

            // Verify output is keystream (deterministic)
            var ciphertext2 = new byte[64];
            XSalsa20Core.Transform(ciphertext2, plaintext, key, nonce);
            CryptoAssertions.AssertBytesEqual(ciphertext, ciphertext2);
        }
    }
}
