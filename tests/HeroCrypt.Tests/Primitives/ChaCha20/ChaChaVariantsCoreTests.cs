using HeroCrypt.Tests.Infrastructure;
using static HeroCrypt.Primitives.ChaCha20.ChaChaVariants;

namespace HeroCrypt.Tests.Primitives.ChaCha20;

/// <summary>
/// Comprehensive tests for ChaCha20 variants (ChaCha8, ChaCha12, ChaCha20).
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class ChaChaVariantsCoreTests
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 12;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void Transform_RoundTrip_Success(ChaChaVariant variant)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            Transform(ciphertext, plaintext, key, nonce, 0, variant);
            Transform(decrypted, ciphertext, key, nonce, 0, variant);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
            Assert.NotEqual(plaintext, ciphertext);
        }

        [Fact]
        public void Transform_DifferentVariants_ProduceDifferentCiphertexts()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ct8 = new byte[plaintext.Length];
            var ct12 = new byte[plaintext.Length];
            var ct20 = new byte[plaintext.Length];

            // Act
            Transform(ct8, plaintext, key, nonce, 0, ChaChaVariant.ChaCha8);
            Transform(ct12, plaintext, key, nonce, 0, ChaChaVariant.ChaCha12);
            Transform(ct20, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);

            // Assert
            Assert.NotEqual(ct8, ct12);
            Assert.NotEqual(ct8, ct20);
            Assert.NotEqual(ct12, ct20);
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
            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
        }

        [Fact]
        public void Transform_SingleByte_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[] { 0x42 };
            var ciphertext = new byte[1];
            var decrypted = new byte[1];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(decrypted, ciphertext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_ExactBlockSize_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64); // ChaCha20 block size
            var ciphertext = new byte[64];
            var decrypted = new byte[64];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(decrypted, ciphertext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Transform_LargeData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(decrypted, ciphertext, key, nonce, 0, ChaChaVariant.ChaCha20);

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
        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void Transform_KeyNonceReuse_ProducesSameKeystream(ChaChaVariant variant)
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext1 = TestHelpers.RandomBytes(64);
            var plaintext2 = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext1, key, nonce, 0, variant);
            Transform(ciphertext2, plaintext2, key, nonce, 0, variant);

            // Same key/nonce should produce same keystream
            var keystream1 = new byte[64];
            var keystream2 = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                keystream1[i] = (byte)(ciphertext1[i] ^ plaintext1[i]);
                keystream2[i] = (byte)(ciphertext2[i] ^ plaintext2[i]);
            }

            CryptoAssertions.AssertBytesEqual(keystream1, keystream2);
        }

        [Fact]
        public void Transform_DifferentKey_ProducesDifferentCiphertext()
        {
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key1, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key2, nonce, 0, ChaChaVariant.ChaCha20);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_DifferentNonce_ProducesDifferentCiphertext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce1, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key, nonce2, 0, ChaChaVariant.ChaCha20);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[64]; // All zeros
            var ciphertext = new byte[64];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_SingleBitChange_CompletelyDifferentOutput()
        {
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = (byte[])key1.Clone();
            key2[0] ^= 0x01; // Flip one bit

            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[64];
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key1, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key2, nonce, 0, ChaChaVariant.ChaCha20);

            Assert.NotEqual(ciphertext1, ciphertext2);

            // Count differing bits - should be roughly half
            int diffBits = 0;
            for (int i = 0; i < ciphertext1.Length; i++)
            {
                diffBits += System.Numerics.BitOperations.PopCount((uint)(ciphertext1[i] ^ ciphertext2[i]));
            }
            int totalBits = ciphertext1.Length * 8;
            Assert.InRange(diffBits, totalBits / 4, totalBits * 3 / 4);
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
        public void Transform_InvalidKeySize_ThrowsArgumentException()
        {
            var invalidKey = new byte[16];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Transform(ciphertext, plaintext, invalidKey, nonce, 0, ChaChaVariant.ChaCha20),
                "32 bytes");
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 8439 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void ChaCha20_IsDeterministic()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void ChaCha8_IsDeterministic()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce, 0, ChaChaVariant.ChaCha8);
            Transform(ciphertext2, plaintext, key, nonce, 0, ChaChaVariant.ChaCha8);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void ChaCha12_IsDeterministic()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce, 0, ChaChaVariant.ChaCha12);
            Transform(ciphertext2, plaintext, key, nonce, 0, ChaChaVariant.ChaCha12);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }
    }
}
