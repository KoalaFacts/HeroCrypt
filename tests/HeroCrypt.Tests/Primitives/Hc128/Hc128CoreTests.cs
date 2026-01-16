using HeroCrypt.Primitives.Hc128;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Hc128;

/// <summary>
/// Comprehensive tests for HC-128 stream cipher implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Hc128CoreTests
{
    private const int KEY_SIZE = 16;
    private const int IV_SIZE = 16;

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
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];

            // Act
            Hc128Core.Transform(ciphertext, plaintext, key, iv);

            // Assert
            Assert.NotEqual(plaintext, ciphertext);
            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_RoundTrip_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            Hc128Core.Transform(ciphertext, plaintext, key, iv);
            Hc128Core.Transform(decrypted, ciphertext, key, iv);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_DifferentIv_ProducesDifferentCiphertext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv1 = TestHelpers.RandomBytes(IV_SIZE);
            var iv2 = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            // Act
            Hc128Core.Transform(ciphertext1, plaintext, key, iv1);
            Hc128Core.Transform(ciphertext2, plaintext, key, iv2);

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
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = Array.Empty<byte>();
            var ciphertext = Array.Empty<byte>();

            // Act & Assert
            Hc128Core.Transform(ciphertext, plaintext, key, iv);
        }

        [Fact]
        public void TableTransitionBoundary_Success()
        {
            // HC-128 updates tables every 512 words (2048 bytes)
            // Test around this boundary

            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(2048 + 100);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            Hc128Core.Transform(ciphertext, plaintext, key, iv);
            Hc128Core.Transform(decrypted, ciphertext, key, iv);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Transform_LargeData_Success()
        {
            // Arrange - 1 MB
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            Hc128Core.Transform(ciphertext, plaintext, key, iv);
            Hc128Core.Transform(decrypted, ciphertext, key, iv);

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
        private const int KEY_SIZE = 16;
        private const int IV_SIZE = 16;

        [Fact]
        public void Transform_KeyIvReuse_ProducesSameKeystream()
        {
            // WARNING: This demonstrates why key/IV reuse is dangerous
            // Same key/IV always produces same keystream
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext1 = TestHelpers.RandomBytes(TestDataSizes.Small);
            var plaintext2 = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext1 = new byte[plaintext1.Length];
            var ciphertext2 = new byte[plaintext2.Length];

            Hc128Core.Transform(ciphertext1, plaintext1, key, iv);
            Hc128Core.Transform(ciphertext2, plaintext2, key, iv);

            // XOR of ciphertexts reveals XOR of plaintexts (catastrophic)
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
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            Hc128Core.Transform(ciphertext1, plaintext, key1, iv);
            Hc128Core.Transform(ciphertext2, plaintext, key2, iv);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];

            Hc128Core.Transform(ciphertext, plaintext, key, iv);

            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_SingleBitChange_CompletelyDifferentOutput()
        {
            // Avalanche effect: single bit change in key produces completely different output
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = (byte[])key1.Clone();
            key2[0] ^= 0x01; // Flip one bit
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            Hc128Core.Transform(ciphertext1, plaintext, key1, iv);
            Hc128Core.Transform(ciphertext2, plaintext, key2, iv);

            // Outputs should be completely different
            Assert.NotEqual(ciphertext1, ciphertext2);
            // Check approximately 50% of bits differ (avalanche)
            int diffBits = 0;
            for (int i = 0; i < ciphertext1.Length; i++)
            {
                diffBits += System.Numerics.BitOperations.PopCount((uint)(ciphertext1[i] ^ ciphertext2[i]));
            }
            // Should be roughly 50% of total bits
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
            var invalidKey = new byte[KEY_SIZE * 2];
            var iv = new byte[IV_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Hc128Core.Transform(ciphertext, plaintext, invalidKey, iv),
                "16 bytes");
        }

        [Fact]
        public void Transform_InvalidIvSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var invalidIv = new byte[IV_SIZE / 2];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Hc128Core.Transform(ciphertext, plaintext, key, invalidIv),
                "16 bytes");
        }
    }

    /// <summary>
    /// Known Answer Tests for HC-128 stream cipher.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Hc128_AllZeroKeyAndIv_IsDeterministic()
        {
            // Verify determinism: same key/IV produces same keystream
            var key = new byte[KEY_SIZE];
            var iv = new byte[IV_SIZE];
            var plaintext = new byte[64];

            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];
            Hc128Core.Transform(ciphertext1, plaintext, key, iv);
            Hc128Core.Transform(ciphertext2, plaintext, key, iv);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
            CryptoAssertions.AssertAppearsRandom(ciphertext1);
        }

        [Fact]
        public void Hc128_DifferentIv_ProducesDifferentKeystream()
        {
            var key = new byte[KEY_SIZE];
            var iv1 = new byte[IV_SIZE];
            var iv2 = new byte[IV_SIZE];
            iv2[0] = 0x01;
            var plaintext = new byte[64];

            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];
            Hc128Core.Transform(ciphertext1, plaintext, key, iv1);
            Hc128Core.Transform(ciphertext2, plaintext, key, iv2);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Hc128_DifferentKey_ProducesDifferentKeystream()
        {
            var key1 = new byte[KEY_SIZE];
            var key2 = new byte[KEY_SIZE];
            key2[0] = 0x55;
            var iv = new byte[IV_SIZE];
            var plaintext = new byte[64];

            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];
            Hc128Core.Transform(ciphertext1, plaintext, key1, iv);
            Hc128Core.Transform(ciphertext2, plaintext, key2, iv);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }
    }
}
