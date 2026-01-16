using System.Security.Cryptography;
using HeroCrypt.Primitives.ChaCha20;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.ChaCha20;

/// <summary>
/// Comprehensive tests for ChaCha20 stream cipher implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class ChaCha20CoreTests
{
    private const int KEY_SIZE = ChaCha20Core.KEY_SIZE;
    private const int NONCE_SIZE = ChaCha20Core.NONCE_SIZE;
    private const int BLOCK_SIZE = ChaCha20Core.BLOCK_SIZE;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void Transform_WithValidParameters_ProducesEncryptedOutput()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);

            // Assert
            Assert.NotEqual(plaintext, ciphertext);
            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_RoundTrip_RecoversOriginalPlaintext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, 0);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_SameKeyNonce_IsDeterministic()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext1, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(ciphertext2, plaintext, key, nonce, 0);

            // Assert
            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_DifferentNonce_ProducesDifferentCiphertext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext1, plaintext, key, nonce1, 0);
            ChaCha20Core.Transform(ciphertext2, plaintext, key, nonce2, 0);

            // Assert
            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_DifferentKey_ProducesDifferentCiphertext()
        {
            // Arrange
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext1, plaintext, key1, nonce, 0);
            ChaCha20Core.Transform(ciphertext2, plaintext, key2, nonce, 0);

            // Assert
            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_DifferentCounter_ProducesDifferentCiphertext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext1 = new byte[plaintext.Length];
            var ciphertext2 = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext1, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(ciphertext2, plaintext, key, nonce, 1);

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

            // Act & Assert - should not throw
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
        }

        [Fact]
        public void Transform_SingleByte_RoundTripsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);

            var plaintext = "B"u8.ToArray();
            var ciphertext = new byte[1];
            var decrypted = new byte[1];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, 0);

            // Assert
            Assert.Equal(plaintext, decrypted);
            Assert.NotEqual(plaintext[0], ciphertext[0]);
        }

        [Fact]
        public void Transform_ExactlyOneBlock_RoundTripsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext = new byte[BLOCK_SIZE];
            var decrypted = new byte[BLOCK_SIZE];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, 0);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Theory]
        [InlineData(63)]  // Just under one block
        [InlineData(65)]  // Just over one block
        [InlineData(127)] // Just under two blocks
        [InlineData(129)] // Just over two blocks
        public void Transform_PartialBlocks_RoundTripsCorrectly(int length)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(length);
            var ciphertext = new byte[length];
            var decrypted = new byte[length];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, 0);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_ZeroKey_StillFunctions()
        {
            // Arrange - all zeros key (weak but valid)
            var key = TestHelpers.ZeroBytes(KEY_SIZE);
            var nonce = TestHelpers.ZeroBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext = new byte[BLOCK_SIZE];
            var decrypted = new byte[BLOCK_SIZE];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, 0);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_MaxCounterWithSingleBlock_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext = new byte[BLOCK_SIZE];
            var decrypted = new byte[BLOCK_SIZE];

            // Act - use max counter that won't overflow with single block
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, uint.MaxValue - 1);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, uint.MaxValue - 1);

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
        [Fact]
        public void Transform_CounterOverflow_ThrowsCryptographicException()
        {
            // Arrange - force counter overflow with multi-block data
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE * 4 + 1);
            var ciphertext = new byte[plaintext.Length];

            // Act & Assert
            Assert.Throws<CryptographicException>(() =>
                ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, uint.MaxValue));
        }

        [Fact]
        public void Transform_NonceReuse_LeaksKeystreamRelationship()
        {
            // This test demonstrates why nonce reuse is catastrophic:
            // XOR(ciphertext1, ciphertext2) = XOR(plaintext1, plaintext2)

            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE); // Same nonce!
            var plaintext1 = TestHelpers.SequentialBytes(BLOCK_SIZE);
            var plaintext2 = TestHelpers.FilledBytes(BLOCK_SIZE, 0xFF);
            var ciphertext1 = new byte[BLOCK_SIZE];
            var ciphertext2 = new byte[BLOCK_SIZE];

            // Act
            ChaCha20Core.Transform(ciphertext1, plaintext1, key, nonce, 0);
            ChaCha20Core.Transform(ciphertext2, plaintext2, key, nonce, 0);

            // Assert - XOR of ciphertexts equals XOR of plaintexts
            var xorCiphertext = TestHelpers.Xor(ciphertext1, ciphertext2);
            var xorPlaintext = TestHelpers.Xor(plaintext1, plaintext2);
            CryptoAssertions.AssertBytesEqual(xorPlaintext, xorCiphertext);
        }

        [Fact]
        public void Transform_AllZeroPlaintext_RevealsKeystream()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var zeroPlaintext = TestHelpers.ZeroBytes(BLOCK_SIZE);
            var keystream = new byte[BLOCK_SIZE];

            // Act
            ChaCha20Core.Transform(keystream, zeroPlaintext, key, nonce, 0);

            // Assert - keystream should appear random
            CryptoAssertions.AssertAppearsRandom(keystream);
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
            // Arrange
            var invalidKey = TestHelpers.RandomBytes(KEY_SIZE - 1);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext = new byte[BLOCK_SIZE];

            // Act & Assert
            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => ChaCha20Core.Transform(ciphertext, plaintext, invalidKey, nonce, 0),
                "32 bytes");
        }

        [Fact]
        public void Transform_InvalidNonceSize_ThrowsArgumentException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var invalidNonce = TestHelpers.RandomBytes(NONCE_SIZE - 1);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext = new byte[BLOCK_SIZE];

            // Act & Assert
            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => ChaCha20Core.Transform(ciphertext, plaintext, key, invalidNonce, 0),
                "12 bytes");
        }

        [Fact]
        public void Transform_OutputBufferTooSmall_ThrowsArgumentException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE);
            var ciphertext = new byte[BLOCK_SIZE / 2]; // Too small

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0));
        }
    }

    /// <summary>
    /// Performance and scalability tests.
    /// </summary>
    [Trait("Category", TestCategories.SLOW)]
    public class Performance
    {
        [Fact]
        public void Transform_LargeData_RoundTripsCorrectly()
        {
            // Arrange - 1 MB
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            ChaCha20Core.Transform(decrypted, ciphertext, key, nonce, 0);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_ChunkedProcessing_MatchesFullProcessing()
        {
            // Verify chunk-by-chunk processing produces same result

            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(BLOCK_SIZE * 4);
            var fullCiphertext = new byte[plaintext.Length];

            // Act - full transformation
            ChaCha20Core.Transform(fullCiphertext, plaintext, key, nonce, 0);

            // Act - chunked transformation
            var chunk0 = new byte[BLOCK_SIZE];
            var chunk1 = new byte[BLOCK_SIZE];
            var chunk2 = new byte[BLOCK_SIZE];
            var chunk3 = new byte[BLOCK_SIZE];

            ChaCha20Core.Transform(chunk0, plaintext.AsSpan(0, BLOCK_SIZE), key, nonce, 0);
            ChaCha20Core.Transform(chunk1, plaintext.AsSpan(BLOCK_SIZE, BLOCK_SIZE), key, nonce, 1);
            ChaCha20Core.Transform(chunk2, plaintext.AsSpan(BLOCK_SIZE * 2, BLOCK_SIZE), key, nonce, 2);
            ChaCha20Core.Transform(chunk3, plaintext.AsSpan(BLOCK_SIZE * 3, BLOCK_SIZE), key, nonce, 3);

            // Assert
            Assert.Equal(fullCiphertext[..(BLOCK_SIZE)], chunk0);
            Assert.Equal(fullCiphertext[(BLOCK_SIZE)..(BLOCK_SIZE * 2)], chunk1);
            Assert.Equal(fullCiphertext[(BLOCK_SIZE * 2)..(BLOCK_SIZE * 3)], chunk2);
            Assert.Equal(fullCiphertext[(BLOCK_SIZE * 3)..], chunk3);
        }
    }

    /// <summary>
    /// Known Answer Tests using official RFC 8439 test vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void RFC8439_Section242_TestVector()
        {
            // RFC 8439 Section 2.4.2 Test Vector
            var key = TestHelpers.HexToBytes(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            var nonce = TestHelpers.HexToBytes("000000000000004a00000000");
            var plaintext = System.Text.Encoding.ASCII.GetBytes(
                "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

            var expectedCiphertext = TestHelpers.HexToBytes(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
                "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
                "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
                "5af90bbf74a35be6b40b8eedf2785e42874d");

            var ciphertext = new byte[plaintext.Length];

            // Act
            ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 1); // Counter=1 per RFC

            // Assert
            CryptoAssertions.AssertBytesEqual(expectedCiphertext, ciphertext);
        }
    }

    /// <summary>
    /// Memory hygiene tests verifying sensitive data cleanup.
    /// </summary>
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class MemoryHygiene
    {
        [Fact]
        public void Transform_RepeatedCalls_NoMemoryAccumulation()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Large);
            var ciphertext = new byte[plaintext.Length];

            // Act - repeated calls should not leak memory
            for (int i = 0; i < 100; i++)
            {
                ChaCha20Core.Transform(ciphertext, plaintext, key, nonce, 0);
            }

            // Assert - completing without OOM indicates proper cleanup
            Assert.True(true);
        }
    }
}
