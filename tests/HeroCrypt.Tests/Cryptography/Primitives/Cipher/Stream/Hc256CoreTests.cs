using HeroCrypt.Cryptography.Primitives.Cipher.Stream;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// Comprehensive tests for HC-256 stream cipher implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Hc256CoreTests
{
    private const int KEY_SIZE = 32;
    private const int IV_SIZE = 32;

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
            Hc256Core.Transform(ciphertext, plaintext, key, iv);

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
            Hc256Core.Transform(ciphertext, plaintext, key, iv);
            Hc256Core.Transform(decrypted, ciphertext, key, iv);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
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
            Hc256Core.Transform(ciphertext, plaintext, key, iv);
        }

        [Fact]
        public void TableTransitionBoundary_Success()
        {
            // HC-256 also has table transitions
            // Test around this boundary (2048 bytes)

            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = TestHelpers.RandomBytes(IV_SIZE);
            var plaintext = TestHelpers.RandomBytes(2048 + 100);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            Hc256Core.Transform(ciphertext, plaintext, key, iv);
            Hc256Core.Transform(decrypted, ciphertext, key, iv);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
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
            var invalidKey = new byte[KEY_SIZE / 2];
            var iv = new byte[IV_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Hc256Core.Transform(ciphertext, plaintext, invalidKey, iv),
                "32 bytes");
        }

        [Fact]
        public void Transform_InvalidIvSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var invalidIv = new byte[IV_SIZE / 2];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Hc256Core.Transform(ciphertext, plaintext, key, invalidIv),
                "32 bytes");
        }
    }
}
