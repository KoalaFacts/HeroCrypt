using HeroCrypt.Cryptography.Primitives.Cipher.Stream;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Stream;

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
}
