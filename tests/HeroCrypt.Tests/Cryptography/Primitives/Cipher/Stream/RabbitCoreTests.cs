using HeroCrypt.Cryptography.Primitives.Cipher.Stream;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// Comprehensive tests for Rabbit stream cipher implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class RabbitCoreTests
{
    private const int KEY_SIZE = 16;
    private const int IV_SIZE = 8;

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
            RabbitCore.Transform(ciphertext, plaintext, key, iv);

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
            RabbitCore.Transform(ciphertext, plaintext, key, iv);
            RabbitCore.Transform(decrypted, ciphertext, key, iv);

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
            RabbitCore.Transform(ciphertext1, plaintext, key, iv1);
            RabbitCore.Transform(ciphertext2, plaintext, key, iv2);

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
            RabbitCore.Transform(ciphertext, plaintext, key, iv);
        }

        [Fact]
        public void Transform_EmptyIv_Succeeds()
        {
            // Rabbit supports key-only mode (empty IV)
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var iv = Array.Empty<byte>();
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            RabbitCore.Transform(ciphertext, plaintext, key, iv);
            RabbitCore.Transform(decrypted, ciphertext, key, iv);

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
            RabbitCore.Transform(ciphertext, plaintext, key, iv);
            RabbitCore.Transform(decrypted, ciphertext, key, iv);

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
            var invalidKey = new byte[KEY_SIZE * 2];
            var iv = new byte[IV_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => RabbitCore.Transform(ciphertext, plaintext, invalidKey, iv),
                "16 bytes");
        }

        [Fact]
        public void Transform_InvalidIvSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var invalidIv = new byte[IV_SIZE * 2]; // 16 bytes
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => RabbitCore.Transform(ciphertext, plaintext, key, invalidIv),
                "8 bytes");
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 4503 test vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc4503_TestVector1_ZeroKey_KeyOnlyMode()
        {
            // RFC 4503 Appendix A.1
            var key = new byte[16];
            var iv = Array.Empty<byte>();
            var plaintext = new byte[48]; // 3 blocks of zeros
            var expectedCiphertext = TestHelpers.HexToBytes(
                "B15754F036A5D6ECF56B45261C4AF702" +
                "88E8D815C59C0C397B696C4789C68AA7" +
                "F416A1C3700CD451DA68D1881673D696");

            var ciphertext = new byte[plaintext.Length];

            RabbitCore.Transform(ciphertext, plaintext, key, iv);

            CryptoAssertions.AssertBytesEqual(expectedCiphertext, ciphertext);
        }

        [Fact]
        public void Rfc4503_TestVector3_ZeroKeyZeroIv()
        {
            // RFC 4503 Appendix A.3
            var key = new byte[16];
            var iv = new byte[8]; // All zeros
            var plaintext = new byte[48];
            var expectedCiphertext = TestHelpers.HexToBytes(
                "C6A7275EF85495D87CCD5D376705B7ED" +
                "5F29A6AC04F5EFD47B8F293270DC4A8D" +
                "2ADE822B29DE6C1EE52BDB8A47BF8F66");

            var ciphertext = new byte[plaintext.Length];

            RabbitCore.Transform(ciphertext, plaintext, key, iv);

            CryptoAssertions.AssertBytesEqual(expectedCiphertext, ciphertext);
        }
    }
}
