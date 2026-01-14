using HeroCrypt.Tests.Infrastructure;
using static HeroCrypt.Cryptography.Primitives.Cipher.Stream.ChaChaVariants;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Stream;

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
}
