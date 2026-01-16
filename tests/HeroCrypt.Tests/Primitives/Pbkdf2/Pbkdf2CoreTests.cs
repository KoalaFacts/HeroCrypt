using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Pbkdf2;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Pbkdf2;

/// <summary>
/// Comprehensive tests for PBKDF2 KDF implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Pbkdf2CoreTests
{
    private const int TEST_ITERATIONS = 10000;
    private const int OUTPUT_LEN = 32;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void DeriveKey_WithValidParameters_ReturnsCorrectLength()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt1234"); // > MIN_SALT_LENGTH

            // Act
            // Use allowWeakParameters=true for lower iteration count in unit tests to keep them fast
            var key = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            // Assert
            Assert.Equal(OUTPUT_LEN, key.Length);
        }

        [Fact]
        public void DeriveKey_IsDeterministic()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            // Act
            var key1 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);
            var key2 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentSalt_ProducesDifferentKeys()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt1 = Encoding.UTF8.GetBytes("salt1234");
            var salt2 = Encoding.UTF8.GetBytes("salt5678");

            // Act
            var key1 = Pbkdf2Core.DeriveKey(password, salt1, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);
            var key2 = Pbkdf2Core.DeriveKey(password, salt2, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void GetRecommendedParameters_ReturnsValidParams()
        {
            var p = Pbkdf2Core.GetRecommendedParameters(Pbkdf2UseCase.PasswordStorage);
            Assert.NotNull(p);
            Assert.Equal(HashAlgorithmName.SHA256, p.HashAlgorithm);
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
        public void DeriveKey_EmptyPassword_Success_WhenWeakParamsAllowed()
        {
            // Arrange
            var password = Array.Empty<byte>();
            var salt = Encoding.UTF8.GetBytes("salt1234");

            // Act
            var key = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            // Assert
            Assert.Equal(OUTPUT_LEN, key.Length);
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
        public void DeriveKey_LowIterations_ThrowsArgumentException_UnlessWeakParamsAllowed()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            // Should throw if weak params not allowed (default iterations check)
            Assert.Throws<ArgumentException>(() =>
                Pbkdf2Core.DeriveKey(password, salt, 1000, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: false));

            // Should NOT throw if weak params allowed
            var key = Pbkdf2Core.DeriveKey(password, salt, 1000, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);
            Assert.NotNull(key);
        }

        [Fact]
        public void DeriveKey_ShortSalt_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = new byte[2]; // Too short

            Assert.Throws<ArgumentException>(() =>
                Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: false));
        }

        [Fact]
        public void DeriveKey_InvalidOutputLength_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            Assert.Throws<ArgumentException>(() =>
                Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, 0, HashAlgorithmName.SHA256, allowWeakParameters: true));
        }
    }
}
