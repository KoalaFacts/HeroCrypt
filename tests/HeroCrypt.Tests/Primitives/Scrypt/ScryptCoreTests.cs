using System.Text;
using HeroCrypt.Primitives.Scrypt;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Scrypt;

/// <summary>
/// Comprehensive tests for Scrypt KDF implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class ScryptCoreTests
{
    private const int N = 16;
    private const int R = 1;
    private const int P = 1;
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
            var salt = Encoding.UTF8.GetBytes("salt");

            // Act
            var key = ScryptCore.DeriveKey(password, salt, N, R, P, OUTPUT_LEN);

            // Assert
            Assert.Equal(OUTPUT_LEN, key.Length);
        }

        [Fact]
        public void DeriveKey_IsDeterministic()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            // Act
            var key1 = ScryptCore.DeriveKey(password, salt, N, R, P, OUTPUT_LEN);
            var key2 = ScryptCore.DeriveKey(password, salt, N, R, P, OUTPUT_LEN);

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentSalt_ProducesDifferentKeys()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt1 = Encoding.UTF8.GetBytes("salt1");
            var salt2 = Encoding.UTF8.GetBytes("salt2");

            // Act
            var key1 = ScryptCore.DeriveKey(password, salt1, N, R, P, OUTPUT_LEN);
            var key2 = ScryptCore.DeriveKey(password, salt2, N, R, P, OUTPUT_LEN);

            // Assert
            Assert.NotEqual(key1, key2);
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
        public void DeriveKey_EmptyPassword_Success()
        {
            // Arrange
            var password = Array.Empty<byte>();
            var salt = Encoding.UTF8.GetBytes("salt");

            // Act
            var key = ScryptCore.DeriveKey(password, salt, N, R, P, OUTPUT_LEN);

            // Assert
            Assert.Equal(OUTPUT_LEN, key.Length);
        }

        [Fact]
        public void DeriveKey_EmptySalt_Success()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Array.Empty<byte>();

            // Act
            var key = ScryptCore.DeriveKey(password, salt, N, R, P, OUTPUT_LEN);

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
        public void DeriveKey_InvalidN_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            // N must be power of 2
            Assert.Throws<ArgumentException>(() =>
                ScryptCore.DeriveKey(password, salt, 14, R, P, OUTPUT_LEN));

            // N must be positive
            Assert.Throws<ArgumentException>(() =>
               ScryptCore.DeriveKey(password, salt, 0, R, P, OUTPUT_LEN));
        }

        [Fact]
        public void DeriveKey_InvalidR_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            Assert.Throws<ArgumentException>(() =>
                ScryptCore.DeriveKey(password, salt, N, 0, P, OUTPUT_LEN));
        }

        [Fact]
        public void DeriveKey_InvalidP_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            Assert.Throws<ArgumentException>(() =>
                ScryptCore.DeriveKey(password, salt, N, R, 0, OUTPUT_LEN));
        }

        [Fact]
        public void DeriveKey_InvalidOutputLength_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            Assert.Throws<ArgumentException>(() =>
                ScryptCore.DeriveKey(password, salt, N, R, P, 0));
        }
    }

    /// <summary>
    /// Known Answer Tests using official vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void RFC7914_TestVector1()
        {
            var password = Array.Empty<byte>();
            var salt = Array.Empty<byte>();

            // Vector 1 parameters: N=16, r=1, p=1
            var key = ScryptCore.DeriveKey(password, salt, 16, 1, 1, 64);

            var expected = Convert.FromHexString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");

            Assert.Equal(expected, key);
        }
    }
}
