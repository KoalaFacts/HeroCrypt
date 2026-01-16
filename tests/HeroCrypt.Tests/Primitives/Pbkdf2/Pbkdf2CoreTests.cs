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
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        [Fact]
        public void DeriveKey_CorrectPassword_Matches()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            var key1 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);
            var key2 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_WrongPassword_DoesNotMatch()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var wrongPassword = Encoding.UTF8.GetBytes("wrong_password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            var key1 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);
            var key2 = Pbkdf2Core.DeriveKey(wrongPassword, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_OutputAppearsRandom()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            var key = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);

            CryptoAssertions.AssertAppearsRandom(key);
        }

        [Fact]
        public void DeriveKey_DifferentHashAlgorithm_ProducesDifferentOutput()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var salt = Encoding.UTF8.GetBytes("salt1234");

            var key256 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA256, allowWeakParameters: true);
            var key512 = Pbkdf2Core.DeriveKey(password, salt, TEST_ITERATIONS, OUTPUT_LEN, HashAlgorithmName.SHA512, allowWeakParameters: true);

            Assert.NotEqual(key256, key512);
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

    /// <summary>
    /// Known Answer Tests using RFC 6070 test vectors.
    /// See: https://datatracker.ietf.org/doc/html/rfc6070
    /// Note: RFC 6070 vectors use HMAC-SHA1; we must allow weak parameters for these tests.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc6070_TestVector1_1Iteration()
        {
            // RFC 6070 Test Vector 1
            // Input:
            //   P = "password" (8 octets)
            //   S = "salt" (4 octets)
            //   c = 1
            //   dkLen = 20
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");
            var expected = TestHelpers.HexToBytes("0c60c80f961f0e71f3a9b524af6012062fe037a6");

            var result = Pbkdf2Core.DeriveKey(password, salt, 1, 20, HashAlgorithmName.SHA1, allowWeakParameters: true);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }

        [Fact]
        public void Rfc6070_TestVector2_2Iterations()
        {
            // RFC 6070 Test Vector 2
            // Input:
            //   P = "password" (8 octets)
            //   S = "salt" (4 octets)
            //   c = 2
            //   dkLen = 20
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");
            var expected = TestHelpers.HexToBytes("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

            var result = Pbkdf2Core.DeriveKey(password, salt, 2, 20, HashAlgorithmName.SHA1, allowWeakParameters: true);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }

        [Fact]
        public void Rfc6070_TestVector3_4096Iterations()
        {
            // RFC 6070 Test Vector 3
            // Input:
            //   P = "password" (8 octets)
            //   S = "salt" (4 octets)
            //   c = 4096
            //   dkLen = 20
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");
            var expected = TestHelpers.HexToBytes("4b007901b765489abead49d926f721d065a429c1");

            var result = Pbkdf2Core.DeriveKey(password, salt, 4096, 20, HashAlgorithmName.SHA1, allowWeakParameters: true);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Rfc6070_TestVector4_16777216Iterations()
        {
            // RFC 6070 Test Vector 4 - Very slow due to high iteration count
            // Input:
            //   P = "password" (8 octets)
            //   S = "salt" (4 octets)
            //   c = 16777216
            //   dkLen = 20
            // Skip this test in normal runs - only for full compliance validation
            Assert.Skip("Skipping extremely slow test (16M iterations). Run with full compliance suite.");
        }

        [Fact]
        public void Rfc6070_TestVector5_LongerPassword()
        {
            // RFC 6070 Test Vector 5
            // Input:
            //   P = "passwordPASSWORDpassword" (24 octets)
            //   S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
            //   c = 4096
            //   dkLen = 25
            var password = Encoding.UTF8.GetBytes("passwordPASSWORDpassword");
            var salt = Encoding.UTF8.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
            var expected = TestHelpers.HexToBytes("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");

            var result = Pbkdf2Core.DeriveKey(password, salt, 4096, 25, HashAlgorithmName.SHA1, allowWeakParameters: true);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }

        [Fact]
        public void Rfc6070_TestVector6_NullByteInPassword()
        {
            // RFC 6070 Test Vector 6
            // Input:
            //   P = "pass\0word" (9 octets)
            //   S = "sa\0lt" (5 octets)
            //   c = 4096
            //   dkLen = 16
            var password = Encoding.UTF8.GetBytes("pass\0word");
            var salt = Encoding.UTF8.GetBytes("sa\0lt");
            var expected = TestHelpers.HexToBytes("56fa6aa75548099dcc37d7f03425e0c3");

            var result = Pbkdf2Core.DeriveKey(password, salt, 4096, 16, HashAlgorithmName.SHA1, allowWeakParameters: true);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }
    }
}
