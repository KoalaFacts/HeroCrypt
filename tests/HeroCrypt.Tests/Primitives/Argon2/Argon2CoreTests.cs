using System.Text;
using HeroCrypt.Primitives.Argon2;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Argon2;

/// <summary>
/// Comprehensive tests for Argon2 KDF implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Argon2CoreTests
{
    private static readonly Argon2Parameters ParamDefaults = new(
        Iterations: 2,
        MemorySizeKb: 8192,
        Parallelism: 2,
        HashLength: 32,
        Type: Argon2Type.Argon2id);

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void Hash_WithValidParameters_ReturnsCorrectLength()
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("password");
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var hash = Argon2Core.Hash(
                password,
                salt,
                ParamDefaults.Iterations,
                ParamDefaults.MemorySizeKb,
                ParamDefaults.Parallelism,
                ParamDefaults.HashLength,
                ParamDefaults.Type);

            // Assert
            Assert.Equal(ParamDefaults.HashLength, hash.Length);
            CryptoAssertions.AssertAppearsRandom(hash);
        }

        [Fact]
        public void Hash_IsDeterministic()
        {
            // Arrange
            var password = TestHelpers.RandomBytes(TestDataSizes.Small);
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var hash1 = HashHelper(password, salt, ParamDefaults);
            var hash2 = HashHelper(password, salt, ParamDefaults);

            // Assert
            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_DifferentSalt_ProducesDifferentHash()
        {
            // Arrange
            var password = TestHelpers.RandomBytes(TestDataSizes.Small);
            var salt1 = TestHelpers.RandomBytes(16);
            var salt2 = TestHelpers.RandomBytes(16);

            // Act
            var hash1 = HashHelper(password, salt1, ParamDefaults);
            var hash2 = HashHelper(password, salt2, ParamDefaults);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Theory]
        [InlineData(Argon2Type.Argon2d)]
        [InlineData(Argon2Type.Argon2i)]
        [InlineData(Argon2Type.Argon2id)]
        public void Hash_AllVariants_Work(Argon2Type type)
        {
            // Arrange
            var password = Encoding.UTF8.GetBytes("TestPassword");
            var salt = TestHelpers.RandomBytes(16);
            var parameters = ParamDefaults with { Type = type };

            // Act
            var hash = HashHelper(password, salt, parameters);

            // Assert
            Assert.Equal(parameters.HashLength, hash.Length);
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
        public void Verify_WithCorrectPassword_Succeeds()
        {
            // Arrange
            var password = TestHelpers.RandomBytes(TestDataSizes.Small);
            var salt = TestHelpers.RandomBytes(16);
            var expected = HashHelper(password, salt, ParamDefaults);

            // Act
            var actual = HashHelper(password, salt, ParamDefaults);

            // Assert
            CryptoAssertions.AssertBytesEqual(expected, actual);
        }

        [Fact]
        public void Verify_WithWrongPassword_Fails()
        {
            // Arrange
            var password = TestHelpers.RandomBytes(TestDataSizes.Small);
            var wrongPassword = TestHelpers.TamperFirst(password);
            var salt = TestHelpers.RandomBytes(16);
            var expected = HashHelper(password, salt, ParamDefaults);

            // Act
            var actual = HashHelper(wrongPassword, salt, ParamDefaults);

            // Assert
            Assert.NotEqual(expected, actual);
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
        public void Hash_InvalidParameters_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentException>(() => HashHelper(password, salt, ParamDefaults with { Iterations = 0 }));
            Assert.Throws<ArgumentException>(() => HashHelper(password, salt, ParamDefaults with { MemorySizeKb = 0 }));
            Assert.Throws<ArgumentException>(() => HashHelper(password, salt, ParamDefaults with { Parallelism = 0 }));
            Assert.Throws<ArgumentException>(() => HashHelper(password, salt, ParamDefaults with { HashLength = 0 }));
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 9106 test vectors.
    /// See: https://datatracker.ietf.org/doc/html/rfc9106#appendix-A
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc9106_AppendixA1_Argon2d()
        {
            // RFC 9106 Appendix A.1 - Argon2d Test Vector
            var password = new byte[] {
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
            };
            var salt = new byte[] {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            };
            var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
            var ad = new byte[] {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04
            };
            var expected = TestHelpers.HexToBytes("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");

            var result = Argon2Core.Hash(
                password: password,
                salt: salt,
                iterations: 3,
                memorySize: 32,
                parallelism: 4,
                hashLength: 32,
                type: Argon2Type.Argon2d,
                associatedData: ad,
                secret: secret);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }

        [Fact]
        public void Rfc9106_AppendixA2_Argon2i()
        {
            // RFC 9106 Appendix A.2 - Argon2i Test Vector
            var password = new byte[] {
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
            };
            var salt = new byte[] {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            };
            var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
            var ad = new byte[] {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04
            };
            var expected = TestHelpers.HexToBytes("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");

            var result = Argon2Core.Hash(
                password: password,
                salt: salt,
                iterations: 3,
                memorySize: 32,
                parallelism: 4,
                hashLength: 32,
                type: Argon2Type.Argon2i,
                associatedData: ad,
                secret: secret);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }

        [Fact]
        public void Rfc9106_AppendixA3_Argon2id()
        {
            // RFC 9106 Appendix A.3 - Argon2id Test Vector
            var password = new byte[] {
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
            };
            var salt = new byte[] {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            };
            var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
            var ad = new byte[] {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04
            };
            var expected = TestHelpers.HexToBytes("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

            var result = Argon2Core.Hash(
                password: password,
                salt: salt,
                iterations: 3,
                memorySize: 32,
                parallelism: 4,
                hashLength: 32,
                type: Argon2Type.Argon2id,
                associatedData: ad,
                secret: secret);

            CryptoAssertions.AssertBytesEqual(expected, result);
        }
    }

    // Helper for easier calling
    private static byte[] HashHelper(byte[] password, byte[] salt, Argon2Parameters p) =>
        Argon2Core.Hash(password, salt, p.Iterations, p.MemorySizeKb, p.Parallelism, p.HashLength, p.Type);

    private readonly record struct Argon2Parameters(
        int Iterations,
        int MemorySizeKb,
        int Parallelism,
        int HashLength,
        Argon2Type Type);
}
