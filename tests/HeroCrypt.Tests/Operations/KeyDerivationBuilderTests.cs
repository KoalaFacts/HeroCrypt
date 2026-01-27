using System.Text;
using HeroCrypt.Operations;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Comprehensive tests for key derivation operations using HeroCryptBuilder.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
/// <remarks>
/// For low-level primitive tests, see individual *CoreTests files in Primitives folder.
/// </remarks>
public class KeyDerivationBuilderTests
{
    private static readonly byte[] TestPassword = Encoding.UTF8.GetBytes("correct horse battery staple");

    /// <summary>
    /// Basic functionality tests for key derivation algorithms.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Theory]
        [InlineData(KeyDerivationAlgorithm.HkdfSha256, 32)]
        [InlineData(KeyDerivationAlgorithm.HkdfSha384, 32)]
        [InlineData(KeyDerivationAlgorithm.HkdfSha512, 32)]
        [InlineData(KeyDerivationAlgorithm.Pbkdf2Sha256, 32)]
        [InlineData(KeyDerivationAlgorithm.Pbkdf2Sha384, 32)]
        [InlineData(KeyDerivationAlgorithm.Pbkdf2Sha512, 32)]
        public void DeriveKey_ReturnsCorrectLength(KeyDerivationAlgorithm algorithm, int expectedLength)
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(algorithm)
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(expectedLength)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(expectedLength, key.Length);
            Assert.False(TestHelpers.AllZeros(key));
        }

        [Fact]
        public void DeriveKey_IsDeterministic()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentPasswords_ProduceDifferentKeys()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);
            var password1 = Encoding.UTF8.GetBytes("password1");
            var password2 = Encoding.UTF8.GetBytes("password2");

            // Act
            var key1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(password1)
                .WithSalt(salt)
                .DeriveKey();

            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(password2)
                .WithSalt(salt)
                .DeriveKey();

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentSalts_ProduceDifferentKeys()
        {
            // Arrange
            var salt1 = TestHelpers.RandomBytes(16);
            var salt2 = TestHelpers.RandomBytes(16);

            // Act
            var key1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt1)
                .DeriveKey();

            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt2)
                .DeriveKey();

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_WithStringPassword_Succeeds()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword("my secret password")
                .WithSalt(salt)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }
    }

    /// <summary>
    /// Tests for memory-hard algorithms (Argon2, Scrypt).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class MemoryHardAlgorithms
    {
        [Theory]
        [InlineData(KeyDerivationAlgorithm.Argon2id)]
        [InlineData(KeyDerivationAlgorithm.Argon2d)]
        [InlineData(KeyDerivationAlgorithm.Argon2i)]
        public void DeriveKey_Argon2Variants_Succeed(KeyDerivationAlgorithm algorithm)
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(algorithm)
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(32)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
            Assert.False(TestHelpers.AllZeros(key));
        }

        [Fact]
        public void DeriveKey_Scrypt_Succeeds()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithScrypt()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(32)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void DeriveKey_Argon2id_IsDeterministic()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key1 = HeroCryptBuilder.DeriveKey()
                .WithArgon2id()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var key2 = HeroCryptBuilder.DeriveKey()
                .WithArgon2id()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

#if !NETSTANDARD2_0
        [Fact]
        public void DeriveKey_BalloonSha256_Succeeds()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithBalloonSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(32)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void DeriveKey_BalloonSha512_Succeeds()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithBalloonSha512()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(64)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(64, key.Length);
        }
#endif
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        [InlineData(128)]
        public void DeriveKey_VariableOutputLengths_Succeed(int outputLength)
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(outputLength)
                .DeriveKey();

            // Assert
            Assert.Equal(outputLength, key.Length);
        }

        [Fact]
        public void DeriveKey_ShortPassword_Succeeds()
        {
            // Arrange
            var shortPassword = Encoding.UTF8.GetBytes("a");
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(shortPassword)
                .WithSalt(salt)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }
    }

    /// <summary>
    /// Tests for different algorithm families.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmFamilies
    {
        [Fact]
        public void DeriveKey_DifferentAlgorithms_ProduceDifferentKeys()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var hkdf = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var pbkdf2 = HeroCryptBuilder.DeriveKey()
                .WithPbkdf2Sha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            // Assert - Different algorithms should produce different keys
            Assert.NotEqual(hkdf, pbkdf2);
        }

        [Fact]
        public void DeriveKey_Pbkdf2_DifferentHashAlgorithms_ProduceDifferentKeys()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var sha256 = HeroCryptBuilder.DeriveKey()
                .WithPbkdf2Sha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var sha512 = HeroCryptBuilder.DeriveKey()
                .WithPbkdf2Sha512()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            // Assert
            Assert.NotEqual(sha256, sha512);
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
        public void DeriveKey_WithoutPassword_ThrowsInvalidOperationException()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.DeriveKey()
                    .WithHkdfSha256()
                    .WithSalt(salt)
                    .DeriveKey());
        }

        [Fact]
        public void DeriveKey_WithoutSalt_ThrowsInvalidOperationException()
        {
            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.DeriveKey()
                    .WithHkdfSha256()
                    .WithPassword(TestPassword)
                    .DeriveKey());
        }
    }

    /// <summary>
    /// Tests for IDisposable implementation and secure memory clearing.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DisposalBehavior
    {
        [Fact]
        public void DeriveKey_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(TestHelpers.RandomBytes(16));
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(builder.DeriveKey);
        }

        [Fact]
        public void WithPassword_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithPassword(TestPassword));
        }

        [Fact]
        public void WithSalt_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithSalt(TestHelpers.RandomBytes(16)));
        }

        [Fact]
        public void Dispose_MultipleTimes_DoesNotThrow()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();

            // Act & Assert - Should not throw
            builder.Dispose();
            builder.Dispose();
        }
    }

    /// <summary>
    /// Tests for WithRandomSalt() and GetSalt() convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RandomSaltGeneration
    {
        [Fact]
        public void WithRandomSalt_GeneratesValidSalt()
        {
            // Act
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithRandomSalt();
            var key = builder.DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void WithRandomSalt_DefaultLength_Is16Bytes()
        {
            // Act
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithRandomSalt();
            var salt = builder.GetSalt();

            // Assert
            Assert.Equal(16, salt.Length);
        }

        [Theory]
        [InlineData(8)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void WithRandomSalt_CustomLength_ProducesCorrectSize(int length)
        {
            // Act
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithRandomSalt(length);
            var salt = builder.GetSalt();

            // Assert
            Assert.Equal(length, salt.Length);
        }

        [Fact]
        public void WithRandomSalt_ZeroLength_ThrowsArgumentOutOfRangeException()
        {
            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                HeroCryptBuilder.DeriveKey().WithRandomSalt(0));
        }

        [Fact]
        public void WithRandomSalt_NegativeLength_ThrowsArgumentOutOfRangeException()
        {
            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                HeroCryptBuilder.DeriveKey().WithRandomSalt(-1));
        }

        [Fact]
        public void GetSalt_WithoutSettingSalt_ThrowsInvalidOperationException()
        {
            // Arrange
            using var builder = HeroCryptBuilder.DeriveKey();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(builder.GetSalt);
        }

        [Fact]
        public void GetSalt_ReturnsCopyOfSalt()
        {
            // Arrange
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithRandomSalt();

            // Act
            var salt1 = builder.GetSalt();
            var salt2 = builder.GetSalt();

            // Assert - Should return copies, not the same reference
            Assert.Equal(salt1, salt2);
            Assert.NotSame(salt1, salt2);
        }

        [Fact]
        public void WithRandomSalt_MultipleCalls_ProducesDifferentSalts()
        {
            // Act
            using var builder1 = HeroCryptBuilder.DeriveKey().WithRandomSalt();
            using var builder2 = HeroCryptBuilder.DeriveKey().WithRandomSalt();

            var salt1 = builder1.GetSalt();
            var salt2 = builder2.GetSalt();

            // Assert - Random salts should be different
            Assert.NotEqual(salt1, salt2);
        }

        [Fact]
        public void WithRandomSalt_CanBeUsedWithDeriveKey()
        {
            // Arrange
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithRandomSalt();

            // Act
            var salt = builder.GetSalt();
            var key = builder.DeriveKey();

            // Assert
            Assert.NotNull(salt);
            Assert.NotNull(key);
            Assert.False(TestHelpers.AllZeros(salt));
            Assert.False(TestHelpers.AllZeros(key));
        }
    }

    /// <summary>
    /// Tests for HKDF info parameter functionality.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class HkdfInfoParameter
    {
        [Fact]
        public void WithInfo_ByteArray_ProducesDifferentKeyThanWithoutInfo()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);
            var info = Encoding.UTF8.GetBytes("my-application-context");

            // Act
            var keyWithoutInfo = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var keyWithInfo = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo(info)
                .DeriveKey();

            // Assert - Different info should produce different keys
            Assert.NotEqual(keyWithoutInfo, keyWithInfo);
        }

        [Fact]
        public void WithInfo_String_ProducesDifferentKeyThanWithoutInfo()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyWithoutInfo = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var keyWithInfo = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo("my-application-context")
                .DeriveKey();

            // Assert - Different info should produce different keys
            Assert.NotEqual(keyWithoutInfo, keyWithInfo);
        }

        [Fact]
        public void WithInfo_DifferentInfoValues_ProduceDifferentKeys()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var encryptionKey = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo("encryption")
                .DeriveKey();

            var authKey = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo("authentication")
                .DeriveKey();

            // Assert - Different info values should produce different keys
            Assert.NotEqual(encryptionKey, authKey);
        }

        [Fact]
        public void WithInfo_SameInfo_ProducesSameKey()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);
            var info = Encoding.UTF8.GetBytes("my-context");

            // Act
            var key1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo(info)
                .DeriveKey();

            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo(info)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Theory]
        [InlineData(KeyDerivationAlgorithm.HkdfSha256)]
        [InlineData(KeyDerivationAlgorithm.HkdfSha384)]
        [InlineData(KeyDerivationAlgorithm.HkdfSha512)]
        public void WithInfo_AllHkdfVariants_ProducesDifferentKeysWithInfo(KeyDerivationAlgorithm algorithm)
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyWithoutInfo = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(algorithm)
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var keyWithInfo = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(algorithm)
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo("context")
                .DeriveKey();

            // Assert
            Assert.NotEqual(keyWithoutInfo, keyWithInfo);
        }

        [Fact]
        public void WithInfo_EmptyInfo_IsSameAsNoInfo()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyWithoutInfo = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKey();

            var keyWithEmptyInfo = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithInfo([])
                .DeriveKey();

            // Assert - Empty info should be equivalent to no info
            CryptoAssertions.AssertBytesEqual(keyWithoutInfo, keyWithEmptyInfo);
        }

        [Fact]
        public void WithInfo_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithInfo("context"));
        }

        [Fact]
        public void WithInfo_ByteArray_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithInfo(Encoding.UTF8.GetBytes("context")));
        }
    }

    /// <summary>
    /// Tests for salt output format convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SaltOutputFormatTests
    {
        [Fact]
        public void GetSaltAsHex_ReturnsLowercaseHexString()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword)
                .WithRandomSalt(16);

            // Act
            var saltHex = kdf.GetSaltAsHex();

            // Assert
            Assert.Equal(32, saltHex.Length); // 16 bytes = 32 hex chars
            Assert.Equal(saltHex.ToLowerInvariant(), saltHex); // lowercase
            Assert.Matches("^[0-9a-f]+$", saltHex); // valid hex
        }

        [Fact]
        public void GetSaltAsHex_MatchesGetSalt()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword)
                .WithRandomSalt(16);

            // Act
            var saltBytes = kdf.GetSalt();
            var saltHex = kdf.GetSaltAsHex();

            // Assert
            Assert.Equal(Convert.ToHexString(saltBytes).ToLowerInvariant(), saltHex);
        }

        [Fact]
        public void GetSaltAsBase64_ReturnsValidBase64()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword)
                .WithRandomSalt(16);

            // Act
            var saltBase64 = kdf.GetSaltAsBase64();

            // Assert
            var decoded = Convert.FromBase64String(saltBase64);
            Assert.Equal(16, decoded.Length);
        }

        [Fact]
        public void GetSaltAsBase64_MatchesGetSalt()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword)
                .WithRandomSalt(16);

            // Act
            var saltBytes = kdf.GetSalt();
            var saltBase64 = kdf.GetSaltAsBase64();

            // Assert
            Assert.Equal(Convert.ToBase64String(saltBytes), saltBase64);
        }

        [Fact]
        public void GetSaltAsBase64Url_ReturnsUrlSafeString()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword)
                .WithRandomSalt(16);

            // Act
            var saltBase64Url = kdf.GetSaltAsBase64Url();

            // Assert
            Assert.DoesNotContain("+", saltBase64Url);
            Assert.DoesNotContain("/", saltBase64Url);
            Assert.DoesNotContain("=", saltBase64Url);
        }

        [Fact]
        public void GetSaltAsBase64Url_CanBeDecodedBack()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword)
                .WithRandomSalt(16);

            // Act
            var saltBytes = kdf.GetSalt();
            var saltBase64Url = kdf.GetSaltAsBase64Url();

            // Convert back from URL-safe Base64
            var base64 = saltBase64Url
                .Replace('-', '+')
                .Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 0: break;
                case 1: break;
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
                default: break;
            }
            var decoded = Convert.FromBase64String(base64);

            // Assert
            Assert.Equal(saltBytes, decoded);
        }

        [Fact]
        public void GetSaltAsHex_WithoutSalt_ThrowsInvalidOperationException()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword);
            // Salt not set

            // Act & Assert
            Assert.Throws<InvalidOperationException>(kdf.GetSaltAsHex);
        }

        [Fact]
        public void GetSaltAsBase64_WithoutSalt_ThrowsInvalidOperationException()
        {
            // Arrange
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256)
                .WithPassword(TestPassword);
            // Salt not set

            // Act & Assert
            Assert.Throws<InvalidOperationException>(kdf.GetSaltAsBase64);
        }
    }

    /// <summary>
    /// Tests for salt input format convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SaltInputFormatTests
    {
        private static readonly byte[] TestSalt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];

        [Fact]
        public void WithSaltFromHex_DerivesCorrectKey()
        {
            // Arrange
            var saltHex = Convert.ToHexString(TestSalt);

            // Act
            var keyFromHex = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromHex(saltHex)
                .DeriveKey();

            var keyFromBytes = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(TestSalt)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(keyFromBytes, keyFromHex);
        }

        [Fact]
        public void WithSaltFromHex_AcceptsLowercaseHex()
        {
            // Arrange
            var saltHex = Convert.ToHexString(TestSalt).ToLowerInvariant();

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromHex(saltHex)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void WithSaltFromHex_AcceptsUppercaseHex()
        {
            // Arrange
            var saltHex = Convert.ToHexString(TestSalt).ToUpperInvariant();

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromHex(saltHex)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void WithSaltFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.DeriveKey()
                    .WithHkdfSha256()
                    .WithPassword(TestPassword)
                    .WithSaltFromHex("not-valid-hex"));
        }

        [Fact]
        public void WithSaltFromBase64_DerivesCorrectKey()
        {
            // Arrange
            var saltBase64 = Convert.ToBase64String(TestSalt);

            // Act
            var keyFromBase64 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromBase64(saltBase64)
                .DeriveKey();

            var keyFromBytes = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(TestSalt)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(keyFromBytes, keyFromBase64);
        }

        [Fact]
        public void WithSaltFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.DeriveKey()
                    .WithHkdfSha256()
                    .WithPassword(TestPassword)
                    .WithSaltFromBase64("not-valid-base64!!!"));
        }

        [Fact]
        public void WithSaltFromBase64Url_DerivesCorrectKey()
        {
            // Arrange
            var saltBase64Url = Convert.ToBase64String(TestSalt)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var keyFromBase64Url = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromBase64Url(saltBase64Url)
                .DeriveKey();

            var keyFromBytes = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(TestSalt)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(keyFromBytes, keyFromBase64Url);
        }

        [Fact]
        public void WithSaltFromBase64Url_AcceptsPaddedInput()
        {
            // Arrange - Include padding (standard Base64)
            var saltBase64Url = Convert.ToBase64String(TestSalt)
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var key = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromBase64Url(saltBase64Url)
                .DeriveKey();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void WithSaltFromHex_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() =>
                builder.WithSaltFromHex(Convert.ToHexString(TestSalt)));
        }

        [Fact]
        public void WithSaltFromBase64_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() =>
                builder.WithSaltFromBase64(Convert.ToBase64String(TestSalt)));
        }

        [Fact]
        public void WithSaltFromBase64Url_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.DeriveKey();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() =>
                builder.WithSaltFromBase64Url("dGVzdA"));
        }

        [Fact]
        public void SaltRoundTrip_HexFormat()
        {
            // Arrange - Generate salt and get as hex
            using var kdf1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithRandomSalt(16);
            var saltHex = kdf1.GetSaltAsHex();
            var key1 = kdf1.DeriveKey();

            // Act - Use hex to derive same key
            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromHex(saltHex)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void SaltRoundTrip_Base64Format()
        {
            // Arrange - Generate salt and get as Base64
            using var kdf1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithRandomSalt(16);
            var saltBase64 = kdf1.GetSaltAsBase64();
            var key1 = kdf1.DeriveKey();

            // Act - Use Base64 to derive same key
            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromBase64(saltBase64)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void SaltRoundTrip_Base64UrlFormat()
        {
            // Arrange - Generate salt and get as Base64Url
            using var kdf1 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithRandomSalt(16);
            var saltBase64Url = kdf1.GetSaltAsBase64Url();
            var key1 = kdf1.DeriveKey();

            // Act - Use Base64Url to derive same key
            var key2 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSaltFromBase64Url(saltBase64Url)
                .DeriveKey();

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }
    }

    /// <summary>
    /// Tests for derived key output format convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DerivedKeyOutputFormatTests
    {
        [Fact]
        public void DeriveKeyToHex_ReturnsLowercaseHexString()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyHex = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKeyToHex();

            // Assert
            Assert.Equal(64, keyHex.Length); // 32 bytes = 64 hex chars
            Assert.Equal(keyHex.ToLowerInvariant(), keyHex); // lowercase
            Assert.Matches("^[0-9a-f]+$", keyHex); // valid hex
        }

        [Fact]
        public void DeriveKeyToHex_MatchesDeriveKey()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt);
            var keyBytes = kdf.DeriveKey();
            var keyHex = kdf.DeriveKeyToHex();

            // Assert
            Assert.Equal(Convert.ToHexString(keyBytes).ToLowerInvariant(), keyHex);
        }

        [Fact]
        public void DeriveKeyToBase64_ReturnsValidBase64()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyBase64 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKeyToBase64();

            // Assert
            var decoded = Convert.FromBase64String(keyBase64);
            Assert.Equal(32, decoded.Length);
        }

        [Fact]
        public void DeriveKeyToBase64_MatchesDeriveKey()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt);
            var keyBytes = kdf.DeriveKey();
            var keyBase64 = kdf.DeriveKeyToBase64();

            // Assert
            Assert.Equal(Convert.ToBase64String(keyBytes), keyBase64);
        }

        [Fact]
        public void DeriveKeyToBase64Url_ReturnsUrlSafeString()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyBase64Url = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKeyToBase64Url();

            // Assert
            Assert.DoesNotContain("+", keyBase64Url);
            Assert.DoesNotContain("/", keyBase64Url);
            Assert.DoesNotContain("=", keyBase64Url);
        }

        [Fact]
        public void DeriveKeyToBase64Url_CanBeDecodedBack()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            using var kdf = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt);
            var keyBytes = kdf.DeriveKey();
            var keyBase64Url = kdf.DeriveKeyToBase64Url();

            // Convert back from URL-safe Base64
            var base64 = keyBase64Url
                .Replace('-', '+')
                .Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 0: break;
                case 1: break;
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
                default: break;
            }
            var decoded = Convert.FromBase64String(base64);

            // Assert
            Assert.Equal(keyBytes, decoded);
        }

        [Fact]
        public void DeriveKeyToHex_WithoutPassword_ThrowsInvalidOperationException()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.DeriveKey()
                    .WithHkdfSha256()
                    .WithSalt(salt)
                    .DeriveKeyToHex());
        }

        [Fact]
        public void DeriveKeyToBase64_WithoutSalt_ThrowsInvalidOperationException()
        {
            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.DeriveKey()
                    .WithHkdfSha256()
                    .WithPassword(TestPassword)
                    .DeriveKeyToBase64());
        }

        [Theory]
        [InlineData(KeyDerivationAlgorithm.HkdfSha256)]
        [InlineData(KeyDerivationAlgorithm.HkdfSha384)]
        [InlineData(KeyDerivationAlgorithm.HkdfSha512)]
        [InlineData(KeyDerivationAlgorithm.Pbkdf2Sha256)]
        public void DeriveKeyToHex_WorksWithVariousAlgorithms(KeyDerivationAlgorithm algorithm)
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyHex = HeroCryptBuilder.DeriveKey()
                .WithAlgorithm(algorithm)
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .DeriveKeyToHex();

            // Assert
            Assert.Equal(64, keyHex.Length); // 32 bytes default output
            Assert.Matches("^[0-9a-f]+$", keyHex);
        }

        [Fact]
        public void DeriveKeyToHex_WithCustomOutputLength()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyHex = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(64)
                .DeriveKeyToHex();

            // Assert
            Assert.Equal(128, keyHex.Length); // 64 bytes = 128 hex chars
        }

        [Fact]
        public void DeriveKeyToBase64_WithCustomOutputLength()
        {
            // Arrange
            var salt = TestHelpers.RandomBytes(16);

            // Act
            var keyBase64 = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword(TestPassword)
                .WithSalt(salt)
                .WithOutputLength(64)
                .DeriveKeyToBase64();

            // Assert
            var decoded = Convert.FromBase64String(keyBase64);
            Assert.Equal(64, decoded.Length);
        }
    }
}
