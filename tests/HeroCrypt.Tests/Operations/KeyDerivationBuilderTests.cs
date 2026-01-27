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
            Assert.Throws<ObjectDisposedException>(() => builder.DeriveKey());
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
            Assert.Throws<InvalidOperationException>(() => builder.GetSalt());
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
}
