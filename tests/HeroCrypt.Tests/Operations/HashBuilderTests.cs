using System.Text;
using HeroCrypt.Operations;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Comprehensive tests for hashing operations using HeroCryptBuilder.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class HashBuilderTests
{
    private static readonly byte[] TestData = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    /// <summary>
    /// Basic functionality tests for hashing algorithms.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Theory]
        [InlineData(HashingAlgorithm.Sha256, 32)]
        [InlineData(HashingAlgorithm.Sha384, 48)]
        [InlineData(HashingAlgorithm.Sha512, 64)]
        [InlineData(HashingAlgorithm.Blake2b256, 32)]
        [InlineData(HashingAlgorithm.Blake2b512, 64)]
        public void ComputeHash_ReturnsCorrectLength(HashingAlgorithm algorithm, int expectedLength)
        {
            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithAlgorithm(algorithm)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(expectedLength, hash.Length);
            Assert.False(TestHelpers.AllZeros(hash));
        }

        [Fact]
        public void ComputeHash_WithSha256_IsDeterministic()
        {
            // Act
            var hash1 = HeroCryptBuilder.Hash().WithSha256().ComputeHash(TestData);
            var hash2 = HeroCryptBuilder.Hash().WithSha256().ComputeHash(TestData);

            // Assert
            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_DifferentData_ProducesDifferentHash()
        {
            // Arrange
            var data1 = Encoding.UTF8.GetBytes("Hello");
            var data2 = Encoding.UTF8.GetBytes("World");

            // Act
            var hash1 = HeroCryptBuilder.Hash().WithSha256().ComputeHash(data1);
            var hash2 = HeroCryptBuilder.Hash().WithSha256().ComputeHash(data2);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_DifferentAlgorithms_ProduceDifferentHashes()
        {
            // Act
            var sha256 = HeroCryptBuilder.Hash().WithSha256().ComputeHash(TestData);
            var sha512 = HeroCryptBuilder.Hash().WithSha512().ComputeHash(TestData);
            var blake2b = HeroCryptBuilder.Hash().WithBlake2b256().ComputeHash(TestData);

            // Assert
            Assert.NotEqual(sha256, sha512);
            Assert.NotEqual(sha256, blake2b);
            Assert.NotEqual(sha512, blake2b);
        }
    }

    /// <summary>
    /// Tests for keyed hashing (HMAC and Blake2b keyed mode).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyedHashing
    {
        [Theory]
        [InlineData(HashingAlgorithm.Sha256, 32)]
        [InlineData(HashingAlgorithm.Sha384, 48)]
        [InlineData(HashingAlgorithm.Sha512, 64)]
        public void ComputeHash_WithKey_ReturnsHmac(HashingAlgorithm algorithm, int expectedLength)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(expectedLength, hash.Length);
        }

        [Fact]
        public void ComputeHash_WithKey_IsDeterministic()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act
            var hash1 = HeroCryptBuilder.Hash().WithSha256().WithKey(key).ComputeHash(TestData);
            var hash2 = HeroCryptBuilder.Hash().WithSha256().WithKey(key).ComputeHash(TestData);

            // Assert
            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_DifferentKeys_ProduceDifferentHashes()
        {
            // Arrange
            var key1 = TestHelpers.RandomBytes(32);
            var key2 = TestHelpers.RandomBytes(32);

            // Act
            var hash1 = HeroCryptBuilder.Hash().WithSha256().WithKey(key1).ComputeHash(TestData);
            var hash2 = HeroCryptBuilder.Hash().WithSha256().WithKey(key2).ComputeHash(TestData);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_WithKeyAndWithout_ProduceDifferentHashes()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act
            var withKey = HeroCryptBuilder.Hash().WithSha256().WithKey(key).ComputeHash(TestData);
            var withoutKey = HeroCryptBuilder.Hash().WithSha256().ComputeHash(TestData);

            // Assert
            Assert.NotEqual(withKey, withoutKey);
        }

        [Fact]
        public void ComputeHash_Blake2bKeyed_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithBlake2b256()
                .WithKey(key)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length);
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
        public void ComputeHash_SingleByte_Succeeds()
        {
            // Arrange
            var data = new byte[] { 0x42 };

            // Act
            var hash = HeroCryptBuilder.Hash().WithSha256().ComputeHash(data);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void ComputeHash_LargeData_Succeeds()
        {
            // Arrange
            var data = TestHelpers.RandomBytes(TestDataSizes.Large);

            // Act
            var hash = HeroCryptBuilder.Hash().WithSha256().ComputeHash(data);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void ComputeHash_AllZerosData_Succeeds()
        {
            // Arrange
            var data = TestHelpers.ZeroBytes(64);

            // Act
            var hash = HeroCryptBuilder.Hash().WithSha256().ComputeHash(data);

            // Assert
            Assert.NotNull(hash);
            Assert.False(TestHelpers.AllZeros(hash));
        }
    }

    /// <summary>
    /// Tests for SHA-3 family (requires .NET 8+).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class Sha3Family
    {
        [Theory]
        [InlineData(HashingAlgorithm.Sha3_256, 32)]
        [InlineData(HashingAlgorithm.Sha3_384, 48)]
        [InlineData(HashingAlgorithm.Sha3_512, 64)]
        public void ComputeHash_Sha3_ReturnsCorrectLength(HashingAlgorithm algorithm, int expectedLength)
        {
            if (!System.Security.Cryptography.SHA3_256.IsSupported)
            {
                Assert.Skip("SHA-3 not supported on this platform (e.g., macOS)");
                return;
            }

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithAlgorithm(algorithm)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(expectedLength, hash.Length);
        }

        [Fact]
        public void ComputeHash_Sha3_256_IsDeterministic()
        {
            if (!System.Security.Cryptography.SHA3_256.IsSupported)
            {
                Assert.Skip("SHA-3 not supported on this platform (e.g., macOS)");
                return;
            }

            // Act
            var hash1 = HeroCryptBuilder.Hash().WithSha3_256().ComputeHash(TestData);
            var hash2 = HeroCryptBuilder.Hash().WithSha3_256().ComputeHash(TestData);

            // Assert
            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }
    }

#if NET9_0_OR_GREATER
    /// <summary>
    /// Tests for SHAKE XOF (requires .NET 9+).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ShakeXof
    {
        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        [InlineData(128)]
        public void ComputeHash_Shake128_ReturnsRequestedLength(int outputLength)
        {
            if (!System.Security.Cryptography.Shake128.IsSupported)
            {
                Assert.Skip("SHAKE not supported on this platform (e.g., macOS)");
                return;
            }

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithShake128(outputLength)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(outputLength, hash.Length);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        [InlineData(128)]
        public void ComputeHash_Shake256_ReturnsRequestedLength(int outputLength)
        {
            if (!System.Security.Cryptography.Shake256.IsSupported)
            {
                Assert.Skip("SHAKE not supported on this platform (e.g., macOS)");
                return;
            }

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithShake256(outputLength)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(outputLength, hash.Length);
        }

        [Fact]
        public void ComputeHash_Shake_IsDeterministic()
        {
            if (!System.Security.Cryptography.Shake256.IsSupported)
            {
                Assert.Skip("SHAKE not supported on this platform (e.g., macOS)");
                return;
            }

            // Act
            var hash1 = HeroCryptBuilder.Hash().WithShake256(64).ComputeHash(TestData);
            var hash2 = HeroCryptBuilder.Hash().WithShake256(64).ComputeHash(TestData);

            // Assert
            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }
    }
#endif

    /// <summary>
    /// Tests for legacy algorithms (MD5, SHA-1).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class LegacyAlgorithms
    {
        [Fact]
        [Obsolete]
        public void ComputeHash_Md5_ReturnsCorrectLength()
        {
            // Act - use legacy mode to allow MD5
            var hash = HeroCrypt.Security.StrictMode.WithLegacyMode(() =>
                HeroCryptBuilder.Hash().WithMd5().ComputeHash(TestData));

            // Assert
            Assert.Equal(16, hash.Length);
        }

        [Fact]
        [Obsolete]
        public void ComputeHash_Sha1_ReturnsCorrectLength()
        {
            // Act - use legacy mode to allow SHA-1
            var hash = HeroCrypt.Security.StrictMode.WithLegacyMode(() =>
                HeroCryptBuilder.Hash().WithSha1().ComputeHash(TestData));

            // Assert
            Assert.Equal(20, hash.Length);
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
        public void ComputeHash_WithEmptyData_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.Hash().WithSha256().ComputeHash([]));
        }

        [Fact]
        public void ComputeHash_KeyedSha3_ThrowsNotSupportedException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act & Assert - SHA-3 doesn't support keyed mode
            Assert.Throws<NotSupportedException>(() =>
                HeroCryptBuilder.Hash().WithSha3_256().WithKey(key).ComputeHash(TestData));
        }
    }
}
