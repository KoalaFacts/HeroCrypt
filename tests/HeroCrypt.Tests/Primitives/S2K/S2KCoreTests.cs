using System.Security.Cryptography;
using HeroCrypt.Primitives.S2K;
#pragma warning disable IDE0300 // Simplify collection initialization
#pragma warning disable IDE0005 // Using directive is unnecessary

namespace HeroCrypt.Tests.Primitives.S2K;

/// <summary>
/// Comprehensive tests for OpenPGP S2K implementation.
/// Tests the String-to-Key functions specified in RFC 4880 Section 3.7.
/// </summary>
public class S2KCoreTests
{
    private static readonly byte[] TestPassword = "password"u8.ToArray();
    private static readonly byte[] TestSalt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    /// <summary>
    /// Basic functionality tests for Simple S2K.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SimpleS2KTests
    {
        [Fact]
        public void SimpleS2K_ProducesKeyOfCorrectSize()
        {
            var key = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void SimpleS2K_IsDeterministic()
        {
            var key1 = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA256);
            var key2 = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA256);

            Assert.Equal(key1, key2);
        }

        [Fact]
        public void SimpleS2K_DifferentPasswords_ProduceDifferentKeys()
        {
            var key1 = S2KCore.SimpleS2K("password1"u8.ToArray(), 32, HashAlgorithmName.SHA256);
            var key2 = S2KCore.SimpleS2K("password2"u8.ToArray(), 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(key1, key2);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(48)]
        [InlineData(64)]
        public void SimpleS2K_ProducesRequestedKeySize(int keySize)
        {
            var key = S2KCore.SimpleS2K(TestPassword, keySize, HashAlgorithmName.SHA256);

            Assert.Equal(keySize, key.Length);
        }
    }

    /// <summary>
    /// Basic functionality tests for Salted S2K.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SaltedS2KTests
    {
        [Fact]
        public void SaltedS2K_ProducesKeyOfCorrectSize()
        {
            var key = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void SaltedS2K_IsDeterministic()
        {
            var key1 = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, HashAlgorithmName.SHA256);
            var key2 = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, HashAlgorithmName.SHA256);

            Assert.Equal(key1, key2);
        }

        [Fact]
        public void SaltedS2K_DifferentSalts_ProduceDifferentKeys()
        {
            var salt1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var salt2 = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

            var key1 = S2KCore.SaltedS2K(TestPassword, salt1, 32, HashAlgorithmName.SHA256);
            var key2 = S2KCore.SaltedS2K(TestPassword, salt2, 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void SaltedS2K_DifferentFromSimple()
        {
            var simpleKey = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA256);
            var saltedKey = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(simpleKey, saltedKey);
        }
    }

    /// <summary>
    /// Basic functionality tests for Iterated S2K.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class IteratedS2KTests
    {
        [Fact]
        public void IteratedS2K_ProducesKeyOfCorrectSize()
        {
            var key = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void IteratedS2K_IsDeterministic()
        {
            var key1 = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, HashAlgorithmName.SHA256);
            var key2 = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, HashAlgorithmName.SHA256);

            Assert.Equal(key1, key2);
        }

        [Fact]
        public void IteratedS2K_DifferentIterations_ProduceDifferentKeys()
        {
            var key1 = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, HashAlgorithmName.SHA256);
            var key2 = S2KCore.IteratedS2K(TestPassword, TestSalt, 131072, 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void IteratedS2K_DifferentFromSalted()
        {
            var saltedKey = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, HashAlgorithmName.SHA256);
            var iteratedKey = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(saltedKey, iteratedKey);
        }
    }

    /// <summary>
    /// Tests for iteration count encoding/decoding.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class IterationCountTests
    {
        [Theory]
        [InlineData(0, 1024)]      // Minimum: (16 + 0) << 6 = 1024
        [InlineData(96, 65536)]    // Common default
        [InlineData(255, 65011712)] // Maximum
        public void DecodeIterationCount_KnownValues(byte encoded, long expected)
        {
            var decoded = S2KCore.DecodeIterationCount(encoded);

            Assert.Equal(expected, decoded);
        }

        [Fact]
        public void EncodeIterationCount_RoundTrips()
        {
            var counts = new long[] { 1024, 65536, 1048576, 16777216 };

            foreach (var originalCount in counts)
            {
                var encoded = S2KCore.EncodeIterationCount(originalCount);
                var decoded = S2KCore.DecodeIterationCount(encoded);

                // Decoded should be >= original (due to encoding granularity)
                Assert.True(decoded >= originalCount,
                    $"Decoded {decoded} should be >= original {originalCount}");
            }
        }

        [Fact]
        public void EncodeIterationCount_SmallValue_ReturnsMinimum()
        {
            var encoded = S2KCore.EncodeIterationCount(100);
            var decoded = S2KCore.DecodeIterationCount(encoded);

            // Should round up to minimum (1024)
            Assert.Equal(1024, decoded);
        }
    }

    /// <summary>
    /// Tests for salt generation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SaltGenerationTests
    {
        [Fact]
        public void GenerateSalt_ReturnsCorrectSize()
        {
            var salt = S2KCore.GenerateSalt();

            Assert.Equal(S2KCore.DEFAULT_SALT_SIZE, salt.Length);
        }

        [Fact]
        public void GenerateSalt_ProducesRandomValues()
        {
            var salt1 = S2KCore.GenerateSalt();
            var salt2 = S2KCore.GenerateSalt();

            Assert.NotEqual(salt1, salt2);
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
        public void SimpleS2K_ZeroKeySize_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                S2KCore.SimpleS2K(TestPassword, 0, HashAlgorithmName.SHA256));
        }

        [Fact]
        public void SimpleS2K_NegativeKeySize_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                S2KCore.SimpleS2K(TestPassword, -1, HashAlgorithmName.SHA256));
        }

        [Fact]
        public void SaltedS2K_WrongSaltSize_ThrowsArgumentException()
        {
            var wrongSalt = new byte[7]; // Should be 8

            Assert.Throws<ArgumentException>(() =>
                S2KCore.SaltedS2K(TestPassword, wrongSalt, 32, HashAlgorithmName.SHA256));
        }

        [Fact]
        public void IteratedS2K_WrongSaltSize_ThrowsArgumentException()
        {
            var wrongSalt = new byte[16]; // Should be 8

            Assert.Throws<ArgumentException>(() =>
                S2KCore.IteratedS2K(TestPassword, wrongSalt, 65536, 32, HashAlgorithmName.SHA256));
        }
    }

    /// <summary>
    /// Tests for different hash algorithms.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class HashAlgorithmTests
    {
        [Theory]
        [InlineData("SHA256")]
        [InlineData("SHA384")]
        [InlineData("SHA512")]
        public void SimpleS2K_DifferentHashAlgorithms_Succeed(string algorithmName)
        {
            var algorithm = new HashAlgorithmName(algorithmName);
            var key = S2KCore.SimpleS2K(TestPassword, 32, algorithm);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void SimpleS2K_DifferentHashes_ProduceDifferentKeys()
        {
            var keySha256 = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA256);
            var keySha512 = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA512);

            Assert.NotEqual(keySha256, keySha512);
        }
    }

    /// <summary>
    /// Builder API tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BuilderApiTests
    {
        [Fact]
        public void Builder_SimpleS2K_MatchesCore()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Simple);

            var builderKey = builder.DeriveKey(TestPassword, 32);
            var coreKey = S2KCore.SimpleS2K(TestPassword, 32, S2KCore.DEFAULT_HASH);

            Assert.Equal(coreKey, builderKey);
        }

        [Fact]
        public void Builder_SaltedS2K_MatchesCore()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Salted)
                .WithSalt(TestSalt);

            var builderKey = builder.DeriveKey(TestPassword, 32);
            var coreKey = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, S2KCore.DEFAULT_HASH);

            Assert.Equal(coreKey, builderKey);
        }

        [Fact]
        public void Builder_IteratedS2K_MatchesCore()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.IteratedAndSalted)
                .WithSalt(TestSalt)
                .WithIterationCount(65536);

            var builderKey = builder.DeriveKey(TestPassword, 32);
            var coreKey = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, S2KCore.DEFAULT_HASH);

            Assert.Equal(coreKey, builderKey);
        }

        [Fact]
        public void Builder_WithRandomSalt_GeneratesSalt()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Salted)
                .WithRandomSalt();

            var salt = builder.GetSalt();

            Assert.NotNull(salt);
            Assert.Equal(S2KCore.DEFAULT_SALT_SIZE, salt.Length);
        }

        [Fact]
        public void Builder_WithStringPassword_Works()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Simple);

            var key = builder.DeriveKey("password", 32);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void Builder_WithEncodedIterationCount_Works()
        {
            using var builder = S2KBuilder.Create()
                .WithEncodedIterationCount(96);

            var encodedCount = builder.GetEncodedIterationCount();

            Assert.Equal(96, encodedCount);
        }

        [Fact]
        public void Builder_SaltRequired_ThrowsWithoutSalt()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Salted);

            Assert.Throws<InvalidOperationException>(() =>
                builder.DeriveKey(TestPassword, 32));
        }

        [Fact]
        public void HeroCryptBuilder_S2K_CreatesBuilder()
        {
            using var builder = HeroCryptBuilder.S2K();

            Assert.NotNull(builder);
            Assert.IsType<S2KBuilder>(builder);
        }
    }

    /// <summary>
    /// Edge case tests.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Fact]
        public void SimpleS2K_EmptyPassword_Succeeds()
        {
            var key = S2KCore.SimpleS2K([], 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void SimpleS2K_LargeKey_Succeeds()
        {
            // Key larger than hash output (32 bytes for SHA256)
            var key = S2KCore.SimpleS2K(TestPassword, 64, HashAlgorithmName.SHA256);

            Assert.Equal(64, key.Length);
        }

        [Fact]
        public void IteratedS2K_MinimumCount_Succeeds()
        {
            // Count less than combined length should be adjusted
            var key = S2KCore.IteratedS2K(TestPassword, TestSalt, 1, 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }
    }
}
