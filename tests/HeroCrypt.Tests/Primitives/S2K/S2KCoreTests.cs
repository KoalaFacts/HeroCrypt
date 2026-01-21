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
    /// Tests for Argon2 S2K (Type 4) - RFC 9580.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class Argon2S2KTests
    {
        private static readonly byte[] Argon2Salt = new byte[]
        {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

        [Fact]
        public void Argon2S2K_ProducesKeyOfCorrectSize()
        {
            var key = S2KCore.Argon2S2K(TestPassword, Argon2Salt, timePasses: 1, parallelism: 1, memoryExponent: 10, keySize: 32);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void Argon2S2K_IsDeterministic()
        {
            var key1 = S2KCore.Argon2S2K(TestPassword, Argon2Salt, timePasses: 1, parallelism: 1, memoryExponent: 10, keySize: 32);
            var key2 = S2KCore.Argon2S2K(TestPassword, Argon2Salt, timePasses: 1, parallelism: 1, memoryExponent: 10, keySize: 32);

            Assert.Equal(key1, key2);
        }

        [Fact]
        public void Argon2S2K_DifferentParameters_ProduceDifferentKeys()
        {
            var key1 = S2KCore.Argon2S2K(TestPassword, Argon2Salt, timePasses: 1, parallelism: 1, memoryExponent: 10, keySize: 32);
            var key2 = S2KCore.Argon2S2K(TestPassword, Argon2Salt, timePasses: 2, parallelism: 1, memoryExponent: 10, keySize: 32);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void Argon2S2K_WrongSaltSize_ThrowsArgumentException()
        {
            var wrongSalt = new byte[8]; // Should be 16

            Assert.Throws<ArgumentException>(() =>
                S2KCore.Argon2S2K(TestPassword, wrongSalt, timePasses: 1, parallelism: 1, memoryExponent: 10, keySize: 32));
        }

        [Fact]
        public void GenerateArgon2Salt_ReturnsCorrectSize()
        {
            var salt = S2KCore.GenerateArgon2Salt();

            Assert.Equal(S2KCore.ARGON2_SALT_SIZE, salt.Length);
        }

        [Fact]
        public void GenerateArgon2Salt_ProducesRandomValues()
        {
            var salt1 = S2KCore.GenerateArgon2Salt();
            var salt2 = S2KCore.GenerateArgon2Salt();

            Assert.NotEqual(salt1, salt2);
        }
    }

    /// <summary>
    /// Tests for S2KParameters struct.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class S2KParametersTests
    {
        [Fact]
        public void CreateIterated_GeneratesValidParameters()
        {
            var s2k = S2KParameters.CreateIterated();

            Assert.Equal(S2KType.IteratedAndSalted, s2k.Type);
            Assert.Equal(8, s2k.Salt.Length);
            Assert.True(s2k.EncodedCount > 0);
        }

        [Fact]
        public void CreateArgon2_GeneratesValidParameters()
        {
            var s2k = S2KParameters.CreateArgon2(timePasses: 3, parallelism: 4, memoryExponent: 16);

            Assert.Equal(S2KType.Argon2, s2k.Type);
            Assert.Equal(16, s2k.Salt.Length);
            Assert.Equal(3, s2k.Argon2TimePasses);
            Assert.Equal(4, s2k.Argon2Parallelism);
            Assert.Equal(16, s2k.Argon2MemoryExponent);
        }

        [Fact]
        public void Serialize_SimpleS2K_ProducesCorrectBytes()
        {
            var s2k = new S2KParameters
            {
                Type = S2KType.Simple,
                HashAlgorithm = HeroCrypt.Operations.HashingAlgorithm.Sha256
            };

            var bytes = s2k.Serialize();

            Assert.Equal(2, bytes.Length);
            Assert.Equal(0, bytes[0]); // Simple S2K type
            Assert.Equal(8, bytes[1]); // SHA256 hash ID
        }

        [Fact]
        public void Parse_SimpleS2K_ReturnsCorrectParameters()
        {
            var data = new byte[] { 0, 8 }; // Simple S2K, SHA256

            var s2k = S2KParameters.Parse(data);

            Assert.Equal(S2KType.Simple, s2k.Type);
            Assert.Equal(HeroCrypt.Operations.HashingAlgorithm.Sha256, s2k.HashAlgorithm);
        }

        [Fact]
        public void Parse_IteratedS2K_ReturnsCorrectParameters()
        {
            var data = new byte[]
            {
                3,    // Iterated S2K type
                8,    // SHA256
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Salt
                0xC0  // Encoded count
            };

            var s2k = S2KParameters.Parse(data);

            Assert.Equal(S2KType.IteratedAndSalted, s2k.Type);
            Assert.Equal(HeroCrypt.Operations.HashingAlgorithm.Sha256, s2k.HashAlgorithm);
            Assert.Equal(8, s2k.Salt.Length);
            Assert.Equal(0xC0, s2k.EncodedCount);
        }

        [Fact]
        public void Parse_Argon2S2K_ReturnsCorrectParameters()
        {
            var data = new byte[]
            {
                4,    // Argon2 S2K type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // 16-byte salt
                3,    // Time passes
                4,    // Parallelism
                16    // Memory exponent
            };

            var s2k = S2KParameters.Parse(data);

            Assert.Equal(S2KType.Argon2, s2k.Type);
            Assert.Equal(16, s2k.Salt.Length);
            Assert.Equal(3, s2k.Argon2TimePasses);
            Assert.Equal(4, s2k.Argon2Parallelism);
            Assert.Equal(16, s2k.Argon2MemoryExponent);
        }

        [Fact]
        public void Serialize_Parse_RoundTrip_Iterated()
        {
            var original = S2KParameters.CreateIterated(
                HeroCrypt.Operations.HashingAlgorithm.Sha256,
                encodedCount: 0xC0);

            var serialized = original.Serialize();
            var parsed = S2KParameters.Parse(serialized);

            Assert.Equal(original.Type, parsed.Type);
            Assert.Equal(original.HashAlgorithm, parsed.HashAlgorithm);
            Assert.Equal(original.EncodedCount, parsed.EncodedCount);
            Assert.Equal(original.Salt.ToArray(), parsed.Salt.ToArray());
        }

        [Fact]
        public void Serialize_Parse_RoundTrip_Argon2()
        {
            var original = S2KParameters.CreateArgon2(timePasses: 3, parallelism: 4, memoryExponent: 16);

            var serialized = original.Serialize();
            var parsed = S2KParameters.Parse(serialized);

            Assert.Equal(original.Type, parsed.Type);
            Assert.Equal(original.Argon2TimePasses, parsed.Argon2TimePasses);
            Assert.Equal(original.Argon2Parallelism, parsed.Argon2Parallelism);
            Assert.Equal(original.Argon2MemoryExponent, parsed.Argon2MemoryExponent);
            Assert.Equal(original.Salt.ToArray(), parsed.Salt.ToArray());
        }

        [Fact]
        public void DeriveKey_Iterated_ProducesCorrectKey()
        {
            var salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            var s2k = new S2KParameters
            {
                Type = S2KType.IteratedAndSalted,
                HashAlgorithm = HeroCrypt.Operations.HashingAlgorithm.Sha256,
                Salt = salt,
                EncodedCount = 0x60 // 65536
            };

            var key = s2k.DeriveKey(TestPassword, 32);

            Assert.Equal(32, key.Length);

            // Verify against core implementation
            var coreKey = S2KCore.IteratedS2K(TestPassword, salt, S2KCore.DecodeIterationCount(0x60), 32, HashAlgorithmName.SHA256);
            Assert.Equal(coreKey, key);
        }

        [Fact]
        public void SerializedLength_ReturnsCorrectValues()
        {
            Assert.Equal(2, new S2KParameters { Type = S2KType.Simple }.SerializedLength);
            Assert.Equal(10, new S2KParameters { Type = S2KType.Salted }.SerializedLength);
            Assert.Equal(11, new S2KParameters { Type = S2KType.IteratedAndSalted }.SerializedLength);
            Assert.Equal(20, new S2KParameters { Type = S2KType.Argon2 }.SerializedLength);
        }
    }

    /// <summary>
    /// Tests for Argon2 S2K in Builder API.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class BuilderArgon2Tests
    {
        private static readonly byte[] Argon2Salt = new byte[]
        {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };

        [Fact]
        public void Builder_Argon2S2K_MatchesCore()
        {
            using var builder = S2KBuilder.Create()
                .WithArgon2Parameters(timePasses: 1, parallelism: 1, memoryExponent: 10)
                .WithSalt(Argon2Salt);

            var builderKey = builder.DeriveKey(TestPassword, 32);
            var coreKey = S2KCore.Argon2S2K(TestPassword, Argon2Salt, timePasses: 1, parallelism: 1, memoryExponent: 10, keySize: 32);

            Assert.Equal(coreKey, builderKey);
        }

        [Fact]
        public void Builder_Argon2_WithRandomSalt_GeneratesCorrectSaltSize()
        {
            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Argon2)
                .WithRandomSalt();

            var salt = builder.GetSalt();

            Assert.NotNull(salt);
            Assert.Equal(S2KCore.ARGON2_SALT_SIZE, salt.Length);
        }

        [Fact]
        public void Builder_Argon2_WrongSaltSize_Throws()
        {
            var wrongSalt = new byte[8]; // Should be 16 for Argon2

            using var builder = S2KBuilder.Create()
                .WithType(S2KType.Argon2);

            Assert.Throws<ArgumentException>(() => builder.WithSalt(wrongSalt));
        }
    }

    /// <summary>
    /// Tests for legacy hash algorithms (SHA-1).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class LegacyHashTests
    {
        [Fact]
        public void SimpleS2K_SHA1_Succeeds()
        {
            var key = S2KCore.SimpleS2K(TestPassword, 32, HashAlgorithmName.SHA1);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void SaltedS2K_SHA1_Succeeds()
        {
            var key = S2KCore.SaltedS2K(TestPassword, TestSalt, 32, HashAlgorithmName.SHA1);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void IteratedS2K_SHA1_Succeeds()
        {
            var key = S2KCore.IteratedS2K(TestPassword, TestSalt, 65536, 32, HashAlgorithmName.SHA1);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void MapHashAlgorithm_SHA1_Works()
        {
#pragma warning disable CS0618
            var hashAlg = S2KCore.MapHashAlgorithm(HeroCrypt.Operations.HashingAlgorithm.Sha1);
#pragma warning restore CS0618

            Assert.Equal(HashAlgorithmName.SHA1, hashAlg);
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
