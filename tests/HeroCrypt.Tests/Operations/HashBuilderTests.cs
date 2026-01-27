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
            // Act - use AllowLegacyAlgorithms() to enable MD5
            var hash = HeroCryptBuilder.Hash()
                .AllowLegacyAlgorithms()
                .WithMd5()
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(16, hash.Length);
        }

        [Fact]
        [Obsolete]
        public void ComputeHash_Sha1_ReturnsCorrectLength()
        {
            // Act - use AllowLegacyAlgorithms() to enable SHA-1
            var hash = HeroCryptBuilder.Hash()
                .AllowLegacyAlgorithms()
                .WithSha1()
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(20, hash.Length);
        }

        [Fact]
        [Obsolete]
        public void WithMd5_WithoutAllowLegacy_ThrowsStrictModeException()
        {
            // Act & Assert - should throw when AllowLegacyAlgorithms() not called
            Assert.Throws<HeroCrypt.Security.StrictModeException>(() =>
                HeroCryptBuilder.Hash().WithMd5());
        }

        [Fact]
        [Obsolete]
        public void WithSha1_WithoutAllowLegacy_ThrowsStrictModeException()
        {
            // Act & Assert - should throw when AllowLegacyAlgorithms() not called
            Assert.Throws<HeroCrypt.Security.StrictModeException>(() =>
                HeroCryptBuilder.Hash().WithSha1());
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

    /// <summary>
    /// Tests for key input format convenience methods (WithKeyFromHex, WithKeyFromBase64, WithKeyFromBase64Url).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyInputFormatTests
    {
        [Fact]
        public void WithKeyFromHex_ComputesCorrectHash()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key);

            // Act
            var hashFromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKey(key)
                .ComputeHash(TestData);

            var hashFromHex = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKeyFromHex(hexKey)
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(hashFromBytes, hashFromHex);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsLowercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKeyFromHex(hexKey)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsUppercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToUpperInvariant();

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKeyFromHex(hexKey)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void WithKeyFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Hash()
                    .WithSha256()
                    .WithKeyFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64_ComputesCorrectHash()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64Key = Convert.ToBase64String(key);

            // Act
            var hashFromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKey(key)
                .ComputeHash(TestData);

            var hashFromBase64 = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKeyFromBase64(base64Key)
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(hashFromBytes, hashFromBase64);
        }

        [Fact]
        public void WithKeyFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Hash()
                    .WithSha256()
                    .WithKeyFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64Url_ComputesCorrectHash()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var hashFromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKey(key)
                .ComputeHash(TestData);

            var hashFromBase64Url = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKeyFromBase64Url(base64UrlKey)
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(hashFromBytes, hashFromBase64Url);
        }

        [Fact]
        public void WithKeyFromBase64Url_AcceptsPaddedInput()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .Replace('+', '-')
                .Replace('/', '_');
            // Keep padding

            // Act
            var hashFromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKey(key)
                .ComputeHash(TestData);

            var hashFromBase64Url = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKeyFromBase64Url(base64UrlKey)
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(hashFromBytes, hashFromBase64Url);
        }

        [Fact]
        public void WithKeyFromBase64Url_WithBlake2b_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var hash = HeroCryptBuilder.Hash()
                .WithBlake2b256()
                .WithKeyFromBase64Url(base64UrlKey)
                .ComputeHash(TestData);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(32, hash.Length);
        }

        [Theory]
        [InlineData(HashingAlgorithm.Sha256)]
        [InlineData(HashingAlgorithm.Sha384)]
        [InlineData(HashingAlgorithm.Sha512)]
        [InlineData(HashingAlgorithm.Blake2b256)]
        [InlineData(HashingAlgorithm.Blake2b512)]
        public void WithKeyFromHex_WorksWithAllKeyedAlgorithms(HashingAlgorithm algorithm)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key);

            // Act
            var hashFromBytes = HeroCryptBuilder.Hash()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .ComputeHash(TestData);

            var hashFromHex = HeroCryptBuilder.Hash()
                .WithAlgorithm(algorithm)
                .WithKeyFromHex(hexKey)
                .ComputeHash(TestData);

            // Assert
            Assert.Equal(hashFromBytes, hashFromHex);
        }
    }

    /// <summary>
    /// Tests for hash output format convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class OutputFormatConvenienceMethods
    {
        [Fact]
        public void ComputeHashToHex_ReturnsLowercaseHexString()
        {
            // Arrange - SHA-256 of "abc" is a well-known RFC test vector
            var abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

            // Act
            var hex = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToHex("abc");

            // Assert
            Assert.Equal(abcHash, hex);
            Assert.Equal(hex, hex.ToLowerInvariant()); // Verify lowercase
        }

        [Fact]
        public void ComputeHashToHex_ByteArray_ReturnsCorrectHex()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("test");

            // Act
            var hexFromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToHex(data);

            var hexFromString = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToHex("test");

            // Assert - Both should produce same result
            Assert.Equal(hexFromBytes, hexFromString);
            Assert.Equal(64, hexFromString.Length); // SHA-256 = 32 bytes = 64 hex chars
        }

        [Theory]
        [InlineData(HashingAlgorithm.Sha256, 64)]  // 32 bytes
        [InlineData(HashingAlgorithm.Sha384, 96)]  // 48 bytes
        [InlineData(HashingAlgorithm.Sha512, 128)] // 64 bytes
        [InlineData(HashingAlgorithm.Blake2b256, 64)] // 32 bytes
        [InlineData(HashingAlgorithm.Blake2b512, 128)] // 64 bytes
        public void ComputeHashToHex_AllAlgorithms_ReturnsCorrectLength(HashingAlgorithm algorithm, int expectedHexLength)
        {
            // Act
            var hex = HeroCryptBuilder.Hash()
                .WithAlgorithm(algorithm)
                .ComputeHashToHex(TestData);

            // Assert
            Assert.Equal(expectedHexLength, hex.Length);
        }

        [Fact]
        public void ComputeHashToBase64_ReturnsValidBase64()
        {
            // Act
            var base64 = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64("test");

            // Assert - Should be valid base64
            var decoded = Convert.FromBase64String(base64);
            Assert.Equal(32, decoded.Length); // SHA-256 = 32 bytes
        }

        [Fact]
        public void ComputeHashToBase64_ByteArray_MatchesStringVersion()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello, World!");

            // Act
            var base64FromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64(data);

            var base64FromString = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64("Hello, World!");

            // Assert
            Assert.Equal(base64FromBytes, base64FromString);
        }

        [Fact]
        public void ComputeHashToHex_And_ComputeHash_ProduceSameResult()
        {
            // Act
            var hashBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHash(TestData);

            var hashHex = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToHex(TestData);

            // Assert - Hex string should represent the same bytes
            var expectedHex = Convert.ToHexString(hashBytes).ToLowerInvariant();
            Assert.Equal(expectedHex, hashHex);
        }

        [Fact]
        public void ComputeHashToBase64Url_ReturnsUrlSafeString()
        {
            // Act
            var base64Url = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64Url("test");

            // Assert - Should not contain URL-unsafe characters
            Assert.NotNull(base64Url);
            Assert.DoesNotContain("+", base64Url);
            Assert.DoesNotContain("/", base64Url);
            Assert.DoesNotContain("=", base64Url);
        }

        [Fact]
        public void ComputeHashToBase64Url_CanBeDecodedBack()
        {
            // Arrange
            var data = "test message";

            // Act
            var hashBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHash(data);

            var base64Url = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64Url(data);

            // Convert back from URL-safe Base64
            var base64 = base64Url
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
            Assert.Equal(hashBytes, decoded);
        }

        [Fact]
        public void ComputeHashToBase64Url_StringOverload_MatchesByteOverload()
        {
            // Arrange
            var stringData = "Hello, World!";
            var byteData = Encoding.UTF8.GetBytes(stringData);

            // Act
            var fromString = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64Url(stringData);

            var fromBytes = HeroCryptBuilder.Hash()
                .WithSha256()
                .ComputeHashToBase64Url(byteData);

            // Assert
            Assert.Equal(fromString, fromBytes);
        }
    }

    /// <summary>
    /// Tests for malformed input handling in HashBuilder.
    /// </summary>
    [Trait("Category", TestCategories.INPUT_VALIDATION)]
    [Trait("Category", TestCategories.FAST)]
    public class InputValidation
    {
        public static TheoryData<string> InvalidHexStrings => new()
        {
            "not-valid-hex",
            "GHIJKL",
            "123",
            "0x1234",
            "!@#$%^&*()",
        };

        public static TheoryData<string> InvalidBase64Strings => new()
        {
            "not valid base64!",
            "!!!",
            "====",
            "a===",
        };

        [Theory]
        [MemberData(nameof(InvalidHexStrings))]
        public void WithKeyFromHex_InvalidHex_ThrowsFormatException(string invalidHex)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Hash()
                    .WithSha256()
                    .WithKeyFromHex(invalidHex));
        }

        [Theory]
        [MemberData(nameof(InvalidBase64Strings))]
        public void WithKeyFromBase64_InvalidBase64_ThrowsFormatException(string invalidBase64)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Hash()
                    .WithSha256()
                    .WithKeyFromBase64(invalidBase64));
        }

        [Fact]
        public void WithNullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                HeroCryptBuilder.Hash()
                    .WithSha256()
                    .WithKey(null!));
        }
    }
}
