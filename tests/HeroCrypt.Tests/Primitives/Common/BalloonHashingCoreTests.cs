using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Common;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Common;

#if !NETSTANDARD2_0

/// <summary>
/// Comprehensive tests for Balloon Hashing implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class BalloonHashingCoreTests
{
    private static readonly byte[] TestPassword = Encoding.UTF8.GetBytes("mySecurePassword123");
    private static readonly byte[] TestSalt = Encoding.UTF8.GetBytes("randomsalt123456");

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void Hash_WithValidParameters_Success()
        {
            // Act
            var hash = BalloonHashing.Hash(TestPassword, TestSalt);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(BalloonHashing.DEFAULT_OUTPUT_LENGTH, hash.Length);
        }

        [Fact]
        public void Hash_CustomParameters_Success()
        {
            // Arrange
            var spaceCost = 8;
            var timeCost = 10;
            var outputLength = 64;

            // Act
            var hash = BalloonHashing.Hash(TestPassword, TestSalt, spaceCost, timeCost, outputLength);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(outputLength, hash.Length);
        }

        [Fact]
        public void Hash_DifferentPasswords_ProduceDifferentHashes()
        {
            // Arrange
            var password1 = Encoding.UTF8.GetBytes("password1");
            var password2 = Encoding.UTF8.GetBytes("password2");

            // Act
            var hash1 = BalloonHashing.Hash(password1, TestSalt);
            var hash2 = BalloonHashing.Hash(password2, TestSalt);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_DifferentSalts_ProduceDifferentHashes()
        {
            // Arrange
            var salt1 = Encoding.UTF8.GetBytes("salt1");
            var salt2 = Encoding.UTF8.GetBytes("salt2");

            // Act
            var hash1 = BalloonHashing.Hash(TestPassword, salt1);
            var hash2 = BalloonHashing.Hash(TestPassword, salt2);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_IsDeterministic()
        {
            // Act
            var hash1 = BalloonHashing.Hash(TestPassword, TestSalt);
            var hash2 = BalloonHashing.Hash(TestPassword, TestSalt);

            // Assert
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void Hash_DifferentSpaceCost_ProducesDifferentHashes()
        {
            // Act
            var hash1 = BalloonHashing.Hash(TestPassword, TestSalt, spaceCost: 8);
            var hash2 = BalloonHashing.Hash(TestPassword, TestSalt, spaceCost: 16);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_DifferentTimeCost_ProducesDifferentHashes()
        {
            // Act
            var hash1 = BalloonHashing.Hash(TestPassword, TestSalt, timeCost: 10);
            var hash2 = BalloonHashing.Hash(TestPassword, TestSalt, timeCost: 20);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_DifferentAlgorithms_ProduceDifferentHashes()
        {
            // Act
            var hashSha256 = BalloonHashing.Hash(TestPassword, TestSalt, hashAlgorithm: HashAlgorithmName.SHA256);
            var hashSha512 = BalloonHashing.Hash(TestPassword, TestSalt, hashAlgorithm: HashAlgorithmName.SHA512);

            // Assert
            Assert.NotEqual(hashSha256, hashSha512);
        }

        [Fact]
        public void Hash_Sha384Algorithm_Success()
        {
            // Act
            var hash = BalloonHashing.Hash(TestPassword, TestSalt, hashAlgorithm: HashAlgorithmName.SHA384);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(BalloonHashing.DEFAULT_OUTPUT_LENGTH, hash.Length);
        }

        [Fact]
        public void HashWithRandomSalt_GeneratesHashWithSalt()
        {
            // Arrange
            var password = "myPassword123";

            // Act
            var hashWithSalt = BalloonHashing.HashWithRandomSalt(password);

            // Assert
            Assert.NotNull(hashWithSalt);
            Assert.True(hashWithSalt.Length > 16); // At least 16 bytes salt + hash
        }

        [Fact]
        public void Verify_CorrectPassword_ReturnsTrue()
        {
            // Arrange
            var password = "testPassword456";
            var hashWithSalt = BalloonHashing.HashWithRandomSalt(password);

            // Act
            var result = BalloonHashing.Verify(password, hashWithSalt);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WrongPassword_ReturnsFalse()
        {
            // Arrange
            var correctPassword = "correctPassword";
            var wrongPassword = "wrongPassword";
            var hashWithSalt = BalloonHashing.HashWithRandomSalt(correctPassword);

            // Act
            var result = BalloonHashing.Verify(wrongPassword, hashWithSalt);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void GetInfo_ReturnsDescription()
        {
            // Act
            var info = BalloonHashing.GetInfo();

            // Assert
            Assert.Contains("Balloon", info);
            Assert.Contains("memory-hard", info, StringComparison.OrdinalIgnoreCase);
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
        public void Hash_EmptyPassword_Success()
        {
            // Arrange
            var emptyPassword = Array.Empty<byte>();

            // Act
            var hash = BalloonHashing.Hash(emptyPassword, TestSalt);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(BalloonHashing.DEFAULT_OUTPUT_LENGTH, hash.Length);
        }

        [Fact]
        public void Hash_EmptySalt_Success()
        {
            // Arrange
            var emptySalt = Array.Empty<byte>();

            // Act
            var hash = BalloonHashing.Hash(TestPassword, emptySalt);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(BalloonHashing.DEFAULT_OUTPUT_LENGTH, hash.Length);
        }

        [Fact]
        public void Hash_LargeOutputLength_Success()
        {
            // Arrange
            var outputLength = 256; // Larger than hash function output

            // Act
            var hash = BalloonHashing.Hash(TestPassword, TestSalt, outputLength: outputLength);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(outputLength, hash.Length);
        }

        [Fact]
        public void Hash_MinimumParameters_Success()
        {
            // Arrange
            var spaceCost = BalloonHashing.MIN_SPACE_COST;
            var timeCost = BalloonHashing.MIN_TIME_COST;

            // Act
            var hash = BalloonHashing.Hash(TestPassword, TestSalt, spaceCost, timeCost);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(BalloonHashing.DEFAULT_OUTPUT_LENGTH, hash.Length);
        }

        [Fact]
        public void Hash_HighParameters_Success()
        {
            // Arrange
            var spaceCost = 128;
            var timeCost = 50;

            // Act
            var hash = BalloonHashing.Hash(TestPassword, TestSalt, spaceCost, timeCost);

            // Assert
            Assert.NotNull(hash);
            Assert.Equal(BalloonHashing.DEFAULT_OUTPUT_LENGTH, hash.Length);
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
        public void Hash_SpaceCostTooLow_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                BalloonHashing.Hash(TestPassword, TestSalt, spaceCost: 0));
        }

        [Fact]
        public void Hash_TimeCostTooLow_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                BalloonHashing.Hash(TestPassword, TestSalt, timeCost: 0));
        }

        [Fact]
        public void Hash_OutputLengthZero_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                BalloonHashing.Hash(TestPassword, TestSalt, outputLength: 0));
        }

        [Fact]
        public void Verify_HashTooShort_ThrowsArgumentException()
        {
            var password = "test";
            var tooShortHash = new byte[10]; // Less than 16 bytes

            Assert.Throws<ArgumentException>(() =>
                BalloonHashing.Verify(password, tooShortHash));
        }

        [Fact]
        public void GetRecommendedParameters_InvalidLevel_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                BalloonHashing.GetRecommendedParameters(0));
            Assert.Throws<ArgumentException>(() =>
                BalloonHashing.GetRecommendedParameters(6));
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
        public void Hash_CorrectPassword_Matches()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var salt = TestHelpers.RandomBytes(16);

            var hash1 = BalloonHashing.Hash(password, salt);
            var hash2 = BalloonHashing.Hash(password, salt);

            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_WrongPassword_DoesNotMatch()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var wrongPassword = Encoding.UTF8.GetBytes("wrong_password");
            var salt = TestHelpers.RandomBytes(16);

            var hash1 = BalloonHashing.Hash(password, salt);
            var hash2 = BalloonHashing.Hash(wrongPassword, salt);

            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_OutputAppearsRandom()
        {
            var password = Encoding.UTF8.GetBytes("test_password");
            var salt = TestHelpers.RandomBytes(16);

            var hash = BalloonHashing.Hash(password, salt);

            CryptoAssertions.AssertAppearsRandom(hash);
        }

        [Fact]
        public void Hash_SingleBitDifference_CompletelyDifferentOutput()
        {
            var password1 = Encoding.UTF8.GetBytes("password1");
            var password2 = Encoding.UTF8.GetBytes("password2");
            var salt = TestHelpers.RandomBytes(16);

            var hash1 = BalloonHashing.Hash(password1, salt);
            var hash2 = BalloonHashing.Hash(password2, salt);

            Assert.NotEqual(hash1, hash2);

            // Count differing bits - should be roughly half
            int diffBits = 0;
            for (int i = 0; i < hash1.Length; i++)
            {
                diffBits += System.Numerics.BitOperations.PopCount((uint)(hash1[i] ^ hash2[i]));
            }
            int totalBits = hash1.Length * 8;
            Assert.InRange(diffBits, totalBits / 4, totalBits * 3 / 4);
        }

        [Fact]
        public void HashWithRandomSalt_DifferentInvocations_ProduceDifferentResults()
        {
            var password = "test_password";

            var hash1 = BalloonHashing.HashWithRandomSalt(password);
            var hash2 = BalloonHashing.HashWithRandomSalt(password);

            // Different salts should produce different hashes
            Assert.NotEqual(hash1, hash2);
        }
    }

    /// <summary>
    /// Known Answer Tests for Balloon Hashing implementation.
    /// Note: No official RFC test vectors exist for Balloon Hashing.
    /// These tests verify determinism and consistency.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Hash_KnownInput_IsDeterministic()
        {
            // Using fixed inputs for reproducibility
            var password = Encoding.UTF8.GetBytes("balloon_test_password");
            var salt = Encoding.UTF8.GetBytes("balloon_test_salt_16");
            var spaceCost = 8;
            var timeCost = 10;

            var hash1 = BalloonHashing.Hash(password, salt, spaceCost, timeCost);
            var hash2 = BalloonHashing.Hash(password, salt, spaceCost, timeCost);

            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_Sha256_DifferentFromSha512()
        {
            var password = Encoding.UTF8.GetBytes("test");
            var salt = Encoding.UTF8.GetBytes("test_salt_16char");

            var hashSha256 = BalloonHashing.Hash(password, salt, hashAlgorithm: HashAlgorithmName.SHA256);
            var hashSha512 = BalloonHashing.Hash(password, salt, hashAlgorithm: HashAlgorithmName.SHA512);

            Assert.NotEqual(hashSha256, hashSha512);
        }

        [Fact]
        public void Hash_DifferentParameters_ProduceDifferentResults()
        {
            var password = Encoding.UTF8.GetBytes("test");
            var salt = Encoding.UTF8.GetBytes("test_salt_16char");

            var hash1 = BalloonHashing.Hash(password, salt, spaceCost: 8, timeCost: 10);
            var hash2 = BalloonHashing.Hash(password, salt, spaceCost: 16, timeCost: 10);
            var hash3 = BalloonHashing.Hash(password, salt, spaceCost: 8, timeCost: 20);

            Assert.NotEqual(hash1, hash2);
            Assert.NotEqual(hash1, hash3);
            Assert.NotEqual(hash2, hash3);
        }
    }
}
#endif
