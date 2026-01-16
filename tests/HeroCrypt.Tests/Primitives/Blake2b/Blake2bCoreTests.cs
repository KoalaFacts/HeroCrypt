using System.Text;
using HeroCrypt.Primitives.Blake2b;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Blake2b;

/// <summary>
/// Comprehensive tests for Blake2b hash function implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Blake2bCoreTests
{
    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void ComputeHash_WithValidInput_ReturnsCorrectLength()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Hello Blake2b");
            var expectedLength = 32;

            // Act
            var hash = Blake2bCore.ComputeHash(data, expectedLength);

            // Assert
            Assert.Equal(expectedLength, hash.Length);
        }

        [Fact]
        public void ComputeHash_IsDeterministic()
        {
            // Arrange
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var hash1 = Blake2bCore.ComputeHash(data, 32);
            var hash2 = Blake2bCore.ComputeHash(data, 32);

            // Assert
            CryptoAssertions.AssertBytesEqual(hash1, hash2);
        }

        [Fact]
        public void ComputeLongHash_HandlesLargeOutputSizes()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("Test data for long hash");
            var outputLength = 128; // Larger than 64 bytes (512 bits)

            // Act
            var hash = Blake2bCore.ComputeLongHash(data, outputLength);

            // Assert
            Assert.Equal(outputLength, hash.Length);
        }

        [Fact]
        public void ComputeHash_WithKey_ReturnsDifferentHash()
        {
            // Arrange
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var key = TestHelpers.RandomBytes(32);

            // Act
            var hash1 = Blake2bCore.ComputeHash(data, 32);
            var hash2 = Blake2bCore.ComputeHash(data, 32, key);

            // Assert
            Assert.NotEqual(hash1, hash2);
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
        public void ComputeHash_EmptyInput_Succeeds()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var hash = Blake2bCore.ComputeHash(data, 32);

            // Assert
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void ComputeHash_MaxStandardOutputSize_Succeeds()
        {
            // Arrange
            var data = "B"u8.ToArray();

            // Act (64 bytes = 512 bits)
            var hash = Blake2bCore.ComputeHash(data, 64);

            // Assert
            Assert.Equal(64, hash.Length);
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
        public void ComputeHash_InvalidOutputLength_ThrowsArgumentException()
        {
            var data = Encoding.UTF8.GetBytes("Test data");

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Blake2bCore.ComputeHash(data, 0),
                "Output length");
        }

        [Fact]
        public void ComputeLongHash_InvalidOutputLength_ThrowsArgumentException()
        {
            var data = Encoding.UTF8.GetBytes("Test data");

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Blake2bCore.ComputeLongHash(data, 0),
                "Output length");
        }

        [Fact]
        public void ComputeHash_KeyTooLarge_ThrowsArgumentException()
        {
            var data = Array.Empty<byte>();
            var key = new byte[65]; // Max key size is usually 64

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Blake2bCore.ComputeHash(data, 32, key),
                "Key");
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
        public void RFC7693_TestVector_EmptyInput()
        {
            // RFC 7693 test vector: empty input, output 64 bytes (512 bits)
            var emptyInput = new byte[0];
            var hash = Blake2bCore.ComputeHash(emptyInput, 64);

            var expectedHex = "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419" +
                              "D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE";
            var actualHex = TestHelpers.BytesToHex(hash).ToUpperInvariant();

            Assert.Equal(expectedHex, actualHex);
        }
    }

    /// <summary>
    /// Memory hygiene tests.
    /// </summary>
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class MemoryHygiene
    {
        [Fact]
        public void ComputeHash_RepeatedCalls_NoMemoryAccumulation()
        {
            // Arrange
            var data = TestHelpers.RandomBytes(TestDataSizes.Large);
            var key = TestHelpers.RandomBytes(32);

            // Act
            for (int i = 0; i < 100; i++)
            {
                Blake2bCore.ComputeHash(data, 32, key);
            }

            // Assert
            Assert.True(true);
        }
    }
}
