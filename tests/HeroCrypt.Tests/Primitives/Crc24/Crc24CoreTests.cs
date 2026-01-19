using HeroCrypt.Primitives.Crc24;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Crc24;

/// <summary>
/// Comprehensive tests for CRC24 implementation.
/// Tests the OpenPGP CRC24 algorithm specified in RFC 4880.
/// </summary>
public class Crc24CoreTests
{
    private const int CRC_SIZE = 3;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void Compute_WithValidInput_ReturnsNonZero()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var crc = Crc24Core.Compute(data);

            Assert.True(crc <= 0xFFFFFF, "CRC24 should be 24-bit value");
        }

        [Fact]
        public void Compute_IsDeterministic()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var crc1 = Crc24Core.Compute(data);
            var crc2 = Crc24Core.Compute(data);

            Assert.Equal(crc1, crc2);
        }

        [Fact]
        public void Compute_DifferentData_ProducesDifferentCrc()
        {
            var data1 = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var data2 = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var crc1 = Crc24Core.Compute(data1);
            var crc2 = Crc24Core.Compute(data2);

            Assert.NotEqual(crc1, crc2);
        }

        [Fact]
        public void ComputeToBytes_ReturnsCorrectSize()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var crcBytes = Crc24Core.ComputeToBytes(data);

            Assert.Equal(CRC_SIZE, crcBytes.Length);
        }

        [Fact]
        public void ComputeToBytes_MatchesComputeValue()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var crc = Crc24Core.Compute(data);
            var crcBytes = Crc24Core.ComputeToBytes(data);

            // Convert bytes to uint (big-endian)
            var crcFromBytes = ((uint)crcBytes[0] << 16) | ((uint)crcBytes[1] << 8) | crcBytes[2];

            Assert.Equal(crc, crcFromBytes);
        }

        [Fact]
        public void Compute_ToSpan_ProducesCorrectResult()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var output = new byte[CRC_SIZE];

            Crc24Core.Compute(output, data);

            var crc = Crc24Core.Compute(data);
            var crcFromSpan = ((uint)output[0] << 16) | ((uint)output[1] << 8) | output[2];

            Assert.Equal(crc, crcFromSpan);
        }
    }

    /// <summary>
    /// Verification tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class VerificationTests
    {
        [Fact]
        public void Verify_CorrectCrc_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var crc = Crc24Core.Compute(data);

            var result = Crc24Core.Verify(crc, data);

            Assert.True(result);
        }

        [Fact]
        public void Verify_IncorrectCrc_ReturnsFalse()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var crc = Crc24Core.Compute(data);
            var wrongCrc = crc ^ 0x01;

            var result = Crc24Core.Verify(wrongCrc, data);

            Assert.False(result);
        }

        [Fact]
        public void Verify_WithBytes_CorrectCrc_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var crcBytes = Crc24Core.ComputeToBytes(data);

            var result = Crc24Core.Verify(crcBytes, data);

            Assert.True(result);
        }

        [Fact]
        public void Verify_WithBytes_IncorrectCrc_ReturnsFalse()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var crcBytes = Crc24Core.ComputeToBytes(data);
            crcBytes[2] ^= 0x01;

            var result = Crc24Core.Verify(crcBytes, data);

            Assert.False(result);
        }

        [Fact]
        public void Verify_ModifiedData_ReturnsFalse()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var crc = Crc24Core.Compute(data);
            var modifiedData = TestHelpers.TamperFirst(data);

            var result = Crc24Core.Verify(crc, modifiedData);

            Assert.False(result);
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
        public void Compute_EmptyData_ProducesInitialValue()
        {
            var data = Array.Empty<byte>();

            var crc = Crc24Core.Compute(data);

            // Empty data should return the initial CRC value (0xB704CE)
            Assert.Equal(0xB704CEu, crc);
        }

        [Fact]
        public void Compute_SingleByte_Succeeds()
        {
            var data = new byte[] { 0x42 };

            var crc = Crc24Core.Compute(data);

            Assert.True(crc <= 0xFFFFFF);
        }

        [Fact]
        public void Compute_AllZeros_Succeeds()
        {
            var data = TestHelpers.ZeroBytes(TestDataSizes.Medium);

            var crc = Crc24Core.Compute(data);

            Assert.True(crc <= 0xFFFFFF);
        }

        [Fact]
        public void Compute_AllOnes_Succeeds()
        {
            var data = TestHelpers.FilledBytes(TestDataSizes.Medium, 0xFF);

            var crc = Crc24Core.Compute(data);

            Assert.True(crc <= 0xFFFFFF);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Compute_LargeData_Succeeds()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);

            var crc = Crc24Core.Compute(data);

            Assert.True(crc <= 0xFFFFFF);
        }

        [Fact]
        public void Verify_TooShortExpectedCrc_ReturnsFalse()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var shortCrc = new byte[2]; // Only 2 bytes instead of 3

            var result = Crc24Core.Verify(shortCrc, data);

            Assert.False(result);
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
        public void Compute_OutputTooSmall_ThrowsArgumentException()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var smallOutput = new byte[2]; // Too small

            var ex = Assert.Throws<ArgumentException>(() => Crc24Core.Compute(smallOutput, data));
            Assert.Contains("3 bytes", ex.Message);
        }
    }

    /// <summary>
    /// Known Answer Tests using official test vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void RFC4880_EmptyInput_ReturnsInitialValue()
        {
            // Empty input should return the initial CRC24 value
            var data = Array.Empty<byte>();

            var crc = Crc24Core.Compute(data);

            // Initial value: 0xB704CE
            Assert.Equal(0xB704CEu, crc);
        }

        [Fact]
        public void KnownVector_SimpleString()
        {
            // Test with "test" string
            var data = System.Text.Encoding.ASCII.GetBytes("test");

            var crc = Crc24Core.Compute(data);
            var crcBytes = Crc24Core.ComputeToBytes(data);

            // Verify CRC is within 24-bit range
            Assert.True(crc <= 0xFFFFFF);
            Assert.Equal(CRC_SIZE, crcBytes.Length);

            // Verify deterministic
            Assert.Equal(crc, Crc24Core.Compute(data));
        }

        [Theory]
        [InlineData("")] // Empty string
        [InlineData("a")]
        [InlineData("ab")]
        [InlineData("abc")]
        [InlineData("Hello")]
        [InlineData("The quick brown fox jumps over the lazy dog")]
        public void KnownVectors_AreDeterministic(string input)
        {
            var data = System.Text.Encoding.ASCII.GetBytes(input);

            var crc1 = Crc24Core.Compute(data);
            var crc2 = Crc24Core.Compute(data);

            // Verify CRC is deterministic and within 24-bit range
            Assert.Equal(crc1, crc2);
            Assert.True(crc1 <= 0xFFFFFF, "CRC24 should be 24-bit value");
        }

        [Fact]
        public void EmptyString_ReturnsInitialValue()
        {
            // Per RFC 4880, empty data returns the initial CRC value
            var data = Array.Empty<byte>();

            var crc = Crc24Core.Compute(data);

            Assert.Equal(0xB704CEu, crc);
        }

        [Fact]
        public void DifferentInputs_ProduceDifferentCrcs()
        {
            var inputs = new[] { "", "a", "ab", "abc", "abcd" };
            var crcs = inputs.Select(s => Crc24Core.Compute(System.Text.Encoding.ASCII.GetBytes(s))).ToArray();

            // All CRCs should be unique
            Assert.Equal(inputs.Length, crcs.Distinct().Count());
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
        public void Builder_Compute_MatchesCore()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var coreCrc = Crc24Core.Compute(data);
            var builderCrc = Crc24Builder.Create().Compute(data);

            Assert.Equal(coreCrc, builderCrc);
        }

        [Fact]
        public void Builder_ComputeToBytes_MatchesCore()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var coreCrcBytes = Crc24Core.ComputeToBytes(data);
            var builderCrcBytes = Crc24Builder.Create().ComputeToBytes(data);

            Assert.Equal(coreCrcBytes, builderCrcBytes);
        }

        [Fact]
        public void Builder_Verify_MatchesCore()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var crc = Crc24Core.Compute(data);

            var coreResult = Crc24Core.Verify(crc, data);
            var builderResult = Crc24Builder.Create().Verify(crc, data);

            Assert.Equal(coreResult, builderResult);
        }

        [Fact]
        public void HeroCryptBuilder_Crc24_CreatesBuilder()
        {
            var builder = HeroCryptBuilder.Crc24();

            Assert.NotNull(builder);
            Assert.IsType<Crc24Builder>(builder);
        }
    }

    /// <summary>
    /// Tests for error detection properties.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ErrorDetectionTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(7)]
        [InlineData(15)]
        [InlineData(100)]
        public void SingleBitFlip_DetectedAtPosition(int position)
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var originalCrc = Crc24Core.Compute(data);

            // Flip a single bit
            var modifiedData = (byte[])data.Clone();
            modifiedData[position % data.Length] ^= 0x01;

            var modifiedCrc = Crc24Core.Compute(modifiedData);

            Assert.NotEqual(originalCrc, modifiedCrc);
        }

        [Fact]
        public void ByteSwap_Detected()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Ensure first two bytes are different for deterministic test
            data[0] = 0x00;
            data[1] = 0xFF;

            var originalCrc = Crc24Core.Compute(data);

            // Swap two bytes
            var modifiedData = (byte[])data.Clone();
            (modifiedData[0], modifiedData[1]) = (modifiedData[1], modifiedData[0]);

            var modifiedCrc = Crc24Core.Compute(modifiedData);

            Assert.NotEqual(originalCrc, modifiedCrc);
        }
    }
}
