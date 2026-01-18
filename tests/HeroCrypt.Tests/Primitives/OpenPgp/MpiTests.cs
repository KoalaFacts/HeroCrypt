using System.Numerics;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for Multi-Precision Integer (MPI) encoding per RFC 4880 Section 3.2.
/// </summary>
public class MpiTests
{
    /// <summary>
    /// Basic functionality tests for MPI encoding/decoding.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void Write_Zero_ProducesCorrectEncoding()
        {
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(BigInteger.Zero, destination);

            Assert.Equal(2, bytesWritten);
            Assert.Equal(0, destination[0]); // Bit count high byte
            Assert.Equal(0, destination[1]); // Bit count low byte
        }

        [Fact]
        public void Write_SmallValue_ProducesCorrectEncoding()
        {
            // Value 5 = binary 101, has 3 significant bits
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(new BigInteger(5), destination);

            Assert.Equal(3, bytesWritten); // 2 for bit count + 1 for data
            Assert.Equal(0, destination[0]); // Bit count high byte
            Assert.Equal(3, destination[1]); // Bit count = 3
            Assert.Equal(5, destination[2]); // Data
        }

        [Fact]
        public void Read_Zero_ReturnsZero()
        {
            var source = new byte[] { 0, 0 };

            var value = Mpi.Read(source, out var bytesConsumed);

            Assert.Equal(BigInteger.Zero, value);
            Assert.Equal(2, bytesConsumed);
        }

        [Fact]
        public void Read_SmallValue_ReturnsCorrectValue()
        {
            // 3-bit value 5
            var source = new byte[] { 0, 3, 5 };

            var value = Mpi.Read(source, out var bytesConsumed);

            Assert.Equal(new BigInteger(5), value);
            Assert.Equal(3, bytesConsumed);
        }

        [Fact]
        public void RoundTrip_SmallValues()
        {
            foreach (var original in new[] { 0, 1, 127, 128, 255, 256, 511, 1000 })
            {
                var bigInt = new BigInteger(original);
                var buffer = new byte[Mpi.GetEncodedLength(bigInt)];
                Mpi.Write(bigInt, buffer);

                var decoded = Mpi.Read(buffer, out _);

                Assert.Equal(bigInt, decoded);
            }
        }

        [Fact]
        public void RoundTrip_LargeValue()
        {
            // 2048-bit RSA-like value
            var bytes = TestHelpers.RandomBytes(256);
            bytes[0] |= 0x80; // Ensure MSB is set
            var original = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);

            var encodedLength = Mpi.GetEncodedLength(original);
            var buffer = new byte[encodedLength];
            Mpi.Write(original, buffer);

            var decoded = Mpi.Read(buffer, out var bytesConsumed);

            Assert.Equal(original, decoded);
            Assert.Equal(encodedLength, bytesConsumed);
        }
    }

    /// <summary>
    /// Tests for writing raw bytes as MPI.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ByteArrayWriteTests
    {
        [Fact]
        public void Write_EmptyBytes_ProducesZeroMpi()
        {
            var source = Array.Empty<byte>();
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(source, destination);

            Assert.Equal(2, bytesWritten);
            Assert.Equal(0, destination[0]);
            Assert.Equal(0, destination[1]);
        }

        [Fact]
        public void Write_AllZeroBytes_ProducesZeroMpi()
        {
            var source = new byte[] { 0, 0, 0, 0 };
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(source, destination);

            Assert.Equal(2, bytesWritten);
            Assert.Equal(0, destination[0]);
            Assert.Equal(0, destination[1]);
        }

        [Fact]
        public void Write_LeadingZeros_StripsLeadingZeros()
        {
            var source = new byte[] { 0, 0, 0x01, 0xFF }; // Leading zeros
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(source, destination);

            // Value is 0x01FF = 511, which is 9 bits
            Assert.Equal(4, bytesWritten); // 2 + 2 bytes
            Assert.Equal(0, destination[0]); // High byte of bit count
            Assert.Equal(9, destination[1]); // 9 bits
            Assert.Equal(0x01, destination[2]);
            Assert.Equal(0xFF, destination[3]);
        }

        [Fact]
        public void ReadBytes_ReturnsRawBytes()
        {
            var source = new byte[] { 0, 9, 0x01, 0xFF }; // 9-bit value 0x01FF

            var bytes = Mpi.ReadBytes(source, out var bytesConsumed);

            Assert.Equal(4, bytesConsumed);
            Assert.Equal(2, bytes.Length);
            Assert.Equal(0x01, bytes[0]);
            Assert.Equal(0xFF, bytes[1]);
        }
    }

    /// <summary>
    /// Tests for TryRead method.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class TryReadTests
    {
        [Fact]
        public void TryRead_ValidInput_ReturnsTrue()
        {
            var source = new byte[] { 0, 3, 5 };

            var result = Mpi.TryRead(source, out var value, out var bytesConsumed);

            Assert.True(result);
            Assert.Equal(new BigInteger(5), value);
            Assert.Equal(3, bytesConsumed);
        }

        [Fact]
        public void TryRead_TooShort_ReturnsFalse()
        {
            var source = new byte[] { 0 }; // Only 1 byte

            var result = Mpi.TryRead(source, out var value, out var bytesConsumed);

            Assert.False(result);
            Assert.Equal(BigInteger.Zero, value);
            Assert.Equal(0, bytesConsumed);
        }

        [Fact]
        public void TryRead_DataTooShort_ReturnsFalse()
        {
            var source = new byte[] { 0, 16 }; // Claims 16 bits (2 bytes) but has no data

            var result = Mpi.TryRead(source, out var value, out var bytesConsumed);

            Assert.False(result);
            Assert.Equal(BigInteger.Zero, value);
            Assert.Equal(0, bytesConsumed);
        }

        [Fact]
        public void TryRead_ZeroLength_ReturnsZero()
        {
            var source = new byte[] { 0, 0 };

            var result = Mpi.TryRead(source, out var value, out var bytesConsumed);

            Assert.True(result);
            Assert.Equal(BigInteger.Zero, value);
            Assert.Equal(2, bytesConsumed);
        }
    }

    /// <summary>
    /// Tests for GetEncodedLength method.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncodedLengthTests
    {
        [Theory]
        [InlineData(0, 2)] // Zero needs just bit count
        [InlineData(1, 3)] // 1 bit + 2 byte header
        [InlineData(127, 3)] // 7 bits
        [InlineData(128, 3)] // 8 bits
        [InlineData(255, 3)] // 8 bits
        [InlineData(256, 4)] // 9 bits
        [InlineData(65535, 4)] // 16 bits
        [InlineData(65536, 5)] // 17 bits
        public void GetEncodedLength_BigInteger_ReturnsCorrectLength(long value, int expectedLength)
        {
            var bigInt = new BigInteger(value);

            var length = Mpi.GetEncodedLength(bigInt);

            Assert.Equal(expectedLength, length);
        }

        [Fact]
        public void GetEncodedLength_Bytes_StripsLeadingZeros()
        {
            var bytes = new byte[] { 0, 0, 0x01, 0xFF };

            var length = Mpi.GetEncodedLength(bytes);

            Assert.Equal(4, length); // 2 header + 2 data (leading zeros stripped)
        }

        [Fact]
        public void GetEncodedLength_AllZeroBytes_ReturnsTwo()
        {
            var bytes = new byte[] { 0, 0, 0, 0 };

            var length = Mpi.GetEncodedLength(bytes);

            Assert.Equal(2, length); // Just the header
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
        public void Write_MaxSingleByte_Correct()
        {
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(new BigInteger(255), destination);

            Assert.Equal(3, bytesWritten);
            Assert.Equal(0, destination[0]);
            Assert.Equal(8, destination[1]); // 8 bits
            Assert.Equal(255, destination[2]);
        }

        [Fact]
        public void Write_PowerOfTwo_CorrectBitCount()
        {
            // 128 = 0x80 = 10000000, which is 8 bits
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(new BigInteger(128), destination);

            Assert.Equal(3, bytesWritten);
            Assert.Equal(0, destination[0]);
            Assert.Equal(8, destination[1]); // 8 bits (not 7)
            Assert.Equal(128, destination[2]);
        }

        [Fact]
        public void Write_511_CorrectBitCount()
        {
            // 511 = 0x01FF = 9 bits
            var destination = new byte[10];

            var bytesWritten = Mpi.Write(new BigInteger(511), destination);

            Assert.Equal(4, bytesWritten);
            Assert.Equal(0, destination[0]);
            Assert.Equal(9, destination[1]); // 9 bits
            Assert.Equal(0x01, destination[2]);
            Assert.Equal(0xFF, destination[3]);
        }

        [Fact]
        public void Read_HighBitSet_InterpretedAsUnsigned()
        {
            // 0xFF00 should be 65280, not negative
            var source = new byte[] { 0, 16, 0xFF, 0x00 };

            var value = Mpi.Read(source, out _);

            Assert.True(value > 0);
            Assert.Equal(new BigInteger(0xFF00), value);
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
        public void Write_NegativeValue_ThrowsArgumentOutOfRangeException()
        {
            var destination = new byte[10];

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                Mpi.Write(new BigInteger(-1), destination));
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var destination = new byte[1]; // Too small

            Assert.Throws<ArgumentException>(() =>
                Mpi.Write(BigInteger.One, destination));
        }

        [Fact]
        public void Read_SourceTooShort_ThrowsArgumentException()
        {
            var source = new byte[] { 0 };

            Assert.Throws<ArgumentException>(() =>
                Mpi.Read(source, out _));
        }

        [Fact]
        public void Read_DataTooShort_ThrowsArgumentException()
        {
            var source = new byte[] { 0, 16 }; // Claims 16 bits but no data

            Assert.Throws<ArgumentException>(() =>
                Mpi.Read(source, out _));
        }

        [Fact]
        public void ReadBytes_SourceTooShort_ThrowsArgumentException()
        {
            var source = new byte[] { 0 };

            Assert.Throws<ArgumentException>(() =>
                Mpi.ReadBytes(source, out _));
        }
    }

    /// <summary>
    /// RFC 4880 compliance tests.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class Rfc4880Compliance
    {
        [Fact]
        public void Rfc4880_Example_511()
        {
            // RFC 4880 Section 3.2 example: 511 (0x01FF) has bit count of 9
            var value = new BigInteger(511);
            var buffer = new byte[10];

            var written = Mpi.Write(value, buffer);

            Assert.Equal(4, written);
            Assert.Equal(0, buffer[0]); // High byte of bit count
            Assert.Equal(9, buffer[1]); // Bit count = 9
            Assert.Equal(0x01, buffer[2]); // High byte of value
            Assert.Equal(0xFF, buffer[3]); // Low byte of value
        }

        [Fact]
        public void Rfc4880_BitCountIsSignificantBits()
        {
            // Verify bit count is the number of significant bits, not byte count * 8
            // 128 = 0x80 has 8 significant bits (bit 7 is set)
            var buffer = new byte[10];

            Mpi.Write(new BigInteger(128), buffer);

            var bitCount = (buffer[0] << 8) | buffer[1];
            Assert.Equal(8, bitCount); // Should be 8, not rounded up
        }

        [Fact]
        public void Rfc4880_NoLeadingZeroBytes()
        {
            // MPI should not have leading zero bytes in the data portion
            var bytes = new byte[] { 0, 0, 0x7F }; // Leading zeros with a value that doesn't need sign extension
            var buffer = new byte[10];

            var written = Mpi.Write(bytes, buffer);

            Assert.Equal(3, written); // 2 header + 1 data byte
            var bitCount = (buffer[0] << 8) | buffer[1];
            Assert.Equal(7, bitCount); // 0x7F has 7 significant bits
        }
    }

    /// <summary>
    /// Tests for leading zero handling (constant-time behavior verification).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class LeadingZeroHandlingTests
    {
        [Theory]
        [InlineData(new byte[] { 0, 0, 0, 1 }, 3)] // 3 leading zeros trimmed, 2 header + 1 data
        [InlineData(new byte[] { 0, 1 }, 3)]       // 1 leading zero trimmed, 2 header + 1 data
        [InlineData(new byte[] { 1 }, 3)]          // No leading zeros, 2 header + 1 data
        [InlineData(new byte[] { 0, 0, 0, 0 }, 2)] // All zeros, just header
        [InlineData(new byte[] { }, 2)]            // Empty, just header
        public void Write_LeadingZeros_ProducesCorrectLength(byte[] input, int expectedWritten)
        {
            var buffer = new byte[20];
            var written = Mpi.Write(input, buffer);
            Assert.Equal(expectedWritten, written);
        }

        [Theory]
        [InlineData(new byte[] { 0, 0, 0, 1 }, 3)] // 3 leading zeros trimmed, 2 header + 1 data
        [InlineData(new byte[] { 0, 0, 0, 0, 0xFF }, 3)] // 4 leading zeros trimmed, 2 header + 1 data
        [InlineData(new byte[] { 0xFF }, 3)]       // No leading zeros, 2 header + 1 data
        [InlineData(new byte[] { 0, 0, 0, 0 }, 2)] // All zeros, just header
        public void GetEncodedLength_LeadingZeros_ReturnsCorrectLength(byte[] input, int expectedLength)
        {
            var length = Mpi.GetEncodedLength(input);
            Assert.Equal(expectedLength, length);
        }

        [Fact]
        public void Write_ManyLeadingZeros_ProducesCorrectResult()
        {
            // 100 leading zeros followed by 0x42
            var input = new byte[101];
            input[100] = 0x42;
            var buffer = new byte[10];

            var written = Mpi.Write(input, buffer);

            Assert.Equal(3, written); // 2 header + 1 data
            Assert.Equal(0, buffer[0]); // High byte of bit count
            Assert.Equal(7, buffer[1]); // 0x42 has 7 significant bits
            Assert.Equal(0x42, buffer[2]);
        }
    }
}
