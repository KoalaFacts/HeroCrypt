using System.IO.Compression;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Compressed Data Packet per RFC 4880 Section 5.6.
/// </summary>
public class PgpCompressedDataPacketTests
{
    private static readonly byte[] TestData = "Hello, this is test data for compression!"u8.ToArray();

    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void Constructor_SetsProperties()
        {
            var compressedData = new byte[] { 0x01, 0x02, 0x03 };
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, compressedData);

            Assert.Equal(PgpCompressionAlgorithm.Zip, packet.Algorithm);
            Assert.Equal(compressedData, packet.CompressedData.ToArray());
        }

        [Fact]
        public void Constructor_WithEmptyData_Works()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Uncompressed, Array.Empty<byte>());

            Assert.Equal(PgpCompressionAlgorithm.Uncompressed, packet.Algorithm);
            Assert.Empty(packet.CompressedData.ToArray());
        }
    }

    /// <summary>
    /// Create factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CreateTests
    {
        [Fact]
        public void Create_Uncompressed_StoresDataAsIs()
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Uncompressed);

            Assert.Equal(PgpCompressionAlgorithm.Uncompressed, packet.Algorithm);
            Assert.Equal(TestData, packet.CompressedData.ToArray());
        }

        [Fact]
        public void Create_Zip_CompressesData()
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zip);

            Assert.Equal(PgpCompressionAlgorithm.Zip, packet.Algorithm);
            // Compressed data should generally be smaller or at least different
            Assert.NotEqual(TestData, packet.CompressedData.ToArray());
        }

        [Fact]
        public void Create_Zlib_CompressesData()
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zlib);

            Assert.Equal(PgpCompressionAlgorithm.Zlib, packet.Algorithm);
            // Zlib has a header starting with 0x78
            Assert.Equal(0x78, packet.CompressedData.Span[0]);
        }

        [Fact]
        public void Create_BZip2_ThrowsNotSupportedException()
        {
            Assert.Throws<NotSupportedException>(() =>
                PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.BZip2));
        }

        [Theory]
        [InlineData(CompressionLevel.Fastest)]
        [InlineData(CompressionLevel.Optimal)]
        public void Create_Zip_DifferentLevels_AllDecompress(CompressionLevel level)
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zip, level);
            var decompressed = packet.Decompress();

            Assert.Equal(TestData, decompressed);
        }

        [Theory]
        [InlineData(CompressionLevel.Fastest)]
        [InlineData(CompressionLevel.Optimal)]
        public void Create_Zlib_DifferentLevels_AllDecompress(CompressionLevel level)
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zlib, level);
            var decompressed = packet.Decompress();

            Assert.Equal(TestData, decompressed);
        }
    }

    /// <summary>
    /// Decompress method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DecompressTests
    {
        [Fact]
        public void Decompress_Uncompressed_ReturnsOriginalData()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Uncompressed, TestData);
            var decompressed = packet.Decompress();

            Assert.Equal(TestData, decompressed);
        }

        [Fact]
        public void Decompress_Zip_RoundTrips()
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zip);
            var decompressed = packet.Decompress();

            Assert.Equal(TestData, decompressed);
        }

        [Fact]
        public void Decompress_Zlib_RoundTrips()
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zlib);
            var decompressed = packet.Decompress();

            Assert.Equal(TestData, decompressed);
        }

        [Fact]
        public void Decompress_BZip2_ThrowsNotSupportedException()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.BZip2, new byte[] { 0x42, 0x5A });

            Assert.Throws<NotSupportedException>(packet.Decompress);
        }

        [Fact]
        public void Decompress_LargeData_RoundTrips()
        {
            var largeData = new byte[100000];
            new Random(42).NextBytes(largeData);

            var packet = PgpCompressedDataPacket.Create(largeData, PgpCompressionAlgorithm.Zip);
            var decompressed = packet.Decompress();

            Assert.Equal(largeData, decompressed);
        }

        [Fact]
        public void Decompress_EmptyData_RoundTrips()
        {
            var packet = PgpCompressedDataPacket.Create([], PgpCompressionAlgorithm.Zip);
            var decompressed = packet.Decompress();

            Assert.Empty(decompressed);
        }
    }

    /// <summary>
    /// Read/TryRead tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ReadTests
    {
        [Fact]
        public void Read_ValidPacket_ParsesCorrectly()
        {
            var original = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zip);
            var encoded = original.ToArray();

            var decoded = PgpCompressedDataPacket.Read(encoded);

            Assert.Equal(original.Algorithm, decoded.Algorithm);
            Assert.Equal(original.CompressedData.ToArray(), decoded.CompressedData.ToArray());
        }

        [Fact]
        public void TryRead_ValidPacket_ReturnsTrue()
        {
            var data = new byte[] { 0x01, 0xAA, 0xBB, 0xCC }; // ZIP algorithm + data

            var result = PgpCompressedDataPacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(PgpCompressionAlgorithm.Zip, packet.Algorithm);
            Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, packet.CompressedData.ToArray());
        }

        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var result = PgpCompressedDataPacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void Read_EmptySource_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpCompressedDataPacket.Read([]));
        }

        [Fact]
        public void Read_OnlyAlgorithmByte_ParsesWithEmptyData()
        {
            var data = new byte[] { 0x00 }; // Uncompressed, no data

            var packet = PgpCompressedDataPacket.Read(data);

            Assert.Equal(PgpCompressionAlgorithm.Uncompressed, packet.Algorithm);
            Assert.Empty(packet.CompressedData.ToArray());
        }
    }

    /// <summary>
    /// Write tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class WriteTests
    {
        [Fact]
        public void GetEncodedLength_ReturnsCorrectLength()
        {
            var compressedData = new byte[] { 0x01, 0x02, 0x03 };
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, compressedData);

            Assert.Equal(4, packet.GetEncodedLength()); // 1 (algorithm) + 3 (data)
        }

        [Fact]
        public void Write_WritesCorrectFormat()
        {
            var compressedData = new byte[] { 0xAA, 0xBB };
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zlib, compressedData);

            var buffer = new byte[10];
            var bytesWritten = packet.Write(buffer);

            Assert.Equal(3, bytesWritten);
            Assert.Equal(0x02, buffer[0]); // Zlib algorithm
            Assert.Equal(0xAA, buffer[1]);
            Assert.Equal(0xBB, buffer[2]);
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[10]);
            var smallBuffer = new byte[5];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[] { 0x01, 0x02 });
            var buffer = new byte[10];

            var result = packet.TryWrite(buffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(3, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[10]);
            var smallBuffer = new byte[5];

            var result = packet.TryWrite(smallBuffer, out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }

        [Fact]
        public void ToArray_ReturnsCorrectBytes()
        {
            var compressedData = new byte[] { 0x11, 0x22, 0x33 };
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Uncompressed, compressedData);

            var result = packet.ToArray();

            Assert.Equal(new byte[] { 0x00, 0x11, 0x22, 0x33 }, result);
        }
    }

    /// <summary>
    /// Round-trip tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RoundTripTests
    {
        [Theory]
        [InlineData(PgpCompressionAlgorithm.Uncompressed)]
        [InlineData(PgpCompressionAlgorithm.Zip)]
        [InlineData(PgpCompressionAlgorithm.Zlib)]
        public void RoundTrip_AllAlgorithms_Preserved(PgpCompressionAlgorithm algorithm)
        {
            var original = PgpCompressedDataPacket.Create(TestData, algorithm);

            var encoded = original.ToArray();
            var decoded = PgpCompressedDataPacket.Read(encoded);
            var decompressed = decoded.Decompress();

            Assert.Equal(original.Algorithm, decoded.Algorithm);
            Assert.Equal(TestData, decompressed);
        }

        [Fact]
        public void RoundTrip_BinaryData_PreservesExactBytes()
        {
            var binaryData = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                binaryData[i] = (byte)i;
            }

            var original = PgpCompressedDataPacket.Create(binaryData, PgpCompressionAlgorithm.Zip);
            var encoded = original.ToArray();
            var decoded = PgpCompressedDataPacket.Read(encoded);
            var decompressed = decoded.Decompress();

            Assert.Equal(binaryData, decompressed);
        }
    }

    /// <summary>
    /// Equality tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EqualityTests
    {
        [Fact]
        public void Equals_SamePacket_ReturnsTrue()
        {
            var data = new byte[] { 0x01, 0x02, 0x03 };
            var packet1 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, data);
            var packet2 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, data);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
        }

        [Fact]
        public void Equals_DifferentAlgorithm_ReturnsFalse()
        {
            var data = new byte[] { 0x01, 0x02, 0x03 };
            var packet1 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, data);
            var packet2 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zlib, data);

            Assert.False(packet1.Equals(packet2));
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentData_ReturnsFalse()
        {
            var packet1 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[] { 0x01 });
            var packet2 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[] { 0x02 });

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void GetHashCode_SamePacket_ReturnsSameHash()
        {
            var data = new byte[] { 0x01, 0x02, 0x03 };
            var packet1 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, data);
            var packet2 = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, data);

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }

        [Fact]
        public void Equals_WithObject_Works()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[] { 0x01 });

            Assert.True(packet.Equals((object)packet));
            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }
    }

    /// <summary>
    /// ToString tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ToStringTests
    {
        [Fact]
        public void ToString_ContainsAlgorithm()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zip, new byte[100]);

            var str = packet.ToString();

            Assert.Contains("Zip", str);
            Assert.Contains("100", str);
        }

        [Fact]
        public void ToString_ContainsDataLength()
        {
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zlib, new byte[50]);

            var str = packet.ToString();

            Assert.Contains("50 bytes", str);
        }
    }

    /// <summary>
    /// Zlib-specific tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ZlibTests
    {
        [Fact]
        public void Zlib_Header_IsValid()
        {
            var packet = PgpCompressedDataPacket.Create(TestData, PgpCompressionAlgorithm.Zlib);
            var data = packet.CompressedData.Span;

            // CMF should be 0x78 (deflate, 32K window)
            Assert.Equal(0x78, data[0]);

            // (CMF * 256 + FLG) % 31 should be 0
            int headerCheck = (data[0] * 256 + data[1]) % 31;
            Assert.Equal(0, headerCheck);
        }

        [Fact]
        public void Zlib_InvalidHeader_ThrowsInvalidDataException()
        {
            // Invalid compression method (0x77 & 0x0F = 7, not 8)
            var invalidData = new byte[] { 0x77, 0x95, 0x00, 0x00, 0x00, 0x01 };
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zlib, invalidData);

            var ex = Assert.Throws<InvalidDataException>(packet.Decompress);
            Assert.Contains("compression method", ex.Message);
        }

        [Fact]
        public void Zlib_TooShort_ThrowsInvalidDataException()
        {
            var shortData = new byte[] { 0x78, 0x9C }; // Just header, no data or checksum
            var packet = new PgpCompressedDataPacket(PgpCompressionAlgorithm.Zlib, shortData);

            Assert.Throws<InvalidDataException>(packet.Decompress);
        }
    }

    /// <summary>
    /// Compression algorithm enum tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmEnumTests
    {
        [Fact]
        public void CompressionAlgorithm_Uncompressed_HasValue0()
        {
            Assert.Equal(0, (byte)PgpCompressionAlgorithm.Uncompressed);
        }

        [Fact]
        public void CompressionAlgorithm_Zip_HasValue1()
        {
            Assert.Equal(1, (byte)PgpCompressionAlgorithm.Zip);
        }

        [Fact]
        public void CompressionAlgorithm_Zlib_HasValue2()
        {
            Assert.Equal(2, (byte)PgpCompressionAlgorithm.Zlib);
        }

        [Fact]
        public void CompressionAlgorithm_BZip2_HasValue3()
        {
            Assert.Equal(3, (byte)PgpCompressionAlgorithm.BZip2);
        }
    }
}
