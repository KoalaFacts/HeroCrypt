using System.Text;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Literal Data Packet per RFC 4880 Section 5.9.
/// </summary>
public class PgpLiteralDataPacketTests
{
    /// <summary>
    /// Factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FactoryMethodTests
    {
        [Fact]
        public void CreateBinary_SetsCorrectFormat()
        {
            var data = TestHelpers.RandomBytes(100);

            var packet = PgpLiteralDataPacket.CreateBinary(data);

            Assert.Equal(PgpLiteralDataFormat.Binary, packet.Format);
            Assert.Equal(data, packet.Data.ToArray());
        }

        [Fact]
        public void CreateBinary_WithFileName_SetsFileName()
        {
            var data = TestHelpers.RandomBytes(100);

            var packet = PgpLiteralDataPacket.CreateBinary(data, "test.bin");

            Assert.Equal("test.bin", packet.FileName);
        }

        [Fact]
        public void CreateBinary_WithDate_SetsDate()
        {
            var data = TestHelpers.RandomBytes(100);
            var date = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);

            var packet = PgpLiteralDataPacket.CreateBinary(data, date: date);

            Assert.Equal(date, packet.Date);
        }

        [Fact]
        public void CreateText_SetsCorrectFormat()
        {
            var packet = PgpLiteralDataPacket.CreateText("Hello, World!");

            Assert.Equal(PgpLiteralDataFormat.Text, packet.Format);
            Assert.Equal("Hello, World!", packet.GetDataAsString());
        }

        [Fact]
        public void CreateUtf8_SetsCorrectFormat()
        {
            var packet = PgpLiteralDataPacket.CreateUtf8("Hello, World!");

            Assert.Equal(PgpLiteralDataFormat.Utf8, packet.Format);
            Assert.Equal("Hello, World!", packet.GetDataAsString());
        }

        [Fact]
        public void CreateText_WithUnicodeText_EncodesCorrectly()
        {
            var text = "Hello, \u4e16\u754c!"; // Hello, World! in Chinese

            var packet = PgpLiteralDataPacket.CreateUtf8(text);

            Assert.Equal(text, packet.GetDataAsString());
        }
    }

    /// <summary>
    /// Round-trip serialization tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RoundTripTests
    {
        [Fact]
        public void RoundTrip_BinaryData_PreservesContent()
        {
            var data = TestHelpers.RandomBytes(500);
            var original = PgpLiteralDataPacket.CreateBinary(data, "test.bin");

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(original.Format, decoded.Format);
            Assert.Equal(original.FileName, decoded.FileName);
            Assert.Equal(original.Data.ToArray(), decoded.Data.ToArray());
        }

        [Fact]
        public void RoundTrip_TextData_PreservesContent()
        {
            var original = PgpLiteralDataPacket.CreateText("Hello, World!", "message.txt");

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(original.Format, decoded.Format);
            Assert.Equal(original.FileName, decoded.FileName);
            Assert.Equal(original.GetDataAsString(), decoded.GetDataAsString());
        }

        [Fact]
        public void RoundTrip_Date_PreservesTimestamp()
        {
            var date = new DateTimeOffset(2024, 6, 15, 12, 30, 45, TimeSpan.Zero);
            var original = PgpLiteralDataPacket.CreateBinary(TestHelpers.RandomBytes(10), date: date);

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            // Unix timestamp has second precision
            Assert.Equal(date.ToUnixTimeSeconds(), decoded.Date.ToUnixTimeSeconds());
        }

        [Fact]
        public void RoundTrip_EmptyFileName_Succeeds()
        {
            var original = PgpLiteralDataPacket.CreateBinary(TestHelpers.RandomBytes(100));

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(string.Empty, decoded.FileName);
        }

        [Fact]
        public void RoundTrip_EmptyData_Succeeds()
        {
            var original = PgpLiteralDataPacket.CreateBinary(ReadOnlyMemory<byte>.Empty, "empty.bin");

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal("empty.bin", decoded.FileName);
            Assert.Empty(decoded.Data.ToArray());
        }

        [Fact]
        public void RoundTrip_UnicodeFileName_PreservesName()
        {
            var original = PgpLiteralDataPacket.CreateBinary(
                TestHelpers.RandomBytes(10),
                "\u6587\u4ef6.txt"); // "file" in Chinese

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(original.FileName, decoded.FileName);
        }
    }

    /// <summary>
    /// Integration tests with PgpPacketWriter/Reader.
    /// </summary>
    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class PacketWriterReaderIntegrationTests
    {
        [Fact]
        public void WriteTo_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpLiteralDataPacket.CreateText("Hello, PGP!", "greeting.txt");
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.LiteralData, tag);

            var decoded = PgpLiteralDataPacket.Read(body.Span);
            Assert.Equal(original.Format, decoded.Format);
            Assert.Equal(original.FileName, decoded.FileName);
            Assert.Equal(original.GetDataAsString(), decoded.GetDataAsString());
        }

        [Fact]
        public void WriteTo_OldFormat_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpLiteralDataPacket.CreateBinary(TestHelpers.RandomBytes(50));
            original.WriteTo(writer, PgpPacketFormat.Old);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) == 0); // Old format
        }
    }

    /// <summary>
    /// Encoding format tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncodingFormatTests
    {
        [Fact]
        public void Write_BinaryFormat_WritesCorrectFormatByte()
        {
            var packet = PgpLiteralDataPacket.CreateBinary(new byte[] { 1, 2, 3 });
            var encoded = packet.ToArray();

            Assert.Equal((byte)'b', encoded[0]);
        }

        [Fact]
        public void Write_TextFormat_WritesCorrectFormatByte()
        {
            var packet = PgpLiteralDataPacket.CreateText("test");
            var encoded = packet.ToArray();

            Assert.Equal((byte)'t', encoded[0]);
        }

        [Fact]
        public void Write_Utf8Format_WritesCorrectFormatByte()
        {
            var packet = PgpLiteralDataPacket.CreateUtf8("test");
            var encoded = packet.ToArray();

            Assert.Equal((byte)'u', encoded[0]);
        }

        [Fact]
        public void Write_FileNameLength_EncodedCorrectly()
        {
            var packet = PgpLiteralDataPacket.CreateBinary(new byte[] { 1 }, "test.bin");
            var encoded = packet.ToArray();

            Assert.Equal(8, encoded[1]); // "test.bin" is 8 bytes
        }

        [Fact]
        public void GetEncodedLength_CalculatesCorrectly()
        {
            var data = new byte[100];
            var fileName = "test.bin"; // 8 bytes
            var packet = new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, fileName, DateTimeOffset.UtcNow, data);

            // format (1) + name length (1) + name (8) + date (4) + data (100) = 114
            Assert.Equal(114, packet.GetEncodedLength());
        }
    }

    /// <summary>
    /// Read error handling tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ReadErrorHandlingTests
    {
        [Fact]
        public void TryRead_TooShort_ReturnsFalse()
        {
            var source = new byte[] { (byte)'b', 0, 0, 0, 0 }; // Only 5 bytes, need 6

            var result = PgpLiteralDataPacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_InvalidFormatByte_ReturnsFalse()
        {
            var source = new byte[] { (byte)'x', 0, 0, 0, 0, 0 }; // 'x' is invalid

            var result = PgpLiteralDataPacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("Invalid literal data format", error);
        }

        [Fact]
        public void TryRead_FileNameTruncated_ReturnsFalse()
        {
            var source = new byte[] { (byte)'b', 10, (byte)'a', (byte)'b', 0, 0, 0, 0 }; // Claims 10 byte filename but only 2

            var result = PgpLiteralDataPacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void Read_Invalid_ThrowsArgumentException()
        {
            var source = new byte[] { (byte)'b' };

            Assert.Throws<ArgumentException>(() => PgpLiteralDataPacket.Read(source));
        }
    }

    /// <summary>
    /// Edge case tests.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCaseTests
    {
        [Fact]
        public void Constructor_FileNameTooLong_ThrowsArgumentException()
        {
            var longFileName = new string('a', 256); // > 255 bytes

            Assert.Throws<ArgumentException>(() =>
                new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, longFileName, DateTimeOffset.UtcNow, Array.Empty<byte>()));
        }

        [Fact]
        public void Constructor_NullFileName_TreatedAsEmpty()
        {
            var packet = new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, null!, DateTimeOffset.UtcNow, Array.Empty<byte>());

            Assert.Equal(string.Empty, packet.FileName);
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = PgpLiteralDataPacket.CreateBinary(TestHelpers.RandomBytes(100));
            var smallBuffer = new byte[10];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
        }

        [Fact]
        public void RoundTrip_MaxFileName_Succeeds()
        {
            var maxFileName = new string('a', 255);
            var original = PgpLiteralDataPacket.CreateBinary(new byte[] { 1 }, maxFileName);

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(maxFileName, decoded.FileName);
        }

        [Fact]
        public void RoundTrip_ZeroDate_Succeeds()
        {
            var original = new PgpLiteralDataPacket(
                PgpLiteralDataFormat.Binary,
                "",
                DateTimeOffset.FromUnixTimeSeconds(0),
                new byte[] { 1, 2, 3 });

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(0, decoded.Date.ToUnixTimeSeconds());
        }

        [Fact]
        public void Date_BeforeEpoch_ClampedToZero()
        {
            var original = new PgpLiteralDataPacket(
                PgpLiteralDataFormat.Binary,
                "",
                new DateTimeOffset(1960, 1, 1, 0, 0, 0, TimeSpan.Zero), // Before Unix epoch
                new byte[] { 1 });

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            // Should be clamped to 0
            Assert.Equal(0, decoded.Date.ToUnixTimeSeconds());
        }

        [Fact]
        public void LargeData_Succeeds()
        {
            var data = TestHelpers.RandomBytes(100000);
            var original = PgpLiteralDataPacket.CreateBinary(data, "large.bin");

            var encoded = original.ToArray();
            var decoded = PgpLiteralDataPacket.Read(encoded);

            Assert.Equal(data, decoded.Data.ToArray());
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
        public void ToString_WithFileName_IncludesFileName()
        {
            var packet = PgpLiteralDataPacket.CreateBinary(new byte[100], "test.bin");

            var str = packet.ToString();

            Assert.Contains("Binary", str);
            Assert.Contains("test.bin", str);
            Assert.Contains("100 bytes", str);
        }

        [Fact]
        public void ToString_NoFileName_ShowsNoFilename()
        {
            var packet = PgpLiteralDataPacket.CreateBinary(new byte[50]);

            var str = packet.ToString();

            Assert.Contains("no filename", str);
        }
    }

    /// <summary>
    /// Data extraction tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DataExtractionTests
    {
        [Fact]
        public void GetDataAsString_ValidUtf8_ReturnsString()
        {
            var text = "Hello, World!";
            var packet = PgpLiteralDataPacket.CreateText(text);

            var result = packet.GetDataAsString();

            Assert.Equal(text, result);
        }

        [Fact]
        public void GetDataAsString_BinaryData_CanDecodeIfValidUtf8()
        {
            // Even binary format can be decoded if data happens to be valid UTF-8
            var validUtf8 = Encoding.UTF8.GetBytes("Hello");
            var packet = new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, "", DateTimeOffset.UtcNow, validUtf8);

            var result = packet.GetDataAsString();

            Assert.Equal("Hello", result);
        }
    }
}
