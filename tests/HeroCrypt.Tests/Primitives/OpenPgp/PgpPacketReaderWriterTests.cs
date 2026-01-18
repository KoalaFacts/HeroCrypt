using System.Numerics;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP packet reading and writing.
/// </summary>
public class PgpPacketReaderWriterTests
{
    /// <summary>
    /// Basic writer functionality tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class WriterBasicTests
    {
        [Fact]
        public void WritePacket_SimpleBody_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(100);

            writer.WritePacket(PgpPacketTag.LiteralData, body);

            stream.Position = 0;
            Assert.Equal(102, stream.Length); // 2-byte header + 100-byte body
        }

        [Fact]
        public void WritePacket_NewFormat_Default()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = new byte[] { 1, 2, 3 };

            writer.WritePacket(PgpPacketTag.LiteralData, body);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) != 0); // New format bit set
        }

        [Fact]
        public void WritePacket_OldFormat_WhenSpecified()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = new byte[] { 1, 2, 3 };

            writer.WritePacket(PgpPacketTag.Signature, body, PgpPacketFormat.Old);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) == 0); // Old format bit not set
        }

        [Fact]
        public void WritePacket_EmptyBody_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            writer.WritePacket(PgpPacketTag.LiteralData, []);

            stream.Position = 0;
            Assert.Equal(2, stream.Length); // Just header
        }

        [Fact]
        public void WritePacket_LargeBody_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(100000);

            writer.WritePacket(PgpPacketTag.LiteralData, body);

            // Header should be 6 bytes (five-octet length)
            Assert.Equal(100006, stream.Length);
        }

        [Fact]
        public void Dispose_ClosesUnderlyingStream_WhenNotLeaveOpen()
        {
            var stream = new MemoryStream();
            var writer = new PgpPacketWriter(stream, leaveOpen: false);

            writer.Dispose();

            Assert.Throws<ObjectDisposedException>(() => stream.WriteByte(0));
        }

        [Fact]
        public void Dispose_LeavesStreamOpen_WhenLeaveOpen()
        {
            var stream = new MemoryStream();
            var writer = new PgpPacketWriter(stream, leaveOpen: true);

            writer.Dispose();

            // Should not throw
            stream.WriteByte(0);
        }
    }

    /// <summary>
    /// Basic reader functionality tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ReaderBasicTests
    {
        [Fact]
        public void ReadNextPacket_SimplePacket_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var originalBody = TestHelpers.RandomBytes(100);
            writer.WritePacket(PgpPacketTag.LiteralData, originalBody);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            var result = reader.ReadNextPacket(out var tag, out var body);

            Assert.True(result);
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal(originalBody, body.ToArray());
        }

        [Fact]
        public void ReadNextPacket_EndOfStream_ReturnsFalse()
        {
            using var stream = new MemoryStream();
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            var result = reader.ReadNextPacket(out _, out _);

            Assert.False(result);
        }

        [Fact]
        public void ReadNextPacket_MultiplePackets_ReadsAll()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body1 = TestHelpers.RandomBytes(50);
            var body2 = TestHelpers.RandomBytes(100);
            var body3 = TestHelpers.RandomBytes(150);
            writer.WritePacket(PgpPacketTag.LiteralData, body1);
            writer.WritePacket(PgpPacketTag.Signature, body2);
            writer.WritePacket(PgpPacketTag.CompressedData, body3);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag1, out var readBody1));
            Assert.Equal(PgpPacketTag.LiteralData, tag1);
            Assert.Equal(body1, readBody1.ToArray());

            Assert.True(reader.ReadNextPacket(out var tag2, out var readBody2));
            Assert.Equal(PgpPacketTag.Signature, tag2);
            Assert.Equal(body2, readBody2.ToArray());

            Assert.True(reader.ReadNextPacket(out var tag3, out var readBody3));
            Assert.Equal(PgpPacketTag.CompressedData, tag3);
            Assert.Equal(body3, readBody3.ToArray());

            Assert.False(reader.ReadNextPacket(out _, out _));
        }

        [Fact]
        public void ReadNextPacket_InvalidFirstByte_ThrowsInvalidDataException()
        {
            using var stream = new MemoryStream([0x00, 0x00]); // Bit 7 not set
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.Throws<InvalidDataException>(() => reader.ReadNextPacket(out _, out _));
        }
    }

    /// <summary>
    /// Tests for streaming/partial body length encoding.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class StreamingTests
    {
        [Fact]
        public void WritePacketStreaming_SmallBody_WritesAsNormalPacket()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(100);
            using var bodyStream = new MemoryStream(body);

            writer.WritePacketStreaming(PgpPacketTag.LiteralData, bodyStream);

            // Should be written as regular packet
            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out var readBody));
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal(body, readBody.ToArray());
        }

        [Fact]
        public void WritePacketStreaming_LargeBody_UsesChunking()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(100000);
            using var bodyStream = new MemoryStream(body);

            writer.WritePacketStreaming(PgpPacketTag.LiteralData, bodyStream, chunkSize: 1024);

            // Verify it can be read back correctly
            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out var readBody));
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal(body, readBody.ToArray());
        }

        [Fact]
        public void WritePacketStreaming_EmptyBody_WritesEmptyPacket()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = new MemoryStream();

            writer.WritePacketStreaming(PgpPacketTag.LiteralData, bodyStream);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out var readBody));
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Empty(readBody.ToArray());
        }

        [Fact]
        public void WritePacketStreaming_InvalidChunkSize_ThrowsArgumentException()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = new MemoryStream(TestHelpers.RandomBytes(100));

            Assert.Throws<ArgumentException>(() =>
                writer.WritePacketStreaming(PgpPacketTag.LiteralData, bodyStream, chunkSize: 100)); // Not power of 2
        }
    }

    /// <summary>
    /// Tests for PgpPacketBodyStream.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PacketBodyStreamTests
    {
        [Fact]
        public void BeginPacket_WritesPacketOnDispose()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            using (var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData))
            {
                bodyStream.Write([1, 2, 3, 4, 5]);
            }

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal([1, 2, 3, 4, 5], body.ToArray());
        }

        [Fact]
        public void BeginPacket_WritesPacketOnFinish()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var bodyStream = writer.BeginPacket(PgpPacketTag.Signature);
            bodyStream.Write([1, 2, 3]);
            bodyStream.Finish();

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out _));
            Assert.Equal(PgpPacketTag.Signature, tag);
        }

        [Fact]
        public void BeginPacket_WriteByte_Works()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            using (var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData))
            {
                bodyStream.WriteByte(0x42);
                bodyStream.WriteByte(0x43);
            }

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out _, out var body));
            Assert.Equal(new byte[] { 0x42, 0x43 }, body.ToArray());
        }

        [Fact]
        public void BeginPacket_WriteMpi_BigInteger_Works()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var value = new BigInteger(12345);

            using (var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData))
            {
                bodyStream.WriteMpi(value);
            }

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out _, out var body));

            var readValue = Mpi.Read(body.Span, out _);
            Assert.Equal(value, readValue);
        }

        [Fact]
        public void BeginPacket_WriteMpi_Bytes_Works()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var value = new byte[] { 0x01, 0xFF }; // 511 in big-endian

            using (var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData))
            {
                bodyStream.WriteMpi(value);
            }

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out _, out var body));

            var readValue = Mpi.Read(body.Span, out _);
            Assert.Equal(new BigInteger(511), readValue);
        }

        [Fact]
        public void BeginPacket_CanRead_IsFalse()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            Assert.False(bodyStream.CanRead);
        }

        [Fact]
        public void BeginPacket_CanWrite_IsTrue()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            Assert.True(bodyStream.CanWrite);
        }

        [Fact]
        public void BeginPacket_CanSeek_IsFalse()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            Assert.False(bodyStream.CanSeek);
        }

        [Fact]
        public void BeginPacket_Read_ThrowsNotSupportedException()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            Assert.Throws<NotSupportedException>(() => bodyStream.Read(new byte[10], 0, 10));
        }

        [Fact]
        public void BeginPacket_Seek_ThrowsNotSupportedException()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            Assert.Throws<NotSupportedException>(() => bodyStream.Seek(0, SeekOrigin.Begin));
        }

        [Fact]
        public void BeginPacket_SetPosition_ThrowsNotSupportedException()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            Assert.Throws<NotSupportedException>(() => bodyStream.Position = 0);
        }

        [Fact]
        public void BeginPacket_Length_ReturnsBufferLength()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            using var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);

            bodyStream.Write([1, 2, 3, 4, 5]);

            Assert.Equal(5, bodyStream.Length);
        }
    }

    /// <summary>
    /// Round-trip tests with various packet sizes.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RoundTripTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(100)]
        [InlineData(191)] // Max one-octet length
        [InlineData(192)] // Min two-octet length
        [InlineData(1000)]
        [InlineData(8383)] // Max two-octet length
        [InlineData(8384)] // Min five-octet length
        [InlineData(50000)]
        public void RoundTrip_VariousSizes_NewFormat(int bodySize)
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(bodySize);
            writer.WritePacket(PgpPacketTag.LiteralData, body);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            var result = reader.ReadNextPacket(out var tag, out var readBody);

            Assert.True(result);
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal(body, readBody.ToArray());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(100)]
        [InlineData(255)] // Max one-octet length (old format)
        [InlineData(256)] // Min two-octet length (old format)
        [InlineData(1000)]
        [InlineData(65535)] // Max two-octet length (old format)
        public void RoundTrip_VariousSizes_OldFormat(int bodySize)
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(bodySize);
            writer.WritePacket(PgpPacketTag.Signature, body, PgpPacketFormat.Old);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            var result = reader.ReadNextPacket(out var tag, out var readBody);

            Assert.True(result);
            Assert.Equal(PgpPacketTag.Signature, tag);
            Assert.Equal(body, readBody.ToArray());
        }
    }

    /// <summary>
    /// Tests for reading packets from a stream source.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class StreamSourceTests
    {
        [Fact]
        public void WritePacket_FromStream_Succeeds()
        {
            using var outputStream = new MemoryStream();
            using var writer = new PgpPacketWriter(outputStream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(1000);
            using var bodyStream = new MemoryStream(body);

            writer.WritePacket(PgpPacketTag.LiteralData, bodyStream, body.Length);

            outputStream.Position = 0;
            using var reader = new PgpPacketReader(outputStream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out var readBody));
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal(body, readBody.ToArray());
        }

        [Fact]
        public void WritePacket_FromStream_OldFormat_Succeeds()
        {
            using var outputStream = new MemoryStream();
            using var writer = new PgpPacketWriter(outputStream, leaveOpen: true);
            var body = TestHelpers.RandomBytes(1000);
            using var bodyStream = new MemoryStream(body);

            writer.WritePacket(PgpPacketTag.Signature, bodyStream, body.Length, PgpPacketFormat.Old);

            outputStream.Position = 0;
            using var reader = new PgpPacketReader(outputStream, leaveOpen: true);
            Assert.True(reader.ReadNextPacket(out var tag, out var readBody));
            Assert.Equal(PgpPacketTag.Signature, tag);
            Assert.Equal(body, readBody.ToArray());
        }

        [Fact]
        public void WritePacket_FromStream_StreamTooShort_ThrowsInvalidOperationException()
        {
            using var outputStream = new MemoryStream();
            using var writer = new PgpPacketWriter(outputStream, leaveOpen: true);
            using var bodyStream = new MemoryStream(new byte[50]);

            Assert.Throws<InvalidOperationException>(() =>
                writer.WritePacket(PgpPacketTag.LiteralData, bodyStream, 100)); // Claiming 100 bytes but only 50 available
        }
    }

    /// <summary>
    /// Tests for reading header without body.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ReadHeaderTests
    {
        [Fact]
        public void ReadNextHeader_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            writer.WritePacket(PgpPacketTag.LiteralData, TestHelpers.RandomBytes(100));

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);
            var result = reader.ReadNextHeader(out var header);

            Assert.True(result);
            Assert.Equal(PgpPacketTag.LiteralData, header.Tag);
            Assert.Equal(100, header.BodyLength);
        }

        [Fact]
        public void ReadNextHeader_EmptyStream_ReturnsFalse()
        {
            using var stream = new MemoryStream();
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            var result = reader.ReadNextHeader(out _);

            Assert.False(result);
        }
    }

    /// <summary>
    /// Disposed state tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DisposedStateTests
    {
        [Fact]
        public void Writer_WriteAfterDispose_ThrowsObjectDisposedException()
        {
            using var stream = new MemoryStream();
            var writer = new PgpPacketWriter(stream, leaveOpen: true);
            writer.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                writer.WritePacket(PgpPacketTag.LiteralData, [1]));
        }

        [Fact]
        public void Reader_ReadAfterDispose_ThrowsObjectDisposedException()
        {
            using var stream = new MemoryStream([0xCB, 1, 0x42]);
            var reader = new PgpPacketReader(stream, leaveOpen: true);
            reader.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                reader.ReadNextPacket(out _, out _));
        }

        [Fact]
        public void BodyStream_WriteAfterDispose_ThrowsObjectDisposedException()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            var bodyStream = writer.BeginPacket(PgpPacketTag.LiteralData);
            bodyStream.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                bodyStream.WriteByte(0x42));
        }

        [Fact]
        public void Writer_DoubleDispose_DoesNotThrow()
        {
            using var stream = new MemoryStream();
            var writer = new PgpPacketWriter(stream, leaveOpen: true);

            writer.Dispose();
            writer.Dispose(); // Should not throw
        }

        [Fact]
        public void Reader_DoubleDispose_DoesNotThrow()
        {
            using var stream = new MemoryStream();
            var reader = new PgpPacketReader(stream, leaveOpen: true);

            reader.Dispose();
            reader.Dispose(); // Should not throw
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
        public void Writer_NullStream_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new PgpPacketWriter(null!));
        }

        [Fact]
        public void Reader_NullStream_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new PgpPacketReader(null!));
        }

        [Fact]
        public void Reader_TruncatedHeader_ThrowsInvalidDataException()
        {
            // New format header that claims two-octet length but missing second byte
            using var stream = new MemoryStream([0xCB, 200]); // 200 means two-octet length
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.Throws<InvalidDataException>(() => reader.ReadNextPacket(out _, out _));
        }

        [Fact]
        public void Reader_TruncatedBody_ThrowsInvalidDataException()
        {
            // Header claims 100 bytes but only 10 available
            var data = new byte[12];
            data[0] = 0xCB; // New format, Literal Data
            data[1] = 100; // Claims 100 bytes
            // Only 10 bytes of body provided

            using var stream = new MemoryStream(data);
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.Throws<InvalidDataException>(() => reader.ReadNextPacket(out _, out _));
        }
    }

    /// <summary>
    /// Tests for max packet size validation (DoS protection).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class MaxPacketSizeTests
    {
        [Fact]
        public void DefaultMaxPacketSize_Is256MB()
        {
            Assert.Equal(256 * 1024 * 1024, PgpPacketReader.DefaultMaxPacketSize);
        }

        [Fact]
        public void Constructor_SetsDefaultMaxPacketSize()
        {
            using var stream = new MemoryStream();
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.Equal(PgpPacketReader.DefaultMaxPacketSize, reader.MaxPacketSize);
        }

        [Fact]
        public void Constructor_WithCustomMaxPacketSize_SetsValue()
        {
            using var stream = new MemoryStream();
            using var reader = new PgpPacketReader(stream, leaveOpen: true, maxPacketSize: 1000);

            Assert.Equal(1000, reader.MaxPacketSize);
        }

        [Fact]
        public void ReadNextPacket_ExceedsMaxSize_ThrowsInvalidDataException()
        {
            // Create a packet claiming 1000 bytes
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            writer.WritePacket(PgpPacketTag.LiteralData, new byte[1000]);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true, maxPacketSize: 500);

            var ex = Assert.Throws<InvalidDataException>(() => reader.ReadNextPacket(out _, out _));
            Assert.Contains("exceeds maximum", ex.Message);
        }

        [Fact]
        public void ReadNextPacket_WithinMaxSize_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            writer.WritePacket(PgpPacketTag.LiteralData, new byte[100]);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true, maxPacketSize: 500);

            var result = reader.ReadNextPacket(out var tag, out var body);

            Assert.True(result);
            Assert.Equal(PgpPacketTag.LiteralData, tag);
            Assert.Equal(100, body.Length);
        }

        [Fact]
        public void ReadNextPacket_MaxSizeDisabled_AllowsLargePackets()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);
            writer.WritePacket(PgpPacketTag.LiteralData, new byte[10000]);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true, maxPacketSize: 0);

            var result = reader.ReadNextPacket(out var tag, out var body);

            Assert.True(result);
            Assert.Equal(10000, body.Length);
        }

        [Fact]
        public void MaxPacketSize_CanBeChangedAfterConstruction()
        {
            using var stream = new MemoryStream();
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            reader.MaxPacketSize = 1024;

            Assert.Equal(1024, reader.MaxPacketSize);
        }
    }
}
