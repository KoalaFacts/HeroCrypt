using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP packet header parsing and writing per RFC 4880 Section 4.2.
/// </summary>
public class PgpPacketHeaderTests
{
    /// <summary>
    /// Tests for reading new format packet headers.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class NewFormatReadTests
    {
        [Fact]
        public void TryRead_OneOctetLength_Succeeds()
        {
            // New format, Literal Data tag (11), length 100
            var source = new byte[] { 0xCB, 100 };

            var result = PgpPacketHeader.TryRead(source, out var header, out var bytesConsumed);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.New, header.Format);
            Assert.Equal(PgpPacketTag.LiteralData, header.Tag);
            Assert.Equal(100, header.BodyLength);
            Assert.Equal(2, header.HeaderLength);
            Assert.Equal(2, bytesConsumed);
        }

        [Fact]
        public void TryRead_TwoOctetLength_Succeeds()
        {
            // New format, length 1000 (encoded as two bytes)
            // 1000 - 192 = 808 = 0x0328
            // First byte: (808 >> 8) + 192 = 3 + 192 = 195
            // Second byte: 808 & 0xFF = 0x28 = 40
            var source = new byte[] { 0xCB, 195, 40 };

            var result = PgpPacketHeader.TryRead(source, out var header, out var bytesConsumed);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.New, header.Format);
            Assert.Equal(1000, header.BodyLength);
            Assert.Equal(3, header.HeaderLength);
            Assert.Equal(3, bytesConsumed);
        }

        [Fact]
        public void TryRead_FiveOctetLength_Succeeds()
        {
            // New format, length 100000 (five-octet encoding)
            var source = new byte[] { 0xCB, 255, 0x00, 0x01, 0x86, 0xA0 }; // 100000 in big-endian

            var result = PgpPacketHeader.TryRead(source, out var header, out var bytesConsumed);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.New, header.Format);
            Assert.Equal(100000, header.BodyLength);
            Assert.Equal(6, header.HeaderLength);
            Assert.Equal(6, bytesConsumed);
        }

        [Fact]
        public void TryRead_PartialLength_Succeeds()
        {
            // New format, partial length (chunk size 2^10 = 1024)
            // Partial length byte: 224 + 10 = 234
            var source = new byte[] { 0xCB, 234 };

            var result = PgpPacketHeader.TryRead(source, out var header, out var bytesConsumed);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.New, header.Format);
            Assert.True(header.IsPartialLength);
            Assert.Equal(-1, header.BodyLength);
            Assert.Equal(1024, header.PartialBodyLength);
            Assert.Equal(2, bytesConsumed);
        }

        [Fact]
        public void TryRead_SourceTooShort_ReturnsFalse()
        {
            var source = new byte[] { 0xCB }; // Missing length byte

            var result = PgpPacketHeader.TryRead(source, out _, out _);

            Assert.False(result);
        }

        [Fact]
        public void TryRead_InvalidFirstByte_ReturnsFalse()
        {
            var source = new byte[] { 0x00 }; // Bit 7 not set

            var result = PgpPacketHeader.TryRead(source, out _, out _);

            Assert.False(result);
        }
    }

    /// <summary>
    /// Tests for reading old format packet headers.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class OldFormatReadTests
    {
        [Fact]
        public void TryRead_OneOctetLength_Succeeds()
        {
            // Old format, Literal Data tag (11), one-octet length 100
            // Header: 10TTTTLL = 10001100 = 0x8C (tag 11, length type 0)
            var source = new byte[] { 0xAC, 100 };

            var result = PgpPacketHeader.TryRead(source, out var header, out _);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.Old, header.Format);
            Assert.Equal(PgpPacketTag.LiteralData, header.Tag);
            Assert.Equal(100, header.BodyLength);
            Assert.Equal(2, header.HeaderLength);
        }

        [Fact]
        public void TryRead_TwoOctetLength_Succeeds()
        {
            // Old format, tag 2, two-octet length 1000
            // Header: 10001001 = 0x89 (tag 2, length type 1)
            var source = new byte[] { 0x89, 0x03, 0xE8 }; // 1000 in big-endian

            var result = PgpPacketHeader.TryRead(source, out var header, out _);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.Old, header.Format);
            Assert.Equal(PgpPacketTag.Signature, header.Tag);
            Assert.Equal(1000, header.BodyLength);
            Assert.Equal(3, header.HeaderLength);
        }

        [Fact]
        public void TryRead_FourOctetLength_Succeeds()
        {
            // Old format, tag 2, four-octet length 100000
            // Header: 10001010 = 0x8A (tag 2, length type 2)
            var source = new byte[] { 0x8A, 0x00, 0x01, 0x86, 0xA0 };

            var result = PgpPacketHeader.TryRead(source, out var header, out _);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.Old, header.Format);
            Assert.Equal(100000, header.BodyLength);
            Assert.Equal(5, header.HeaderLength);
        }

        [Fact]
        public void TryRead_IndeterminateLength_Succeeds()
        {
            // Old format, tag 2, indeterminate length
            // Header: 10001011 = 0x8B (tag 2, length type 3)
            var source = new byte[] { 0x8B };

            var result = PgpPacketHeader.TryRead(source, out var header, out _);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.Old, header.Format);
            Assert.True(header.IsPartialLength);
            Assert.Equal(-1, header.BodyLength);
            Assert.Equal(1, header.HeaderLength);
        }
    }

    /// <summary>
    /// Tests for writing new format packet headers.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class NewFormatWriteTests
    {
        [Fact]
        public void WriteNewFormat_OneOctetLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteNewFormat(PgpPacketTag.LiteralData, 100, destination);

            Assert.Equal(2, bytesWritten);
            Assert.Equal(0xCB, destination[0]); // 0xC0 | 11
            Assert.Equal(100, destination[1]);
        }

        [Fact]
        public void WriteNewFormat_TwoOctetLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteNewFormat(PgpPacketTag.LiteralData, 1000, destination);

            Assert.Equal(3, bytesWritten);
            Assert.Equal(0xCB, destination[0]);
            // 1000 - 192 = 808, first byte = (808 >> 8) + 192 = 195
            Assert.Equal(195, destination[1]);
            // Second byte = 808 & 0xFF = 40
            Assert.Equal(40, destination[2]);
        }

        [Fact]
        public void WriteNewFormat_FiveOctetLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteNewFormat(PgpPacketTag.LiteralData, 100000, destination);

            Assert.Equal(6, bytesWritten);
            Assert.Equal(0xCB, destination[0]);
            Assert.Equal(255, destination[1]);
            // 100000 = 0x000186A0
            Assert.Equal(0x00, destination[2]);
            Assert.Equal(0x01, destination[3]);
            Assert.Equal(0x86, destination[4]);
            Assert.Equal(0xA0, destination[5]);
        }

        [Fact]
        public void WriteNewFormat_DestinationTooSmall_ThrowsArgumentException()
        {
            var destination = new byte[1];

            Assert.Throws<ArgumentException>(() =>
                PgpPacketHeader.WriteNewFormat(PgpPacketTag.LiteralData, 100, destination));
        }

        [Fact]
        public void WriteNewFormat_NegativeLength_ThrowsArgumentOutOfRangeException()
        {
            var destination = new byte[10];

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpPacketHeader.WriteNewFormat(PgpPacketTag.LiteralData, -1, destination));
        }
    }

    /// <summary>
    /// Tests for writing old format packet headers.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class OldFormatWriteTests
    {
        [Fact]
        public void WriteOldFormat_OneOctetLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteOldFormat(PgpPacketTag.Signature, 100, destination);

            Assert.Equal(2, bytesWritten);
            // 0x80 | (tag << 2) | 0 = 0x80 | (2 << 2) | 0 = 0x88
            Assert.Equal(0x88, destination[0]);
            Assert.Equal(100, destination[1]);
        }

        [Fact]
        public void WriteOldFormat_TwoOctetLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteOldFormat(PgpPacketTag.Signature, 1000, destination);

            Assert.Equal(3, bytesWritten);
            // 0x80 | (tag << 2) | 1 = 0x80 | (2 << 2) | 1 = 0x89
            Assert.Equal(0x89, destination[0]);
            Assert.Equal(0x03, destination[1]); // 1000 >> 8
            Assert.Equal(0xE8, destination[2]); // 1000 & 0xFF
        }

        [Fact]
        public void WriteOldFormat_FourOctetLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteOldFormat(PgpPacketTag.Signature, 100000, destination);

            Assert.Equal(5, bytesWritten);
            // 0x80 | (tag << 2) | 2 = 0x80 | (2 << 2) | 2 = 0x8A
            Assert.Equal(0x8A, destination[0]);
        }

        [Fact]
        public void WriteOldFormat_IndeterminateLength_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteOldFormat(PgpPacketTag.Signature, -1, destination);

            Assert.Equal(1, bytesWritten);
            // 0x80 | (tag << 2) | 3 = 0x80 | (2 << 2) | 3 = 0x8B
            Assert.Equal(0x8B, destination[0]);
        }

        [Fact]
        public void WriteOldFormat_TagTooLarge_ReturnsFalse()
        {
            var destination = new byte[10];

            var result = PgpPacketHeader.TryWriteOldFormat(
                (PgpPacketTag)16, // Tags > 15 not supported in old format
                100,
                destination,
                out _);

            Assert.False(result);
        }
    }

    /// <summary>
    /// Tests for partial length header writing.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PartialLengthWriteTests
    {
        [Fact]
        public void WriteNewFormatPartial_FirstChunk_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteNewFormatPartial(
                PgpPacketTag.LiteralData,
                10, // 2^10 = 1024 byte chunks
                isFirst: true,
                destination);

            Assert.Equal(2, bytesWritten);
            Assert.Equal(0xCB, destination[0]); // Tag header
            Assert.Equal(234, destination[1]); // 224 + 10
        }

        [Fact]
        public void WriteNewFormatPartial_ContinuationChunk_Succeeds()
        {
            var destination = new byte[10];

            var bytesWritten = PgpPacketHeader.WriteNewFormatPartial(
                PgpPacketTag.LiteralData,
                10,
                isFirst: false,
                destination);

            Assert.Equal(1, bytesWritten);
            Assert.Equal(234, destination[0]); // Just the length byte
        }

        [Fact]
        public void WriteNewFormatPartial_InvalidChunkPower_ThrowsArgumentOutOfRangeException()
        {
            var destination = new byte[10];

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpPacketHeader.WriteNewFormatPartial(PgpPacketTag.LiteralData, 31, true, destination));
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
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(191)] // Max one-octet
        [InlineData(192)] // Min two-octet
        [InlineData(1000)]
        [InlineData(8383)] // Max two-octet
        [InlineData(8384)] // Min five-octet
        [InlineData(100000)]
        public void NewFormat_RoundTrip_PreservesData(int bodyLength)
        {
            var tag = PgpPacketTag.LiteralData;
            var buffer = new byte[10];
            var written = PgpPacketHeader.WriteNewFormat(tag, bodyLength, buffer);

            var result = PgpPacketHeader.TryRead(buffer.AsSpan(0, written), out var header, out var consumed);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.New, header.Format);
            Assert.Equal(tag, header.Tag);
            Assert.Equal(bodyLength, header.BodyLength);
            Assert.Equal(written, consumed);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(255)] // Max one-octet
        [InlineData(256)] // Min two-octet
        [InlineData(1000)]
        [InlineData(65535)] // Max two-octet
        [InlineData(65536)] // Min four-octet
        [InlineData(100000)]
        public void OldFormat_RoundTrip_PreservesData(long bodyLength)
        {
            var tag = PgpPacketTag.Signature; // Tag 2, valid for old format
            var buffer = new byte[10];
            var written = PgpPacketHeader.WriteOldFormat(tag, bodyLength, buffer);

            var result = PgpPacketHeader.TryRead(buffer.AsSpan(0, written), out var header, out var consumed);

            Assert.True(result);
            Assert.Equal(PgpPacketFormat.Old, header.Format);
            Assert.Equal(tag, header.Tag);
            Assert.Equal(bodyLength, header.BodyLength);
            Assert.Equal(written, consumed);
        }
    }

    /// <summary>
    /// Header size calculation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class HeaderSizeTests
    {
        [Theory]
        [InlineData(0, 2)]
        [InlineData(191, 2)]
        [InlineData(192, 3)]
        [InlineData(8383, 3)]
        [InlineData(8384, 6)]
        [InlineData(100000, 6)]
        public void GetNewFormatHeaderSize_ReturnsCorrectSize(long bodyLength, int expectedSize)
        {
            var size = PgpPacketHeader.GetNewFormatHeaderSize(bodyLength);

            Assert.Equal(expectedSize, size);
        }

        [Theory]
        [InlineData(-1, 1)] // Indeterminate
        [InlineData(0, 2)]
        [InlineData(255, 2)]
        [InlineData(256, 3)]
        [InlineData(65535, 3)]
        [InlineData(65536, 5)]
        [InlineData(100000, 5)]
        public void GetOldFormatHeaderSize_ReturnsCorrectSize(long bodyLength, int expectedSize)
        {
            var size = PgpPacketHeader.GetOldFormatHeaderSize(bodyLength);

            Assert.Equal(expectedSize, size);
        }
    }

    /// <summary>
    /// Tests for all packet tags.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PacketTagTests
    {
        [Theory]
        [InlineData(PgpPacketTag.PublicKeyEncryptedSessionKey)]
        [InlineData(PgpPacketTag.Signature)]
        [InlineData(PgpPacketTag.SymmetricKeyEncryptedSessionKey)]
        [InlineData(PgpPacketTag.OnePassSignature)]
        [InlineData(PgpPacketTag.SecretKey)]
        [InlineData(PgpPacketTag.PublicKey)]
        [InlineData(PgpPacketTag.SecretSubkey)]
        [InlineData(PgpPacketTag.CompressedData)]
        [InlineData(PgpPacketTag.SymmetricallyEncryptedData)]
        [InlineData(PgpPacketTag.Marker)]
        [InlineData(PgpPacketTag.LiteralData)]
        [InlineData(PgpPacketTag.Trust)]
        [InlineData(PgpPacketTag.UserId)]
        [InlineData(PgpPacketTag.PublicSubkey)]
        public void NewFormat_SupportsAllTags(PgpPacketTag tag)
        {
            var buffer = new byte[10];
            var written = PgpPacketHeader.WriteNewFormat(tag, 100, buffer);

            var result = PgpPacketHeader.TryRead(buffer.AsSpan(0, written), out var header, out _);

            Assert.True(result);
            Assert.Equal(tag, header.Tag);
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
        public void ToString_DefiniteLength_ShowsBodyLength()
        {
            var header = new PgpPacketHeader(PgpPacketFormat.New, PgpPacketTag.LiteralData, 100, 2);

            var str = header.ToString();

            Assert.Contains("New", str);
            Assert.Contains("LiteralData", str);
            Assert.Contains("100 bytes", str);
        }

        [Fact]
        public void ToString_PartialLength_ShowsPartialInfo()
        {
            var header = new PgpPacketHeader(PgpPacketFormat.New, PgpPacketTag.LiteralData, -1, 2, 1024);

            var str = header.ToString();

            Assert.Contains("Partial", str);
            Assert.Contains("1024", str);
        }
    }
}
