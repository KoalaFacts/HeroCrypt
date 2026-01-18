using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP User Attribute Packet per RFC 4880 Section 5.12.
/// </summary>
public class PgpUserAttributePacketTests
{
    // Minimal valid JPEG header for testing
    private static readonly byte[] MinimalJpegData =
    [
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9
    ];

    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void Constructor_WithData_StoresData()
        {
            var data = TestHelpers.RandomBytes(100);

            var packet = new PgpUserAttributePacket(data);

            Assert.Equal(data, packet.SubpacketData.ToArray());
        }

        [Fact]
        public void Constructor_WithEmptyData_AllowsEmpty()
        {
            var packet = new PgpUserAttributePacket(Array.Empty<byte>());

            Assert.Empty(packet.SubpacketData.ToArray());
        }
    }

    /// <summary>
    /// CreateWithImage factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CreateWithImageTests
    {
        [Fact]
        public void CreateWithImage_JpegData_CreatesValidPacket()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            Assert.True(packet.TryGetImageData(out var imageData, out var encoding));
            Assert.Equal(PgpImageEncoding.Jpeg, encoding);
            Assert.Equal(MinimalJpegData, imageData.ToArray());
        }

        [Fact]
        public void CreateWithImage_WithEncoding_SetsEncoding()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData, PgpImageEncoding.Jpeg);

            Assert.True(packet.TryGetImageData(out _, out var encoding));
            Assert.Equal(PgpImageEncoding.Jpeg, encoding);
        }

        [Fact]
        public void CreateWithImage_SmallImage_Works()
        {
            var smallImage = new byte[] { 0xFF, 0xD8, 0xFF, 0xD9 }; // Minimal JPEG

            var packet = PgpUserAttributePacket.CreateWithImage(smallImage);

            Assert.True(packet.TryGetImageData(out var imageData, out _));
            Assert.Equal(smallImage, imageData.ToArray());
        }

        [Fact]
        public void CreateWithImage_LargeImage_Works()
        {
            var largeImage = TestHelpers.RandomBytes(50000);

            var packet = PgpUserAttributePacket.CreateWithImage(largeImage);

            Assert.True(packet.TryGetImageData(out var imageData, out _));
            Assert.Equal(largeImage, imageData.ToArray());
        }
    }

    /// <summary>
    /// TryGetImageData tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class TryGetImageDataTests
    {
        [Fact]
        public void TryGetImageData_ValidImage_ReturnsTrue()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            var result = packet.TryGetImageData(out var imageData, out var encoding);

            Assert.True(result);
            Assert.Equal(MinimalJpegData, imageData.ToArray());
            Assert.Equal(PgpImageEncoding.Jpeg, encoding);
        }

        [Fact]
        public void TryGetImageData_EmptyPacket_ReturnsFalse()
        {
            var packet = new PgpUserAttributePacket(Array.Empty<byte>());

            var result = packet.TryGetImageData(out var imageData, out _);

            Assert.False(result);
            Assert.True(imageData.IsEmpty);
        }

        [Fact]
        public void TryGetImageData_InvalidSubpacket_ReturnsFalse()
        {
            // Too short to be a valid image subpacket
            var packet = new PgpUserAttributePacket(new byte[] { 0x05, 0x01, 0x00, 0x00 });

            var result = packet.TryGetImageData(out _, out _);

            Assert.False(result);
        }

        [Fact]
        public void GetImageData_ValidImage_ReturnsData()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            var imageData = packet.GetImageData();

            Assert.Equal(MinimalJpegData, imageData.ToArray());
        }

        [Fact]
        public void GetImageData_NoImage_ReturnsEmpty()
        {
            var packet = new PgpUserAttributePacket(Array.Empty<byte>());

            var imageData = packet.GetImageData();

            Assert.True(imageData.IsEmpty);
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
        public void Read_ValidData_ReturnsPacket()
        {
            var original = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var encoded = original.ToArray();

            var packet = PgpUserAttributePacket.Read(encoded);

            Assert.Equal(encoded, packet.SubpacketData.ToArray());
        }

        [Fact]
        public void Read_EmptySource_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpUserAttributePacket.Read([]));
        }

        [Fact]
        public void TryRead_ValidData_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(50);

            var result = PgpUserAttributePacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(data, packet.SubpacketData.ToArray());
        }

        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var result = PgpUserAttributePacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("empty", error);
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
        public void RoundTrip_ImagePacket_PreservesContent()
        {
            var original = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            var encoded = original.ToArray();
            var decoded = PgpUserAttributePacket.Read(encoded);

            Assert.True(decoded.TryGetImageData(out var imageData, out var encoding));
            Assert.Equal(MinimalJpegData, imageData.ToArray());
            Assert.Equal(PgpImageEncoding.Jpeg, encoding);
        }

        [Fact]
        public void RoundTrip_LargeImage_PreservesContent()
        {
            var largeImage = TestHelpers.RandomBytes(10000);
            var original = PgpUserAttributePacket.CreateWithImage(largeImage);

            var encoded = original.ToArray();
            var decoded = PgpUserAttributePacket.Read(encoded);

            Assert.True(decoded.TryGetImageData(out var imageData, out _));
            Assert.Equal(largeImage, imageData.ToArray());
        }
    }

    /// <summary>
    /// Write method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class WriteTests
    {
        [Fact]
        public void Write_SufficientBuffer_WritesCorrectly()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var buffer = new byte[packet.GetEncodedLength() + 10];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(packet.GetEncodedLength(), bytesWritten);
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var smallBuffer = new byte[5];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
        }

        [Fact]
        public void GetEncodedLength_ReturnsSubpacketDataLength()
        {
            var data = TestHelpers.RandomBytes(123);
            var packet = new PgpUserAttributePacket(data);

            Assert.Equal(123, packet.GetEncodedLength());
        }
    }

    /// <summary>
    /// TryWrite tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class TryWriteTests
    {
        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var buffer = new byte[packet.GetEncodedLength() + 10];

            var result = packet.TryWrite(buffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(packet.GetEncodedLength(), bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var smallBuffer = new byte[5];

            var result = packet.TryWrite(smallBuffer, out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
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

            var original = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.UserAttribute, tag);

            var decoded = PgpUserAttributePacket.Read(body.Span);
            Assert.True(decoded.TryGetImageData(out var imageData, out _));
            Assert.Equal(MinimalJpegData, imageData.ToArray());
        }

        [Fact]
        public void WriteTo_OldFormat_ThrowsForTag17()
        {
            // Tag 17 (User Attribute) is not valid for old format (only tags 0-15 supported)
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            Assert.Throws<ArgumentException>(() => original.WriteTo(writer, PgpPacketFormat.Old));
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
        public void Equals_SameData_ReturnsTrue()
        {
            var packet1 = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var packet2 = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentData_ReturnsFalse()
        {
            var packet1 = PgpUserAttributePacket.CreateWithImage([0xFF, 0xD8, 0x01, 0xFF, 0xD9]);
            var packet2 = PgpUserAttributePacket.CreateWithImage([0xFF, 0xD8, 0x02, 0xFF, 0xD9]);

            Assert.False(packet1.Equals(packet2));
            Assert.False(packet1 == packet2);
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SameData_ReturnsSameHash()
        {
            var packet1 = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);
            var packet2 = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }

        [Fact]
        public void GetHashCode_DifferentData_LikelyDifferentHash()
        {
            var packet1 = PgpUserAttributePacket.CreateWithImage([1, 2, 3]);
            var packet2 = PgpUserAttributePacket.CreateWithImage([4, 5, 6]);

            Assert.NotEqual(packet1.GetHashCode(), packet2.GetHashCode());
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
        public void ToString_WithImage_ShowsImageInfo()
        {
            var packet = PgpUserAttributePacket.CreateWithImage(MinimalJpegData);

            var str = packet.ToString();

            Assert.Contains("Image", str);
            Assert.Contains("Jpeg", str);
            Assert.Contains($"{MinimalJpegData.Length} bytes", str);
        }

        [Fact]
        public void ToString_NoImage_ShowsDataLength()
        {
            var packet = new PgpUserAttributePacket(TestHelpers.RandomBytes(50));

            var str = packet.ToString();

            Assert.Contains("50 bytes", str);
        }
    }

    /// <summary>
    /// Subpacket length encoding tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SubpacketLengthTests
    {
        [Theory]
        [InlineData(10)]    // Small image, 1-byte length
        [InlineData(191)]   // Max 1-byte length
        [InlineData(192)]   // Min 2-byte length
        [InlineData(1000)]  // Medium image, 2-byte length
        [InlineData(16000)] // Larger image, still 2-byte length
        public void CreateWithImage_VariousSizes_EncodesCorrectly(int imageSize)
        {
            var imageData = TestHelpers.RandomBytes(imageSize);
            var packet = PgpUserAttributePacket.CreateWithImage(imageData);

            Assert.True(packet.TryGetImageData(out var extracted, out _));
            Assert.Equal(imageData, extracted.ToArray());
        }
    }

    /// <summary>
    /// Image encoding enum tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ImageEncodingTests
    {
        [Fact]
        public void PgpImageEncoding_Jpeg_HasValue1()
        {
            Assert.Equal(1, (byte)PgpImageEncoding.Jpeg);
        }

        [Fact]
        public void PgpUserAttributeSubpacketType_Image_HasValue1()
        {
            Assert.Equal(1, (byte)PgpUserAttributeSubpacketType.Image);
        }
    }
}
