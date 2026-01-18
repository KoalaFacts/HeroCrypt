using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Marker Packet per RFC 4880 Section 5.8.
/// </summary>
public class PgpMarkerPacketTests
{
    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void DefaultConstructor_CreatesPgpMarker()
        {
            var packet = new PgpMarkerPacket();

            Assert.True(packet.IsValid);
            Assert.Equal(3, packet.Content.Length);
            Assert.Equal((byte)'P', packet.Content.Span[0]);
            Assert.Equal((byte)'G', packet.Content.Span[1]);
            Assert.Equal((byte)'P', packet.Content.Span[2]);
        }

        [Fact]
        public void DefaultConstructor_MatchesMarkerContent()
        {
            var packet = new PgpMarkerPacket();

            Assert.Equal(PgpMarkerPacket.MarkerContent, packet.Content.ToArray());
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
        public void Read_ValidPgp_ReturnsValidPacket()
        {
            byte[] data = [(byte)'P', (byte)'G', (byte)'P'];

            var packet = PgpMarkerPacket.Read(data);

            Assert.True(packet.IsValid);
            Assert.Equal(data, packet.Content.ToArray());
        }

        [Fact]
        public void Read_TooShort_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpMarkerPacket.Read([(byte)'P', (byte)'G']));
        }

        [Fact]
        public void Read_TooLong_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpMarkerPacket.Read([(byte)'P', (byte)'G', (byte)'P', (byte)'X']));
        }

        [Fact]
        public void Read_InvalidContent_ReturnsInvalidPacket()
        {
            byte[] data = [0x01, 0x02, 0x03];

            var packet = PgpMarkerPacket.Read(data);

            Assert.False(packet.IsValid);
            Assert.Equal(data, packet.Content.ToArray());
        }

        [Fact]
        public void TryRead_ValidData_ReturnsTrue()
        {
            byte[] data = [(byte)'P', (byte)'G', (byte)'P'];

            var result = PgpMarkerPacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.True(packet.IsValid);
        }

        [Fact]
        public void TryRead_TooShort_ReturnsFalse()
        {
            var result = PgpMarkerPacket.TryRead([(byte)'P'], out _, out var error);

            Assert.False(result);
            Assert.Contains("3", error);
        }

        [Fact]
        public void TryRead_Empty_ReturnsFalse()
        {
            var result = PgpMarkerPacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("3", error);
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
        public void RoundTrip_PreservesContent()
        {
            var original = new PgpMarkerPacket();

            var encoded = original.ToArray();
            var decoded = PgpMarkerPacket.Read(encoded);

            Assert.Equal(original.Content.ToArray(), decoded.Content.ToArray());
            Assert.True(decoded.IsValid);
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
        public void Write_SufficientBuffer_WritesCorrectly()
        {
            var packet = new PgpMarkerPacket();
            var buffer = new byte[10];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(3, bytesWritten);
            Assert.Equal((byte)'P', buffer[0]);
            Assert.Equal((byte)'G', buffer[1]);
            Assert.Equal((byte)'P', buffer[2]);
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpMarkerPacket();

            Assert.Throws<ArgumentException>(() => packet.Write(new byte[2]));
        }

        [Fact]
        public void GetEncodedLength_Returns3()
        {
            var packet = new PgpMarkerPacket();

            Assert.Equal(3, packet.GetEncodedLength());
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpMarkerPacket();

            var result = packet.TryWrite(new byte[10], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(3, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpMarkerPacket();

            var result = packet.TryWrite(new byte[2], out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }

        [Fact]
        public void TryWrite_ExactSpace_ReturnsTrue()
        {
            var packet = new PgpMarkerPacket();

            var result = packet.TryWrite(new byte[3], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(3, bytesWritten);
        }
    }

    /// <summary>
    /// Integration tests with PgpPacketWriter/Reader.
    /// </summary>
    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class IntegrationTests
    {
        [Fact]
        public void WriteTo_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpMarkerPacket();
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.Marker, tag);

            var decoded = PgpMarkerPacket.Read(body.Span);
            Assert.True(decoded.IsValid);
            Assert.Equal(original.Content.ToArray(), decoded.Content.ToArray());
        }

        [Fact]
        public void WriteTo_OldFormat_Succeeds()
        {
            // Tag 10 (Marker) is valid for old format (tags 0-15 supported)
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpMarkerPacket();
            original.WriteTo(writer, PgpPacketFormat.Old);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.Marker, tag);
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
        public void Equals_SameContent_ReturnsTrue()
        {
            var packet1 = new PgpMarkerPacket();
            var packet2 = new PgpMarkerPacket();

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var packet = new PgpMarkerPacket();

            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SameContent_SameHash()
        {
            var packet1 = new PgpMarkerPacket();
            var packet2 = new PgpMarkerPacket();

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
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
        public void ToString_ValidMarker_ShowsPgp()
        {
            var packet = new PgpMarkerPacket();

            var str = packet.ToString();

            Assert.Contains("Marker", str);
            Assert.Contains("PGP", str);
        }

        [Fact]
        public void ToString_InvalidMarker_ShowsInvalid()
        {
            byte[] data = [0x01, 0x02, 0x03];
            var packet = PgpMarkerPacket.Read(data);

            var str = packet.ToString();

            Assert.Contains("invalid", str);
        }
    }

    /// <summary>
    /// MarkerContent static field tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class MarkerContentTests
    {
        [Fact]
        public void MarkerContent_IsPgp()
        {
            Assert.Equal(3, PgpMarkerPacket.MarkerContent.Length);
            Assert.Equal((byte)'P', PgpMarkerPacket.MarkerContent[0]);
            Assert.Equal((byte)'G', PgpMarkerPacket.MarkerContent[1]);
            Assert.Equal((byte)'P', PgpMarkerPacket.MarkerContent[2]);
        }

        [Fact]
        public void MarkerLength_Is3()
        {
            Assert.Equal(3, PgpMarkerPacket.MarkerLength);
        }
    }
}
