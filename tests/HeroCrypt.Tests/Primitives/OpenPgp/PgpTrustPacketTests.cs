using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Trust Packet per RFC 4880 Section 5.10.
/// </summary>
public class PgpTrustPacketTests
{
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
            var data = TestHelpers.RandomBytes(10);

            var packet = new PgpTrustPacket(data);

            Assert.Equal(data, packet.TrustData.ToArray());
        }

        [Fact]
        public void Constructor_SingleByte_Works()
        {
            byte[] data = [0x60]; // Common GnuPG trust value

            var packet = new PgpTrustPacket(data);

            Assert.Equal(data, packet.TrustData.ToArray());
        }

        [Fact]
        public void Constructor_MultipleBytes_Works()
        {
            var data = TestHelpers.RandomBytes(50);

            var packet = new PgpTrustPacket(data);

            Assert.Equal(data, packet.TrustData.ToArray());
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
            var data = TestHelpers.RandomBytes(5);

            var packet = PgpTrustPacket.Read(data);

            Assert.Equal(data, packet.TrustData.ToArray());
        }

        [Fact]
        public void Read_SingleByte_Works()
        {
            byte[] data = [0x60];

            var packet = PgpTrustPacket.Read(data);

            Assert.Equal(data, packet.TrustData.ToArray());
        }

        [Fact]
        public void Read_EmptyData_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpTrustPacket.Read([]));
        }

        [Fact]
        public void TryRead_ValidData_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(5);

            var result = PgpTrustPacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(data, packet.TrustData.ToArray());
        }

        [Fact]
        public void TryRead_EmptyData_ReturnsFalse()
        {
            var result = PgpTrustPacket.TryRead([], out _, out var error);

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
        public void RoundTrip_PreservesData()
        {
            var data = TestHelpers.RandomBytes(10);
            var original = new PgpTrustPacket(data);

            var encoded = original.ToArray();
            var decoded = PgpTrustPacket.Read(encoded);

            Assert.Equal(original.TrustData.ToArray(), decoded.TrustData.ToArray());
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(100)]
        public void RoundTrip_VariousSizes_PreservesData(int size)
        {
            var data = TestHelpers.RandomBytes(size);
            var original = new PgpTrustPacket(data);

            var encoded = original.ToArray();
            var decoded = PgpTrustPacket.Read(encoded);

            Assert.Equal(data, decoded.TrustData.ToArray());
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
            var data = TestHelpers.RandomBytes(10);
            var packet = new PgpTrustPacket(data);
            var buffer = new byte[20];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(10, bytesWritten);
            Assert.Equal(data, buffer.AsSpan(0, 10).ToArray());
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpTrustPacket(TestHelpers.RandomBytes(20));

            Assert.Throws<ArgumentException>(() => packet.Write(new byte[10]));
        }

        [Fact]
        public void GetEncodedLength_ReturnsTrustDataLength()
        {
            var data = TestHelpers.RandomBytes(15);
            var packet = new PgpTrustPacket(data);

            Assert.Equal(15, packet.GetEncodedLength());
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpTrustPacket(TestHelpers.RandomBytes(10));

            var result = packet.TryWrite(new byte[20], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(10, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpTrustPacket(TestHelpers.RandomBytes(20));

            var result = packet.TryWrite(new byte[10], out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }

        [Fact]
        public void TryWrite_ExactSpace_ReturnsTrue()
        {
            var packet = new PgpTrustPacket(TestHelpers.RandomBytes(10));

            var result = packet.TryWrite(new byte[10], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(10, bytesWritten);
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

            var original = new PgpTrustPacket(TestHelpers.RandomBytes(10));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.Trust, tag);

            var decoded = PgpTrustPacket.Read(body.Span);
            Assert.Equal(original.TrustData.ToArray(), decoded.TrustData.ToArray());
        }

        [Fact]
        public void WriteTo_OldFormat_Succeeds()
        {
            // Tag 12 (Trust) is valid for old format (tags 0-15 supported)
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpTrustPacket((byte[])[0x60]);
            original.WriteTo(writer, PgpPacketFormat.Old);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.Trust, tag);
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
            byte[] data = [0x60, 0x01, 0x02];
            var packet1 = new PgpTrustPacket(data);
            var packet2 = new PgpTrustPacket(data);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentData_ReturnsFalse()
        {
            var packet1 = new PgpTrustPacket((byte[])[0x60, 0x01]);
            var packet2 = new PgpTrustPacket((byte[])[0x60, 0x02]);

            Assert.False(packet1.Equals(packet2));
            Assert.False(packet1 == packet2);
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var packet = new PgpTrustPacket((byte[])[0x60]);

            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SameData_SameHash()
        {
            byte[] data = [0x60, 0x01, 0x02];
            var packet1 = new PgpTrustPacket(data);
            var packet2 = new PgpTrustPacket(data);

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }

        [Fact]
        public void GetHashCode_DifferentData_LikelyDifferentHash()
        {
            var packet1 = new PgpTrustPacket((byte[])[0x60, 0x01]);
            var packet2 = new PgpTrustPacket((byte[])[0x60, 0x02]);

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
        public void ToString_ContainsLength()
        {
            var packet = new PgpTrustPacket(TestHelpers.RandomBytes(15));

            var str = packet.ToString();

            Assert.Contains("Trust", str);
            Assert.Contains("15 bytes", str);
        }
    }

    /// <summary>
    /// Common trust value tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CommonTrustValueTests
    {
        [Theory]
        [InlineData(0x00)] // Unknown trust
        [InlineData(0x01)] // Expired
        [InlineData(0x02)] // Undefined
        [InlineData(0x03)] // Never trust
        [InlineData(0x04)] // Marginal
        [InlineData(0x05)] // Full
        [InlineData(0x06)] // Ultimate
        [InlineData(0x60)] // Common GnuPG format
        public void Constructor_CommonTrustValues_Accepted(byte trustValue)
        {
            byte[] data = [trustValue];

            var packet = new PgpTrustPacket(data);

            Assert.Equal(trustValue, packet.TrustData.Span[0]);
        }
    }
}
