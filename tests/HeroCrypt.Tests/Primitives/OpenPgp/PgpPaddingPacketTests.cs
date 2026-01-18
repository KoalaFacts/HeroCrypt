using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Padding Packet per RFC 9580.
/// </summary>
public class PgpPaddingPacketTests
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
            var data = TestHelpers.RandomBytes(100);

            var packet = new PgpPaddingPacket(data);

            Assert.Equal(data, packet.Data.ToArray());
        }

        [Fact]
        public void Constructor_WithEmptyData_AllowsEmpty()
        {
            var packet = new PgpPaddingPacket(Array.Empty<byte>());

            Assert.Empty(packet.Data.ToArray());
        }

        [Fact]
        public void Constructor_WithLargeData_Works()
        {
            var largeData = TestHelpers.RandomBytes(100000);

            var packet = new PgpPaddingPacket(largeData);

            Assert.Equal(largeData, packet.Data.ToArray());
        }
    }

    /// <summary>
    /// CreateRandom factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CreateRandomTests
    {
        [Fact]
        public void CreateRandom_WithLength_CreatesPacketOfCorrectSize()
        {
            var packet = PgpPaddingPacket.CreateRandom(50);

            Assert.Equal(50, packet.Data.Length);
        }

        [Fact]
        public void CreateRandom_WithZeroLength_CreatesEmptyPacket()
        {
            var packet = PgpPaddingPacket.CreateRandom(0);

            Assert.Empty(packet.Data.ToArray());
        }

        [Fact]
        public void CreateRandom_NegativeLength_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => PgpPaddingPacket.CreateRandom(-1));
        }

        [Fact]
        public void CreateRandom_TwoCallsProduceDifferentData()
        {
            var packet1 = PgpPaddingPacket.CreateRandom(32);
            var packet2 = PgpPaddingPacket.CreateRandom(32);

            // Very unlikely to be equal if truly random
            Assert.NotEqual(packet1.Data.ToArray(), packet2.Data.ToArray());
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
            var data = TestHelpers.RandomBytes(50);

            var packet = PgpPaddingPacket.Read(data);

            Assert.Equal(data, packet.Data.ToArray());
        }

        [Fact]
        public void Read_EmptyData_ReturnsEmptyPacket()
        {
            var packet = PgpPaddingPacket.Read([]);

            Assert.Empty(packet.Data.ToArray());
        }

        [Fact]
        public void TryRead_ValidData_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(50);

            var result = PgpPaddingPacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(data, packet.Data.ToArray());
        }

        [Fact]
        public void TryRead_EmptyData_ReturnsTrue()
        {
            var result = PgpPaddingPacket.TryRead([], out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Empty(packet.Data.ToArray());
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
            var original = PgpPaddingPacket.CreateRandom(100);

            var encoded = original.ToArray();
            var decoded = PgpPaddingPacket.Read(encoded);

            Assert.Equal(original.Data.ToArray(), decoded.Data.ToArray());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(100)]
        [InlineData(1000)]
        public void RoundTrip_VariousSizes_PreservesData(int size)
        {
            byte[] data = size > 0 ? TestHelpers.RandomBytes(size) : [];
            var original = new PgpPaddingPacket(data);

            var encoded = original.ToArray();
            var decoded = PgpPaddingPacket.Read(encoded);

            Assert.Equal(data, decoded.Data.ToArray());
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
            var data = TestHelpers.RandomBytes(50);
            var packet = new PgpPaddingPacket(data);
            var buffer = new byte[100];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(50, bytesWritten);
            Assert.Equal(data, buffer.AsSpan(0, 50).ToArray());
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpPaddingPacket(TestHelpers.RandomBytes(100));

            Assert.Throws<ArgumentException>(() => packet.Write(new byte[50]));
        }

        [Fact]
        public void GetEncodedLength_ReturnsDataLength()
        {
            var data = TestHelpers.RandomBytes(123);
            var packet = new PgpPaddingPacket(data);

            Assert.Equal(123, packet.GetEncodedLength());
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpPaddingPacket(TestHelpers.RandomBytes(50));

            var result = packet.TryWrite(new byte[100], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(50, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpPaddingPacket(TestHelpers.RandomBytes(100));

            var result = packet.TryWrite(new byte[50], out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
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

            var original = PgpPaddingPacket.CreateRandom(100);
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.Padding, tag);

            var decoded = PgpPaddingPacket.Read(body.Span);
            Assert.Equal(original.Data.ToArray(), decoded.Data.ToArray());
        }

        [Fact]
        public void WriteTo_OldFormat_ThrowsForTag21()
        {
            // Tag 21 (Padding) is not valid for old format (only tags 0-15 supported)
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpPaddingPacket.CreateRandom(50);

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
            byte[] data = [1, 2, 3, 4, 5];
            var packet1 = new PgpPaddingPacket(data);
            var packet2 = new PgpPaddingPacket(data);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentData_ReturnsFalse()
        {
            var packet1 = new PgpPaddingPacket((byte[])[1, 2, 3]);
            var packet2 = new PgpPaddingPacket((byte[])[4, 5, 6]);

            Assert.False(packet1.Equals(packet2));
            Assert.False(packet1 == packet2);
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var packet = new PgpPaddingPacket((byte[])[1, 2, 3]);

            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SameData_SameHash()
        {
            byte[] data = [1, 2, 3, 4, 5];
            var packet1 = new PgpPaddingPacket(data);
            var packet2 = new PgpPaddingPacket(data);

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }

        [Fact]
        public void GetHashCode_DifferentData_LikelyDifferentHash()
        {
            var packet1 = new PgpPaddingPacket((byte[])[1, 2, 3]);
            var packet2 = new PgpPaddingPacket((byte[])[4, 5, 6]);

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
            var packet = new PgpPaddingPacket(TestHelpers.RandomBytes(123));

            var str = packet.ToString();

            Assert.Contains("Padding", str);
            Assert.Contains("123 bytes", str);
        }
    }
}
