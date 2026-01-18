using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Symmetrically Encrypted Data Packet per RFC 4880 Section 5.7.
/// </summary>
public class PgpSymmetricallyEncryptedDataPacketTests
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
            var encryptedData = TestHelpers.RandomBytes(100);

            var packet = new PgpSymmetricallyEncryptedDataPacket(encryptedData);

            Assert.Equal(encryptedData, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Constructor_WithEmptyData_AllowsEmpty()
        {
            var packet = new PgpSymmetricallyEncryptedDataPacket(Array.Empty<byte>());

            Assert.Empty(packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Constructor_WithLargeData_HandlesCorrectly()
        {
            var largeData = TestHelpers.RandomBytes(100000);

            var packet = new PgpSymmetricallyEncryptedDataPacket(largeData);

            Assert.Equal(largeData, packet.EncryptedData.ToArray());
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

            var packet = PgpSymmetricallyEncryptedDataPacket.Read(data);

            Assert.Equal(data, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Read_EmptySource_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpSymmetricallyEncryptedDataPacket.Read([]));
        }

        [Fact]
        public void TryRead_ValidData_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(50);

            var result = PgpSymmetricallyEncryptedDataPacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(data, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var result = PgpSymmetricallyEncryptedDataPacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("empty", error);
        }

        [Fact]
        public void TryRead_SingleByte_Succeeds()
        {
            var data = new byte[] { 0xFF };

            var result = PgpSymmetricallyEncryptedDataPacket.TryRead(data, out var packet, out _);

            Assert.True(result);
            Assert.Equal(data, packet.EncryptedData.ToArray());
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
            var data = TestHelpers.RandomBytes(200);
            var original = new PgpSymmetricallyEncryptedDataPacket(data);

            var encoded = original.ToArray();
            var decoded = PgpSymmetricallyEncryptedDataPacket.Read(encoded);

            Assert.Equal(original.EncryptedData.ToArray(), decoded.EncryptedData.ToArray());
        }

        [Fact]
        public void RoundTrip_LargeData_PreservesContent()
        {
            var largeData = TestHelpers.RandomBytes(50000);
            var original = new PgpSymmetricallyEncryptedDataPacket(largeData);

            var encoded = original.ToArray();
            var decoded = PgpSymmetricallyEncryptedDataPacket.Read(encoded);

            Assert.Equal(largeData, decoded.EncryptedData.ToArray());
        }

        [Theory]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(256)]
        [InlineData(1024)]
        public void RoundTrip_VariousSizes_Succeed(int size)
        {
            var data = TestHelpers.RandomBytes(size);
            var original = new PgpSymmetricallyEncryptedDataPacket(data);

            var encoded = original.ToArray();
            var decoded = PgpSymmetricallyEncryptedDataPacket.Read(encoded);

            Assert.Equal(data, decoded.EncryptedData.ToArray());
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
            var data = TestHelpers.RandomBytes(50);
            var packet = new PgpSymmetricallyEncryptedDataPacket(data);
            var buffer = new byte[100];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(50, bytesWritten);
            Assert.Equal(data, buffer.AsSpan(0, bytesWritten).ToArray());
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(100));
            var smallBuffer = new byte[10];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
        }

        [Fact]
        public void GetEncodedLength_ReturnsCorrectLength()
        {
            var data = TestHelpers.RandomBytes(123);
            var packet = new PgpSymmetricallyEncryptedDataPacket(data);

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
            var packet = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(50));
            var buffer = new byte[100];

            var result = packet.TryWrite(buffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(50, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(100));
            var smallBuffer = new byte[10];

            var result = packet.TryWrite(smallBuffer, out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }

        [Fact]
        public void TryWrite_ExactSpace_ReturnsTrue()
        {
            var packet = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(50));
            var exactBuffer = new byte[50];

            var result = packet.TryWrite(exactBuffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(50, bytesWritten);
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

            var original = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(100));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.SymmetricallyEncryptedData, tag);

            var decoded = PgpSymmetricallyEncryptedDataPacket.Read(body.Span);
            Assert.Equal(original.EncryptedData.ToArray(), decoded.EncryptedData.ToArray());
        }

        [Fact]
        public void WriteTo_OldFormat_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(50));
            original.WriteTo(writer, PgpPacketFormat.Old);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) == 0); // Old format
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
            var data = new byte[] { 1, 2, 3, 4, 5 };
            var packet1 = new PgpSymmetricallyEncryptedDataPacket(data);
            var packet2 = new PgpSymmetricallyEncryptedDataPacket(data);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentData_ReturnsFalse()
        {
            var packet1 = new PgpSymmetricallyEncryptedDataPacket(new byte[] { 1, 2, 3 });
            var packet2 = new PgpSymmetricallyEncryptedDataPacket(new byte[] { 1, 2, 4 });

            Assert.False(packet1.Equals(packet2));
            Assert.False(packet1 == packet2);
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentLength_ReturnsFalse()
        {
            var packet1 = new PgpSymmetricallyEncryptedDataPacket(new byte[] { 1, 2, 3 });
            var packet2 = new PgpSymmetricallyEncryptedDataPacket(new byte[] { 1, 2 });

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var data = new byte[] { 1, 2, 3 };
            var packet1 = new PgpSymmetricallyEncryptedDataPacket(data);
            var packet2 = new PgpSymmetricallyEncryptedDataPacket(data);

            Assert.True(packet1.Equals((object)packet2));
            Assert.False(packet1.Equals(null));
            Assert.False(packet1.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SameData_ReturnsSameHash()
        {
            var data = new byte[] { 1, 2, 3, 4, 5 };
            var packet1 = new PgpSymmetricallyEncryptedDataPacket(data);
            var packet2 = new PgpSymmetricallyEncryptedDataPacket(data);

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }

        [Fact]
        public void GetHashCode_DifferentData_LikelyDifferentHash()
        {
            var packet1 = new PgpSymmetricallyEncryptedDataPacket(new byte[] { 1, 2, 3 });
            var packet2 = new PgpSymmetricallyEncryptedDataPacket(new byte[] { 4, 5, 6 });

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
        public void ToString_IncludesDataLength()
        {
            var packet = new PgpSymmetricallyEncryptedDataPacket(TestHelpers.RandomBytes(123));

            var str = packet.ToString();

            Assert.Contains("SymmetricallyEncryptedData", str);
            Assert.Contains("123 bytes", str);
        }

        [Fact]
        public void ToString_EmptyData_ShowsZeroBytes()
        {
            var packet = new PgpSymmetricallyEncryptedDataPacket(Array.Empty<byte>());

            var str = packet.ToString();

            Assert.Contains("0 bytes", str);
        }
    }

    /// <summary>
    /// ToArray tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ToArrayTests
    {
        [Fact]
        public void ToArray_ReturnsCopy()
        {
            var data = TestHelpers.RandomBytes(50);
            var packet = new PgpSymmetricallyEncryptedDataPacket(data);

            var array = packet.ToArray();

            Assert.Equal(data, array);
            Assert.NotSame(data, array); // Should be a copy
        }
    }
}
