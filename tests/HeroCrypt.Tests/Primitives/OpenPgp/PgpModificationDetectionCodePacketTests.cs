using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Modification Detection Code (MDC) Packet per RFC 4880 Section 5.14.
/// </summary>
public class PgpModificationDetectionCodePacketTests
{
    // SHA-1 produces 20 bytes
    private static readonly byte[] ValidHash = TestHelpers.RandomBytes(20);

    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void Constructor_With20Bytes_Succeeds()
        {
            var hash = TestHelpers.RandomBytes(20);

            var packet = new PgpModificationDetectionCodePacket(hash);

            Assert.Equal(hash, packet.Hash.ToArray());
        }

        [Fact]
        public void Constructor_WithLessThan20Bytes_ThrowsArgumentException()
        {
            var shortHash = TestHelpers.RandomBytes(19);

            Assert.Throws<ArgumentException>(() => new PgpModificationDetectionCodePacket(shortHash));
        }

        [Fact]
        public void Constructor_WithMoreThan20Bytes_ThrowsArgumentException()
        {
            var longHash = TestHelpers.RandomBytes(21);

            Assert.Throws<ArgumentException>(() => new PgpModificationDetectionCodePacket(longHash));
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
        public void Read_Exactly20Bytes_ReturnsPacket()
        {
            var hash = TestHelpers.RandomBytes(20);

            var packet = PgpModificationDetectionCodePacket.Read(hash);

            Assert.Equal(hash, packet.Hash.ToArray());
        }

        [Fact]
        public void Read_LessThan20Bytes_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpModificationDetectionCodePacket.Read(new byte[19]));
        }

        [Fact]
        public void Read_MoreThan20Bytes_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpModificationDetectionCodePacket.Read(new byte[21]));
        }

        [Fact]
        public void TryRead_Valid_ReturnsTrue()
        {
            var hash = TestHelpers.RandomBytes(20);

            var result = PgpModificationDetectionCodePacket.TryRead(hash, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(hash, packet.Hash.ToArray());
        }

        [Fact]
        public void TryRead_TooShort_ReturnsFalse()
        {
            var result = PgpModificationDetectionCodePacket.TryRead(new byte[10], out _, out var error);

            Assert.False(result);
            Assert.Contains("20", error);
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
        public void RoundTrip_PreservesHash()
        {
            var original = new PgpModificationDetectionCodePacket(ValidHash);

            var encoded = original.ToArray();
            var decoded = PgpModificationDetectionCodePacket.Read(encoded);

            Assert.Equal(original.Hash.ToArray(), decoded.Hash.ToArray());
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
        public void Write_Writes20Bytes()
        {
            var packet = new PgpModificationDetectionCodePacket(ValidHash);
            var buffer = new byte[30];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(20, bytesWritten);
        }

        [Fact]
        public void Write_TooSmallBuffer_ThrowsArgumentException()
        {
            var packet = new PgpModificationDetectionCodePacket(ValidHash);

            Assert.Throws<ArgumentException>(() => packet.Write(new byte[19]));
        }

        [Fact]
        public void GetEncodedLength_Returns20()
        {
            var packet = new PgpModificationDetectionCodePacket(ValidHash);

            Assert.Equal(20, packet.GetEncodedLength());
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpModificationDetectionCodePacket(ValidHash);

            var result = packet.TryWrite(new byte[20], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(20, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpModificationDetectionCodePacket(ValidHash);

            var result = packet.TryWrite(new byte[19], out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }
    }

    /// <summary>
    /// Integration tests.
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

            var original = new PgpModificationDetectionCodePacket(ValidHash);
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.ModificationDetectionCode, tag);

            var decoded = PgpModificationDetectionCodePacket.Read(body.Span);
            Assert.Equal(original.Hash.ToArray(), decoded.Hash.ToArray());
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
        public void Equals_SameHash_ReturnsTrue()
        {
            var hash = TestHelpers.RandomBytes(20);
            var packet1 = new PgpModificationDetectionCodePacket(hash);
            var packet2 = new PgpModificationDetectionCodePacket(hash);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
        }

        [Fact]
        public void Equals_DifferentHash_ReturnsFalse()
        {
            var packet1 = new PgpModificationDetectionCodePacket(TestHelpers.RandomBytes(20));
            var packet2 = new PgpModificationDetectionCodePacket(TestHelpers.RandomBytes(20));

            Assert.False(packet1.Equals(packet2));
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void GetHashCode_SameHash_SameCode()
        {
            var hash = TestHelpers.RandomBytes(20);
            var packet1 = new PgpModificationDetectionCodePacket(hash);
            var packet2 = new PgpModificationDetectionCodePacket(hash);

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
        public void ToString_ContainsHexPrefix()
        {
            var hash = new byte[20];
            hash[0] = 0xAB;
            hash[1] = 0xCD;
            var packet = new PgpModificationDetectionCodePacket(hash);

            var str = packet.ToString();

            Assert.Contains("MDC", str);
            Assert.Contains("ABCD", str);
        }
    }
}
