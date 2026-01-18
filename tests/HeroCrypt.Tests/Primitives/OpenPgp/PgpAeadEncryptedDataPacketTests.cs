using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP AEAD Encrypted Data Packet per RFC 9580 Section 5.16.
/// </summary>
public class PgpAeadEncryptedDataPacketTests
{
    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void Constructor_WithValidParameters_StoresValues()
        {
            var encryptedData = TestHelpers.RandomBytes(100);

            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                encryptedData);

            Assert.Equal(1, packet.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, packet.CipherAlgorithm);
            Assert.Equal(AeadAlgorithm.Gcm, packet.AeadAlgorithm);
            Assert.Equal(6, packet.ChunkSize);
            Assert.Equal(encryptedData, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Constructor_WithNoneAeadAlgorithm_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                new PgpAeadEncryptedDataPacket(
                    SymmetricCipherAlgorithm.Aes256,
                    AeadAlgorithm.None,
                    6,
                    TestHelpers.RandomBytes(50)));
        }

        [Fact]
        public void Constructor_WithEmptyData_AllowsEmpty()
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes128,
                AeadAlgorithm.Ocb,
                6,
                Array.Empty<byte>());

            Assert.Empty(packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Constructor_WithLargeData_HandlesCorrectly()
        {
            var largeData = TestHelpers.RandomBytes(100000);

            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                largeData);

            Assert.Equal(largeData, packet.EncryptedData.ToArray());
        }
    }

    /// <summary>
    /// Chunk size calculation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ChunkSizeTests
    {
        [Theory]
        [InlineData(0, 64)]        // 1 << (0 + 6) = 64
        [InlineData(1, 128)]       // 1 << (1 + 6) = 128
        [InlineData(2, 256)]       // 1 << (2 + 6) = 256
        [InlineData(6, 4096)]      // 1 << (6 + 6) = 4096 (default)
        [InlineData(10, 65536)]    // 1 << (10 + 6) = 65536 (64 KiB)
        [InlineData(14, 1048576)]  // 1 << (14 + 6) = 1048576 (1 MiB)
        public void GetChunkSizeBytes_ReturnsCorrectValue(byte chunkSizeExponent, int expectedBytes)
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                chunkSizeExponent,
                Array.Empty<byte>());

            Assert.Equal(expectedBytes, packet.GetChunkSizeBytes());
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
            // version=1, cipher=AES256(9), aead=GCM(3), chunk=6
            byte[] header = [0x01, 0x09, 0x03, 0x06];
            var data = TestHelpers.RandomBytes(50);
            var source = header.Concat(data).ToArray();

            var packet = PgpAeadEncryptedDataPacket.Read(source);

            Assert.Equal(1, packet.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, packet.CipherAlgorithm);
            Assert.Equal(AeadAlgorithm.Gcm, packet.AeadAlgorithm);
            Assert.Equal(6, packet.ChunkSize);
            Assert.Equal(data, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Read_TooShort_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                PgpAeadEncryptedDataPacket.Read([0x01, 0x09, 0x03]));
        }

        [Fact]
        public void Read_InvalidVersion_ThrowsArgumentException()
        {
            byte[] source = [0x02, 0x09, 0x03, 0x06]; // version=2 (invalid)

            Assert.Throws<ArgumentException>(() =>
                PgpAeadEncryptedDataPacket.Read(source));
        }

        [Fact]
        public void Read_AeadNone_ThrowsArgumentException()
        {
            byte[] source = [0x01, 0x09, 0x00, 0x06]; // AEAD=None (invalid)

            Assert.Throws<ArgumentException>(() =>
                PgpAeadEncryptedDataPacket.Read(source));
        }

        [Fact]
        public void TryRead_ValidData_ReturnsTrue()
        {
            byte[] header = [0x01, 0x09, 0x03, 0x06];
            var data = TestHelpers.RandomBytes(50);
            var source = header.Concat(data).ToArray();

            var result = PgpAeadEncryptedDataPacket.TryRead(source, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(data, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void TryRead_TooShort_ReturnsFalse()
        {
            var result = PgpAeadEncryptedDataPacket.TryRead(
                [0x01, 0x09, 0x03],
                out _,
                out var error);

            Assert.False(result);
            Assert.Contains("too short", error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void TryRead_InvalidVersion_ReturnsFalse()
        {
            var result = PgpAeadEncryptedDataPacket.TryRead(
                [0x02, 0x09, 0x03, 0x06],
                out _,
                out var error);

            Assert.False(result);
            Assert.Contains("version", error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void TryRead_AeadNone_ReturnsFalse()
        {
            var result = PgpAeadEncryptedDataPacket.TryRead(
                [0x01, 0x09, 0x00, 0x06],
                out _,
                out var error);

            Assert.False(result);
            Assert.Contains("AEAD", error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void TryRead_HeaderOnly_ReturnsTrue()
        {
            // Just the header, no encrypted data
            var result = PgpAeadEncryptedDataPacket.TryRead(
                [0x01, 0x09, 0x03, 0x06],
                out var packet,
                out _);

            Assert.True(result);
            Assert.Empty(packet.EncryptedData.ToArray());
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
        public void RoundTrip_PreservesAllFields()
        {
            var original = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(200));

            var encoded = original.ToArray();
            var decoded = PgpAeadEncryptedDataPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.CipherAlgorithm, decoded.CipherAlgorithm);
            Assert.Equal(original.AeadAlgorithm, decoded.AeadAlgorithm);
            Assert.Equal(original.ChunkSize, decoded.ChunkSize);
            Assert.Equal(original.EncryptedData.ToArray(), decoded.EncryptedData.ToArray());
        }

        [Theory]
        [InlineData(SymmetricCipherAlgorithm.Aes128, AeadAlgorithm.Ocb, 0)]
        [InlineData(SymmetricCipherAlgorithm.Aes192, AeadAlgorithm.Gcm, 6)]
        [InlineData(SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Eax, 10)]
        public void RoundTrip_VariousConfigurations_Succeed(
            SymmetricCipherAlgorithm cipher,
            AeadAlgorithm aead,
            byte chunkSize)
        {
            var original = new PgpAeadEncryptedDataPacket(cipher, aead, chunkSize, TestHelpers.RandomBytes(100));

            var encoded = original.ToArray();
            var decoded = PgpAeadEncryptedDataPacket.Read(encoded);

            Assert.Equal(cipher, decoded.CipherAlgorithm);
            Assert.Equal(aead, decoded.AeadAlgorithm);
            Assert.Equal(chunkSize, decoded.ChunkSize);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(100)]
        [InlineData(10000)]
        public void RoundTrip_VariousDataSizes_Succeed(int size)
        {
            var data = size > 0 ? TestHelpers.RandomBytes(size) : Array.Empty<byte>();
            var original = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                data);

            var encoded = original.ToArray();
            var decoded = PgpAeadEncryptedDataPacket.Read(encoded);

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
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                data);

            var buffer = new byte[100];
            var bytesWritten = packet.Write(buffer);

            Assert.Equal(54, bytesWritten); // 4 header + 50 data

            // Verify header
            Assert.Equal(1, buffer[0]);  // version
            Assert.Equal(9, buffer[1]);  // AES256
            Assert.Equal(3, buffer[2]);  // GCM
            Assert.Equal(6, buffer[3]);  // chunk size
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(100));

            Assert.Throws<ArgumentException>(() => packet.Write(new byte[10]));
        }

        [Fact]
        public void GetEncodedLength_ReturnsCorrectLength()
        {
            var data = TestHelpers.RandomBytes(123);
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                data);

            Assert.Equal(127, packet.GetEncodedLength()); // 4 header + 123 data
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
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(50));

            var result = packet.TryWrite(new byte[100], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(54, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(100));

            var result = packet.TryWrite(new byte[10], out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }

        [Fact]
        public void TryWrite_ExactSpace_ReturnsTrue()
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(50));

            var result = packet.TryWrite(new byte[54], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(54, bytesWritten);
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

            var original = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(100));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.AeadEncryptedData, tag);

            var decoded = PgpAeadEncryptedDataPacket.Read(body.Span);
            Assert.Equal(original.CipherAlgorithm, decoded.CipherAlgorithm);
            Assert.Equal(original.AeadAlgorithm, decoded.AeadAlgorithm);
            Assert.Equal(original.EncryptedData.ToArray(), decoded.EncryptedData.ToArray());
        }

        [Fact]
        public void WriteTo_OldFormat_ThrowsForTag20()
        {
            // Tag 20 (AEAD Encrypted Data) is not valid for old format (only tags 0-15 supported)
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(50));

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
        public void Equals_SameValues_ReturnsTrue()
        {
            byte[] data = [1, 2, 3, 4, 5];
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentCipher_ReturnsFalse()
        {
            byte[] data = [1, 2, 3];
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes128, AeadAlgorithm.Gcm, 6, data);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_DifferentAead_ReturnsFalse()
        {
            byte[] data = [1, 2, 3];
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Ocb, 6, data);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_DifferentChunkSize_ReturnsFalse()
        {
            byte[] data = [1, 2, 3];
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 10, data);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_DifferentData_ReturnsFalse()
        {
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, [1, 2, 3]);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, [4, 5, 6]);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, [1, 2, 3]);

            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SameValues_ReturnsSameHash()
        {
            byte[] data = [1, 2, 3, 4, 5];
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, data);

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }

        [Fact]
        public void GetHashCode_DifferentValues_LikelyDifferentHash()
        {
            var packet1 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 6, [1, 2, 3]);
            var packet2 = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes128, AeadAlgorithm.Ocb, 10, [4, 5, 6]);

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
        public void ToString_IncludesAllInfo()
        {
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                TestHelpers.RandomBytes(123));

            var str = packet.ToString();

            Assert.Contains("AeadEncryptedData", str);
            Assert.Contains("v1", str);
            Assert.Contains("Aes256", str);
            Assert.Contains("Gcm", str);
            Assert.Contains("4096", str); // chunk size
            Assert.Contains("123 bytes", str);
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
        public void ToArray_ReturnsCorrectFormat()
        {
            byte[] data = [0xAA, 0xBB, 0xCC];
            var packet = new PgpAeadEncryptedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                6,
                data);

            var array = packet.ToArray();

            Assert.Equal(7, array.Length); // 4 header + 3 data
            Assert.Equal(1, array[0]);     // version
            Assert.Equal(9, array[1]);     // AES256
            Assert.Equal(3, array[2]);     // GCM
            Assert.Equal(6, array[3]);     // chunk size
            Assert.Equal(0xAA, array[4]);
            Assert.Equal(0xBB, array[5]);
            Assert.Equal(0xCC, array[6]);
        }
    }

    /// <summary>
    /// Algorithm enumeration tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmTests
    {
        [Theory]
        [InlineData(AeadAlgorithm.Eax, 1)]
        [InlineData(AeadAlgorithm.Ocb, 2)]
        [InlineData(AeadAlgorithm.Gcm, 3)]
        public void AeadAlgorithm_HasCorrectValues(AeadAlgorithm alg, byte expectedValue)
        {
            Assert.Equal(expectedValue, (byte)alg);
        }

        [Theory]
        [InlineData(SymmetricCipherAlgorithm.Aes128, 7)]
        [InlineData(SymmetricCipherAlgorithm.Aes192, 8)]
        [InlineData(SymmetricCipherAlgorithm.Aes256, 9)]
        public void SymmetricCipherAlgorithm_HasCorrectValues(SymmetricCipherAlgorithm alg, byte expectedValue)
        {
            Assert.Equal(expectedValue, (byte)alg);
        }
    }
}
