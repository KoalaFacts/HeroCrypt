using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Symmetrically Encrypted Integrity Protected Data Packet
/// per RFC 4880 Section 5.13 and RFC 9580.
/// </summary>
public class PgpSymEncryptedIntegrityProtectedDataPacketTests
{
    private static readonly byte[] TestSalt = TestHelpers.SequentialBytes(32);

    /// <summary>
    /// Version 1 constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class V1ConstructorTests
    {
        [Fact]
        public void Constructor_V1_SetsVersionTo1()
        {
            var encryptedData = TestHelpers.RandomBytes(100);

            var packet = new PgpSymEncryptedIntegrityProtectedDataPacket(encryptedData);

            Assert.Equal(PgpSymEncryptedIntegrityProtectedDataPacket.VersionCfbMdc, packet.Version);
        }

        [Fact]
        public void Constructor_V1_StoresEncryptedData()
        {
            var encryptedData = TestHelpers.RandomBytes(100);

            var packet = new PgpSymEncryptedIntegrityProtectedDataPacket(encryptedData);

            Assert.Equal(encryptedData, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Constructor_V1_SetsDefaultsForV2Fields()
        {
            var packet = new PgpSymEncryptedIntegrityProtectedDataPacket(TestHelpers.RandomBytes(50));

            Assert.Equal(SymmetricCipherAlgorithm.Plaintext, packet.CipherAlgorithm);
            Assert.Equal(AeadAlgorithm.None, packet.AeadAlgorithm);
            Assert.Equal(0, packet.ChunkSize);
            Assert.Empty(packet.Salt.ToArray());
        }

        [Fact]
        public void CreateV1_CreatesVersionOnePacket()
        {
            var encryptedData = TestHelpers.RandomBytes(75);

            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(encryptedData);

            Assert.Equal(1, packet.Version);
            Assert.Equal(encryptedData, packet.EncryptedData.ToArray());
        }
    }

    /// <summary>
    /// Version 2 constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class V2ConstructorTests
    {
        [Fact]
        public void Constructor_V2_SetsVersionTo2()
        {
            var packet = new PgpSymEncryptedIntegrityProtectedDataPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                TestHelpers.RandomBytes(100));

            Assert.Equal(PgpSymEncryptedIntegrityProtectedDataPacket.VersionAead, packet.Version);
        }

        [Fact]
        public void Constructor_V2_StoresAllParameters()
        {
            var encryptedData = TestHelpers.RandomBytes(100);

            var packet = new PgpSymEncryptedIntegrityProtectedDataPacket(
                SymmetricCipherAlgorithm.Aes128,
                AeadAlgorithm.Ocb,
                8,
                TestSalt,
                encryptedData);

            Assert.Equal(SymmetricCipherAlgorithm.Aes128, packet.CipherAlgorithm);
            Assert.Equal(AeadAlgorithm.Ocb, packet.AeadAlgorithm);
            Assert.Equal(8, packet.ChunkSize);
            Assert.Equal(TestSalt, packet.Salt.ToArray());
            Assert.Equal(encryptedData, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Constructor_V2_InvalidSaltLength_ThrowsArgumentException()
        {
            var shortSalt = new byte[16]; // Should be 32

            Assert.Throws<ArgumentException>(() =>
                new PgpSymEncryptedIntegrityProtectedDataPacket(
                    SymmetricCipherAlgorithm.Aes256,
                    AeadAlgorithm.Gcm,
                    10,
                    shortSalt,
                    TestHelpers.RandomBytes(50)));
        }

        [Fact]
        public void CreateV2_CreatesVersionTwoPacket()
        {
            var encryptedData = TestHelpers.RandomBytes(75);

            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                encryptedData);

            Assert.Equal(2, packet.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, packet.CipherAlgorithm);
            Assert.Equal(AeadAlgorithm.Gcm, packet.AeadAlgorithm);
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
        [InlineData(0, 64)]        // 2^(0+6) = 64
        [InlineData(1, 128)]       // 2^(1+6) = 128
        [InlineData(6, 4096)]      // 2^(6+6) = 4096
        [InlineData(10, 65536)]    // 2^(10+6) = 65536
        public void GetChunkSizeBytes_V2_CalculatesCorrectly(byte chunkSizeExp, int expectedBytes)
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                chunkSizeExp,
                TestSalt,
                TestHelpers.RandomBytes(10));

            Assert.Equal(expectedBytes, packet.GetChunkSizeBytes());
        }

        [Fact]
        public void GetChunkSizeBytes_V1_ReturnsZero()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(TestHelpers.RandomBytes(50));

            Assert.Equal(0, packet.GetChunkSizeBytes());
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
        public void Read_V1_ParsesCorrectly()
        {
            // Version 1: version byte + encrypted data
            var data = new byte[] { 0x01, 0xAA, 0xBB, 0xCC };

            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.Read(data);

            Assert.Equal(1, packet.Version);
            Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, packet.EncryptedData.ToArray());
        }

        [Fact]
        public void Read_V2_ParsesCorrectly()
        {
            // Version 2: version(1) + cipher(1) + aead(1) + chunk(1) + salt(32) + data
            var data = new byte[36 + 10];
            data[0] = 0x02; // Version
            data[1] = (byte)SymmetricCipherAlgorithm.Aes256; // Cipher
            data[2] = (byte)AeadAlgorithm.Gcm; // AEAD
            data[3] = 10; // Chunk size
            TestSalt.CopyTo(data.AsSpan(4));
            for (int i = 0; i < 10; i++) data[36 + i] = (byte)(0xF0 + i);

            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.Read(data);

            Assert.Equal(2, packet.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, packet.CipherAlgorithm);
            Assert.Equal(AeadAlgorithm.Gcm, packet.AeadAlgorithm);
            Assert.Equal(10, packet.ChunkSize);
            Assert.Equal(TestSalt, packet.Salt.ToArray());
            Assert.Equal(10, packet.EncryptedData.Length);
        }

        [Fact]
        public void Read_TooShort_ThrowsArgumentException()
        {
            var data = new byte[] { 0x01 }; // Only version, no data

            Assert.Throws<ArgumentException>(() => PgpSymEncryptedIntegrityProtectedDataPacket.Read(data));
        }

        [Fact]
        public void Read_UnsupportedVersion_ThrowsArgumentException()
        {
            var data = new byte[] { 0x03, 0xAA, 0xBB }; // Version 3 doesn't exist

            Assert.Throws<ArgumentException>(() => PgpSymEncryptedIntegrityProtectedDataPacket.Read(data));
        }

        [Fact]
        public void TryRead_V1_ReturnsTrue()
        {
            var data = new byte[] { 0x01, 0xAA, 0xBB };

            var result = PgpSymEncryptedIntegrityProtectedDataPacket.TryRead(data, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(1, packet.Version);
        }

        [Fact]
        public void TryRead_V2TooShort_ReturnsFalse()
        {
            // Version 2 but not enough bytes for header
            var data = new byte[] { 0x02, 0x09, 0x03 }; // Missing chunk size and salt

            var result = PgpSymEncryptedIntegrityProtectedDataPacket.TryRead(data, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var result = PgpSymEncryptedIntegrityProtectedDataPacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
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
        public void RoundTrip_V1_PreservesData()
        {
            var encryptedData = TestHelpers.RandomBytes(200);
            var original = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(encryptedData);

            var encoded = original.ToArray();
            var decoded = PgpSymEncryptedIntegrityProtectedDataPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.EncryptedData.ToArray(), decoded.EncryptedData.ToArray());
        }

        [Fact]
        public void RoundTrip_V2_PreservesAllFields()
        {
            var encryptedData = TestHelpers.RandomBytes(150);
            var original = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Ocb,
                8,
                TestSalt,
                encryptedData);

            var encoded = original.ToArray();
            var decoded = PgpSymEncryptedIntegrityProtectedDataPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.CipherAlgorithm, decoded.CipherAlgorithm);
            Assert.Equal(original.AeadAlgorithm, decoded.AeadAlgorithm);
            Assert.Equal(original.ChunkSize, decoded.ChunkSize);
            Assert.Equal(original.Salt.ToArray(), decoded.Salt.ToArray());
            Assert.Equal(original.EncryptedData.ToArray(), decoded.EncryptedData.ToArray());
        }

        [Theory]
        [InlineData(SymmetricCipherAlgorithm.Aes128)]
        [InlineData(SymmetricCipherAlgorithm.Aes192)]
        [InlineData(SymmetricCipherAlgorithm.Aes256)]
        public void RoundTrip_V2_DifferentCiphers_Preserved(SymmetricCipherAlgorithm cipher)
        {
            var original = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                cipher,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                TestHelpers.RandomBytes(50));

            var encoded = original.ToArray();
            var decoded = PgpSymEncryptedIntegrityProtectedDataPacket.Read(encoded);

            Assert.Equal(cipher, decoded.CipherAlgorithm);
        }

        [Theory]
        [InlineData(AeadAlgorithm.Eax)]
        [InlineData(AeadAlgorithm.Ocb)]
        [InlineData(AeadAlgorithm.Gcm)]
        public void RoundTrip_V2_DifferentAead_Preserved(AeadAlgorithm aead)
        {
            var original = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                aead,
                10,
                TestSalt,
                TestHelpers.RandomBytes(50));

            var encoded = original.ToArray();
            var decoded = PgpSymEncryptedIntegrityProtectedDataPacket.Read(encoded);

            Assert.Equal(aead, decoded.AeadAlgorithm);
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
        public void GetEncodedLength_V1_ReturnsCorrectLength()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(TestHelpers.RandomBytes(100));

            // V1: version (1) + encrypted data (100) = 101
            Assert.Equal(101, packet.GetEncodedLength());
        }

        [Fact]
        public void GetEncodedLength_V2_ReturnsCorrectLength()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                TestHelpers.RandomBytes(100));

            // V2: version (1) + cipher (1) + aead (1) + chunk (1) + salt (32) + data (100) = 136
            Assert.Equal(136, packet.GetEncodedLength());
        }

        [Fact]
        public void Write_V1_WritesCorrectBytes()
        {
            var encryptedData = new byte[] { 0x11, 0x22, 0x33 };
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(encryptedData);
            var buffer = new byte[10];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(4, bytesWritten);
            Assert.Equal(0x01, buffer[0]); // Version
            Assert.Equal(0x11, buffer[1]);
            Assert.Equal(0x22, buffer[2]);
            Assert.Equal(0x33, buffer[3]);
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(TestHelpers.RandomBytes(100));
            var smallBuffer = new byte[10];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
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
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(TestHelpers.RandomBytes(50));
            var buffer = new byte[100];

            var result = packet.TryWrite(buffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(51, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                TestHelpers.RandomBytes(100));
            var smallBuffer = new byte[10];

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
        public void WriteTo_V1_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(TestHelpers.RandomBytes(100));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, tag);

            var decoded = PgpSymEncryptedIntegrityProtectedDataPacket.Read(body.Span);
            Assert.Equal(1, decoded.Version);
        }

        [Fact]
        public void WriteTo_V2_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                TestHelpers.RandomBytes(100));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, tag);

            var decoded = PgpSymEncryptedIntegrityProtectedDataPacket.Read(body.Span);
            Assert.Equal(2, decoded.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, decoded.CipherAlgorithm);
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
        public void Equals_V1_SameData_ReturnsTrue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5 };
            var packet1 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(data);
            var packet2 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(data);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
            Assert.False(packet1 != packet2);
        }

        [Fact]
        public void Equals_V2_SameData_ReturnsTrue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5 };
            var packet1 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 10, TestSalt, data);
            var packet2 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 10, TestSalt, data);

            Assert.True(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_DifferentVersion_ReturnsFalse()
        {
            var data = new byte[] { 1, 2, 3 };
            var packet1 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(data);
            var packet2 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 10, TestSalt, data);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_DifferentCipher_ReturnsFalse()
        {
            var data = new byte[] { 1, 2, 3 };
            var packet1 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes128, AeadAlgorithm.Gcm, 10, TestSalt, data);
            var packet2 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256, AeadAlgorithm.Gcm, 10, TestSalt, data);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_Object_WorksCorrectly()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(new byte[] { 1, 2, 3 });

            Assert.False(packet.Equals(null));
            Assert.False(packet.Equals("not a packet"));
        }

        [Fact]
        public void GetHashCode_SamePackets_ReturnsSameHash()
        {
            var data = new byte[] { 1, 2, 3 };
            var packet1 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(data);
            var packet2 = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(data);

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
        public void ToString_V1_ContainsVersionAndSize()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(TestHelpers.RandomBytes(123));

            var str = packet.ToString();

            Assert.Contains("v1", str);
            Assert.Contains("123 bytes", str);
        }

        [Fact]
        public void ToString_V2_ContainsAllDetails()
        {
            var packet = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                10,
                TestSalt,
                TestHelpers.RandomBytes(100));

            var str = packet.ToString();

            Assert.Contains("v2", str);
            Assert.Contains("Aes256", str);
            Assert.Contains("Gcm", str);
            Assert.Contains("100 bytes", str);
        }
    }
}
