using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Public-Key Encrypted Session Key (PKESK) Packet per RFC 4880 Section 5.1.
/// </summary>
public class PgpPublicKeyEncryptedSessionKeyPacketTests
{
    private static readonly byte[] ValidKeyId = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void ConstructorV3_WithValidKeyId_Succeeds()
        {
            var encryptedKey = TestHelpers.RandomBytes(256);

            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                encryptedKey);

            Assert.Equal(3, packet.Version);
            Assert.Equal(ValidKeyId, packet.KeyId.ToArray());
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, packet.Algorithm);
            Assert.Equal(encryptedKey, packet.EncryptedSessionKey.ToArray());
        }

        [Fact]
        public void ConstructorV3_WithInvalidKeyId_ThrowsArgumentException()
        {
            var shortKeyId = new byte[] { 0x01, 0x02, 0x03 };

            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKeyEncryptedSessionKeyPacket(shortKeyId, PgpPublicKeyAlgorithm.RsaEncryptOrSign, Array.Empty<byte>()));
        }

        [Fact]
        public void ConstructorV6_WithFingerprint_Succeeds()
        {
            var fingerprint = TestHelpers.RandomBytes(32);
            var encryptedKey = TestHelpers.RandomBytes(256);

            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                6,
                fingerprint,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                encryptedKey);

            Assert.Equal(6, packet.Version);
            Assert.Equal(6, packet.KeyVersion);
            Assert.Equal(fingerprint, packet.Fingerprint.ToArray());
            Assert.Equal(encryptedKey, packet.EncryptedSessionKey.ToArray());
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
        public void ReadV3_ValidPacket_ReturnsPacket()
        {
            // v3 format: version(1) + keyId(8) + algorithm(1) + encrypted data
            var encryptedKey = TestHelpers.RandomBytes(128);
            var source = new byte[10 + encryptedKey.Length];
            source[0] = 3; // version
            ValidKeyId.CopyTo(source, 1);
            source[9] = (byte)PgpPublicKeyAlgorithm.RsaEncryptOrSign;
            encryptedKey.CopyTo(source, 10);

            var packet = PgpPublicKeyEncryptedSessionKeyPacket.Read(source);

            Assert.Equal(3, packet.Version);
            Assert.Equal(ValidKeyId, packet.KeyId.ToArray());
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, packet.Algorithm);
            Assert.Equal(encryptedKey, packet.EncryptedSessionKey.ToArray());
        }

        [Fact]
        public void Read_TooShort_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpPublicKeyEncryptedSessionKeyPacket.Read(new byte[5]));
        }

        [Fact]
        public void Read_UnsupportedVersion_ThrowsArgumentException()
        {
            var source = new byte[11];
            source[0] = 99; // invalid version

            Assert.Throws<ArgumentException>(() => PgpPublicKeyEncryptedSessionKeyPacket.Read(source));
        }

        [Fact]
        public void TryReadV3_ValidPacket_ReturnsTrue()
        {
            var source = new byte[10];
            source[0] = 3;
            ValidKeyId.CopyTo(source, 1);
            source[9] = 1; // RSA

            var result = PgpPublicKeyEncryptedSessionKeyPacket.TryRead(source, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(3, packet.Version);
        }

        [Fact]
        public void TryRead_UnsupportedVersion_ReturnsFalse()
        {
            var source = new byte[11];
            source[0] = 5; // unsupported version

            var result = PgpPublicKeyEncryptedSessionKeyPacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("version", error, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Round-trip tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RoundTripTests
    {
        [Fact]
        public void RoundTripV3_PreservesAllFields()
        {
            var encryptedKey = TestHelpers.RandomBytes(256);
            var original = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                encryptedKey);

            var encoded = original.ToArray();
            var decoded = PgpPublicKeyEncryptedSessionKeyPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.KeyId.ToArray(), decoded.KeyId.ToArray());
            Assert.Equal(original.Algorithm, decoded.Algorithm);
            Assert.Equal(original.EncryptedSessionKey.ToArray(), decoded.EncryptedSessionKey.ToArray());
        }

        [Fact]
        public void RoundTripV6_PreservesAllFields()
        {
            var fingerprint = TestHelpers.RandomBytes(32);
            var encryptedKey = TestHelpers.RandomBytes(256);
            var original = new PgpPublicKeyEncryptedSessionKeyPacket(
                6,
                fingerprint,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                encryptedKey);

            var encoded = original.ToArray();
            var decoded = PgpPublicKeyEncryptedSessionKeyPacket.Read(encoded);

            Assert.Equal(6, decoded.Version);
            Assert.Equal(original.Fingerprint.ToArray(), decoded.Fingerprint.ToArray());
            Assert.Equal(original.Algorithm, decoded.Algorithm);
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
        public void WriteV3_CorrectFormat()
        {
            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                new byte[] { 0xAA, 0xBB });

            var buffer = packet.ToArray();

            Assert.Equal(3, buffer[0]); // version
            Assert.Equal(ValidKeyId, buffer.AsSpan(1, 8).ToArray());
            Assert.Equal((byte)PgpPublicKeyAlgorithm.RsaEncryptOrSign, buffer[9]);
            Assert.Equal(0xAA, buffer[10]);
            Assert.Equal(0xBB, buffer[11]);
        }

        [Fact]
        public void GetEncodedLengthV3_Correct()
        {
            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            Assert.Equal(110, packet.GetEncodedLength()); // 1 + 8 + 1 + 100
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(50));

            var result = packet.TryWrite(new byte[100], out var bytesWritten);

            Assert.True(result);
            Assert.Equal(60, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            var result = packet.TryWrite(new byte[50], out var bytesWritten);

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

            var original = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(128));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.PublicKeyEncryptedSessionKey, tag);

            var decoded = PgpPublicKeyEncryptedSessionKeyPacket.Read(body.Span);
            Assert.Equal(original.KeyId.ToArray(), decoded.KeyId.ToArray());
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
            var encryptedKey = TestHelpers.RandomBytes(100);
            var packet1 = new PgpPublicKeyEncryptedSessionKeyPacket(ValidKeyId, PgpPublicKeyAlgorithm.RsaEncryptOrSign, encryptedKey);
            var packet2 = new PgpPublicKeyEncryptedSessionKeyPacket(ValidKeyId, PgpPublicKeyAlgorithm.RsaEncryptOrSign, encryptedKey);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
        }

        [Fact]
        public void Equals_DifferentKeyId_ReturnsFalse()
        {
            var keyId2 = new byte[] { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
            var packet1 = new PgpPublicKeyEncryptedSessionKeyPacket(ValidKeyId, PgpPublicKeyAlgorithm.RsaEncryptOrSign, Array.Empty<byte>());
            var packet2 = new PgpPublicKeyEncryptedSessionKeyPacket(keyId2, PgpPublicKeyAlgorithm.RsaEncryptOrSign, Array.Empty<byte>());

            Assert.False(packet1.Equals(packet2));
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void GetHashCode_SameValues_SameCode()
        {
            var encryptedKey = TestHelpers.RandomBytes(100);
            var packet1 = new PgpPublicKeyEncryptedSessionKeyPacket(ValidKeyId, PgpPublicKeyAlgorithm.RsaEncryptOrSign, encryptedKey);
            var packet2 = new PgpPublicKeyEncryptedSessionKeyPacket(ValidKeyId, PgpPublicKeyAlgorithm.RsaEncryptOrSign, encryptedKey);

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
        public void ToStringV3_ContainsKeyInfo()
        {
            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                ValidKeyId,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            var str = packet.ToString();

            Assert.Contains("PKESK", str);
            Assert.Contains("v3", str);
            Assert.Contains("0102030405060708", str); // KeyId hex
        }

        [Fact]
        public void ToStringV6_ContainsVersionInfo()
        {
            var packet = new PgpPublicKeyEncryptedSessionKeyPacket(
                6,
                TestHelpers.RandomBytes(32),
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            var str = packet.ToString();

            Assert.Contains("PKESK", str);
            Assert.Contains("v6", str);
        }
    }
}
