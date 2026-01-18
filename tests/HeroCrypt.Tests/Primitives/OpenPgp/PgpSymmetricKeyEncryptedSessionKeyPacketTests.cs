using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Symmetric-Key Encrypted Session Key (SKESK) Packet per RFC 4880 Section 5.3.
/// </summary>
public class PgpSymmetricKeyEncryptedSessionKeyPacketTests
{
    // Simple S2K specifier: type(1) + hash algorithm(1) = 2 bytes
    private static readonly byte[] SimpleS2k = [0x00, 0x02]; // Simple S2K with SHA-1

    // Salted S2K specifier: type(1) + hash(1) + salt(8) = 10 bytes
    private static readonly byte[] SaltedS2k = [0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    // Iterated S2K: type(1) + hash(1) + salt(8) + count(1) = 11 bytes
    private static readonly byte[] IteratedS2k = [0x03, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF];

    /// <summary>
    /// Constructor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void ConstructorV4_WithS2K_Succeeds()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k);

            Assert.Equal(4, packet.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, packet.CipherAlgorithm);
            Assert.Equal(SaltedS2k, packet.S2kSpecifier.ToArray());
            Assert.Empty(packet.EncryptedSessionKey.ToArray());
        }

        [Fact]
        public void ConstructorV4_WithEncryptedKey_Succeeds()
        {
            var encryptedKey = TestHelpers.RandomBytes(33);

            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k,
                encryptedKey);

            Assert.Equal(encryptedKey, packet.EncryptedSessionKey.ToArray());
        }

        [Fact]
        public void ConstructorV6_WithAead_Succeeds()
        {
            var iv = TestHelpers.RandomBytes(12);
            var encryptedKey = TestHelpers.RandomBytes(48);

            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                SaltedS2k,
                iv,
                encryptedKey);

            Assert.Equal(6, packet.Version);
            Assert.Equal(AeadAlgorithm.Gcm, packet.AeadAlgorithm);
            Assert.Equal(iv, packet.IV.ToArray());
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
        public void ReadV4_SimpleS2K_ReturnsPacket()
        {
            // v4: version(1) + algorithm(1) + s2k
            var source = new byte[2 + SimpleS2k.Length];
            source[0] = 4; // version
            source[1] = (byte)SymmetricCipherAlgorithm.Aes256;
            SimpleS2k.CopyTo(source, 2);

            var packet = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(source);

            Assert.Equal(4, packet.Version);
            Assert.Equal(SymmetricCipherAlgorithm.Aes256, packet.CipherAlgorithm);
        }

        [Fact]
        public void ReadV4_WithEncryptedKey_ReturnsPacket()
        {
            var encryptedKey = TestHelpers.RandomBytes(33);
            var source = new byte[2 + SaltedS2k.Length + encryptedKey.Length];
            source[0] = 4;
            source[1] = (byte)SymmetricCipherAlgorithm.Aes256;
            SaltedS2k.CopyTo(source, 2);
            encryptedKey.CopyTo(source, 2 + SaltedS2k.Length);

            var packet = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(source);

            Assert.Equal(encryptedKey, packet.EncryptedSessionKey.ToArray());
        }

        [Fact]
        public void Read_TooShort_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.Read(new byte[2]));
        }

        [Fact]
        public void Read_UnsupportedVersion_ThrowsArgumentException()
        {
            var source = new byte[5];
            source[0] = 3; // unsupported version

            Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.Read(source));
        }

        [Fact]
        public void TryReadV4_ValidPacket_ReturnsTrue()
        {
            var source = new byte[2 + SimpleS2k.Length];
            source[0] = 4;
            source[1] = (byte)SymmetricCipherAlgorithm.Aes256;
            SimpleS2k.CopyTo(source, 2);

            var result = PgpSymmetricKeyEncryptedSessionKeyPacket.TryRead(source, out var packet, out var error);

            Assert.True(result);
            Assert.Equal(string.Empty, error);
            Assert.Equal(4, packet.Version);
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
        public void RoundTripV4_DirectKey_PreservesFields()
        {
            var original = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                IteratedS2k);

            var encoded = original.ToArray();
            var decoded = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.CipherAlgorithm, decoded.CipherAlgorithm);
            Assert.Equal(original.S2kSpecifier.ToArray(), decoded.S2kSpecifier.ToArray());
        }

        [Fact]
        public void RoundTripV4_WithEncryptedKey_PreservesFields()
        {
            var encryptedKey = TestHelpers.RandomBytes(33);
            var original = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k,
                encryptedKey);

            var encoded = original.ToArray();
            var decoded = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(encoded);

            Assert.Equal(original.EncryptedSessionKey.ToArray(), decoded.EncryptedSessionKey.ToArray());
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
        public void WriteV4_CorrectFormat()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SimpleS2k);

            var buffer = packet.ToArray();

            Assert.Equal(4, buffer[0]); // version
            Assert.Equal((byte)SymmetricCipherAlgorithm.Aes256, buffer[1]);
        }

        [Fact]
        public void GetEncodedLengthV4_Correct()
        {
            var encryptedKey = TestHelpers.RandomBytes(33);
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k,
                encryptedKey);

            // version(1) + algorithm(1) + s2k(10) + encryptedKey(33) = 45
            Assert.Equal(45, packet.GetEncodedLength());
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SimpleS2k);

            var result = packet.TryWrite(new byte[100], out var bytesWritten);

            Assert.True(result);
            Assert.True(bytesWritten > 0);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                IteratedS2k,
                TestHelpers.RandomBytes(50));

            var result = packet.TryWrite(new byte[10], out var bytesWritten);

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

            var original = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k,
                TestHelpers.RandomBytes(33));
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.SymmetricKeyEncryptedSessionKey, tag);

            var decoded = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(body.Span);
            Assert.Equal(original.CipherAlgorithm, decoded.CipherAlgorithm);
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
            var encryptedKey = TestHelpers.RandomBytes(33);
            var packet1 = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes256, SaltedS2k, encryptedKey);
            var packet2 = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes256, SaltedS2k, encryptedKey);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
        }

        [Fact]
        public void Equals_DifferentCipher_ReturnsFalse()
        {
            var packet1 = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes256, SaltedS2k);
            var packet2 = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes128, SaltedS2k);

            Assert.False(packet1.Equals(packet2));
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void GetHashCode_SameValues_SameCode()
        {
            var encryptedKey = TestHelpers.RandomBytes(33);
            var packet1 = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes256, SaltedS2k, encryptedKey);
            var packet2 = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes256, SaltedS2k, encryptedKey);

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
        public void ToStringV4_DirectKey_ContainsInfo()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k);

            var str = packet.ToString();

            Assert.Contains("SKESK", str);
            Assert.Contains("v4", str);
            Assert.Contains("direct key", str);
        }

        [Fact]
        public void ToStringV4_WithEncryptedKey_ContainsInfo()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                SaltedS2k,
                TestHelpers.RandomBytes(33));

            var str = packet.ToString();

            Assert.Contains("SKESK", str);
            Assert.Contains("ESK=", str);
        }

        [Fact]
        public void ToStringV6_ContainsAeadInfo()
        {
            var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
                SymmetricCipherAlgorithm.Aes256,
                AeadAlgorithm.Gcm,
                SaltedS2k,
                TestHelpers.RandomBytes(12),
                TestHelpers.RandomBytes(48));

            var str = packet.ToString();

            Assert.Contains("v6", str);
            Assert.Contains("Gcm", str);
        }
    }
}
