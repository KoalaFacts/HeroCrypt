using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP One-Pass Signature Packet per RFC 4880 Section 5.4 and RFC 9580.
/// </summary>
public class PgpOnePassSignaturePacketTests
{
    private static readonly byte[] TestKeyId = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    private static readonly byte[] TestFingerprint = new byte[32];
    private static readonly byte[] TestSalt = [0xAA, 0xBB, 0xCC, 0xDD];

    static PgpOnePassSignaturePacketTests()
    {
        // Initialize test fingerprint with recognizable pattern
        for (int i = 0; i < 32; i++)
        {
            TestFingerprint[i] = (byte)(i + 1);
        }
    }

    /// <summary>
    /// Version 3 constructor and factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class V3ConstructorTests
    {
        [Fact]
        public void CreateV3_SetsAllProperties()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8, // SHA-256
                publicKeyAlgorithm: 1, // RSA
                TestKeyId,
                isNested: true);

            Assert.Equal(3, packet.Version);
            Assert.Equal(PgpSignatureType.BinaryDocument, packet.SignatureType);
            Assert.Equal(8, packet.HashAlgorithm);
            Assert.Equal(1, packet.PublicKeyAlgorithm);
            Assert.Equal(TestKeyId, packet.KeyIdOrFingerprint.ToArray());
            Assert.True(packet.IsNested);
            Assert.Empty(packet.Salt.ToArray());
        }

        [Fact]
        public void CreateV3_DefaultIsNested_IsTrue()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.CanonicalTextDocument,
                hashAlgorithm: 2,
                publicKeyAlgorithm: 17,
                TestKeyId);

            Assert.True(packet.IsNested);
        }

        [Fact]
        public void CreateV3_WithIsNestedFalse_SetsCorrectly()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.CanonicalTextDocument,
                hashAlgorithm: 2,
                publicKeyAlgorithm: 17,
                TestKeyId,
                isNested: false);

            Assert.False(packet.IsNested);
        }

        [Fact]
        public void Constructor_V3WithWrongKeyIdLength_ThrowsArgumentException()
        {
            var shortKeyId = new byte[4];

            Assert.Throws<ArgumentException>(() => new PgpOnePassSignaturePacket(
                version: 3,
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                shortKeyId,
                salt: ReadOnlyMemory<byte>.Empty,
                isNested: true));
        }

        [Fact]
        public void Constructor_UnsupportedVersion_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new PgpOnePassSignaturePacket(
                version: 4, // Invalid
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId,
                salt: ReadOnlyMemory<byte>.Empty,
                isNested: true));
        }
    }

    /// <summary>
    /// Version 6 constructor and factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class V6ConstructorTests
    {
        [Fact]
        public void CreateV6_SetsAllProperties()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 10, // SHA-512
                publicKeyAlgorithm: 27, // Ed25519
                TestSalt,
                TestFingerprint,
                isNested: true);

            Assert.Equal(6, packet.Version);
            Assert.Equal(PgpSignatureType.BinaryDocument, packet.SignatureType);
            Assert.Equal(10, packet.HashAlgorithm);
            Assert.Equal(27, packet.PublicKeyAlgorithm);
            Assert.Equal(TestFingerprint, packet.KeyIdOrFingerprint.ToArray());
            Assert.Equal(TestSalt, packet.Salt.ToArray());
            Assert.True(packet.IsNested);
        }

        [Fact]
        public void CreateV6_WithEmptySalt_Succeeds()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 27,
                salt: ReadOnlyMemory<byte>.Empty,
                TestFingerprint,
                isNested: true);

            Assert.Empty(packet.Salt.ToArray());
        }

        [Fact]
        public void Constructor_V6WithWrongFingerprintLength_ThrowsArgumentException()
        {
            var shortFingerprint = new byte[20];

            Assert.Throws<ArgumentException>(() => new PgpOnePassSignaturePacket(
                version: 6,
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 27,
                shortFingerprint,
                TestSalt,
                isNested: true));
        }
    }

    /// <summary>
    /// Key ID and fingerprint accessor tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyIdFingerprintTests
    {
        [Fact]
        public void GetKeyId_V3_ReturnsKeyId()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var keyId = packet.GetKeyId();

            Assert.Equal(TestKeyId, keyId);
        }

        [Fact]
        public void GetKeyId_V6_ThrowsInvalidOperationException()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint);

            Assert.Throws<InvalidOperationException>(packet.GetKeyId);
        }

        [Fact]
        public void GetFingerprint_V6_ReturnsFingerprint()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint);

            var fingerprint = packet.GetFingerprint();

            Assert.Equal(TestFingerprint, fingerprint);
        }

        [Fact]
        public void GetFingerprint_V3_ThrowsInvalidOperationException()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            Assert.Throws<InvalidOperationException>(packet.GetFingerprint);
        }

        [Fact]
        public void GetKeyIdFromFingerprint_V3_ReturnsKeyId()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var keyId = packet.GetKeyIdFromFingerprint();

            Assert.Equal(TestKeyId, keyId);
        }

        [Fact]
        public void GetKeyIdFromFingerprint_V6_ReturnsFirst8Bytes()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint);

            var keyId = packet.GetKeyIdFromFingerprint();

            Assert.Equal(8, keyId.Length);
            Assert.Equal(TestFingerprint.AsSpan(0, 8).ToArray(), keyId);
        }
    }

    /// <summary>
    /// Round-trip serialization tests for version 3.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class V3RoundTripTests
    {
        [Fact]
        public void RoundTrip_V3_PreservesAllFields()
        {
            var original = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId,
                isNested: true);

            var encoded = original.ToArray();
            var decoded = PgpOnePassSignaturePacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.SignatureType, decoded.SignatureType);
            Assert.Equal(original.HashAlgorithm, decoded.HashAlgorithm);
            Assert.Equal(original.PublicKeyAlgorithm, decoded.PublicKeyAlgorithm);
            Assert.Equal(original.KeyIdOrFingerprint.ToArray(), decoded.KeyIdOrFingerprint.ToArray());
            Assert.Equal(original.IsNested, decoded.IsNested);
        }

        [Fact]
        public void RoundTrip_V3_WithIsNestedFalse_PreservesFlag()
        {
            var original = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.CanonicalTextDocument,
                hashAlgorithm: 2,
                publicKeyAlgorithm: 17,
                TestKeyId,
                isNested: false);

            var encoded = original.ToArray();
            var decoded = PgpOnePassSignaturePacket.Read(encoded);

            Assert.False(decoded.IsNested);
        }

        [Theory]
        [InlineData(PgpSignatureType.BinaryDocument)]
        [InlineData(PgpSignatureType.CanonicalTextDocument)]
        [InlineData(PgpSignatureType.Standalone)]
        [InlineData(PgpSignatureType.GenericCertification)]
        public void RoundTrip_V3_DifferentSignatureTypes_Preserved(PgpSignatureType sigType)
        {
            var original = PgpOnePassSignaturePacket.CreateV3(
                sigType,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var decoded = PgpOnePassSignaturePacket.Read(original.ToArray());

            Assert.Equal(sigType, decoded.SignatureType);
        }
    }

    /// <summary>
    /// Round-trip serialization tests for version 6.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class V6RoundTripTests
    {
        [Fact]
        public void RoundTrip_V6_PreservesAllFields()
        {
            var original = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 10,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint,
                isNested: true);

            var encoded = original.ToArray();
            var decoded = PgpOnePassSignaturePacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.SignatureType, decoded.SignatureType);
            Assert.Equal(original.HashAlgorithm, decoded.HashAlgorithm);
            Assert.Equal(original.PublicKeyAlgorithm, decoded.PublicKeyAlgorithm);
            Assert.Equal(original.KeyIdOrFingerprint.ToArray(), decoded.KeyIdOrFingerprint.ToArray());
            Assert.Equal(original.Salt.ToArray(), decoded.Salt.ToArray());
            Assert.Equal(original.IsNested, decoded.IsNested);
        }

        [Fact]
        public void RoundTrip_V6_EmptySalt_PreservesField()
        {
            var original = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 27,
                salt: ReadOnlyMemory<byte>.Empty,
                TestFingerprint);

            var decoded = PgpOnePassSignaturePacket.Read(original.ToArray());

            Assert.Empty(decoded.Salt.ToArray());
        }

        [Fact]
        public void RoundTrip_V6_LargeSalt_PreservesField()
        {
            var largeSalt = new byte[64];
            for (int i = 0; i < largeSalt.Length; i++)
            {
                largeSalt[i] = (byte)i;
            }

            var original = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 10,
                publicKeyAlgorithm: 27,
                largeSalt,
                TestFingerprint);

            var decoded = PgpOnePassSignaturePacket.Read(original.ToArray());

            Assert.Equal(largeSalt, decoded.Salt.ToArray());
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
        public void WriteTo_V3_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.OnePassSignature, tag);

            var decoded = PgpOnePassSignaturePacket.Read(body.Span);
            Assert.Equal(original.Version, decoded.Version);
        }

        [Fact]
        public void WriteTo_V6_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 10,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint);

            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.OnePassSignature, tag);

            var decoded = PgpOnePassSignaturePacket.Read(body.Span);
            Assert.Equal(6, decoded.Version);
        }
    }

    /// <summary>
    /// Encoding format tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncodingTests
    {
        [Fact]
        public void GetEncodedLength_V3_Returns13()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            Assert.Equal(13, packet.GetEncodedLength());
        }

        [Fact]
        public void GetEncodedLength_V6_IncludesSaltLength()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 10,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint);

            // version(1) + sigtype(1) + hash(1) + pubalg(1) + saltlen(1) + salt(4) + fingerprint(32) + nested(1) = 42
            Assert.Equal(42, packet.GetEncodedLength());
        }

        [Fact]
        public void ToArray_V3_HasCorrectStructure()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument, // 0x00
                hashAlgorithm: 8, // SHA-256
                publicKeyAlgorithm: 1, // RSA
                TestKeyId,
                isNested: true);

            var encoded = packet.ToArray();

            Assert.Equal(13, encoded.Length);
            Assert.Equal(3, encoded[0]); // Version
            Assert.Equal(0, encoded[1]); // SignatureType.BinaryDocument
            Assert.Equal(8, encoded[2]); // HashAlgorithm
            Assert.Equal(1, encoded[3]); // PublicKeyAlgorithm
            Assert.Equal(TestKeyId, encoded.AsSpan(4, 8).ToArray()); // Key ID
            Assert.Equal(1, encoded[12]); // Nested = true
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var smallBuffer = new byte[5];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var buffer = new byte[100];
            var result = packet.TryWrite(buffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(13, bytesWritten);
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var smallBuffer = new byte[5];
            var result = packet.TryWrite(smallBuffer, out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }
    }

    /// <summary>
    /// Read error handling tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ReadErrorHandlingTests
    {
        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var result = PgpOnePassSignaturePacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_UnsupportedVersion_ReturnsFalse()
        {
            var invalidData = new byte[] { 5, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

            var result = PgpOnePassSignaturePacket.TryRead(invalidData, out _, out var error);

            Assert.False(result);
            Assert.Contains("Unsupported", error);
            Assert.Contains("version", error);
        }

        [Fact]
        public void TryRead_V3TooShort_ReturnsFalse()
        {
            var shortData = new byte[] { 3, 0, 8, 1 }; // Only 4 bytes

            var result = PgpOnePassSignaturePacket.TryRead(shortData, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_V6TooShort_ReturnsFalse()
        {
            var shortData = new byte[] { 6, 0, 8, 27, 4 }; // Claims 4-byte salt but no data

            var result = PgpOnePassSignaturePacket.TryRead(shortData, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void Read_InvalidData_ThrowsArgumentException()
        {
            var invalidData = new byte[] { 5 }; // Invalid version

            Assert.Throws<ArgumentException>(() => PgpOnePassSignaturePacket.Read(invalidData));
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
        public void Equals_SamePacket_ReturnsTrue()
        {
            var packet1 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var packet2 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
        }

        [Fact]
        public void Equals_DifferentSignatureType_ReturnsFalse()
        {
            var packet1 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var packet2 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.CanonicalTextDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            Assert.False(packet1.Equals(packet2));
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_DifferentKeyId_ReturnsFalse()
        {
            var otherKeyId = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8 };

            var packet1 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var packet2 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                otherKeyId);

            Assert.False(packet1.Equals(packet2));
        }

        [Fact]
        public void GetHashCode_SamePacket_ReturnsSameHash()
        {
            var packet1 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var packet2 = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

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
        public void ToString_V3_ContainsVersion()
        {
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                TestKeyId);

            var str = packet.ToString();

            Assert.Contains("v3", str);
            Assert.Contains("BinaryDocument", str);
        }

        [Fact]
        public void ToString_V6_ContainsVersion()
        {
            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.CanonicalTextDocument,
                hashAlgorithm: 10,
                publicKeyAlgorithm: 27,
                TestSalt,
                TestFingerprint);

            var str = packet.ToString();

            Assert.Contains("v6", str);
            Assert.Contains("TextDocument", str);
        }
    }

    /// <summary>
    /// Edge case tests.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCaseTests
    {
        [Fact]
        public void RoundTrip_AllZeroKeyId_Succeeds()
        {
            var zeroKeyId = new byte[8];
            var packet = PgpOnePassSignaturePacket.CreateV3(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 8,
                publicKeyAlgorithm: 1,
                zeroKeyId);

            var decoded = PgpOnePassSignaturePacket.Read(packet.ToArray());

            Assert.Equal(zeroKeyId, decoded.KeyIdOrFingerprint.ToArray());
        }

        [Fact]
        public void RoundTrip_MaxByteValues_Succeeds()
        {
            var maxKeyId = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            var packet = PgpOnePassSignaturePacket.CreateV3(
                (PgpSignatureType)0xFF,
                hashAlgorithm: 0xFF,
                publicKeyAlgorithm: 0xFF,
                maxKeyId,
                isNested: true);

            var decoded = PgpOnePassSignaturePacket.Read(packet.ToArray());

            Assert.Equal((PgpSignatureType)0xFF, decoded.SignatureType);
            Assert.Equal(0xFF, decoded.HashAlgorithm);
            Assert.Equal(0xFF, decoded.PublicKeyAlgorithm);
            Assert.Equal(maxKeyId, decoded.KeyIdOrFingerprint.ToArray());
        }

        [Fact]
        public void V6_MaxSaltLength_Succeeds()
        {
            // Salt length is 1 byte, so max is 255
            var maxSalt = new byte[255];
            for (int i = 0; i < maxSalt.Length; i++)
            {
                maxSalt[i] = (byte)i;
            }

            var packet = PgpOnePassSignaturePacket.CreateV6(
                PgpSignatureType.BinaryDocument,
                hashAlgorithm: 10,
                publicKeyAlgorithm: 27,
                maxSalt,
                TestFingerprint);

            var decoded = PgpOnePassSignaturePacket.Read(packet.ToArray());

            Assert.Equal(255, decoded.Salt.Length);
            Assert.Equal(maxSalt, decoded.Salt.ToArray());
        }
    }
}
