using System.Numerics;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Signature Packet per RFC 4880 Section 5.2.
/// </summary>
public class PgpSignaturePacketTests
{
    /// <summary>
    /// PgpSignatureSubpacket tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SubpacketTests
    {
        [Fact]
        public void CreateSignatureCreationTime_CreatesCorrectSubpacket()
        {
            var time = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);

            var subpacket = PgpSignatureSubpacket.CreateSignatureCreationTime(time);

            Assert.Equal(PgpSignatureSubpacketType.SignatureCreationTime, subpacket.Type);
            Assert.False(subpacket.IsCritical);
            Assert.Equal(4, subpacket.Data.Length);
            Assert.Equal(time, subpacket.GetSignatureCreationTime());
        }

        [Fact]
        public void CreateSignatureCreationTime_Critical_SetsCriticalFlag()
        {
            var time = DateTimeOffset.UtcNow;

            var subpacket = PgpSignatureSubpacket.CreateSignatureCreationTime(time, isCritical: true);

            Assert.True(subpacket.IsCritical);
        }

        [Fact]
        public void CreateIssuerKeyId_CreatesCorrectSubpacket()
        {
            var keyId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

            var subpacket = PgpSignatureSubpacket.CreateIssuerKeyId(keyId);

            Assert.Equal(PgpSignatureSubpacketType.IssuerKeyId, subpacket.Type);
            Assert.Equal(keyId, subpacket.GetIssuerKeyId());
        }

        [Fact]
        public void CreateIssuerKeyId_InvalidLength_ThrowsArgumentException()
        {
            var shortKeyId = new byte[] { 0x01, 0x02, 0x03 };

            Assert.Throws<ArgumentException>(() => PgpSignatureSubpacket.CreateIssuerKeyId(shortKeyId));
        }

        [Fact]
        public void CreateKeyFlags_CreatesCorrectSubpacket()
        {
            var flags = PgpKeyCapabilities.Sign | PgpKeyCapabilities.Certify;

            var subpacket = PgpSignatureSubpacket.CreateKeyFlags(flags);

            Assert.Equal(PgpSignatureSubpacketType.KeyFlags, subpacket.Type);
            Assert.Equal(flags, subpacket.GetKeyFlags());
        }

        [Fact]
        public void CreateFeatures_CreatesCorrectSubpacket()
        {
            var features = PgpFeatures.ModificationDetection | PgpFeatures.AeadEncryptedData;

            var subpacket = PgpSignatureSubpacket.CreateFeatures(features);

            Assert.Equal(PgpSignatureSubpacketType.Features, subpacket.Type);
            Assert.Equal(1, subpacket.Data.Length);
            Assert.Equal((byte)features, subpacket.Data.Span[0]);
        }

        [Fact]
        public void CreatePreferredSymmetricAlgorithms_CreatesCorrectSubpacket()
        {
            var algos = new byte[] { 9, 8, 7 }; // AES256, AES192, AES128

            var subpacket = PgpSignatureSubpacket.CreatePreferredSymmetricAlgorithms(algos);

            Assert.Equal(PgpSignatureSubpacketType.PreferredSymmetricAlgorithms, subpacket.Type);
            Assert.Equal(algos, subpacket.Data.ToArray());
        }

        [Fact]
        public void RoundTrip_SmallSubpacket_PreservesData()
        {
            var original = PgpSignatureSubpacket.CreateSignatureCreationTime(
                new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));

            var encoded = original.ToArray();
            var success = PgpSignatureSubpacket.TryRead(encoded, out var decoded, out _, out _);

            Assert.True(success);
            Assert.Equal(original.Type, decoded.Type);
            Assert.Equal(original.IsCritical, decoded.IsCritical);
            Assert.Equal(original.Data.ToArray(), decoded.Data.ToArray());
        }

        [Fact]
        public void RoundTrip_CriticalSubpacket_PreservesCriticalFlag()
        {
            var original = PgpSignatureSubpacket.CreateSignatureCreationTime(
                DateTimeOffset.UtcNow,
                isCritical: true);

            var encoded = original.ToArray();
            PgpSignatureSubpacket.TryRead(encoded, out var decoded, out _, out _);

            Assert.True(decoded.IsCritical);
        }

        [Fact]
        public void RoundTrip_LargerSubpacket_PreservesData()
        {
            var data = TestHelpers.RandomBytes(200);
            var original = new PgpSignatureSubpacket(
                PgpSignatureSubpacketType.NotationData,
                false,
                data);

            var encoded = original.ToArray();
            PgpSignatureSubpacket.TryRead(encoded, out var decoded, out var consumed, out _);

            Assert.Equal(encoded.Length, consumed);
            Assert.Equal(original.Type, decoded.Type);
            Assert.Equal(data, decoded.Data.ToArray());
        }

        [Fact]
        public void TryRead_TooShort_ReturnsFalse()
        {
            var source = new byte[] { 0x01 }; // Only length, no type

            var result = PgpSignatureSubpacket.TryRead(source, out _, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_ZeroLength_ReturnsFalse()
        {
            // Length 0 (invalid - must have at least type byte)
            // Need at least 2 bytes to read length (1) + type (1)
            var source = new byte[] { 0x00, 0x00 }; // Length 0, but need type byte

            var result = PgpSignatureSubpacket.TryRead(source, out _, out _, out var error);

            Assert.False(result);
            Assert.Contains("at least 1", error);
        }

        [Fact]
        public void ReadAll_MultipleSubpackets_ReadsAll()
        {
            var sp1 = PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow);
            var sp2 = PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.Sign);
            var sp3 = PgpSignatureSubpacket.CreateIssuerKeyId(new byte[8]);

            var combined = PgpSignatureSubpacket.WriteAll([sp1, sp2, sp3]);
            var parsed = PgpSignatureSubpacket.ReadAll(combined);

            Assert.Equal(3, parsed.Count);
            Assert.Equal(sp1.Type, parsed[0].Type);
            Assert.Equal(sp2.Type, parsed[1].Type);
            Assert.Equal(sp3.Type, parsed[2].Type);
        }

        [Fact]
        public void WriteAll_EmptyList_ReturnsEmptyArray()
        {
            var result = PgpSignatureSubpacket.WriteAll([]);

            Assert.Empty(result);
        }

        [Fact]
        public void GetSignatureCreationTime_WrongType_ThrowsInvalidOperationException()
        {
            var subpacket = PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.Sign);

            Assert.Throws<InvalidOperationException>(() => subpacket.GetSignatureCreationTime());
        }

        [Fact]
        public void GetIssuerKeyId_WrongType_ThrowsInvalidOperationException()
        {
            var subpacket = PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.Sign);

            Assert.Throws<InvalidOperationException>(() => subpacket.GetIssuerKeyId());
        }

        [Fact]
        public void GetKeyFlags_WrongType_ThrowsInvalidOperationException()
        {
            var subpacket = PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow);

            Assert.Throws<InvalidOperationException>(() => subpacket.GetKeyFlags());
        }

        [Fact]
        public void ToString_IncludesTypeAndSize()
        {
            var subpacket = PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow);

            var str = subpacket.ToString();

            Assert.Contains("SignatureCreationTime", str);
            Assert.Contains("4 bytes", str);
        }

        [Fact]
        public void ToString_Critical_IncludesCriticalMarker()
        {
            var subpacket = PgpSignatureSubpacket.CreateSignatureCreationTime(
                DateTimeOffset.UtcNow,
                isCritical: true);

            var str = subpacket.ToString();

            Assert.Contains("critical", str);
        }
    }

    /// <summary>
    /// PgpSignaturePacket factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FactoryMethodTests
    {
        [Fact]
        public void CreateV4_SetsCorrectVersion()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1, // RSA
                hashAlgorithm: 8, // SHA256
                hashedSubpackets: [],
                unhashedSubpackets: null,
                hashPrefix: 0x1234,
                signatureData: new byte[256]);

            Assert.Equal(4, packet.Version);
            Assert.Equal(PgpSignatureType.BinaryDocument, packet.SignatureType);
            Assert.Equal(1, packet.PublicKeyAlgorithm);
            Assert.Equal(8, packet.HashAlgorithm);
            Assert.Equal(0x1234, packet.HashPrefix);
        }

        [Fact]
        public void Constructor_UnsupportedVersion_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new PgpSignaturePacket(
                version: 3, // Unsupported
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: Array.Empty<byte>()));
        }

        [Fact]
        public void Constructor_Version6_Succeeds()
        {
            var packet = new PgpSignaturePacket(
                version: 6,
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 27, // Ed25519
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0xABCD,
                signatureData: new byte[64]);

            Assert.Equal(6, packet.Version);
        }
    }

    /// <summary>
    /// Round-trip serialization tests for PgpSignaturePacket.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RoundTripTests
    {
        [Fact]
        public void RoundTrip_V4_MinimalSignature_PreservesData()
        {
            var signatureData = TestHelpers.RandomBytes(256);
            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0x1234,
                signatureData: signatureData);

            var encoded = original.ToArray();
            var success = PgpSignaturePacket.TryRead(encoded, out var decoded, out _);

            Assert.True(success);
            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.SignatureType, decoded.SignatureType);
            Assert.Equal(original.PublicKeyAlgorithm, decoded.PublicKeyAlgorithm);
            Assert.Equal(original.HashAlgorithm, decoded.HashAlgorithm);
            Assert.Equal(original.HashPrefix, decoded.HashPrefix);
            Assert.Equal(signatureData, decoded.SignatureData.ToArray());
        }

        [Fact]
        public void RoundTrip_V4_WithSubpackets_PreservesSubpackets()
        {
            var creationTime = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);
            var keyId = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };

            var hashedSubpackets = new List<PgpSignatureSubpacket>
            {
                PgpSignatureSubpacket.CreateSignatureCreationTime(creationTime),
                PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.Sign | PgpKeyCapabilities.Certify),
            };

            var unhashedSubpackets = new List<PgpSignatureSubpacket>
            {
                PgpSignatureSubpacket.CreateIssuerKeyId(keyId),
            };

            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.GenericCertification,
                publicKeyAlgorithm: 19, // ECDSA
                hashAlgorithm: 8,
                hashedSubpackets: hashedSubpackets,
                unhashedSubpackets: unhashedSubpackets,
                hashPrefix: 0x5678,
                signatureData: TestHelpers.RandomBytes(64));

            var encoded = original.ToArray();
            var decoded = PgpSignaturePacket.Read(encoded);

            Assert.Equal(2, decoded.HashedSubpackets.Count);
            Assert.Single(decoded.UnhashedSubpackets);
            Assert.Equal(creationTime, decoded.GetCreationTime());
            Assert.Equal(keyId, decoded.GetIssuerKeyId());
            Assert.Equal(PgpKeyCapabilities.Sign | PgpKeyCapabilities.Certify, decoded.GetKeyFlags());
        }

        [Fact]
        public void RoundTrip_V6_PreservesData()
        {
            var signatureData = TestHelpers.RandomBytes(64);
            var original = new PgpSignaturePacket(
                version: 6,
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 27,
                hashAlgorithm: 12, // SHA3-256
                hashedSubpackets:
                [
                    PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow),
                ],
                unhashedSubpackets: [],
                hashPrefix: 0xDEAD,
                signatureData: signatureData);

            var encoded = original.ToArray();
            var decoded = PgpSignaturePacket.Read(encoded);

            Assert.Equal(6, decoded.Version);
            Assert.Equal(signatureData, decoded.SignatureData.ToArray());
        }

        [Fact]
        public void RoundTrip_AllSignatureTypes_Succeed()
        {
            var sigTypes = new[]
            {
                PgpSignatureType.BinaryDocument,
                PgpSignatureType.CanonicalTextDocument,
                PgpSignatureType.GenericCertification,
                PgpSignatureType.SubkeyBinding,
                PgpSignatureType.KeyRevocation,
            };

            foreach (var sigType in sigTypes)
            {
                var original = PgpSignaturePacket.CreateV4(
                    sigType,
                    publicKeyAlgorithm: 1,
                    hashAlgorithm: 8,
                    hashedSubpackets: [],
                    unhashedSubpackets: [],
                    hashPrefix: 0,
                    signatureData: new byte[128]);

                var encoded = original.ToArray();
                var decoded = PgpSignaturePacket.Read(encoded);

                Assert.Equal(sigType, decoded.SignatureType);
            }
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
        public void TryRead_Empty_ReturnsFalse()
        {
            var result = PgpSignaturePacket.TryRead([], out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_UnsupportedVersion_ReturnsFalse()
        {
            var source = new byte[] { 3, 0, 1, 8, 0, 0, 0, 0, 0, 0 }; // Version 3

            var result = PgpSignaturePacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("version", error.ToLower());
        }

        [Fact]
        public void TryRead_TruncatedHeader_ReturnsFalse()
        {
            var source = new byte[] { 4, 0, 1 }; // Incomplete v4 header

            var result = PgpSignaturePacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_TruncatedHashedSubpackets_ReturnsFalse()
        {
            // Version 4 header claiming 100 bytes of hashed subpackets but only 2 provided
            var source = new byte[] { 4, 0, 1, 8, 0, 100, 0x01, 0x02 };

            var result = PgpSignaturePacket.TryRead(source, out _, out var error);

            Assert.False(result);
            Assert.Contains("too short", error.ToLower());
        }

        [Fact]
        public void Read_Invalid_ThrowsArgumentException()
        {
            var source = new byte[] { 4 }; // Too short

            Assert.Throws<ArgumentException>(() => PgpSignaturePacket.Read(source));
        }
    }

    /// <summary>
    /// Subpacket access helper tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SubpacketAccessTests
    {
        [Fact]
        public void GetCreationTime_NotPresent_ReturnsNull()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            Assert.Null(packet.GetCreationTime());
        }

        [Fact]
        public void GetIssuerKeyId_InUnhashed_ReturnsKeyId()
        {
            var keyId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [PgpSignatureSubpacket.CreateIssuerKeyId(keyId)],
                hashPrefix: 0,
                signatureData: new byte[128]);

            Assert.Equal(keyId, packet.GetIssuerKeyId());
        }

        [Fact]
        public void GetIssuerKeyId_InHashed_ReturnsKeyId()
        {
            var keyId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [PgpSignatureSubpacket.CreateIssuerKeyId(keyId)],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            Assert.Equal(keyId, packet.GetIssuerKeyId());
        }

        [Fact]
        public void GetIssuerKeyId_NotPresent_ReturnsNull()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            Assert.Null(packet.GetIssuerKeyId());
        }

        [Fact]
        public void GetKeyFlags_ReturnsFlags()
        {
            var flags = PgpKeyCapabilities.Sign | PgpKeyCapabilities.Authentication;
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.SubkeyBinding,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [PgpSignatureSubpacket.CreateKeyFlags(flags)],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            Assert.Equal(flags, packet.GetKeyFlags());
        }

        [Fact]
        public void GetIssuerFingerprint_ReturnsFingerprint()
        {
            var fingerprint = TestHelpers.RandomBytes(20);
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [PgpSignatureSubpacket.CreateIssuerFingerprint(4, fingerprint)],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            var result = packet.GetIssuerFingerprint();
            Assert.NotNull(result);
            Assert.Equal(4, result[0]); // Version
            Assert.Equal(fingerprint, result.Skip(1).ToArray());
        }
    }

    /// <summary>
    /// Signature data reading tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SignatureDataTests
    {
        [Fact]
        public void ReadRsaSignature_ReadsMpi()
        {
            // Create an MPI-encoded value
            var value = new BigInteger(12345678);
            var mpiBuffer = new byte[Mpi.GetEncodedLength(value)];
            Mpi.Write(value, mpiBuffer);

            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: mpiBuffer);

            var result = packet.ReadRsaSignature();

            Assert.Equal(value, result);
        }

        [Fact]
        public void ReadDsaSignature_ReadsTwoMpis()
        {
            var r = new BigInteger(111111);
            var s = new BigInteger(222222);

            var rBuffer = new byte[Mpi.GetEncodedLength(r)];
            var sBuffer = new byte[Mpi.GetEncodedLength(s)];
            Mpi.Write(r, rBuffer);
            Mpi.Write(s, sBuffer);

            var combined = rBuffer.Concat(sBuffer).ToArray();

            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 19, // ECDSA
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: combined);

            var (resultR, resultS) = packet.ReadDsaSignature();

            Assert.Equal(r, resultR);
            Assert.Equal(s, resultS);
        }
    }

    /// <summary>
    /// Critical subpacket handling tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CriticalSubpacketTests
    {
        [Fact]
        public void GetUnrecognizedCriticalSubpackets_NoCritical_ReturnsEmpty()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow)],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            var unrecognized = packet.GetUnrecognizedCriticalSubpackets();

            Assert.Empty(unrecognized);
        }

        [Fact]
        public void GetUnrecognizedCriticalSubpackets_RecognizedCritical_ReturnsEmpty()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets:
                [
                    PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow, isCritical: true),
                ],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            var unrecognized = packet.GetUnrecognizedCriticalSubpackets();

            Assert.Empty(unrecognized);
        }

        [Fact]
        public void GetUnrecognizedCriticalSubpackets_UnknownCritical_ReturnsType()
        {
            // Create a subpacket with a "private" type that won't be recognized
            var unknownSubpacket = new PgpSignatureSubpacket(
                (PgpSignatureSubpacketType)100, // Private/experimental
                isCritical: true,
                new byte[] { 0x01, 0x02 });

            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [unknownSubpacket],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            var unrecognized = packet.GetUnrecognizedCriticalSubpackets();

            Assert.Single(unrecognized);
            Assert.Equal((PgpSignatureSubpacketType)100, unrecognized[0]);
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

            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets:
                [
                    PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow),
                ],
                unhashedSubpackets:
                [
                    PgpSignatureSubpacket.CreateIssuerKeyId(new byte[8]),
                ],
                hashPrefix: 0x1234,
                signatureData: TestHelpers.RandomBytes(128));

            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.Signature, tag);

            var decoded = PgpSignaturePacket.Read(body.Span);
            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.SignatureType, decoded.SignatureType);
            Assert.Equal(original.HashPrefix, decoded.HashPrefix);
        }

        [Fact]
        public void WriteTo_OldFormat_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[50]);

            original.WriteTo(writer, PgpPacketFormat.Old);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) == 0); // Old format
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
        public void ToString_IncludesVersionAndType()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            var str = packet.ToString();

            Assert.Contains("v4", str);
            Assert.Contains("BinaryDocument", str);
        }

        [Fact]
        public void ToString_WithCreationTime_IncludesDate()
        {
            var time = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [PgpSignatureSubpacket.CreateSignatureCreationTime(time)],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[128]);

            var str = packet.ToString();

            Assert.Contains("2024", str);
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
        public void RoundTrip_EmptySignatureData_Succeeds()
        {
            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: Array.Empty<byte>());

            var encoded = original.ToArray();
            var decoded = PgpSignaturePacket.Read(encoded);

            Assert.Empty(decoded.SignatureData.ToArray());
        }

        [Fact]
        public void RoundTrip_ManySubpackets_Succeeds()
        {
            var hashedSubpackets = new List<PgpSignatureSubpacket>();
            for (int i = 0; i < 20; i++)
            {
                hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredHashAlgorithms([8, 9, 10]));
            }

            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.GenericCertification,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: hashedSubpackets,
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[64]);

            var encoded = original.ToArray();
            var decoded = PgpSignaturePacket.Read(encoded);

            Assert.Equal(20, decoded.HashedSubpackets.Count);
        }

        [Fact]
        public void RoundTrip_LargeSubpacketData_Succeeds()
        {
            // Subpacket with > 192 bytes of data (requires two-byte length encoding)
            var largeData = TestHelpers.RandomBytes(500);
            var subpacket = new PgpSignatureSubpacket(
                PgpSignatureSubpacketType.NotationData,
                false,
                largeData);

            var original = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets: [subpacket],
                unhashedSubpackets: [],
                hashPrefix: 0,
                signatureData: new byte[64]);

            var encoded = original.ToArray();
            var decoded = PgpSignaturePacket.Read(encoded);

            Assert.Equal(largeData, decoded.HashedSubpackets[0].Data.ToArray());
        }

        [Fact]
        public void GetEncodedLength_MatchesActualLength()
        {
            var packet = PgpSignaturePacket.CreateV4(
                PgpSignatureType.BinaryDocument,
                publicKeyAlgorithm: 1,
                hashAlgorithm: 8,
                hashedSubpackets:
                [
                    PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow),
                    PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.Sign),
                ],
                unhashedSubpackets:
                [
                    PgpSignatureSubpacket.CreateIssuerKeyId(new byte[8]),
                ],
                hashPrefix: 0x5678,
                signatureData: TestHelpers.RandomBytes(128));

            var expectedLength = packet.GetEncodedLength();
            var actualLength = packet.ToArray().Length;

            Assert.Equal(expectedLength, actualLength);
        }
    }

    /// <summary>
    /// Key flags enum tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyFlagsTests
    {
        [Fact]
        public void KeyFlags_Certify_HasCorrectValue()
        {
            Assert.Equal(0x01, (byte)PgpKeyCapabilities.Certify);
        }

        [Fact]
        public void KeyFlags_Sign_HasCorrectValue()
        {
            Assert.Equal(0x02, (byte)PgpKeyCapabilities.Sign);
        }

        [Fact]
        public void KeyFlags_EncryptCommunications_HasCorrectValue()
        {
            Assert.Equal(0x04, (byte)PgpKeyCapabilities.EncryptCommunications);
        }

        [Fact]
        public void KeyFlags_EncryptStorage_HasCorrectValue()
        {
            Assert.Equal(0x08, (byte)PgpKeyCapabilities.EncryptStorage);
        }

        [Fact]
        public void KeyFlags_Authentication_HasCorrectValue()
        {
            Assert.Equal(0x20, (byte)PgpKeyCapabilities.Authentication);
        }

        [Fact]
        public void KeyFlags_Combined_WorksCorrectly()
        {
            var combined = PgpKeyCapabilities.Sign | PgpKeyCapabilities.Certify | PgpKeyCapabilities.Authentication;

            Assert.True(combined.HasFlag(PgpKeyCapabilities.Sign));
            Assert.True(combined.HasFlag(PgpKeyCapabilities.Certify));
            Assert.True(combined.HasFlag(PgpKeyCapabilities.Authentication));
            Assert.False(combined.HasFlag(PgpKeyCapabilities.EncryptCommunications));
        }
    }

    /// <summary>
    /// Feature flags enum tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FeatureFlagsTests
    {
        [Fact]
        public void FeatureFlags_ModificationDetection_HasCorrectValue()
        {
            Assert.Equal(0x01, (byte)PgpFeatures.ModificationDetection);
        }

        [Fact]
        public void FeatureFlags_AeadEncryptedData_HasCorrectValue()
        {
            Assert.Equal(0x02, (byte)PgpFeatures.AeadEncryptedData);
        }

        [Fact]
        public void FeatureFlags_Version6Keys_HasCorrectValue()
        {
            Assert.Equal(0x04, (byte)PgpFeatures.Version6Keys);
        }
    }
}
