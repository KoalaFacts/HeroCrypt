using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Signature Packet (Tag 2) as defined in RFC 4880 Section 5.2.
/// </summary>
/// <remarks>
/// <para>
/// A Signature packet contains a digital signature. This implementation supports
/// version 4 signatures (RFC 4880) and version 6 signatures (RFC 9580).
/// </para>
/// <para>
/// <b>Version 4 Wire format:</b>
/// <code>
/// +----+------+------+------+--------+--------+--------+--------+------+------+
/// |Ver |SigTyp|PubAlg|Hash |HashedLen|Hashed |UnhashLen|Unhashed|Left16| MPIs |
/// |1 B | 1 B  | 1 B  | 1 B | 2 B    | var   | 2 B    | var    | 2 B  | var  |
/// +----+------+------+------+--------+--------+--------+--------+------+------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpSignaturePacket
{
    /// <summary>
    /// Gets the signature version (4 or 6).
    /// </summary>
    public byte Version { get; }

    /// <summary>
    /// Gets the signature type.
    /// </summary>
    public PgpSignatureType SignatureType { get; }

    /// <summary>
    /// Gets the public-key algorithm ID.
    /// </summary>
    public byte PublicKeyAlgorithm { get; }

    /// <summary>
    /// Gets the hash algorithm ID.
    /// </summary>
    public byte HashAlgorithm { get; }

    /// <summary>
    /// Gets the hashed subpackets (included in signature hash).
    /// </summary>
    public IReadOnlyList<PgpSignatureSubpacket> HashedSubpackets { get; }

    /// <summary>
    /// Gets the unhashed subpackets (not included in signature hash).
    /// </summary>
    public IReadOnlyList<PgpSignatureSubpacket> UnhashedSubpackets { get; }

    /// <summary>
    /// Gets the left 16 bits of the signed hash value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is used as a quick check to see if the signature is likely valid
    /// before performing the expensive signature verification.
    /// </para>
    /// </remarks>
    public ushort HashPrefix { get; }

    /// <summary>
    /// Gets the signature data (algorithm-specific MPIs or raw bytes for EdDSA).
    /// </summary>
    public ReadOnlyMemory<byte> SignatureData { get; }

    /// <summary>
    /// Gets the salt for V6 signatures (RFC 9580).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The salt is included in the hash computation and helps prevent attacks
    /// that depend on the ability to predict the signature. The salt length
    /// depends on the hash algorithm used.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>
    /// Initializes a new signature packet.
    /// </summary>
    /// <param name="version">The signature version.</param>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="publicKeyAlgorithm">The public-key algorithm ID.</param>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="hashedSubpackets">The hashed subpackets.</param>
    /// <param name="unhashedSubpackets">The unhashed subpackets.</param>
    /// <param name="hashPrefix">The left 16 bits of the signed hash.</param>
    /// <param name="signatureData">The signature data.</param>
    /// <param name="salt">The salt for V6 signatures (RFC 9580). Required for V6, ignored for V4.</param>
    public PgpSignaturePacket(
        byte version,
        PgpSignatureType signatureType,
        byte publicKeyAlgorithm,
        byte hashAlgorithm,
        IReadOnlyList<PgpSignatureSubpacket> hashedSubpackets,
        IReadOnlyList<PgpSignatureSubpacket> unhashedSubpackets,
        ushort hashPrefix,
        ReadOnlyMemory<byte> signatureData,
        ReadOnlyMemory<byte> salt = default)
    {
        if (version != 4 && version != 6)
        {
            throw new ArgumentException("Only signature versions 4 and 6 are supported.", nameof(version));
        }

        if (version == 6 && salt.IsEmpty)
        {
            throw new ArgumentException("V6 signatures require a salt.", nameof(salt));
        }

        Version = version;
        SignatureType = signatureType;
        PublicKeyAlgorithm = publicKeyAlgorithm;
        HashAlgorithm = hashAlgorithm;
        HashedSubpackets = hashedSubpackets ?? [];
        UnhashedSubpackets = unhashedSubpackets ?? [];
        HashPrefix = hashPrefix;
        SignatureData = signatureData;
        Salt = version == 6 ? salt : ReadOnlyMemory<byte>.Empty;
    }

    /// <summary>
    /// Creates a version 4 signature packet.
    /// </summary>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="publicKeyAlgorithm">The public-key algorithm ID.</param>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="hashedSubpackets">The hashed subpackets.</param>
    /// <param name="unhashedSubpackets">The unhashed subpackets.</param>
    /// <param name="hashPrefix">The left 16 bits of the signed hash.</param>
    /// <param name="signatureData">The signature data (MPIs).</param>
    /// <returns>A new version 4 signature packet.</returns>
    public static PgpSignaturePacket CreateV4(
        PgpSignatureType signatureType,
        byte publicKeyAlgorithm,
        byte hashAlgorithm,
        IReadOnlyList<PgpSignatureSubpacket> hashedSubpackets,
        IReadOnlyList<PgpSignatureSubpacket>? unhashedSubpackets,
        ushort hashPrefix,
        ReadOnlyMemory<byte> signatureData)
    {
        return new PgpSignaturePacket(
            version: 4,
            signatureType,
            publicKeyAlgorithm,
            hashAlgorithm,
            hashedSubpackets,
            unhashedSubpackets ?? [],
            hashPrefix,
            signatureData);
    }

    /// <summary>
    /// Creates a version 6 signature packet (RFC 9580).
    /// </summary>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="publicKeyAlgorithm">The public-key algorithm ID.</param>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="hashedSubpackets">The hashed subpackets.</param>
    /// <param name="unhashedSubpackets">The unhashed subpackets.</param>
    /// <param name="hashPrefix">The left 16 bits of the signed hash.</param>
    /// <param name="salt">The salt (length depends on hash algorithm).</param>
    /// <param name="signatureData">The signature data.</param>
    /// <returns>A new version 6 signature packet.</returns>
    public static PgpSignaturePacket CreateV6(
        PgpSignatureType signatureType,
        byte publicKeyAlgorithm,
        byte hashAlgorithm,
        IReadOnlyList<PgpSignatureSubpacket> hashedSubpackets,
        IReadOnlyList<PgpSignatureSubpacket>? unhashedSubpackets,
        ushort hashPrefix,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> signatureData)
    {
        return new PgpSignaturePacket(
            version: 6,
            signatureType,
            publicKeyAlgorithm,
            hashAlgorithm,
            hashedSubpackets,
            unhashedSubpackets ?? [],
            hashPrefix,
            signatureData,
            salt);
    }

    /// <summary>
    /// Gets the expected salt length for a given hash algorithm per RFC 9580.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <returns>The expected salt length in bytes.</returns>
    public static int GetExpectedSaltLength(byte hashAlgorithm)
    {
        // Per RFC 9580 Section 5.2.3:
        // The salt SHOULD be the digest output size of the hash algorithm.
        // Common algorithms and their output sizes:
        return hashAlgorithm switch
        {
            1 => 16,   // MD5 (deprecated, but included for completeness)
            2 => 20,   // SHA-1 (deprecated)
            3 => 20,   // RIPE-MD/160
            8 => 32,   // SHA-256
            9 => 48,   // SHA-384
            10 => 64,  // SHA-512
            11 => 28,  // SHA-224
            12 => 32,  // SHA3-256
            14 => 64,  // SHA3-512
            _ => 32,   // Default to 32 bytes for unknown algorithms
        };
    }

    /// <summary>
    /// Reads a signature packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed signature packet.</returns>
    /// <exception cref="ArgumentException">If the source is too short or malformed.</exception>
    public static PgpSignaturePacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a signature packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSignaturePacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for signature packet version.";
            return false;
        }

        byte version = source[0];
        if (version == 4)
        {
            return TryReadV4(source, out packet, out error);
        }

        if (version == 6)
        {
            return TryReadV6(source, out packet, out error);
        }

        error = $"Unsupported signature version: {version}. Only versions 4 and 6 are supported.";
        return false;
    }

    private static bool TryReadV4(ReadOnlySpan<byte> source, out PgpSignaturePacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        // Minimum: version(1) + sigtype(1) + pubalg(1) + hashalg(1) + hashedlen(2) + unhashedlen(2) + hash16(2) = 10
        if (source.Length < 10)
        {
            error = "Source too short for v4 signature packet header.";
            return false;
        }

        int offset = 0;

        byte version = source[offset++];
        var signatureType = (PgpSignatureType)source[offset++];
        byte publicKeyAlgorithm = source[offset++];
        byte hashAlgorithm = source[offset++];

        // Read hashed subpackets
        ushort hashedLength = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(offset));
        offset += 2;

        if (source.Length < offset + hashedLength + 2 + 2)
        {
            error = $"Source too short for hashed subpackets. Need at least {offset + hashedLength + 4} bytes.";
            return false;
        }

        List<PgpSignatureSubpacket> hashedSubpackets;
        try
        {
            hashedSubpackets = PgpSignatureSubpacket.ReadAll(source.Slice(offset, hashedLength));
        }
        catch (ArgumentException ex)
        {
            error = $"Failed to parse hashed subpackets: {ex.Message}";
            return false;
        }

        offset += hashedLength;

        // Read unhashed subpackets
        ushort unhashedLength = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(offset));
        offset += 2;

        if (source.Length < offset + unhashedLength + 2)
        {
            error = $"Source too short for unhashed subpackets. Need at least {offset + unhashedLength + 2} bytes.";
            return false;
        }

        List<PgpSignatureSubpacket> unhashedSubpackets;
        try
        {
            unhashedSubpackets = PgpSignatureSubpacket.ReadAll(source.Slice(offset, unhashedLength));
        }
        catch (ArgumentException ex)
        {
            error = $"Failed to parse unhashed subpackets: {ex.Message}";
            return false;
        }

        offset += unhashedLength;

        // Read hash prefix
        if (source.Length < offset + 2)
        {
            error = "Source too short for hash prefix.";
            return false;
        }

        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(offset));
        offset += 2;

        // Remaining data is signature MPIs
        var signatureData = source.Slice(offset).ToArray();

        packet = new PgpSignaturePacket(
            version,
            signatureType,
            publicKeyAlgorithm,
            hashAlgorithm,
            hashedSubpackets,
            unhashedSubpackets,
            hashPrefix,
            signatureData);

        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, out PgpSignaturePacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        // V6 has similar structure but with 4-byte subpacket lengths
        // Minimum: version(1) + sigtype(1) + pubalg(1) + hashalg(1) + hashedlen(4) + unhashedlen(4) + hash16(2) = 14
        if (source.Length < 14)
        {
            error = "Source too short for v6 signature packet header.";
            return false;
        }

        int offset = 0;

        byte version = source[offset++];
        var signatureType = (PgpSignatureType)source[offset++];
        byte publicKeyAlgorithm = source[offset++];
        byte hashAlgorithm = source[offset++];

        // Read hashed subpackets (4-byte length in v6)
        uint hashedLength = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;

        if (hashedLength > int.MaxValue || source.Length < offset + (int)hashedLength + 4 + 2)
        {
            error = $"Source too short for hashed subpackets or length too large.";
            return false;
        }

        List<PgpSignatureSubpacket> hashedSubpackets;
        try
        {
            hashedSubpackets = PgpSignatureSubpacket.ReadAll(source.Slice(offset, (int)hashedLength));
        }
        catch (ArgumentException ex)
        {
            error = $"Failed to parse hashed subpackets: {ex.Message}";
            return false;
        }

        offset += (int)hashedLength;

        // Read unhashed subpackets (4-byte length in v6)
        uint unhashedLength = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;

        if (unhashedLength > int.MaxValue || source.Length < offset + (int)unhashedLength + 2)
        {
            error = $"Source too short for unhashed subpackets or length too large.";
            return false;
        }

        List<PgpSignatureSubpacket> unhashedSubpackets;
        try
        {
            unhashedSubpackets = PgpSignatureSubpacket.ReadAll(source.Slice(offset, (int)unhashedLength));
        }
        catch (ArgumentException ex)
        {
            error = $"Failed to parse unhashed subpackets: {ex.Message}";
            return false;
        }

        offset += (int)unhashedLength;

        // Read hash prefix
        if (source.Length < offset + 2)
        {
            error = "Source too short for hash prefix.";
            return false;
        }

        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(offset));
        offset += 2;

        // In v6, read the salt length and salt before signature data
        // Per RFC 9580 Section 5.2.3
        if (source.Length < offset + 1)
        {
            error = "Source too short for salt length.";
            return false;
        }

        byte saltLength = source[offset++];

        if (source.Length < offset + saltLength)
        {
            error = $"Source too short for salt. Need {saltLength} bytes.";
            return false;
        }

        var salt = source.Slice(offset, saltLength).ToArray();
        offset += saltLength;

        // Remaining data is signature
        var signatureData = source.Slice(offset).ToArray();

        packet = new PgpSignaturePacket(
            version,
            signatureType,
            publicKeyAlgorithm,
            hashAlgorithm,
            hashedSubpackets,
            unhashedSubpackets,
            hashPrefix,
            signatureData,
            salt);

        return true;
    }

    /// <summary>
    /// Gets the total encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(HashedSubpackets);
        var unhashedSubpacketData = PgpSignatureSubpacket.WriteAll(UnhashedSubpackets);

        if (Version == 4)
        {
            // version(1) + sigtype(1) + pubalg(1) + hashalg(1) + hashedlen(2) + hashed + unhashedlen(2) + unhashed + hash16(2) + sig
            return 1 + 1 + 1 + 1 + 2 + hashedSubpacketData.Length + 2 + unhashedSubpacketData.Length + 2 + SignatureData.Length;
        }
        else
        {
            // V6: version(1) + sigtype(1) + pubalg(1) + hashalg(1) + hashedlen(4) + hashed + unhashedlen(4) + unhashed + hash16(2) + saltlen(1) + salt + sig
            return 1 + 1 + 1 + 1 + 4 + hashedSubpacketData.Length + 4 + unhashedSubpacketData.Length + 2 + 1 + Salt.Length + SignatureData.Length;
        }
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            throw new ArgumentException($"Destination too small. Need {encodedLength} bytes.", nameof(destination));
        }

        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(HashedSubpackets);
        var unhashedSubpacketData = PgpSignatureSubpacket.WriteAll(UnhashedSubpackets);

        int offset = 0;

        // Write header
        destination[offset++] = Version;
        destination[offset++] = (byte)SignatureType;
        destination[offset++] = PublicKeyAlgorithm;
        destination[offset++] = HashAlgorithm;

        // Write hashed subpackets
        if (Version == 4)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset), (ushort)hashedSubpacketData.Length);
            offset += 2;
        }
        else
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset), (uint)hashedSubpacketData.Length);
            offset += 4;
        }

        hashedSubpacketData.CopyTo(destination.Slice(offset));
        offset += hashedSubpacketData.Length;

        // Write unhashed subpackets
        if (Version == 4)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset), (ushort)unhashedSubpacketData.Length);
            offset += 2;
        }
        else
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset), (uint)unhashedSubpacketData.Length);
            offset += 4;
        }

        unhashedSubpacketData.CopyTo(destination.Slice(offset));
        offset += unhashedSubpacketData.Length;

        // Write hash prefix
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset), HashPrefix);
        offset += 2;

        // For V6, write salt length and salt
        if (Version == 6)
        {
            destination[offset++] = (byte)Salt.Length;
            Salt.Span.CopyTo(destination.Slice(offset));
            offset += Salt.Length;
        }

        // Write signature data
        SignatureData.Span.CopyTo(destination.Slice(offset));
        offset += SignatureData.Length;

        return offset;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The encoded packet body.</returns>
    public byte[] ToArray()
    {
        byte[] result = new byte[GetEncodedLength()];
        Write(result);
        return result;
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.Signature, body, format);
    }

    /// <summary>
    /// Gets the signature creation time from the hashed subpackets.
    /// </summary>
    /// <returns>The signature creation time, or null if not present.</returns>
    public DateTimeOffset? GetCreationTime()
    {
        foreach (var subpacket in HashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.SignatureCreationTime)
            {
                return subpacket.GetSignatureCreationTime();
            }
        }

        return null;
    }

    /// <summary>
    /// Gets the issuer key ID from the subpackets (checks unhashed first, then hashed).
    /// </summary>
    /// <returns>The issuer key ID, or null if not present.</returns>
    public byte[]? GetIssuerKeyId()
    {
        // Check unhashed first (common location for issuer key ID)
        foreach (var subpacket in UnhashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.IssuerKeyId)
            {
                return subpacket.GetIssuerKeyId();
            }
        }

        // Check hashed
        foreach (var subpacket in HashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.IssuerKeyId)
            {
                return subpacket.GetIssuerKeyId();
            }
        }

        return null;
    }

    /// <summary>
    /// Gets the issuer fingerprint from the subpackets.
    /// </summary>
    /// <returns>The issuer fingerprint (version + fingerprint), or null if not present.</returns>
    public byte[]? GetIssuerFingerprint()
    {
        foreach (var subpacket in HashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.IssuerFingerprint)
            {
                return subpacket.Data.ToArray();
            }
        }

        foreach (var subpacket in UnhashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.IssuerFingerprint)
            {
                return subpacket.Data.ToArray();
            }
        }

        return null;
    }

    /// <summary>
    /// Gets the key flags from the hashed subpackets.
    /// </summary>
    /// <returns>The key flags, or null if not present.</returns>
    public PgpKeyCapabilities? GetKeyFlags()
    {
        foreach (var subpacket in HashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.KeyFlags)
            {
                return subpacket.GetKeyFlags();
            }
        }

        return null;
    }

    /// <summary>
    /// Reads the RSA signature as MPIs.
    /// </summary>
    /// <returns>The RSA signature value.</returns>
    /// <exception cref="InvalidOperationException">If the signature data is malformed.</exception>
    public BigInteger ReadRsaSignature()
    {
        return Mpi.Read(SignatureData.Span, out _);
    }

    /// <summary>
    /// Reads the DSA/ECDSA signature as two MPIs (r, s).
    /// </summary>
    /// <returns>A tuple of (r, s) values.</returns>
    /// <exception cref="InvalidOperationException">If the signature data is malformed.</exception>
    public (BigInteger R, BigInteger S) ReadDsaSignature()
    {
        var r = Mpi.Read(SignatureData.Span, out int consumed);
        var s = Mpi.Read(SignatureData.Span.Slice(consumed), out _);
        return (r, s);
    }

    /// <summary>
    /// Reads the EdDSA signature as raw bytes.
    /// </summary>
    /// <returns>The EdDSA signature bytes.</returns>
    public byte[] ReadEdDsaSignature()
    {
        // EdDSA in OpenPGP uses native format (64 bytes for Ed25519)
        // In RFC 9580, it may be stored as MPI or raw depending on version
        // For v6, it's typically raw. For v4 with algorithm 27/28, it's MPI-encoded.

        // Try MPI format first
        if (SignatureData.Length >= 2)
        {
            if (Mpi.TryRead(SignatureData.Span, out _, out int consumed) && consumed <= SignatureData.Length)
            {
                // Read as MPI
                return Mpi.ReadBytes(SignatureData.Span, out _);
            }
        }

        // Return as raw bytes
        return SignatureData.ToArray();
    }

    /// <summary>
    /// Checks if any critical subpackets are unrecognized.
    /// </summary>
    /// <param name="recognizedTypes">Set of recognized subpacket types.</param>
    /// <returns>List of unrecognized critical subpacket types.</returns>
    public List<PgpSignatureSubpacketType> GetUnrecognizedCriticalSubpackets(ISet<PgpSignatureSubpacketType>? recognizedTypes = null)
    {
        recognizedTypes ??= GetStandardSubpacketTypes();
        var unrecognized = new List<PgpSignatureSubpacketType>();

        foreach (var subpacket in HashedSubpackets)
        {
            if (subpacket.IsCritical && !recognizedTypes.Contains(subpacket.Type))
            {
                unrecognized.Add(subpacket.Type);
            }
        }

        foreach (var subpacket in UnhashedSubpackets)
        {
            if (subpacket.IsCritical && !recognizedTypes.Contains(subpacket.Type))
            {
                unrecognized.Add(subpacket.Type);
            }
        }

        return unrecognized;
    }

    private static HashSet<PgpSignatureSubpacketType> GetStandardSubpacketTypes()
    {
        return
        [
            PgpSignatureSubpacketType.SignatureCreationTime,
            PgpSignatureSubpacketType.SignatureExpirationTime,
            PgpSignatureSubpacketType.ExportableCertification,
            PgpSignatureSubpacketType.TrustSignature,
            PgpSignatureSubpacketType.RegularExpression,
            PgpSignatureSubpacketType.Revocable,
            PgpSignatureSubpacketType.KeyExpirationTime,
            PgpSignatureSubpacketType.PreferredSymmetricAlgorithms,
            PgpSignatureSubpacketType.RevocationKey,
            PgpSignatureSubpacketType.IssuerKeyId,
            PgpSignatureSubpacketType.NotationData,
            PgpSignatureSubpacketType.PreferredHashAlgorithms,
            PgpSignatureSubpacketType.PreferredCompressionAlgorithms,
            PgpSignatureSubpacketType.KeyServerPreferences,
            PgpSignatureSubpacketType.PreferredKeyServer,
            PgpSignatureSubpacketType.PrimaryUserId,
            PgpSignatureSubpacketType.PolicyUri,
            PgpSignatureSubpacketType.KeyFlags,
            PgpSignatureSubpacketType.SignersUserId,
            PgpSignatureSubpacketType.ReasonForRevocation,
            PgpSignatureSubpacketType.Features,
            PgpSignatureSubpacketType.SignatureTarget,
            PgpSignatureSubpacketType.EmbeddedSignature,
            PgpSignatureSubpacketType.IssuerFingerprint,
            PgpSignatureSubpacketType.PreferredAeadAlgorithms,
            PgpSignatureSubpacketType.IntendedRecipientFingerprint,
        ];
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        var creationTime = GetCreationTime();
        var timeStr = creationTime.HasValue ? creationTime.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "unknown";
        return $"Signature(v{Version}, {SignatureType}, created {timeStr}, {HashedSubpackets.Count} hashed, {UnhashedSubpackets.Count} unhashed)";
    }
}
