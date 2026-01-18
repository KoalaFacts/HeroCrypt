namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a One-Pass Signature Packet (Tag 4) as defined in RFC 4880 Section 5.4 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// A One-Pass Signature packet precedes the signed data and enables streaming verification
/// by providing the signature metadata before the data is processed. After the data,
/// a corresponding Signature packet follows with the actual signature.
/// </para>
/// <para>
/// <b>Version 3 Wire format (RFC 4880):</b>
/// <code>
/// +-----+--------+--------+--------+---------+--------+
/// | Ver | SigTyp | HashAlg| PubAlg |  KeyID  | Nested |
/// | 1 B |  1 B   |  1 B   |  1 B   |   8 B   |  1 B   |
/// +-----+--------+--------+--------+---------+--------+
/// </code>
/// </para>
/// <para>
/// <b>Version 6 Wire format (RFC 9580):</b>
/// <code>
/// +-----+--------+--------+--------+------+-------------+--------+
/// | Ver | SigTyp | HashAlg| PubAlg | Salt | Fingerprint | Nested |
/// | 1 B |  1 B   |  1 B   |  1 B   | var  |    32 B     |  1 B   |
/// +-----+--------+--------+--------+------+-------------+--------+
/// </code>
/// </para>
/// <para>
/// The nested flag indicates whether this is the last one-pass signature (1) or if
/// another one-pass signature packet follows (0), enabling nested/multiple signatures.
/// </para>
/// </remarks>
public readonly struct PgpOnePassSignaturePacket : IEquatable<PgpOnePassSignaturePacket>
{
    /// <summary>
    /// Version 3 packet length: version(1) + sigtype(1) + hash(1) + pubalg(1) + keyid(8) + nested(1) = 13.
    /// </summary>
    private const int V3PacketLength = 13;

    /// <summary>
    /// Key ID length in version 3 packets.
    /// </summary>
    private const int KeyIdLength = 8;

    /// <summary>
    /// Fingerprint length in version 6 packets.
    /// </summary>
    private const int V6FingerprintLength = 32;

    /// <summary>
    /// Gets the packet version (3 or 6).
    /// </summary>
    public byte Version { get; }

    /// <summary>
    /// Gets the signature type.
    /// </summary>
    public PgpSignatureType SignatureType { get; }

    /// <summary>
    /// Gets the hash algorithm ID.
    /// </summary>
    public byte HashAlgorithm { get; }

    /// <summary>
    /// Gets the public-key algorithm ID.
    /// </summary>
    public byte PublicKeyAlgorithm { get; }

    /// <summary>
    /// Gets the issuer key ID (for version 3) or fingerprint (for version 6).
    /// </summary>
    /// <remarks>
    /// <para>
    /// For version 3 packets, this is the 8-byte key ID.
    /// For version 6 packets, this is the 32-byte fingerprint.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> KeyIdOrFingerprint { get; }

    /// <summary>
    /// Gets the salt value (only for version 6 packets).
    /// </summary>
    /// <remarks>
    /// The salt is used in version 6 signatures to provide domain separation.
    /// For version 3 packets, this is empty.
    /// </remarks>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>
    /// Gets whether this is the last one-pass signature (true) or more follow (false).
    /// </summary>
    /// <remarks>
    /// <para>
    /// When multiple signatures are applied to the same data, multiple one-pass
    /// signature packets precede the data. The nested flag is 0 for all but the
    /// last one-pass signature packet.
    /// </para>
    /// </remarks>
    public bool IsNested { get; }

    /// <summary>
    /// Initializes a new One-Pass Signature packet.
    /// </summary>
    /// <param name="version">The packet version (3 or 6).</param>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="publicKeyAlgorithm">The public-key algorithm ID.</param>
    /// <param name="keyIdOrFingerprint">The issuer key ID (v3) or fingerprint (v6).</param>
    /// <param name="salt">The salt value (v6 only, empty for v3).</param>
    /// <param name="isNested">Whether this is the last one-pass signature.</param>
    /// <exception cref="ArgumentException">If the version is not 3 or 6, or if key ID/fingerprint has wrong length.</exception>
    public PgpOnePassSignaturePacket(
        byte version,
        PgpSignatureType signatureType,
        byte hashAlgorithm,
        byte publicKeyAlgorithm,
        ReadOnlyMemory<byte> keyIdOrFingerprint,
        ReadOnlyMemory<byte> salt,
        bool isNested)
    {
        if (version != 3 && version != 6)
        {
            throw new ArgumentException("Only versions 3 and 6 are supported.", nameof(version));
        }

        if (version == 3 && keyIdOrFingerprint.Length != KeyIdLength)
        {
            throw new ArgumentException($"Version 3 requires an 8-byte key ID, got {keyIdOrFingerprint.Length} bytes.", nameof(keyIdOrFingerprint));
        }

        if (version == 6 && keyIdOrFingerprint.Length != V6FingerprintLength)
        {
            throw new ArgumentException($"Version 6 requires a 32-byte fingerprint, got {keyIdOrFingerprint.Length} bytes.", nameof(keyIdOrFingerprint));
        }

        Version = version;
        SignatureType = signatureType;
        HashAlgorithm = hashAlgorithm;
        PublicKeyAlgorithm = publicKeyAlgorithm;
        KeyIdOrFingerprint = keyIdOrFingerprint;
        Salt = version == 6 ? salt : ReadOnlyMemory<byte>.Empty;
        IsNested = isNested;
    }

    /// <summary>
    /// Creates a version 3 One-Pass Signature packet.
    /// </summary>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="publicKeyAlgorithm">The public-key algorithm ID.</param>
    /// <param name="keyId">The 8-byte issuer key ID.</param>
    /// <param name="isNested">Whether this is the last one-pass signature (default: true).</param>
    /// <returns>A new version 3 One-Pass Signature packet.</returns>
    public static PgpOnePassSignaturePacket CreateV3(
        PgpSignatureType signatureType,
        byte hashAlgorithm,
        byte publicKeyAlgorithm,
        ReadOnlyMemory<byte> keyId,
        bool isNested = true)
    {
        return new PgpOnePassSignaturePacket(
            version: 3,
            signatureType,
            hashAlgorithm,
            publicKeyAlgorithm,
            keyId,
            salt: ReadOnlyMemory<byte>.Empty,
            isNested);
    }

    /// <summary>
    /// Creates a version 6 One-Pass Signature packet.
    /// </summary>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="publicKeyAlgorithm">The public-key algorithm ID.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="fingerprint">The 32-byte issuer fingerprint.</param>
    /// <param name="isNested">Whether this is the last one-pass signature (default: true).</param>
    /// <returns>A new version 6 One-Pass Signature packet.</returns>
    public static PgpOnePassSignaturePacket CreateV6(
        PgpSignatureType signatureType,
        byte hashAlgorithm,
        byte publicKeyAlgorithm,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> fingerprint,
        bool isNested = true)
    {
        return new PgpOnePassSignaturePacket(
            version: 6,
            signatureType,
            hashAlgorithm,
            publicKeyAlgorithm,
            fingerprint,
            salt,
            isNested);
    }

    /// <summary>
    /// Gets the issuer key ID (version 3 only).
    /// </summary>
    /// <returns>The 8-byte key ID.</returns>
    /// <exception cref="InvalidOperationException">If this is a version 6 packet.</exception>
    public byte[] GetKeyId()
    {
        if (Version != 3)
        {
            throw new InvalidOperationException("Key ID is only available for version 3 packets. Use GetFingerprint() for version 6.");
        }

        return KeyIdOrFingerprint.ToArray();
    }

    /// <summary>
    /// Gets the issuer fingerprint (version 6 only).
    /// </summary>
    /// <returns>The 32-byte fingerprint.</returns>
    /// <exception cref="InvalidOperationException">If this is a version 3 packet.</exception>
    public byte[] GetFingerprint()
    {
        if (Version != 6)
        {
            throw new InvalidOperationException("Fingerprint is only available for version 6 packets. Use GetKeyId() for version 3.");
        }

        return KeyIdOrFingerprint.ToArray();
    }

    /// <summary>
    /// Gets the key ID from the fingerprint for version 6 packets.
    /// </summary>
    /// <returns>The first 8 bytes of the fingerprint as key ID.</returns>
    /// <remarks>
    /// For version 6, the key ID is the first 8 bytes of the fingerprint.
    /// For version 3, this returns the key ID directly.
    /// </remarks>
    public byte[] GetKeyIdFromFingerprint()
    {
        if (Version == 3)
        {
            return KeyIdOrFingerprint.ToArray();
        }

        // V6: Key ID is first 8 bytes of fingerprint
        return KeyIdOrFingerprint.Slice(0, KeyIdLength).ToArray();
    }

    /// <summary>
    /// Reads a One-Pass Signature packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed One-Pass Signature packet.</returns>
    /// <exception cref="ArgumentException">If the source is too short or malformed.</exception>
    public static PgpOnePassSignaturePacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a One-Pass Signature packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpOnePassSignaturePacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for One-Pass Signature packet version.";
            return false;
        }

        byte version = source[0];
        if (version == 3)
        {
            return TryReadV3(source, out packet, out error);
        }

        if (version == 6)
        {
            return TryReadV6(source, out packet, out error);
        }

        error = $"Unsupported One-Pass Signature version: {version}. Only versions 3 and 6 are supported.";
        return false;
    }

    private static bool TryReadV3(ReadOnlySpan<byte> source, out PgpOnePassSignaturePacket packet, out string error)
    {
        packet = default;

        if (source.Length < V3PacketLength)
        {
            error = $"Source too short for v3 One-Pass Signature packet. Need {V3PacketLength} bytes, got {source.Length}.";
            return false;
        }

        int offset = 0;

        byte version = source[offset++];
        var signatureType = (PgpSignatureType)source[offset++];
        byte hashAlgorithm = source[offset++];
        byte publicKeyAlgorithm = source[offset++];

        var keyId = source.Slice(offset, KeyIdLength).ToArray();
        offset += KeyIdLength;

        bool isNested = source[offset] != 0;

        packet = new PgpOnePassSignaturePacket(
            version,
            signatureType,
            hashAlgorithm,
            publicKeyAlgorithm,
            keyId,
            salt: ReadOnlyMemory<byte>.Empty,
            isNested);

        error = string.Empty;
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, out PgpOnePassSignaturePacket packet, out string error)
    {
        packet = default;

        // Minimum: version(1) + sigtype(1) + hash(1) + pubalg(1) + saltlen(1) = 5
        if (source.Length < 5)
        {
            error = "Source too short for v6 One-Pass Signature packet header.";
            return false;
        }

        int offset = 0;

        byte version = source[offset++];
        var signatureType = (PgpSignatureType)source[offset++];
        byte hashAlgorithm = source[offset++];
        byte publicKeyAlgorithm = source[offset++];

        // Read salt length and salt
        byte saltLength = source[offset++];

        if (source.Length < 5 + saltLength + V6FingerprintLength + 1)
        {
            error = $"Source too short for v6 One-Pass Signature packet. Need at least {5 + saltLength + V6FingerprintLength + 1} bytes.";
            return false;
        }

        var salt = source.Slice(offset, saltLength).ToArray();
        offset += saltLength;

        var fingerprint = source.Slice(offset, V6FingerprintLength).ToArray();
        offset += V6FingerprintLength;

        bool isNested = source[offset] != 0;

        packet = new PgpOnePassSignaturePacket(
            version,
            signatureType,
            hashAlgorithm,
            publicKeyAlgorithm,
            fingerprint,
            salt,
            isNested);

        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the total encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        if (Version == 3)
        {
            return V3PacketLength;
        }

        // V6: version(1) + sigtype(1) + hash(1) + pubalg(1) + saltlen(1) + salt + fingerprint(32) + nested(1)
        return 5 + Salt.Length + V6FingerprintLength + 1;
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

        int offset = 0;

        destination[offset++] = Version;
        destination[offset++] = (byte)SignatureType;
        destination[offset++] = HashAlgorithm;
        destination[offset++] = PublicKeyAlgorithm;

        if (Version == 3)
        {
            KeyIdOrFingerprint.Span.CopyTo(destination.Slice(offset));
            offset += KeyIdLength;
        }
        else
        {
            // V6: write salt length + salt + fingerprint
            destination[offset++] = (byte)Salt.Length;
            Salt.Span.CopyTo(destination.Slice(offset));
            offset += Salt.Length;

            KeyIdOrFingerprint.Span.CopyTo(destination.Slice(offset));
            offset += V6FingerprintLength;
        }

        destination[offset++] = (byte)(IsNested ? 1 : 0);

        return offset;
    }

    /// <summary>
    /// Tries to write the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <param name="bytesWritten">The number of bytes written if successful.</param>
    /// <returns>True if the write was successful; false if the destination is too small.</returns>
    public bool TryWrite(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            return false;
        }

        bytesWritten = Write(destination);
        return true;
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
        writer.WritePacket(PgpPacketTag.OnePassSignature, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        var keyIdHex = Convert.ToHexString(GetKeyIdFromFingerprint()).ToLowerInvariant();
        return $"OnePassSignature(v{Version}, {SignatureType}, nested={IsNested}, keyId={keyIdHex})";
    }

    /// <inheritdoc />
    public bool Equals(PgpOnePassSignaturePacket other)
    {
        return Version == other.Version
            && SignatureType == other.SignatureType
            && HashAlgorithm == other.HashAlgorithm
            && PublicKeyAlgorithm == other.PublicKeyAlgorithm
            && KeyIdOrFingerprint.Span.SequenceEqual(other.KeyIdOrFingerprint.Span)
            && Salt.Span.SequenceEqual(other.Salt.Span)
            && IsNested == other.IsNested;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpOnePassSignaturePacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Version.GetHashCode();
            hash = hash * 31 + SignatureType.GetHashCode();
            hash = hash * 31 + HashAlgorithm.GetHashCode();
            hash = hash * 31 + PublicKeyAlgorithm.GetHashCode();
            hash = hash * 31 + IsNested.GetHashCode();
            foreach (var b in KeyIdOrFingerprint.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpOnePassSignaturePacket left, PgpOnePassSignaturePacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpOnePassSignaturePacket left, PgpOnePassSignaturePacket right) => !left.Equals(right);
}
