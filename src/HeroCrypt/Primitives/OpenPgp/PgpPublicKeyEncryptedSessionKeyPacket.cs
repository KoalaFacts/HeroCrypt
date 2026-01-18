namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Public-Key Encrypted Session Key (PKESK) Packet (Tag 1) as defined
/// in RFC 4880 Section 5.1 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// A Public-Key Encrypted Session Key packet contains the session key used to
/// encrypt a message, encrypted to a public key. When decrypted, it yields the
/// session key and symmetric algorithm used to encrypt the data.
/// </para>
/// <para>
/// <b>Wire format (v3):</b>
/// <code>
/// +----------+--------+-----------+----------------------+
/// | Version  | Key ID | Algorithm | Encrypted Session Key|
/// | 1 byte   | 8 bytes|  1 byte   |      variable        |
/// +----------+--------+-----------+----------------------+
/// </code>
/// </para>
/// <para>
/// <b>Wire format (v6 - RFC 9580):</b>
/// <code>
/// +----------+---------+--------+-------------+-----------+----------------------+
/// | Version  | Key Ver |FP Len  | Fingerprint | Algorithm | Encrypted Session Key|
/// | 1 byte   | 1 byte  |1 byte  |  variable   |  1 byte   |      variable        |
/// +----------+---------+--------+-------------+-----------+----------------------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpPublicKeyEncryptedSessionKeyPacket : IEquatable<PgpPublicKeyEncryptedSessionKeyPacket>
{
    /// <summary>
    /// Version 3 packet (RFC 4880).
    /// </summary>
    public const int Version3 = 3;

    /// <summary>
    /// Version 6 packet (RFC 9580).
    /// </summary>
    public const int Version6 = 6;

    /// <summary>
    /// Minimum packet size for v3: version (1) + key ID (8) + algorithm (1).
    /// </summary>
    public const int MinSizeV3 = 10;

    /// <summary>
    /// Minimum packet size for v6: version (1) + key version (1) + fp length (1) + algorithm (1).
    /// </summary>
    public const int MinSizeV6 = 4;

    /// <summary>
    /// Gets the version number.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the key ID (v3 only, 8 bytes).
    /// </summary>
    /// <remarks>
    /// <para>For v6 packets, use <see cref="Fingerprint"/> instead.</para>
    /// </remarks>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>
    /// Gets the key version (v6 only).
    /// </summary>
    public int KeyVersion { get; }

    /// <summary>
    /// Gets the key fingerprint (v6 only).
    /// </summary>
    public ReadOnlyMemory<byte> Fingerprint { get; }

    /// <summary>
    /// Gets the public-key algorithm.
    /// </summary>
    public PgpPublicKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the encrypted session key data (algorithm-specific).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The format depends on the algorithm:
    /// <list type="bullet">
    /// <item>RSA: encrypted value as an MPI</item>
    /// <item>Elgamal: two MPIs (g^k mod p, session key XOR (y^k mod p))</item>
    /// <item>ECDH: ephemeral key + wrapped session key</item>
    /// </list>
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> EncryptedSessionKey { get; }

    /// <summary>
    /// Initializes a new v3 PKESK packet.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <param name="algorithm">The public-key algorithm.</param>
    /// <param name="encryptedSessionKey">The encrypted session key data.</param>
    /// <exception cref="ArgumentException">If keyId is not 8 bytes.</exception>
    public PgpPublicKeyEncryptedSessionKeyPacket(
        ReadOnlyMemory<byte> keyId,
        PgpPublicKeyAlgorithm algorithm,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        if (keyId.Length != 8)
        {
            throw new ArgumentException("Key ID must be exactly 8 bytes.", nameof(keyId));
        }

        Version = Version3;
        KeyId = keyId;
        KeyVersion = 0;
        Fingerprint = ReadOnlyMemory<byte>.Empty;
        Algorithm = algorithm;
        EncryptedSessionKey = encryptedSessionKey;
    }

    /// <summary>
    /// Initializes a new v6 PKESK packet.
    /// </summary>
    /// <param name="keyVersion">The key version.</param>
    /// <param name="fingerprint">The key fingerprint.</param>
    /// <param name="algorithm">The public-key algorithm.</param>
    /// <param name="encryptedSessionKey">The encrypted session key data.</param>
    public PgpPublicKeyEncryptedSessionKeyPacket(
        int keyVersion,
        ReadOnlyMemory<byte> fingerprint,
        PgpPublicKeyAlgorithm algorithm,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        Version = Version6;
        KeyId = ReadOnlyMemory<byte>.Empty;
        KeyVersion = keyVersion;
        Fingerprint = fingerprint;
        Algorithm = algorithm;
        EncryptedSessionKey = encryptedSessionKey;
    }

    // Internal constructor for reading
    private PgpPublicKeyEncryptedSessionKeyPacket(
        int version,
        ReadOnlyMemory<byte> keyId,
        int keyVersion,
        ReadOnlyMemory<byte> fingerprint,
        PgpPublicKeyAlgorithm algorithm,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        Version = version;
        KeyId = keyId;
        KeyVersion = keyVersion;
        Fingerprint = fingerprint;
        Algorithm = algorithm;
        EncryptedSessionKey = encryptedSessionKey;
    }

    /// <summary>
    /// Reads a PKESK packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is invalid.</exception>
    public static PgpPublicKeyEncryptedSessionKeyPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a PKESK packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpPublicKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for PKESK packet.";
            return false;
        }

        int version = source[0];

        if (version == Version3)
        {
            return TryReadV3(source, out packet, out error);
        }
        else if (version == Version6)
        {
            return TryReadV6(source, out packet, out error);
        }
        else
        {
            error = $"Unsupported PKESK version {version}. Supported: 3, 6.";
            return false;
        }
    }

    private static bool TryReadV3(ReadOnlySpan<byte> source, out PgpPublicKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < MinSizeV3)
        {
            error = $"Source too short for v3 PKESK packet. Need at least {MinSizeV3} bytes.";
            return false;
        }

        var keyId = source.Slice(1, 8).ToArray();
        var algorithm = (PgpPublicKeyAlgorithm)source[9];
        var encryptedSessionKey = source.Slice(10).ToArray();

        packet = new PgpPublicKeyEncryptedSessionKeyPacket(
            Version3,
            keyId,
            0,
            ReadOnlyMemory<byte>.Empty,
            algorithm,
            encryptedSessionKey);
        error = string.Empty;
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, out PgpPublicKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < MinSizeV6)
        {
            error = $"Source too short for v6 PKESK packet. Need at least {MinSizeV6} bytes.";
            return false;
        }

        int keyVersion = source[1];
        int fpLength = source[2];

        if (source.Length < 3 + fpLength + 1)
        {
            error = "Source too short for v6 PKESK packet fingerprint.";
            return false;
        }

        var fingerprint = source.Slice(3, fpLength).ToArray();
        var algorithm = (PgpPublicKeyAlgorithm)source[3 + fpLength];
        var encryptedSessionKey = source.Slice(4 + fpLength).ToArray();

        packet = new PgpPublicKeyEncryptedSessionKeyPacket(
            Version6,
            ReadOnlyMemory<byte>.Empty,
            keyVersion,
            fingerprint,
            algorithm,
            encryptedSessionKey);
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        if (Version == Version3)
        {
            return 1 + 8 + 1 + EncryptedSessionKey.Length; // version + keyId + algorithm + data
        }
        else
        {
            return 1 + 1 + 1 + Fingerprint.Length + 1 + EncryptedSessionKey.Length;
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

        int offset = 0;
        destination[offset++] = (byte)Version;

        if (Version == Version3)
        {
            KeyId.Span.CopyTo(destination.Slice(offset));
            offset += 8;
            destination[offset++] = (byte)Algorithm;
        }
        else
        {
            destination[offset++] = (byte)KeyVersion;
            destination[offset++] = (byte)Fingerprint.Length;
            Fingerprint.Span.CopyTo(destination.Slice(offset));
            offset += Fingerprint.Length;
            destination[offset++] = (byte)Algorithm;
        }

        EncryptedSessionKey.Span.CopyTo(destination.Slice(offset));

        return encodedLength;
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
        var result = new byte[GetEncodedLength()];
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
        writer.WritePacket(PgpPacketTag.PublicKeyEncryptedSessionKey, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        if (Version == Version3)
        {
            var keyIdHex = Convert.ToHexString(KeyId.Span);
            return $"PKESK(v3, {Algorithm}, KeyId={keyIdHex}, {EncryptedSessionKey.Length} bytes)";
        }
        else
        {
            return $"PKESK(v6, {Algorithm}, KeyVer={KeyVersion}, FP={Fingerprint.Length} bytes, {EncryptedSessionKey.Length} bytes)";
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpPublicKeyEncryptedSessionKeyPacket other)
    {
        return Version == other.Version
            && KeyVersion == other.KeyVersion
            && Algorithm == other.Algorithm
            && KeyId.Span.SequenceEqual(other.KeyId.Span)
            && Fingerprint.Span.SequenceEqual(other.Fingerprint.Span)
            && EncryptedSessionKey.Span.SequenceEqual(other.EncryptedSessionKey.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpPublicKeyEncryptedSessionKeyPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Version;
            hash = hash * 31 + KeyVersion;
            hash = hash * 31 + (int)Algorithm;
            foreach (var b in KeyId.Span)
            {
                hash = hash * 31 + b;
            }

            foreach (var b in EncryptedSessionKey.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpPublicKeyEncryptedSessionKeyPacket left, PgpPublicKeyEncryptedSessionKeyPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpPublicKeyEncryptedSessionKeyPacket left, PgpPublicKeyEncryptedSessionKeyPacket right) => !left.Equals(right);
}
