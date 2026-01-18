using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Symmetric-Key Encrypted Session Key (SKESK) Packet (Tag 3) as defined
/// in RFC 4880 Section 5.3 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// A Symmetric-Key Encrypted Session Key packet contains the session key used to
/// encrypt a message, encrypted with a passphrase-derived key using String-to-Key (S2K).
/// </para>
/// <para>
/// <b>Wire format (v4):</b>
/// <code>
/// +----------+-----------+----------------+----------------------+
/// | Version  | Algorithm | S2K Specifier  | Encrypted Session Key|
/// | 1 byte   |  1 byte   |   variable     |  optional/variable   |
/// +----------+-----------+----------------+----------------------+
/// </code>
/// </para>
/// <para>
/// <b>Wire format (v6 - RFC 9580):</b>
/// <code>
/// +----------+-------+-----------+------+-------+----------------+----+----------------------+
/// | Version  | Count | Algorithm | AEAD | S2KCnt| S2K Specifier  | IV | Encrypted SK + Tag   |
/// | 1 byte   |1 byte |  1 byte   |1 byte|1 byte |   variable     |var |      variable        |
/// +----------+-------+-----------+------+-------+----------------+----+----------------------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpSymmetricKeyEncryptedSessionKeyPacket : IEquatable<PgpSymmetricKeyEncryptedSessionKeyPacket>
{
    /// <summary>
    /// Version 4 packet (RFC 4880).
    /// </summary>
    public const int Version4 = 4;

    /// <summary>
    /// Version 6 packet (RFC 9580).
    /// </summary>
    public const int Version6 = 6;

    /// <summary>
    /// Minimum packet size for v4: version (1) + algorithm (1) + s2k type (1).
    /// </summary>
    public const int MinSizeV4 = 3;

    /// <summary>
    /// Minimum packet size for v6: version (1) + count (1) + algorithm (1) + aead (1) + s2k count (1).
    /// </summary>
    public const int MinSizeV6 = 5;

    /// <summary>
    /// Gets the version number.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the symmetric cipher algorithm.
    /// </summary>
    public SymmetricCipherAlgorithm CipherAlgorithm { get; }

    /// <summary>
    /// Gets the AEAD algorithm (v6 only).
    /// </summary>
    public AeadAlgorithm AeadAlgorithm { get; }

    /// <summary>
    /// Gets the S2K specifier data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The S2K specifier defines how the passphrase is converted to a key.
    /// The format depends on the S2K type (first byte): Simple (0), Salted (1),
    /// Iterated and Salted (3), or Argon2 (4).
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> S2kSpecifier { get; }

    /// <summary>
    /// Gets the initialization vector (v6 only).
    /// </summary>
    public ReadOnlyMemory<byte> IV { get; }

    /// <summary>
    /// Gets the encrypted session key data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For v4: Optional. If present, contains the encrypted session key.
    /// If absent, the S2K-derived key is used directly.
    /// </para>
    /// <para>
    /// For v6: Contains the AEAD-encrypted session key with authentication tag.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> EncryptedSessionKey { get; }

    /// <summary>
    /// Initializes a new v4 SKESK packet.
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="s2kSpecifier">The S2K specifier data.</param>
    /// <param name="encryptedSessionKey">The encrypted session key (optional).</param>
    public PgpSymmetricKeyEncryptedSessionKeyPacket(
        SymmetricCipherAlgorithm cipherAlgorithm,
        ReadOnlyMemory<byte> s2kSpecifier,
        ReadOnlyMemory<byte> encryptedSessionKey = default)
    {
        Version = Version4;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = AeadAlgorithm.None;
        S2kSpecifier = s2kSpecifier;
        IV = ReadOnlyMemory<byte>.Empty;
        EncryptedSessionKey = encryptedSessionKey;
    }

    /// <summary>
    /// Initializes a new v6 SKESK packet.
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="aeadAlgorithm">The AEAD algorithm.</param>
    /// <param name="s2kSpecifier">The S2K specifier data.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="encryptedSessionKey">The AEAD-encrypted session key with tag.</param>
    public PgpSymmetricKeyEncryptedSessionKeyPacket(
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        ReadOnlyMemory<byte> s2kSpecifier,
        ReadOnlyMemory<byte> iv,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        Version = Version6;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        S2kSpecifier = s2kSpecifier;
        IV = iv;
        EncryptedSessionKey = encryptedSessionKey;
    }

    // Internal constructor for reading
    private PgpSymmetricKeyEncryptedSessionKeyPacket(
        int version,
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        ReadOnlyMemory<byte> s2kSpecifier,
        ReadOnlyMemory<byte> iv,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        Version = version;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        S2kSpecifier = s2kSpecifier;
        IV = iv;
        EncryptedSessionKey = encryptedSessionKey;
    }

    /// <summary>
    /// Reads a SKESK packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is invalid.</exception>
    public static PgpSymmetricKeyEncryptedSessionKeyPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a SKESK packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSymmetricKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for SKESK packet.";
            return false;
        }

        int version = source[0];

        if (version == Version4)
        {
            return TryReadV4(source, out packet, out error);
        }
        else if (version == Version6)
        {
            return TryReadV6(source, out packet, out error);
        }
        else
        {
            error = $"Unsupported SKESK version {version}. Supported: 4, 6.";
            return false;
        }
    }

    private static bool TryReadV4(ReadOnlySpan<byte> source, out PgpSymmetricKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < MinSizeV4)
        {
            error = $"Source too short for v4 SKESK packet. Need at least {MinSizeV4} bytes.";
            return false;
        }

        var cipherAlgorithm = (SymmetricCipherAlgorithm)source[1];

        // Parse S2K specifier
        if (!TryGetS2kLength(source.Slice(2), out int s2kLength, out error))
        {
            return false;
        }

        if (source.Length < 2 + s2kLength)
        {
            error = "Source too short for v4 SKESK S2K specifier.";
            return false;
        }

        var s2kSpecifier = source.Slice(2, s2kLength).ToArray();
        var encryptedSessionKey = source.Slice(2 + s2kLength).ToArray();

        packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
            Version4,
            cipherAlgorithm,
            AeadAlgorithm.None,
            s2kSpecifier,
            ReadOnlyMemory<byte>.Empty,
            encryptedSessionKey);
        error = string.Empty;
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, out PgpSymmetricKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < MinSizeV6)
        {
            error = $"Source too short for v6 SKESK packet. Need at least {MinSizeV6} bytes.";
            return false;
        }

        int count = source[1];
        if (source.Length < 2 + count)
        {
            error = "Source too short for v6 SKESK packet fields.";
            return false;
        }

        var cipherAlgorithm = (SymmetricCipherAlgorithm)source[2];
        var aeadAlgorithm = (AeadAlgorithm)source[3];

        // S2K count byte at offset 4
        // S2K specifier follows
        if (!TryGetS2kLength(source.Slice(5), out int s2kLength, out error))
        {
            return false;
        }

        int ivOffset = 5 + s2kLength;
        int ivLength = GetIvLength(aeadAlgorithm);

        if (source.Length < ivOffset + ivLength)
        {
            error = "Source too short for v6 SKESK IV.";
            return false;
        }

        var s2kSpecifier = source.Slice(5, s2kLength).ToArray();
        var iv = source.Slice(ivOffset, ivLength).ToArray();
        var encryptedSessionKey = source.Slice(ivOffset + ivLength).ToArray();

        packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
            Version6,
            cipherAlgorithm,
            aeadAlgorithm,
            s2kSpecifier,
            iv,
            encryptedSessionKey);
        error = string.Empty;
        return true;
    }

    private static bool TryGetS2kLength(ReadOnlySpan<byte> s2kData, out int length, out string error)
    {
        length = 0;
        error = string.Empty;

        if (s2kData.Length < 1)
        {
            error = "S2K data too short.";
            return false;
        }

        byte s2kType = s2kData[0];

        // S2K length depends on type
        // Type 0 (Simple): 2 bytes (type + hash)
        // Type 1 (Salted): 10 bytes (type + hash + 8-byte salt)
        // Type 3 (Iterated): 11 bytes (type + hash + 8-byte salt + count)
        // Type 4 (Argon2): 4 bytes (type + salt length + parallelism + passes) + salt
        length = s2kType switch
        {
            0 => 2,  // Simple S2K
            1 => 10, // Salted S2K
            3 => 11, // Iterated and Salted S2K
            4 => s2kData.Length >= 2 ? 4 + s2kData[1] : 4, // Argon2
            _ => 2   // Unknown, assume minimal
        };

        return true;
    }

    private static int GetIvLength(AeadAlgorithm aeadAlgorithm)
    {
        return aeadAlgorithm switch
        {
            AeadAlgorithm.Eax => 16,
            AeadAlgorithm.Ocb => 15,
            AeadAlgorithm.Gcm => 12,
            _ => 0
        };
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        if (Version == Version4)
        {
            return 1 + 1 + S2kSpecifier.Length + EncryptedSessionKey.Length;
        }
        else
        {
            // v6: version + count + algorithm + aead + s2k count (1) + s2k + iv + encrypted
            int fieldsLength = 1 + 1 + 1 + S2kSpecifier.Length + IV.Length;
            return 1 + 1 + fieldsLength + EncryptedSessionKey.Length;
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

        if (Version == Version4)
        {
            destination[offset++] = (byte)CipherAlgorithm;
            S2kSpecifier.Span.CopyTo(destination.Slice(offset));
            offset += S2kSpecifier.Length;
        }
        else
        {
            // v6 format
            int fieldsLength = 1 + 1 + 1 + S2kSpecifier.Length + IV.Length;
            destination[offset++] = (byte)fieldsLength;
            destination[offset++] = (byte)CipherAlgorithm;
            destination[offset++] = (byte)AeadAlgorithm;
            destination[offset++] = 0; // S2K count byte (placeholder)
            S2kSpecifier.Span.CopyTo(destination.Slice(offset));
            offset += S2kSpecifier.Length;
            IV.Span.CopyTo(destination.Slice(offset));
            offset += IV.Length;
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
        writer.WritePacket(PgpPacketTag.SymmetricKeyEncryptedSessionKey, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        if (Version == Version4)
        {
            string eskInfo = EncryptedSessionKey.Length > 0
                ? $", ESK={EncryptedSessionKey.Length} bytes"
                : ", direct key";
            return $"SKESK(v4, {CipherAlgorithm}, S2K={S2kSpecifier.Length} bytes{eskInfo})";
        }
        else
        {
            return $"SKESK(v6, {CipherAlgorithm}, {AeadAlgorithm}, IV={IV.Length}, ESK={EncryptedSessionKey.Length} bytes)";
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpSymmetricKeyEncryptedSessionKeyPacket other)
    {
        return Version == other.Version
            && CipherAlgorithm == other.CipherAlgorithm
            && AeadAlgorithm == other.AeadAlgorithm
            && S2kSpecifier.Span.SequenceEqual(other.S2kSpecifier.Span)
            && IV.Span.SequenceEqual(other.IV.Span)
            && EncryptedSessionKey.Span.SequenceEqual(other.EncryptedSessionKey.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpSymmetricKeyEncryptedSessionKeyPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Version;
            hash = hash * 31 + (int)CipherAlgorithm;
            hash = hash * 31 + (int)AeadAlgorithm;
            foreach (var b in S2kSpecifier.Span)
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
    public static bool operator ==(PgpSymmetricKeyEncryptedSessionKeyPacket left, PgpSymmetricKeyEncryptedSessionKeyPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpSymmetricKeyEncryptedSessionKeyPacket left, PgpSymmetricKeyEncryptedSessionKeyPacket right) => !left.Equals(right);
}
