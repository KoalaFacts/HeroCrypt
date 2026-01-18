using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
/// as defined in RFC 4880 Section 5.13 and RFC 9580 Section 5.13.
/// </summary>
/// <remarks>
/// <para>
/// This packet contains symmetrically encrypted data with integrity protection.
/// It supersedes the deprecated Symmetrically Encrypted Data packet (Tag 9)
/// by including mechanisms to detect modification of the encrypted data.
/// </para>
/// <para>
/// <b>Version 1 Wire format (RFC 4880):</b>
/// <code>
/// +--------+------------------------+
/// |Version |    Encrypted Data      |
/// | 1 byte |       variable         |
/// +--------+------------------------+
/// </code>
/// The encrypted data includes a random prefix, the actual data, and a
/// Modification Detection Code (MDC) packet containing a SHA-1 hash.
/// </para>
/// <para>
/// <b>Version 2 Wire format (RFC 9580):</b>
/// <code>
/// +--------+--------+------+-------+------+------------------+
/// |Version | Cipher | AEAD | Chunk | Salt | Encrypted Data   |
/// | 1 byte | 1 byte |1 byte|1 byte |32 B  |    variable      |
/// +--------+--------+------+-------+------+------------------+
/// </code>
/// Version 2 uses AEAD encryption for authenticated encryption.
/// </para>
/// </remarks>
public readonly struct PgpSymEncryptedIntegrityProtectedDataPacket : IEquatable<PgpSymEncryptedIntegrityProtectedDataPacket>
{
    /// <summary>
    /// Version 1 - CFB mode with MDC (RFC 4880).
    /// </summary>
    public const int VersionCfbMdc = 1;

    /// <summary>
    /// Version 2 - AEAD mode (RFC 9580).
    /// </summary>
    public const int VersionAead = 2;

    /// <summary>
    /// Salt length for version 2 packets.
    /// </summary>
    public const int SaltLength = 32;

    /// <summary>
    /// Gets the packet version.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Version 1 uses CFB mode with a SHA-1 MDC for integrity.
    /// Version 2 uses AEAD for authenticated encryption.
    /// </para>
    /// </remarks>
    public int Version { get; }

    /// <summary>
    /// Gets the symmetric cipher algorithm (version 2 only).
    /// </summary>
    /// <remarks>
    /// <para>
    /// For version 1 packets, this is <see cref="SymmetricCipherAlgorithm.Plaintext"/>
    /// as the algorithm is determined by the session key packet.
    /// </para>
    /// </remarks>
    public SymmetricCipherAlgorithm CipherAlgorithm { get; }

    /// <summary>
    /// Gets the AEAD algorithm (version 2 only).
    /// </summary>
    /// <remarks>
    /// <para>
    /// For version 1 packets, this is <see cref="AeadAlgorithm.None"/>.
    /// </para>
    /// </remarks>
    public AeadAlgorithm AeadAlgorithm { get; }

    /// <summary>
    /// Gets the chunk size exponent (version 2 only).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The actual chunk size is 2^(chunkSizeByte + 6) bytes.
    /// For version 1 packets, this is 0.
    /// </para>
    /// </remarks>
    public byte ChunkSize { get; }

    /// <summary>
    /// Gets the salt (version 2 only).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A 32-byte random salt used for key derivation in AEAD mode.
    /// For version 1 packets, this is empty.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>
    /// Gets the encrypted data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For version 1: Encrypted data including prefix and MDC.
    /// For version 2: AEAD encrypted and authenticated data.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> EncryptedData { get; }

    /// <summary>
    /// Initializes a new version 1 SEIPD packet.
    /// </summary>
    /// <param name="encryptedData">The encrypted data (including prefix and MDC).</param>
    public PgpSymEncryptedIntegrityProtectedDataPacket(ReadOnlyMemory<byte> encryptedData)
    {
        Version = VersionCfbMdc;
        CipherAlgorithm = SymmetricCipherAlgorithm.Plaintext;
        AeadAlgorithm = AeadAlgorithm.None;
        ChunkSize = 0;
        Salt = ReadOnlyMemory<byte>.Empty;
        EncryptedData = encryptedData;
    }

    /// <summary>
    /// Initializes a new version 2 SEIPD packet.
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="aeadAlgorithm">The AEAD algorithm.</param>
    /// <param name="chunkSize">The chunk size exponent.</param>
    /// <param name="salt">The 32-byte salt.</param>
    /// <param name="encryptedData">The AEAD encrypted data.</param>
    /// <exception cref="ArgumentException">If salt is not 32 bytes.</exception>
    public PgpSymEncryptedIntegrityProtectedDataPacket(
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        byte chunkSize,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> encryptedData)
    {
        if (salt.Length != SaltLength)
        {
            throw new ArgumentException($"Salt must be {SaltLength} bytes.", nameof(salt));
        }

        Version = VersionAead;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        ChunkSize = chunkSize;
        Salt = salt;
        EncryptedData = encryptedData;
    }

    // Private constructor for parsing
    private PgpSymEncryptedIntegrityProtectedDataPacket(
        int version,
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        byte chunkSize,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> encryptedData)
    {
        Version = version;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        ChunkSize = chunkSize;
        Salt = salt;
        EncryptedData = encryptedData;
    }

    /// <summary>
    /// Creates a version 1 SEIPD packet (CFB with MDC).
    /// </summary>
    /// <param name="encryptedData">The encrypted data including prefix and MDC.</param>
    /// <returns>A new version 1 SEIPD packet.</returns>
    public static PgpSymEncryptedIntegrityProtectedDataPacket CreateV1(ReadOnlyMemory<byte> encryptedData)
    {
        return new PgpSymEncryptedIntegrityProtectedDataPacket(encryptedData);
    }

    /// <summary>
    /// Creates a version 2 SEIPD packet (AEAD).
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="aeadAlgorithm">The AEAD algorithm.</param>
    /// <param name="chunkSize">The chunk size exponent.</param>
    /// <param name="salt">The 32-byte salt.</param>
    /// <param name="encryptedData">The AEAD encrypted data.</param>
    /// <returns>A new version 2 SEIPD packet.</returns>
    public static PgpSymEncryptedIntegrityProtectedDataPacket CreateV2(
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        byte chunkSize,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> encryptedData)
    {
        return new PgpSymEncryptedIntegrityProtectedDataPacket(
            cipherAlgorithm, aeadAlgorithm, chunkSize, salt, encryptedData);
    }

    /// <summary>
    /// Gets the actual chunk size in bytes for version 2 packets.
    /// </summary>
    /// <returns>The chunk size in bytes, or 0 for version 1 packets.</returns>
    public int GetChunkSizeBytes()
    {
        if (Version != VersionAead)
        {
            return 0;
        }

        return 1 << (ChunkSize + 6);
    }

    /// <summary>
    /// Reads a SEIPD packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is malformed.</exception>
    public static PgpSymEncryptedIntegrityProtectedDataPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a SEIPD packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSymEncryptedIntegrityProtectedDataPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 2)
        {
            error = "Source too short for SEIPD packet. Need at least 2 bytes.";
            return false;
        }

        int version = source[0];

        if (version == VersionCfbMdc)
        {
            return TryReadV1(source, out packet, out error);
        }
        else if (version == VersionAead)
        {
            return TryReadV2(source, out packet, out error);
        }
        else
        {
            error = $"Unsupported SEIPD version: {version}. Only versions 1 and 2 are supported.";
            return false;
        }
    }

    private static bool TryReadV1(ReadOnlySpan<byte> source, out PgpSymEncryptedIntegrityProtectedDataPacket packet, out string error)
    {
        packet = default;

        // Version 1: version (1) + encrypted data (variable, at least 1 byte)
        if (source.Length < 2)
        {
            error = "Source too short for v1 SEIPD packet.";
            return false;
        }

        var encryptedData = source.Slice(1).ToArray();

        packet = new PgpSymEncryptedIntegrityProtectedDataPacket(
            VersionCfbMdc,
            SymmetricCipherAlgorithm.Plaintext,
            AeadAlgorithm.None,
            0,
            ReadOnlyMemory<byte>.Empty,
            encryptedData);

        error = string.Empty;
        return true;
    }

    private static bool TryReadV2(ReadOnlySpan<byte> source, out PgpSymEncryptedIntegrityProtectedDataPacket packet, out string error)
    {
        packet = default;

        // Version 2: version (1) + cipher (1) + aead (1) + chunk (1) + salt (32) + data (variable)
        const int v2HeaderLength = 1 + 1 + 1 + 1 + SaltLength;

        if (source.Length < v2HeaderLength)
        {
            error = $"Source too short for v2 SEIPD packet. Need at least {v2HeaderLength} bytes.";
            return false;
        }

        var cipherAlgorithm = (SymmetricCipherAlgorithm)source[1];
        var aeadAlgorithm = (AeadAlgorithm)source[2];
        var chunkSize = source[3];
        var salt = source.Slice(4, SaltLength).ToArray();
        var encryptedData = source.Slice(v2HeaderLength).ToArray();

        packet = new PgpSymEncryptedIntegrityProtectedDataPacket(
            VersionAead,
            cipherAlgorithm,
            aeadAlgorithm,
            chunkSize,
            salt,
            encryptedData);

        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        if (Version == VersionCfbMdc)
        {
            return 1 + EncryptedData.Length;
        }
        else
        {
            // Version 2: version (1) + cipher (1) + aead (1) + chunk (1) + salt (32) + data
            return 1 + 1 + 1 + 1 + SaltLength + EncryptedData.Length;
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

        if (Version == VersionAead)
        {
            destination[offset++] = (byte)CipherAlgorithm;
            destination[offset++] = (byte)AeadAlgorithm;
            destination[offset++] = ChunkSize;
            Salt.Span.CopyTo(destination.Slice(offset));
            offset += SaltLength;
        }

        EncryptedData.Span.CopyTo(destination.Slice(offset));
        offset += EncryptedData.Length;

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
        writer.WritePacket(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        if (Version == VersionCfbMdc)
        {
            return $"SEIPD(v1, {EncryptedData.Length} bytes)";
        }
        else
        {
            return $"SEIPD(v2, {CipherAlgorithm}, {AeadAlgorithm}, chunk={GetChunkSizeBytes()}, {EncryptedData.Length} bytes)";
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpSymEncryptedIntegrityProtectedDataPacket other)
    {
        return Version == other.Version
            && CipherAlgorithm == other.CipherAlgorithm
            && AeadAlgorithm == other.AeadAlgorithm
            && ChunkSize == other.ChunkSize
            && Salt.Span.SequenceEqual(other.Salt.Span)
            && EncryptedData.Span.SequenceEqual(other.EncryptedData.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpSymEncryptedIntegrityProtectedDataPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Version;
            hash = hash * 31 + (int)CipherAlgorithm;
            hash = hash * 31 + (int)AeadAlgorithm;
            hash = hash * 31 + ChunkSize;
            foreach (var b in Salt.Span)
            {
                hash = hash * 31 + b;
            }

            foreach (var b in EncryptedData.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpSymEncryptedIntegrityProtectedDataPacket left, PgpSymEncryptedIntegrityProtectedDataPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpSymEncryptedIntegrityProtectedDataPacket left, PgpSymEncryptedIntegrityProtectedDataPacket right) => !left.Equals(right);
}
