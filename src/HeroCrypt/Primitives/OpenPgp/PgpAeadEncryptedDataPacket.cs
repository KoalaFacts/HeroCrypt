using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents an AEAD Encrypted Data Packet (Tag 20) as defined in RFC 9580 Section 5.16.
/// </summary>
/// <remarks>
/// <para>
/// The AEAD Encrypted Data packet contains AEAD-encrypted data. This is the preferred
/// encryption format in OpenPGP Crypto-Refresh (RFC 9580), replacing both the legacy
/// Symmetrically Encrypted Data packet (Tag 9) and SEIPD v1 packets.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +----------+--------+------+-------+------------------+
/// | Version  | Cipher | AEAD | Chunk | Encrypted Data   |
/// | 1 byte   | 1 byte |1 byte|1 byte |    variable      |
/// +----------+--------+------+-------+------------------+
/// </code>
/// </para>
/// <para>
/// <b>Encrypted data structure:</b> The encrypted data consists of zero or more
/// encrypted chunks followed by a final authentication tag. Each chunk is:
/// <code>
/// +------------------+--------+
/// | Ciphertext Chunk |  Tag   |
/// |    variable      |16 bytes|
/// +------------------+--------+
/// </code>
/// </para>
/// <para>
/// <b>Chunk size:</b> The chunk size is encoded as a power of 2 plus 6:
/// actual_size = 1 &lt;&lt; (chunk_size_octet + 6). Common values:
/// <list type="bullet">
/// <item>0 = 64 bytes</item>
/// <item>6 = 4096 bytes (default)</item>
/// <item>10 = 65536 bytes (64 KiB)</item>
/// </list>
/// </para>
/// </remarks>
public readonly struct PgpAeadEncryptedDataPacket : IEquatable<PgpAeadEncryptedDataPacket>
{
    /// <summary>
    /// The only valid version for this packet type.
    /// </summary>
    public const int CurrentVersion = 1;

    /// <summary>
    /// Minimum header size: version (1) + cipher (1) + aead (1) + chunk size (1).
    /// </summary>
    public const int HeaderSize = 4;

    /// <summary>
    /// Gets the version number (always 1).
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the symmetric cipher algorithm used for encryption.
    /// </summary>
    public SymmetricCipherAlgorithm CipherAlgorithm { get; }

    /// <summary>
    /// Gets the AEAD algorithm used for authenticated encryption.
    /// </summary>
    public AeadAlgorithm AeadAlgorithm { get; }

    /// <summary>
    /// Gets the chunk size exponent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The actual chunk size in bytes is computed as: 1 &lt;&lt; (ChunkSize + 6).
    /// Use <see cref="GetChunkSizeBytes"/> to get the actual byte count.
    /// </para>
    /// </remarks>
    public byte ChunkSize { get; }

    /// <summary>
    /// Gets the encrypted data (chunks and authentication tags).
    /// </summary>
    public ReadOnlyMemory<byte> EncryptedData { get; }

    /// <summary>
    /// Initializes a new AEAD Encrypted Data packet.
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="aeadAlgorithm">The AEAD algorithm.</param>
    /// <param name="chunkSize">The chunk size exponent (0-16).</param>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <exception cref="ArgumentException">If the AEAD algorithm is None.</exception>
    public PgpAeadEncryptedDataPacket(
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        byte chunkSize,
        ReadOnlyMemory<byte> encryptedData)
    {
        if (aeadAlgorithm == AeadAlgorithm.None)
        {
            throw new ArgumentException("AEAD algorithm cannot be None for AEAD Encrypted Data packet.", nameof(aeadAlgorithm));
        }

        Version = CurrentVersion;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        ChunkSize = chunkSize;
        EncryptedData = encryptedData;
    }

    // Internal constructor for reading packets
    private PgpAeadEncryptedDataPacket(
        int version,
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        byte chunkSize,
        ReadOnlyMemory<byte> encryptedData)
    {
        Version = version;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        ChunkSize = chunkSize;
        EncryptedData = encryptedData;
    }

    /// <summary>
    /// Gets the actual chunk size in bytes.
    /// </summary>
    /// <returns>The chunk size in bytes.</returns>
    public int GetChunkSizeBytes()
    {
        return 1 << (ChunkSize + 6);
    }

    /// <summary>
    /// Reads an AEAD Encrypted Data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is invalid.</exception>
    public static PgpAeadEncryptedDataPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read an AEAD Encrypted Data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpAeadEncryptedDataPacket packet, out string error)
    {
        packet = default;

        if (source.Length < HeaderSize)
        {
            error = $"Source too short. AEAD Encrypted Data packet requires at least {HeaderSize} bytes.";
            return false;
        }

        int version = source[0];
        if (version != CurrentVersion)
        {
            error = $"Unsupported version {version}. Only version {CurrentVersion} is supported.";
            return false;
        }

        var cipherAlgorithm = (SymmetricCipherAlgorithm)source[1];
        var aeadAlgorithm = (AeadAlgorithm)source[2];
        byte chunkSize = source[3];

        if (aeadAlgorithm == AeadAlgorithm.None)
        {
            error = "Invalid AEAD algorithm (None) in AEAD Encrypted Data packet.";
            return false;
        }

        var encryptedData = source.Slice(HeaderSize).ToArray();

        packet = new PgpAeadEncryptedDataPacket(version, cipherAlgorithm, aeadAlgorithm, chunkSize, encryptedData);
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        return HeaderSize + EncryptedData.Length;
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

        destination[0] = (byte)Version;
        destination[1] = (byte)CipherAlgorithm;
        destination[2] = (byte)AeadAlgorithm;
        destination[3] = ChunkSize;
        EncryptedData.Span.CopyTo(destination.Slice(HeaderSize));

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
        writer.WritePacket(PgpPacketTag.AeadEncryptedData, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        return $"AeadEncryptedData(v{Version}, {CipherAlgorithm}, {AeadAlgorithm}, chunk={GetChunkSizeBytes()}, {EncryptedData.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpAeadEncryptedDataPacket other)
    {
        return Version == other.Version
            && CipherAlgorithm == other.CipherAlgorithm
            && AeadAlgorithm == other.AeadAlgorithm
            && ChunkSize == other.ChunkSize
            && EncryptedData.Span.SequenceEqual(other.EncryptedData.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpAeadEncryptedDataPacket other && Equals(other);

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
    public static bool operator ==(PgpAeadEncryptedDataPacket left, PgpAeadEncryptedDataPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpAeadEncryptedDataPacket left, PgpAeadEncryptedDataPacket right) => !left.Equals(right);
}
