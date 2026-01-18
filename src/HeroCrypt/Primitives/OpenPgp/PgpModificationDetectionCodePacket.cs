namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Modification Detection Code (MDC) Packet (Tag 19) as defined in RFC 4880 Section 5.14.
/// </summary>
/// <remarks>
/// <para>
/// The Modification Detection Code packet contains a SHA-1 hash of the preceding
/// plaintext data, used to verify integrity in SEIPD v1 packets. It is always
/// exactly 20 bytes (the size of a SHA-1 hash).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +------------------+
/// |   SHA-1 Hash     |
/// |     20 bytes     |
/// +------------------+
/// </code>
/// </para>
/// <para>
/// <b>Usage:</b> The MDC packet is the last packet inside the encrypted portion
/// of a SEIPD v1 packet. The SHA-1 hash covers the prefix bytes and all plaintext
/// up to and including the two bytes 0xD3, 0x14 (the MDC packet header).
/// </para>
/// <para>
/// <b>Security Note:</b> SHA-1 is cryptographically weak. RFC 9580 SEIPD v2
/// with AEAD is preferred for new implementations.
/// </para>
/// </remarks>
public readonly struct PgpModificationDetectionCodePacket : IEquatable<PgpModificationDetectionCodePacket>
{
    /// <summary>
    /// The fixed length of the SHA-1 hash.
    /// </summary>
    public const int HashLength = 20;

    /// <summary>
    /// Gets the SHA-1 hash.
    /// </summary>
    public ReadOnlyMemory<byte> Hash { get; }

    /// <summary>
    /// Initializes a new MDC packet with the specified hash.
    /// </summary>
    /// <param name="hash">The 20-byte SHA-1 hash.</param>
    /// <exception cref="ArgumentException">If the hash is not exactly 20 bytes.</exception>
    public PgpModificationDetectionCodePacket(ReadOnlyMemory<byte> hash)
    {
        if (hash.Length != HashLength)
        {
            throw new ArgumentException($"MDC hash must be exactly {HashLength} bytes, got {hash.Length}.", nameof(hash));
        }

        Hash = hash;
    }

    /// <summary>
    /// Reads an MDC packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is not exactly 20 bytes.</exception>
    public static PgpModificationDetectionCodePacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read an MDC packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpModificationDetectionCodePacket packet, out string error)
    {
        packet = default;

        if (source.Length != HashLength)
        {
            error = $"MDC packet must be exactly {HashLength} bytes, got {source.Length}.";
            return false;
        }

        packet = new PgpModificationDetectionCodePacket(source.ToArray());
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>Always returns 20.</returns>
    public int GetEncodedLength()
    {
        return HashLength;
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written (always 20).</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        if (destination.Length < HashLength)
        {
            throw new ArgumentException($"Destination too small. Need {HashLength} bytes.", nameof(destination));
        }

        Hash.Span.CopyTo(destination);
        return HashLength;
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
        if (destination.Length < HashLength)
        {
            return false;
        }

        bytesWritten = Write(destination);
        return true;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The 20-byte hash.</returns>
    public byte[] ToArray()
    {
        return Hash.ToArray();
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.ModificationDetectionCode, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        var span = Hash.Span;
        return $"MDC({span[0]:X2}{span[1]:X2}{span[2]:X2}{span[3]:X2}...)";
    }

    /// <inheritdoc />
    public bool Equals(PgpModificationDetectionCodePacket other)
    {
        return Hash.Span.SequenceEqual(other.Hash.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpModificationDetectionCodePacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            foreach (var b in Hash.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpModificationDetectionCodePacket left, PgpModificationDetectionCodePacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpModificationDetectionCodePacket left, PgpModificationDetectionCodePacket right) => !left.Equals(right);
}
