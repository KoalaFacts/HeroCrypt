namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Padding Packet (Tag 21) as defined in RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// The Padding packet contains random padding data used to obscure the actual
/// message size and provide protection against traffic analysis. Implementations
/// SHOULD ignore the contents of this packet when reading.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +------------------+
/// |   Padding Data   |
/// |     n bytes      |
/// +------------------+
/// </code>
/// </para>
/// <para>
/// <b>Security:</b> The padding data SHOULD be cryptographically random to
/// prevent leaking information about the padding length through patterns.
/// </para>
/// </remarks>
public readonly struct PgpPaddingPacket : IEquatable<PgpPaddingPacket>
{
    /// <summary>
    /// Gets the padding data.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// Initializes a new Padding packet with the specified data.
    /// </summary>
    /// <param name="data">The padding data (should be random bytes).</param>
    public PgpPaddingPacket(ReadOnlyMemory<byte> data)
    {
        Data = data;
    }

    /// <summary>
    /// Creates a Padding packet with cryptographically random data.
    /// </summary>
    /// <param name="length">The length of the padding in bytes.</param>
    /// <returns>A new Padding packet with random data.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If length is negative.</exception>
    public static PgpPaddingPacket CreateRandom(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");
        }

        if (length == 0)
        {
            return new PgpPaddingPacket(ReadOnlyMemory<byte>.Empty);
        }

        var data = new byte[length];
        System.Security.Cryptography.RandomNumberGenerator.Fill(data);
        return new PgpPaddingPacket(data);
    }

    /// <summary>
    /// Reads a Padding packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    public static PgpPaddingPacket Read(ReadOnlySpan<byte> source)
    {
        // Padding packets can be any length, including empty
        return new PgpPaddingPacket(source.ToArray());
    }

    /// <summary>
    /// Tries to read a Padding packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed (always empty for padding).</param>
    /// <returns>Always returns true as padding packets have no validation requirements.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpPaddingPacket packet, out string error)
    {
        packet = Read(source);
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The length of the padding data.</returns>
    public int GetEncodedLength()
    {
        return Data.Length;
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        if (destination.Length < Data.Length)
        {
            throw new ArgumentException($"Destination too small. Need {Data.Length} bytes.", nameof(destination));
        }

        Data.Span.CopyTo(destination);
        return Data.Length;
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
        if (destination.Length < Data.Length)
        {
            return false;
        }

        bytesWritten = Write(destination);
        return true;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The padding data.</returns>
    public byte[] ToArray()
    {
        return Data.ToArray();
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New). Note: Tag 21 requires new format.</param>
    /// <exception cref="ArgumentException">If old format is specified (Tag 21 > 15).</exception>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.Padding, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        return $"Padding({Data.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpPaddingPacket other)
    {
        return Data.Span.SequenceEqual(other.Data.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpPaddingPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Data.Length;
            foreach (var b in Data.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpPaddingPacket left, PgpPaddingPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpPaddingPacket left, PgpPaddingPacket right) => !left.Equals(right);
}
