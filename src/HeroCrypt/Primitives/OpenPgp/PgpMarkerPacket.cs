namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Marker Packet (Tag 10) as defined in RFC 4880 Section 5.8.
/// </summary>
/// <remarks>
/// <para>
/// The Marker packet is an obsolete literal packet that contains the three octets
/// "PGP" (0x50, 0x47, 0x50). It was used in early implementations for compatibility
/// detection.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +---+---+---+
/// | P | G | P |
/// +---+---+---+
///  50  47  50 (hex)
/// </code>
/// </para>
/// <para>
/// <b>Note:</b> This packet is OBSOLETE. Implementations MUST be able to read it
/// but SHOULD NOT generate it. When encountered, implementations SHOULD ignore
/// this packet.
/// </para>
/// </remarks>
public readonly struct PgpMarkerPacket : IEquatable<PgpMarkerPacket>
{
    /// <summary>
    /// The expected marker content: "PGP" (0x50, 0x47, 0x50).
    /// </summary>
    public static readonly byte[] MarkerContent = [(byte)'P', (byte)'G', (byte)'P'];

    /// <summary>
    /// The fixed length of the marker packet body.
    /// </summary>
    public const int MarkerLength = 3;

    /// <summary>
    /// Gets a value indicating whether this marker packet contains the standard "PGP" content.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the raw content of this marker packet.
    /// </summary>
    /// <remarks>
    /// While RFC 4880 specifies the content should be "PGP", implementations
    /// should be tolerant of non-conforming content.
    /// </remarks>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>
    /// Initializes a new Marker packet with the standard "PGP" content.
    /// </summary>
    public PgpMarkerPacket()
    {
        Content = MarkerContent;
        IsValid = true;
    }

    /// <summary>
    /// Initializes a new Marker packet with the specified content.
    /// </summary>
    /// <param name="content">The marker content.</param>
    internal PgpMarkerPacket(ReadOnlyMemory<byte> content)
    {
        Content = content;
        IsValid = content.Length == MarkerLength
            && content.Span[0] == (byte)'P'
            && content.Span[1] == (byte)'G'
            && content.Span[2] == (byte)'P';
    }

    /// <summary>
    /// Reads a Marker packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is not exactly 3 bytes.</exception>
    public static PgpMarkerPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a Marker packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpMarkerPacket packet, out string error)
    {
        packet = default;

        if (source.Length != MarkerLength)
        {
            error = $"Marker packet must be exactly {MarkerLength} bytes, got {source.Length}.";
            return false;
        }

        packet = new PgpMarkerPacket(source.ToArray());
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>Always returns 3.</returns>
    public int GetEncodedLength()
    {
        return MarkerLength;
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written (always 3).</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        if (destination.Length < MarkerLength)
        {
            throw new ArgumentException($"Destination too small. Need {MarkerLength} bytes.", nameof(destination));
        }

        Content.Span.CopyTo(destination);
        return MarkerLength;
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
        if (destination.Length < MarkerLength)
        {
            return false;
        }

        bytesWritten = Write(destination);
        return true;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The marker content (3 bytes).</returns>
    public byte[] ToArray()
    {
        return Content.ToArray();
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    /// <remarks>
    /// <para><b>Note:</b> This packet is obsolete and SHOULD NOT be generated.
    /// This method is provided for completeness and testing purposes.</para>
    /// </remarks>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.Marker, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        return IsValid ? "Marker(PGP)" : $"Marker(invalid: {Content.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpMarkerPacket other)
    {
        return Content.Span.SequenceEqual(other.Content.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpMarkerPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            foreach (var b in Content.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpMarkerPacket left, PgpMarkerPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpMarkerPacket left, PgpMarkerPacket right) => !left.Equals(right);
}
