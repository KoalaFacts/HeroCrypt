namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Trust Packet (Tag 12) as defined in RFC 4880 Section 5.10.
/// </summary>
/// <remarks>
/// <para>
/// The Trust packet contains data that is used only within keyrings and is not
/// normally exported. Trust packets contain data that record the user's trust
/// assignments for keys and are implementation-specific.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +------------------+
/// |   Trust Data     |
/// |     n bytes      |
/// +------------------+
/// </code>
/// </para>
/// <para>
/// <b>Note:</b> Trust packets are implementation-specific. The format and meaning
/// of the trust data varies between implementations (e.g., GnuPG, OpenPGP.js).
/// When importing keys, implementations typically strip trust packets and
/// recompute trust values locally.
/// </para>
/// </remarks>
public readonly struct PgpTrustPacket : IEquatable<PgpTrustPacket>
{
    /// <summary>
    /// Gets the trust data.
    /// </summary>
    /// <remarks>
    /// The format of this data is implementation-specific and should not be
    /// relied upon for interoperability.
    /// </remarks>
    public ReadOnlyMemory<byte> TrustData { get; }

    /// <summary>
    /// Initializes a new Trust packet with the specified trust data.
    /// </summary>
    /// <param name="trustData">The implementation-specific trust data.</param>
    public PgpTrustPacket(ReadOnlyMemory<byte> trustData)
    {
        TrustData = trustData;
    }

    /// <summary>
    /// Reads a Trust packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is empty.</exception>
    public static PgpTrustPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a Trust packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpTrustPacket packet, out string error)
    {
        packet = default;

        if (source.Length == 0)
        {
            error = "Trust packet cannot be empty.";
            return false;
        }

        packet = new PgpTrustPacket(source.ToArray());
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The length of the trust data.</returns>
    public int GetEncodedLength()
    {
        return TrustData.Length;
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        if (destination.Length < TrustData.Length)
        {
            throw new ArgumentException($"Destination too small. Need {TrustData.Length} bytes.", nameof(destination));
        }

        TrustData.Span.CopyTo(destination);
        return TrustData.Length;
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
        if (destination.Length < TrustData.Length)
        {
            return false;
        }

        bytesWritten = Write(destination);
        return true;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The trust data.</returns>
    public byte[] ToArray()
    {
        return TrustData.ToArray();
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.Trust, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        return $"Trust({TrustData.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpTrustPacket other)
    {
        return TrustData.Span.SequenceEqual(other.TrustData.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpTrustPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            foreach (var b in TrustData.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpTrustPacket left, PgpTrustPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpTrustPacket left, PgpTrustPacket right) => !left.Equals(right);
}
