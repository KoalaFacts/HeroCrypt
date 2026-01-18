namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Symmetrically Encrypted Data Packet (Tag 9) as defined in RFC 4880 Section 5.7.
/// </summary>
/// <remarks>
/// <para>
/// A Symmetrically Encrypted Data packet contains data encrypted with a symmetric-key
/// algorithm. The body of this packet consists of encrypted data, which when decrypted
/// yields one or more OpenPGP packets.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +---------------------------+
/// |     Encrypted Data        |
/// |        variable           |
/// +---------------------------+
/// </code>
/// </para>
/// <para>
/// <b>Security Note:</b> This packet type does not include any integrity protection.
/// It has been deprecated in favor of <see cref="PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData"/>
/// (Tag 18), which provides integrity verification via the Modification Detection Code (MDC).
/// Implementations SHOULD use SEIPD packets for new messages.
/// </para>
/// <para>
/// The encrypted data is created by first prefixing a block-sized random prefix plus
/// two repeated bytes for a "quick check", then encrypting using CFB mode with the
/// session key. The decryption process must verify the quick check bytes match.
/// </para>
/// </remarks>
public readonly struct PgpSymmetricallyEncryptedDataPacket : IEquatable<PgpSymmetricallyEncryptedDataPacket>
{
    /// <summary>
    /// Gets the encrypted data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This data includes the encrypted random prefix, quick check bytes, and the actual
    /// encrypted content. Decryption requires the session key and knowledge of the
    /// symmetric algorithm used.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> EncryptedData { get; }

    /// <summary>
    /// Initializes a new Symmetrically Encrypted Data packet.
    /// </summary>
    /// <param name="encryptedData">The encrypted data.</param>
    public PgpSymmetricallyEncryptedDataPacket(ReadOnlyMemory<byte> encryptedData)
    {
        EncryptedData = encryptedData;
    }

    /// <summary>
    /// Reads a Symmetrically Encrypted Data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is empty.</exception>
    public static PgpSymmetricallyEncryptedDataPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a Symmetrically Encrypted Data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSymmetricallyEncryptedDataPacket packet, out string error)
    {
        packet = default;

        if (source.Length == 0)
        {
            error = "Source is empty. Symmetrically Encrypted Data packet must contain encrypted data.";
            return false;
        }

        packet = new PgpSymmetricallyEncryptedDataPacket(source.ToArray());
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        return EncryptedData.Length;
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

        EncryptedData.Span.CopyTo(destination);
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
        return EncryptedData.ToArray();
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.SymmetricallyEncryptedData, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        return $"SymmetricallyEncryptedData({EncryptedData.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpSymmetricallyEncryptedDataPacket other)
    {
        return EncryptedData.Span.SequenceEqual(other.EncryptedData.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpSymmetricallyEncryptedDataPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
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
    public static bool operator ==(PgpSymmetricallyEncryptedDataPacket left, PgpSymmetricallyEncryptedDataPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpSymmetricallyEncryptedDataPacket left, PgpSymmetricallyEncryptedDataPacket right) => !left.Equals(right);
}
