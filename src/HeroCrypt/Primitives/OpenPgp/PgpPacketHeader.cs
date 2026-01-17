using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a parsed OpenPGP packet header.
/// </summary>
/// <remarks>
/// <para>
/// Every OpenPGP packet begins with a header that specifies the packet type and length.
/// This structure contains the parsed header information.
/// </para>
/// </remarks>
public readonly struct PgpPacketHeader
{
    /// <summary>
    /// Gets the packet format (old or new).
    /// </summary>
    public PgpPacketFormat Format { get; }

    /// <summary>
    /// Gets the packet tag identifying the packet type.
    /// </summary>
    public PgpPacketTag Tag { get; }

    /// <summary>
    /// Gets the packet body length in bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A value of -1 indicates an indeterminate length (old format) or
    /// partial body length (new format), where the packet continues to EOF
    /// or uses chunked encoding.
    /// </para>
    /// </remarks>
    public long BodyLength { get; }

    /// <summary>
    /// Gets the total header length in bytes.
    /// </summary>
    public int HeaderLength { get; }

    /// <summary>
    /// Gets whether this packet has an indeterminate or partial length.
    /// </summary>
    public bool IsPartialLength => BodyLength < 0;

    /// <summary>
    /// Gets the partial body length if this is a partial-length packet.
    /// </summary>
    /// <remarks>
    /// <para>Only valid when <see cref="IsPartialLength"/> is true for new format packets.</para>
    /// </remarks>
    public int PartialBodyLength { get; }

    /// <summary>
    /// Initializes a new packet header.
    /// </summary>
    public PgpPacketHeader(PgpPacketFormat format, PgpPacketTag tag, long bodyLength, int headerLength, int partialBodyLength = 0)
    {
        Format = format;
        Tag = tag;
        BodyLength = bodyLength;
        HeaderLength = headerLength;
        PartialBodyLength = partialBodyLength;
    }

    /// <summary>
    /// Reads a packet header from a span.
    /// </summary>
    /// <param name="source">The source span.</param>
    /// <param name="header">The parsed header.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <returns>True if the header was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpPacketHeader header, out int bytesConsumed)
    {
        header = default;
        bytesConsumed = 0;

        if (source.IsEmpty)
        {
            return false;
        }

        byte firstByte = source[0];

        // Bit 7 must be set (packet tag bit)
        if ((firstByte & 0x80) == 0)
        {
            return false;
        }

        // Bit 6 determines old vs new format
        bool isNewFormat = (firstByte & 0x40) != 0;

        if (isNewFormat)
        {
            return TryReadNewFormat(source, out header, out bytesConsumed);
        }
        else
        {
            return TryReadOldFormat(source, out header, out bytesConsumed);
        }
    }

    /// <summary>
    /// Reads a packet header from a span, throwing on failure.
    /// </summary>
    public static PgpPacketHeader Read(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (!TryRead(source, out var header, out bytesConsumed))
        {
            throw new InvalidOperationException("Invalid or incomplete packet header.");
        }

        return header;
    }

    private static bool TryReadNewFormat(ReadOnlySpan<byte> source, out PgpPacketHeader header, out int bytesConsumed)
    {
        header = default;
        bytesConsumed = 0;

        if (source.Length < 2)
        {
            return false;
        }

        // Tag is in bits 5-0
        var tag = (PgpPacketTag)(source[0] & 0x3F);

        // Parse length (RFC 4880 Section 4.2.2)
        byte lenByte = source[1];

        if (lenByte < 192)
        {
            // One-octet length: 0-191 bytes
            header = new PgpPacketHeader(PgpPacketFormat.New, tag, lenByte, 2);
            bytesConsumed = 2;
            return true;
        }
        else if (lenByte < 224)
        {
            // Two-octet length: 192-8383 bytes
            if (source.Length < 3)
            {
                return false;
            }

            int length = ((lenByte - 192) << 8) + source[2] + 192;
            header = new PgpPacketHeader(PgpPacketFormat.New, tag, length, 3);
            bytesConsumed = 3;
            return true;
        }
        else if (lenByte == 255)
        {
            // Five-octet length: 0-4294967295 bytes
            if (source.Length < 6)
            {
                return false;
            }

            uint length = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(2));
            header = new PgpPacketHeader(PgpPacketFormat.New, tag, length, 6);
            bytesConsumed = 6;
            return true;
        }
        else
        {
            // Partial body length (224-254): power of 2 chunk size
            int partialLength = 1 << (lenByte & 0x1F);
            header = new PgpPacketHeader(PgpPacketFormat.New, tag, -1, 2, partialLength);
            bytesConsumed = 2;
            return true;
        }
    }

    private static bool TryReadOldFormat(ReadOnlySpan<byte> source, out PgpPacketHeader header, out int bytesConsumed)
    {
        header = default;
        bytesConsumed = 0;

        if (source.IsEmpty)
        {
            return false;
        }

        byte firstByte = source[0];

        // Tag is in bits 5-2
        var tag = (PgpPacketTag)((firstByte & 0x3C) >> 2);

        // Length type is in bits 1-0
        int lengthType = firstByte & 0x03;

        switch (lengthType)
        {
            case 0:
                // One-octet length
                if (source.Length < 2)
                {
                    return false;
                }

                header = new PgpPacketHeader(PgpPacketFormat.Old, tag, source[1], 2);
                bytesConsumed = 2;
                return true;

            case 1:
                // Two-octet length
                if (source.Length < 3)
                {
                    return false;
                }

                header = new PgpPacketHeader(PgpPacketFormat.Old, tag, BinaryPrimitives.ReadUInt16BigEndian(source.Slice(1)), 3);
                bytesConsumed = 3;
                return true;

            case 2:
                // Four-octet length
                if (source.Length < 5)
                {
                    return false;
                }

                header = new PgpPacketHeader(PgpPacketFormat.Old, tag, BinaryPrimitives.ReadUInt32BigEndian(source.Slice(1)), 5);
                bytesConsumed = 5;
                return true;

            case 3:
                // Indeterminate length (read until EOF)
                header = new PgpPacketHeader(PgpPacketFormat.Old, tag, -1, 1);
                bytesConsumed = 1;
                return true;

            default:
                return false;
        }
    }

    /// <summary>
    /// Writes a new format packet header to a span.
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="bodyLength">The body length.</param>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    public static int WriteNewFormat(PgpPacketTag tag, long bodyLength, Span<byte> destination)
    {
        if (!TryWriteNewFormat(tag, bodyLength, destination, out int bytesWritten))
        {
            throw new ArgumentException("Destination too small for packet header.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Tries to write a new format packet header.
    /// </summary>
    public static bool TryWriteNewFormat(PgpPacketTag tag, long bodyLength, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;

        if (bodyLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bodyLength), "Use WriteNewFormatPartial for partial length packets.");
        }

        // Header byte: 11TTTTTT
        byte headerByte = (byte)(0xC0 | ((byte)tag & 0x3F));

        if (bodyLength < 192)
        {
            // One-octet length
            if (destination.Length < 2)
            {
                return false;
            }

            destination[0] = headerByte;
            destination[1] = (byte)bodyLength;
            bytesWritten = 2;
            return true;
        }
        else if (bodyLength < 8384)
        {
            // Two-octet length: ((first - 192) << 8) + second + 192 = length
            if (destination.Length < 3)
            {
                return false;
            }

            int adjusted = (int)bodyLength - 192;
            destination[0] = headerByte;
            destination[1] = (byte)((adjusted >> 8) + 192);
            destination[2] = (byte)(adjusted & 0xFF);
            bytesWritten = 3;
            return true;
        }
        else
        {
            // Five-octet length
            if (destination.Length < 6)
            {
                return false;
            }

            destination[0] = headerByte;
            destination[1] = 255;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(2), (uint)bodyLength);
            bytesWritten = 6;
            return true;
        }
    }

    /// <summary>
    /// Writes a partial length header byte for chunked encoding.
    /// </summary>
    /// <param name="tag">The packet tag (only used for first chunk).</param>
    /// <param name="chunkPower">Power of 2 for chunk size (0-30, giving 1 to 1GB chunks).</param>
    /// <param name="isFirst">Whether this is the first chunk (includes tag).</param>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    public static int WriteNewFormatPartial(PgpPacketTag tag, int chunkPower, bool isFirst, Span<byte> destination)
    {
        if (chunkPower < 0 || chunkPower > 30)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkPower), "Chunk power must be 0-30.");
        }

        if (isFirst)
        {
            if (destination.Length < 2)
            {
                throw new ArgumentException("Destination too small.", nameof(destination));
            }

            destination[0] = (byte)(0xC0 | ((byte)tag & 0x3F));
            destination[1] = (byte)(224 + chunkPower);
            return 2;
        }
        else
        {
            if (destination.IsEmpty)
            {
                throw new ArgumentException("Destination too small.", nameof(destination));
            }

            destination[0] = (byte)(224 + chunkPower);
            return 1;
        }
    }

    /// <summary>
    /// Writes an old format packet header.
    /// </summary>
    /// <param name="tag">The packet tag (must be 0-15).</param>
    /// <param name="bodyLength">The body length.</param>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    public static int WriteOldFormat(PgpPacketTag tag, long bodyLength, Span<byte> destination)
    {
        if (!TryWriteOldFormat(tag, bodyLength, destination, out int bytesWritten))
        {
            throw new ArgumentException("Destination too small or invalid tag for old format.", nameof(destination));
        }

        return bytesWritten;
    }

    /// <summary>
    /// Tries to write an old format packet header.
    /// </summary>
    public static bool TryWriteOldFormat(PgpPacketTag tag, long bodyLength, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;

        if ((byte)tag > 15)
        {
            return false; // Old format only supports tags 0-15
        }

        if (bodyLength < 0)
        {
            // Indeterminate length
            if (destination.IsEmpty)
            {
                return false;
            }

            destination[0] = (byte)(0x80 | (((byte)tag & 0x0F) << 2) | 0x03);
            bytesWritten = 1;
            return true;
        }
        else if (bodyLength <= 255)
        {
            // One-octet length
            if (destination.Length < 2)
            {
                return false;
            }

            destination[0] = (byte)(0x80 | (((byte)tag & 0x0F) << 2) | 0x00);
            destination[1] = (byte)bodyLength;
            bytesWritten = 2;
            return true;
        }
        else if (bodyLength <= 65535)
        {
            // Two-octet length
            if (destination.Length < 3)
            {
                return false;
            }

            destination[0] = (byte)(0x80 | (((byte)tag & 0x0F) << 2) | 0x01);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(1), (ushort)bodyLength);
            bytesWritten = 3;
            return true;
        }
        else
        {
            // Four-octet length
            if (destination.Length < 5)
            {
                return false;
            }

            destination[0] = (byte)(0x80 | (((byte)tag & 0x0F) << 2) | 0x02);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(1), (uint)bodyLength);
            bytesWritten = 5;
            return true;
        }
    }

    /// <summary>
    /// Gets the header size for a new format packet with the given body length.
    /// </summary>
    public static int GetNewFormatHeaderSize(long bodyLength)
    {
        if (bodyLength < 192)
        {
            return 2;
        }
        else if (bodyLength < 8384)
        {
            return 3;
        }
        else
        {
            return 6;
        }
    }

    /// <summary>
    /// Gets the header size for an old format packet with the given body length.
    /// </summary>
    public static int GetOldFormatHeaderSize(long bodyLength)
    {
        if (bodyLength < 0)
        {
            return 1; // Indeterminate
        }
        else if (bodyLength <= 255)
        {
            return 2;
        }
        else if (bodyLength <= 65535)
        {
            return 3;
        }
        else
        {
            return 5;
        }
    }

    /// <inheritdoc />
    public override string ToString() =>
        IsPartialLength
            ? $"PgpPacketHeader({Format}, {Tag}, Partial: {PartialBodyLength})"
            : $"PgpPacketHeader({Format}, {Tag}, {BodyLength} bytes)";
}
