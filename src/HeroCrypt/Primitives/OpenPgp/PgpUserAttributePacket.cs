using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a User Attribute Packet (Tag 17) as defined in RFC 4880 Section 5.12.
/// </summary>
/// <remarks>
/// <para>
/// The User Attribute packet is similar to the User ID packet, but instead of
/// containing text, it contains one or more subpackets of binary data. Currently,
/// the only defined subpacket type is the Image Attribute subpacket.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +-------------------------+
/// |  Subpackets (variable)  |
/// +-------------------------+
/// </code>
/// Each subpacket has the format:
/// <code>
/// +--------+------+-----------+
/// | Length | Type |   Data    |
/// |1-5 byte|1 byte| variable  |
/// +--------+------+-----------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpUserAttributePacket : IEquatable<PgpUserAttributePacket>
{
    /// <summary>
    /// Gets the raw subpacket data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This contains one or more subpackets in their encoded form.
    /// Use <see cref="GetImageData"/> to extract the first image.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> SubpacketData { get; }

    /// <summary>
    /// Initializes a new User Attribute packet with raw subpacket data.
    /// </summary>
    /// <param name="subpacketData">The raw subpacket data.</param>
    public PgpUserAttributePacket(ReadOnlyMemory<byte> subpacketData)
    {
        SubpacketData = subpacketData;
    }

    /// <summary>
    /// Creates a User Attribute packet containing a JPEG image.
    /// </summary>
    /// <param name="jpegData">The JPEG image data.</param>
    /// <returns>A new User Attribute packet.</returns>
    public static PgpUserAttributePacket CreateWithImage(ReadOnlySpan<byte> jpegData)
    {
        return CreateWithImage(jpegData, PgpImageEncoding.Jpeg);
    }

    /// <summary>
    /// Creates a User Attribute packet containing an image.
    /// </summary>
    /// <param name="imageData">The image data.</param>
    /// <param name="encoding">The image encoding.</param>
    /// <returns>A new User Attribute packet.</returns>
    public static PgpUserAttributePacket CreateWithImage(ReadOnlySpan<byte> imageData, PgpImageEncoding encoding)
    {
        // Image attribute subpacket format:
        // - Image header length (2 bytes, little-endian) = 16 (fixed for v1)
        // - Image header version (1 byte) = 1
        // - Image encoding (1 byte)
        // - 12 bytes reserved (zeros)
        // - Image data

        const int imageHeaderLength = 16;
        int subpacketDataLength = imageHeaderLength + imageData.Length;

        // Calculate subpacket length encoding
        int subpacketLengthBytes = GetSubpacketLengthBytes(subpacketDataLength + 1); // +1 for type byte
        int totalLength = subpacketLengthBytes + 1 + subpacketDataLength; // length + type + data

        var result = new byte[totalLength];
        int offset = 0;

        // Write subpacket length
        offset += WriteSubpacketLength(result.AsSpan(offset), subpacketDataLength + 1);

        // Write subpacket type (Image = 1)
        result[offset++] = (byte)PgpUserAttributeSubpacketType.Image;

        // Write image header length (little-endian)
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(offset), imageHeaderLength);
        offset += 2;

        // Write image header version
        result[offset++] = 1;

        // Write image encoding
        result[offset++] = (byte)encoding;

        // Write 12 reserved bytes (zeros) - already zero-initialized
        offset += 12;

        // Write image data
        imageData.CopyTo(result.AsSpan(offset));

        return new PgpUserAttributePacket(result);
    }

    /// <summary>
    /// Gets the image data from the first Image Attribute subpacket.
    /// </summary>
    /// <param name="imageData">The extracted image data.</param>
    /// <param name="encoding">The image encoding.</param>
    /// <returns>True if an image was found; otherwise false.</returns>
    public bool TryGetImageData(out ReadOnlyMemory<byte> imageData, out PgpImageEncoding encoding)
    {
        imageData = ReadOnlyMemory<byte>.Empty;
        encoding = PgpImageEncoding.Jpeg;

        var span = SubpacketData.Span;
        int offset = 0;

        while (offset < span.Length)
        {
            // Read subpacket length
            if (!TryReadSubpacketLength(span.Slice(offset), out int subpacketLength, out int lengthBytes))
            {
                return false;
            }

            offset += lengthBytes;

            if (offset >= span.Length || subpacketLength < 1)
            {
                return false;
            }

            // Read subpacket type
            var subpacketType = (PgpUserAttributeSubpacketType)span[offset];
            int dataLength = subpacketLength - 1;

            if (subpacketType == PgpUserAttributeSubpacketType.Image)
            {
                // Parse image attribute
                if (dataLength < 16) // Minimum header size
                {
                    return false;
                }

                int dataStart = offset + 1;

                // Read image header length (little-endian)
                int imageHeaderLength = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(dataStart, 2));

                if (dataLength < imageHeaderLength)
                {
                    return false;
                }

                // Read version (should be 1)
                // byte version = span[dataStart + 2];

                // Read encoding
                encoding = (PgpImageEncoding)span[dataStart + 3];

                // Image data starts after header
                int imageStart = dataStart + imageHeaderLength;
                int imageLength = dataLength - imageHeaderLength;

                if (imageLength > 0)
                {
                    imageData = SubpacketData.Slice(imageStart, imageLength);
                }

                return true;
            }

            // Skip to next subpacket
            offset += subpacketLength;
        }

        return false;
    }

    /// <summary>
    /// Gets the image data from the first Image Attribute subpacket.
    /// </summary>
    /// <returns>The image data, or empty if no image found.</returns>
    public ReadOnlyMemory<byte> GetImageData()
    {
        TryGetImageData(out var imageData, out _);
        return imageData;
    }

    /// <summary>
    /// Reads a User Attribute packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is empty.</exception>
    public static PgpUserAttributePacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a User Attribute packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpUserAttributePacket packet, out string error)
    {
        packet = default;

        if (source.Length == 0)
        {
            error = "Source is empty. User Attribute packet must contain subpacket data.";
            return false;
        }

        packet = new PgpUserAttributePacket(source.ToArray());
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        return SubpacketData.Length;
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

        SubpacketData.Span.CopyTo(destination);
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
        return SubpacketData.ToArray();
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.UserAttribute, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        if (TryGetImageData(out var imageData, out var encoding))
        {
            return $"UserAttribute(Image: {encoding}, {imageData.Length} bytes)";
        }

        return $"UserAttribute({SubpacketData.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpUserAttributePacket other)
    {
        return SubpacketData.Span.SequenceEqual(other.SubpacketData.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpUserAttributePacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            foreach (var b in SubpacketData.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpUserAttributePacket left, PgpUserAttributePacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpUserAttributePacket left, PgpUserAttributePacket right) => !left.Equals(right);

    private static int GetSubpacketLengthBytes(int length)
    {
        if (length < 192)
        {
            return 1;
        }
        else if (length < 16576) // 192 + 255*256
        {
            return 2;
        }
        else
        {
            return 5;
        }
    }

    private static int WriteSubpacketLength(Span<byte> destination, int length)
    {
        if (length < 192)
        {
            destination[0] = (byte)length;
            return 1;
        }
        else if (length < 16576)
        {
            int adjusted = length - 192;
            destination[0] = (byte)((adjusted >> 8) + 192);
            destination[1] = (byte)(adjusted & 0xFF);
            return 2;
        }
        else
        {
            destination[0] = 0xFF;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(1), (uint)length);
            return 5;
        }
    }

    private static bool TryReadSubpacketLength(ReadOnlySpan<byte> source, out int length, out int bytesRead)
    {
        length = 0;
        bytesRead = 0;

        if (source.Length < 1)
        {
            return false;
        }

        byte first = source[0];

        if (first < 192)
        {
            length = first;
            bytesRead = 1;
            return true;
        }
        else if (first < 255)
        {
            if (source.Length < 2)
            {
                return false;
            }

            length = ((first - 192) << 8) + source[1] + 192;
            bytesRead = 2;
            return true;
        }
        else
        {
            if (source.Length < 5)
            {
                return false;
            }

            length = (int)BinaryPrimitives.ReadUInt32BigEndian(source.Slice(1));
            bytesRead = 5;
            return true;
        }
    }
}
