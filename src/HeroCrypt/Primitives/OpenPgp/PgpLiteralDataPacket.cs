using System.Buffers.Binary;
using System.Text;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Literal Data Packet (Tag 11) as defined in RFC 4880 Section 5.9.
/// </summary>
/// <remarks>
/// <para>
/// A Literal Data packet contains the body of a message; data that is not to be
/// further interpreted. The body of this packet consists of:
/// </para>
/// <list type="bullet">
///   <item>A one-octet field that describes how the data is formatted</item>
///   <item>File name as a string (one-octet length followed by a file name)</item>
///   <item>A four-octet number indicating a date associated with the literal data</item>
///   <item>The remainder of the packet is literal data</item>
/// </list>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +------+--------+----------+------+------------+
/// |Format|Name Len| Filename | Date |    Data    |
/// |1 byte| 1 byte | variable |4 byte|  variable  |
/// +------+--------+----------+------+------------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpLiteralDataPacket : IEquatable<PgpLiteralDataPacket>
{
    /// <summary>
    /// Gets the data format indicator.
    /// </summary>
    public PgpLiteralDataFormat Format { get; }

    /// <summary>
    /// Gets the filename associated with the data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// May be empty string if no filename is specified.
    /// Limited to 255 bytes when UTF-8 encoded.
    /// </para>
    /// </remarks>
    public string FileName { get; }

    /// <summary>
    /// Gets the date/time associated with the literal data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Typically the file modification time. May be zero if not applicable.
    /// </para>
    /// </remarks>
    public DateTimeOffset Date { get; }

    /// <summary>
    /// Gets the literal data content.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// Initializes a new literal data packet.
    /// </summary>
    /// <param name="format">The data format.</param>
    /// <param name="fileName">The filename (empty string if none).</param>
    /// <param name="date">The date/time associated with the data.</param>
    /// <param name="data">The literal data content.</param>
    public PgpLiteralDataPacket(PgpLiteralDataFormat format, string fileName, DateTimeOffset date, ReadOnlyMemory<byte> data)
    {
        Format = format;
        FileName = fileName ?? string.Empty;
        Date = date;
        Data = data;

        var fileNameBytes = Encoding.UTF8.GetByteCount(FileName);
        if (fileNameBytes > 255)
        {
            throw new ArgumentException("Filename cannot exceed 255 bytes when UTF-8 encoded.", nameof(fileName));
        }
    }

    /// <summary>
    /// Creates a literal data packet for binary data.
    /// </summary>
    /// <param name="data">The binary data.</param>
    /// <param name="fileName">Optional filename.</param>
    /// <param name="date">Optional date (defaults to now).</param>
    /// <returns>A new literal data packet.</returns>
    public static PgpLiteralDataPacket CreateBinary(ReadOnlyMemory<byte> data, string fileName = "", DateTimeOffset? date = null)
    {
        return new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, fileName, date ?? DateTimeOffset.UtcNow, data);
    }

    /// <summary>
    /// Creates a literal data packet for text data.
    /// </summary>
    /// <param name="text">The text data.</param>
    /// <param name="fileName">Optional filename.</param>
    /// <param name="date">Optional date (defaults to now).</param>
    /// <returns>A new literal data packet.</returns>
    public static PgpLiteralDataPacket CreateText(string text, string fileName = "", DateTimeOffset? date = null)
    {
        var data = Encoding.UTF8.GetBytes(text);
        return new PgpLiteralDataPacket(PgpLiteralDataFormat.Text, fileName, date ?? DateTimeOffset.UtcNow, data);
    }

    /// <summary>
    /// Creates a literal data packet for UTF-8 text data.
    /// </summary>
    /// <param name="text">The UTF-8 text data.</param>
    /// <param name="fileName">Optional filename.</param>
    /// <param name="date">Optional date (defaults to now).</param>
    /// <returns>A new literal data packet.</returns>
    public static PgpLiteralDataPacket CreateUtf8(string text, string fileName = "", DateTimeOffset? date = null)
    {
        var data = Encoding.UTF8.GetBytes(text);
        return new PgpLiteralDataPacket(PgpLiteralDataFormat.Utf8, fileName, date ?? DateTimeOffset.UtcNow, data);
    }

    /// <summary>
    /// Reads a literal data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed literal data packet.</returns>
    /// <exception cref="ArgumentException">If the source is too short or malformed.</exception>
    public static PgpLiteralDataPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a literal data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpLiteralDataPacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        // Minimum: 1 (format) + 1 (name length) + 0 (name) + 4 (date) = 6 bytes
        if (source.Length < 6)
        {
            error = "Source too short for literal data packet header.";
            return false;
        }

        // Parse format byte
        var formatByte = source[0];
        if (formatByte != (byte)'b' && formatByte != (byte)'t' && formatByte != (byte)'u')
        {
            error = $"Invalid literal data format: 0x{formatByte:X2}. Expected 'b', 't', or 'u'.";
            return false;
        }

        var format = (PgpLiteralDataFormat)formatByte;

        // Parse filename length
        int nameLength = source[1];
        int headerLength = 2 + nameLength + 4; // format + name length + name + date

        if (source.Length < headerLength)
        {
            error = $"Source too short for literal data packet. Expected at least {headerLength} bytes, got {source.Length}.";
            return false;
        }

        // Parse filename
        string fileName = string.Empty;
        if (nameLength > 0)
        {
            try
            {
                fileName = Encoding.UTF8.GetString(source.Slice(2, nameLength));
            }
            catch (DecoderFallbackException)
            {
                error = "Invalid UTF-8 sequence in filename.";
                return false;
            }
        }

        // Parse date (4-byte big-endian Unix timestamp)
        uint timestamp = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(2 + nameLength, 4));
        var date = DateTimeOffset.FromUnixTimeSeconds(timestamp);

        // Extract data
        var data = source.Slice(headerLength).ToArray();

        packet = new PgpLiteralDataPacket(format, fileName, date, data);
        return true;
    }

    /// <summary>
    /// Gets the total encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        int fileNameLength = Encoding.UTF8.GetByteCount(FileName);
        return 1 + 1 + fileNameLength + 4 + Data.Length; // format + name length + name + date + data
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

        // Write format byte
        destination[offset++] = (byte)Format;

        // Write filename
        byte[] fileNameBytes = Encoding.UTF8.GetBytes(FileName);
        destination[offset++] = (byte)fileNameBytes.Length;
        fileNameBytes.CopyTo(destination.Slice(offset));
        offset += fileNameBytes.Length;

        // Write date as Unix timestamp
        long unixTime = Date.ToUnixTimeSeconds();
        if (unixTime < 0)
        {
            unixTime = 0;
        }
        else if (unixTime > uint.MaxValue)
        {
            unixTime = uint.MaxValue;
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset), (uint)unixTime);
        offset += 4;

        // Write data
        Data.Span.CopyTo(destination.Slice(offset));
        offset += Data.Length;

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
        writer.WritePacket(PgpPacketTag.LiteralData, body, format);
    }

    /// <summary>
    /// Gets the data as a UTF-8 string.
    /// </summary>
    /// <returns>The data decoded as UTF-8.</returns>
    /// <exception cref="InvalidOperationException">If the data is not valid UTF-8.</exception>
    public string GetDataAsString()
    {
        try
        {
            return Encoding.UTF8.GetString(Data.Span);
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidOperationException("Data is not valid UTF-8.", ex);
        }
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        var fileNamePart = string.IsNullOrEmpty(FileName) ? "no filename" : $"\"{FileName}\"";
        return $"LiteralData({Format}, {fileNamePart}, {Data.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpLiteralDataPacket other)
    {
        return Format == other.Format
            && FileName == other.FileName
            && Date.ToUnixTimeSeconds() == other.Date.ToUnixTimeSeconds()
            && Data.Span.SequenceEqual(other.Data.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpLiteralDataPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Format.GetHashCode();
            hash = hash * 31 + FileName.GetHashCode();
            hash = hash * 31 + Date.ToUnixTimeSeconds().GetHashCode();
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
    public static bool operator ==(PgpLiteralDataPacket left, PgpLiteralDataPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpLiteralDataPacket left, PgpLiteralDataPacket right) => !left.Equals(right);
}
