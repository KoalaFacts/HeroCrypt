using System.IO.Compression;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Compressed Data Packet (Tag 8) as defined in RFC 4880 Section 5.6.
/// </summary>
/// <remarks>
/// <para>
/// A Compressed Data Packet contains compressed data. The body of this packet
/// consists of one octet specifying the compression algorithm, followed by the
/// compressed data.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +----------+-------------------+
/// | Algorithm|  Compressed Data  |
/// |   1 B    |    variable       |
/// +----------+-------------------+
/// </code>
/// </para>
/// <para>
/// The compressed data, when decompressed, yields one or more OpenPGP packets
/// that make up the message body.
/// </para>
/// </remarks>
public readonly struct PgpCompressedDataPacket : IEquatable<PgpCompressedDataPacket>
{
    /// <summary>
    /// Gets the compression algorithm used.
    /// </summary>
    public PgpCompressionAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the compressed data (or uncompressed data if algorithm is Uncompressed).
    /// </summary>
    public ReadOnlyMemory<byte> CompressedData { get; }

    /// <summary>
    /// Initializes a new Compressed Data packet.
    /// </summary>
    /// <param name="algorithm">The compression algorithm.</param>
    /// <param name="compressedData">The compressed data.</param>
    public PgpCompressedDataPacket(PgpCompressionAlgorithm algorithm, ReadOnlyMemory<byte> compressedData)
    {
        Algorithm = algorithm;
        CompressedData = compressedData;
    }

    /// <summary>
    /// Creates a Compressed Data packet by compressing the given data.
    /// </summary>
    /// <param name="data">The data to compress.</param>
    /// <param name="algorithm">The compression algorithm to use.</param>
    /// <param name="compressionLevel">The compression level (default: Optimal).</param>
    /// <returns>A new Compressed Data packet.</returns>
    /// <exception cref="NotSupportedException">If the compression algorithm is not supported.</exception>
    public static PgpCompressedDataPacket Create(
        ReadOnlySpan<byte> data,
        PgpCompressionAlgorithm algorithm,
        CompressionLevel compressionLevel = CompressionLevel.Optimal)
    {
        byte[] compressedData = algorithm switch
        {
            PgpCompressionAlgorithm.Uncompressed => data.ToArray(),
            PgpCompressionAlgorithm.Zip => CompressDeflate(data, compressionLevel),
            PgpCompressionAlgorithm.Zlib => CompressZlib(data, compressionLevel),
            PgpCompressionAlgorithm.BZip2 => throw new NotSupportedException("BZip2 compression is not supported. Use Zip or Zlib instead."),
            _ => throw new NotSupportedException($"Unknown compression algorithm: {algorithm}"),
        };

        return new PgpCompressedDataPacket(algorithm, compressedData);
    }

    /// <summary>
    /// Decompresses the data contained in this packet.
    /// </summary>
    /// <returns>The decompressed data.</returns>
    /// <exception cref="NotSupportedException">If the compression algorithm is not supported.</exception>
    /// <exception cref="InvalidDataException">If the compressed data is invalid.</exception>
    public byte[] Decompress()
    {
        return Algorithm switch
        {
            PgpCompressionAlgorithm.Uncompressed => CompressedData.ToArray(),
            PgpCompressionAlgorithm.Zip => DecompressDeflate(CompressedData.Span),
            PgpCompressionAlgorithm.Zlib => DecompressZlib(CompressedData.Span),
            PgpCompressionAlgorithm.BZip2 => throw new NotSupportedException("BZip2 decompression is not supported."),
            _ => throw new NotSupportedException($"Unknown compression algorithm: {Algorithm}"),
        };
    }

    /// <summary>
    /// Reads a Compressed Data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed Compressed Data packet.</returns>
    /// <exception cref="ArgumentException">If the source is too short.</exception>
    public static PgpCompressedDataPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a Compressed Data packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpCompressedDataPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for Compressed Data packet. Need at least 1 byte for algorithm.";
            return false;
        }

        var algorithm = (PgpCompressionAlgorithm)source[0];
        var compressedData = source.Slice(1).ToArray();

        packet = new PgpCompressedDataPacket(algorithm, compressedData);
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        return 1 + CompressedData.Length;
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

        destination[0] = (byte)Algorithm;
        CompressedData.Span.CopyTo(destination.Slice(1));

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
        writer.WritePacket(PgpPacketTag.CompressedData, body, format);
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        return $"CompressedData({Algorithm}, {CompressedData.Length} bytes)";
    }

    /// <inheritdoc />
    public bool Equals(PgpCompressedDataPacket other)
    {
        return Algorithm == other.Algorithm
            && CompressedData.Span.SequenceEqual(other.CompressedData.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpCompressedDataPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Algorithm.GetHashCode();
            foreach (var b in CompressedData.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpCompressedDataPacket left, PgpCompressedDataPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpCompressedDataPacket left, PgpCompressedDataPacket right) => !left.Equals(right);

    private static byte[] CompressDeflate(ReadOnlySpan<byte> data, CompressionLevel level)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, level, leaveOpen: true))
        {
#if NETSTANDARD2_0
            var array = data.ToArray();
            deflate.Write(array, 0, array.Length);
#else
            deflate.Write(data);
#endif
        }

        return output.ToArray();
    }

    private static byte[] DecompressDeflate(ReadOnlySpan<byte> data)
    {
        using var input = new MemoryStream(data.ToArray());
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] CompressZlib(ReadOnlySpan<byte> data, CompressionLevel level)
    {
        using var output = new MemoryStream();

        // Write zlib header (CMF + FLG)
        // CMF: CM=8 (deflate), CINFO=7 (32K window) => 0x78
        // FLG: FCHECK=0x9C for level 6 (default), 0x01 for fastest, 0xDA for best
        // FLG values for different compression levels
        // SmallestSize (value 3) was added in .NET 7
        byte flg = (int)level switch
        {
            (int)CompressionLevel.Fastest => 0x01,
            3 => 0xDA, // SmallestSize
            _ => 0x9C, // Optimal/default
        };

        // Adjust FCHECK so (CMF * 256 + FLG) is divisible by 31
        byte cmf = 0x78;
        int check = (cmf * 256 + flg) % 31;
        if (check != 0)
        {
            flg = (byte)(flg + (31 - check));
        }

        output.WriteByte(cmf);
        output.WriteByte(flg);

        // Write deflate-compressed data
        using (var deflate = new DeflateStream(output, level, leaveOpen: true))
        {
#if NETSTANDARD2_0
            var array = data.ToArray();
            deflate.Write(array, 0, array.Length);
#else
            deflate.Write(data);
#endif
        }

        // Calculate and write Adler-32 checksum (big-endian)
        uint adler = ComputeAdler32(data);
        output.WriteByte((byte)(adler >> 24));
        output.WriteByte((byte)(adler >> 16));
        output.WriteByte((byte)(adler >> 8));
        output.WriteByte((byte)adler);

        return output.ToArray();
    }

    private static byte[] DecompressZlib(ReadOnlySpan<byte> data)
    {
        if (data.Length < 6)
        {
            throw new InvalidDataException("Zlib data too short. Need at least 6 bytes for header and checksum.");
        }

        // Verify zlib header
        byte cmf = data[0];
        byte flg = data[1];

        if ((cmf & 0x0F) != 8)
        {
            throw new InvalidDataException($"Invalid zlib compression method: {cmf & 0x0F}. Expected 8 (deflate).");
        }

        if ((cmf * 256 + flg) % 31 != 0)
        {
            throw new InvalidDataException("Invalid zlib header checksum.");
        }

        // Skip header (2 bytes), decompress, verify checksum
        var compressedData = data.Slice(2, data.Length - 6);

        using var input = new MemoryStream(compressedData.ToArray());
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        var decompressed = output.ToArray();

        // Verify Adler-32 checksum
        uint expectedAdler = (uint)((data[data.Length - 4] << 24) |
                                    (data[data.Length - 3] << 16) |
                                    (data[data.Length - 2] << 8) |
                                    data[data.Length - 1]);
        uint actualAdler = ComputeAdler32(decompressed);

        if (expectedAdler != actualAdler)
        {
            throw new InvalidDataException("Zlib checksum mismatch.");
        }

        return decompressed;
    }

    private static uint ComputeAdler32(ReadOnlySpan<byte> data)
    {
        const uint MOD_ADLER = 65521;
        uint a = 1;
        uint b = 0;

        foreach (byte d in data)
        {
            a = (a + d) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }

        return (b << 16) | a;
    }
}
