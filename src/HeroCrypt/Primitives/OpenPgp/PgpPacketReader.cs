using System.Buffers;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Reads OpenPGP packets from a stream.
/// </summary>
/// <remarks>
/// <para>
/// This class provides sequential access to OpenPGP packets in a stream.
/// It handles both old and new format packets, including partial body lengths.
/// </para>
/// <para>
/// <b>Usage:</b>
/// <code>
/// using var reader = new PgpPacketReader(stream);
/// while (reader.ReadNextPacket(out var tag, out var body))
/// {
///     ProcessPacket(tag, body);
/// }
/// </code>
/// </para>
/// <para>
/// <b>Security:</b> To prevent denial-of-service attacks via oversized packets,
/// configure <see cref="MaxPacketSize"/> to an appropriate limit for your use case.
/// </para>
/// </remarks>
public sealed class PgpPacketReader : IDisposable
{
    /// <summary>
    /// The default maximum packet size (256 MB).
    /// </summary>
    public const int DefaultMaxPacketSize = 256 * 1024 * 1024;

    private readonly Stream stream;
    private readonly bool leaveOpen;
    private readonly byte[] headerBuffer;
    private bool disposed;

    /// <summary>
    /// Gets or sets the maximum allowed packet size in bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This limit protects against denial-of-service attacks where a malicious
    /// packet claims an extremely large body size, causing excessive memory allocation.
    /// </para>
    /// <para>
    /// Set to 0 or negative to disable the limit (not recommended).
    /// The default is <see cref="DefaultMaxPacketSize"/> (256 MB).
    /// </para>
    /// </remarks>
    public int MaxPacketSize { get; set; } = DefaultMaxPacketSize;

    /// <summary>
    /// Initializes a new packet reader for the given stream.
    /// </summary>
    /// <param name="stream">The stream to read packets from.</param>
    /// <param name="leaveOpen">Whether to leave the stream open when disposed.</param>
    public PgpPacketReader(Stream stream, bool leaveOpen = false)
        : this(stream, leaveOpen, DefaultMaxPacketSize)
    {
    }

    /// <summary>
    /// Initializes a new packet reader with a custom maximum packet size.
    /// </summary>
    /// <param name="stream">The stream to read packets from.</param>
    /// <param name="leaveOpen">Whether to leave the stream open when disposed.</param>
    /// <param name="maxPacketSize">Maximum packet size in bytes (0 or negative to disable).</param>
    public PgpPacketReader(Stream stream, bool leaveOpen, int maxPacketSize)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
        this.leaveOpen = leaveOpen;
        MaxPacketSize = maxPacketSize;
        headerBuffer = new byte[6]; // Maximum header size
    }

    /// <summary>
    /// Reads the next packet from the stream.
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="body">The packet body (caller must dispose).</param>
    /// <returns>True if a packet was read, false if end of stream.</returns>
    public bool ReadNextPacket(out PgpPacketTag tag, out ReadOnlyMemory<byte> body)
    {
        ThrowIfDisposed();

        tag = default;
        body = default;

        // Try to read the first header byte
        int firstByte = stream.ReadByte();
        if (firstByte < 0)
        {
            return false; // End of stream
        }

        // Validate packet tag bit
        if ((firstByte & 0x80) == 0)
        {
            throw new InvalidDataException("Invalid packet: bit 7 must be set.");
        }

        bool isNewFormat = (firstByte & 0x40) != 0;

        if (isNewFormat)
        {
            return ReadNewFormatPacket((byte)firstByte, out tag, out body);
        }
        else
        {
            return ReadOldFormatPacket((byte)firstByte, out tag, out body);
        }
    }

    /// <summary>
    /// Reads the next packet header without consuming the body.
    /// </summary>
    /// <param name="header">The parsed header.</param>
    /// <returns>True if a header was read, false if end of stream.</returns>
    /// <remarks>
    /// <para>
    /// This method reads the header but does not consume the packet body.
    /// The stream position will be after the header, ready to read body data.
    /// </para>
    /// </remarks>
    public bool ReadNextHeader(out PgpPacketHeader header)
    {
        ThrowIfDisposed();

        header = default;

        int bytesRead = stream.Read(headerBuffer, 0, 1);
        if (bytesRead == 0)
        {
            return false;
        }

        // Read enough bytes for the header
        int maxHeaderBytes = (headerBuffer[0] & 0x40) != 0 ? 6 : 5;
        int totalRead = 1;

        while (totalRead < maxHeaderBytes)
        {
            int read = stream.Read(headerBuffer, totalRead, 1);
            if (read == 0)
            {
                break;
            }

            totalRead++;

            // Check if we have enough for the header
            if (PgpPacketHeader.TryRead(headerBuffer.AsSpan(0, totalRead), out header, out _))
            {
                return true;
            }
        }

        // Try one final parse
        return PgpPacketHeader.TryRead(headerBuffer.AsSpan(0, totalRead), out header, out _);
    }

    private bool ReadNewFormatPacket(byte firstByte, out PgpPacketTag tag, out ReadOnlyMemory<byte> body)
    {
        tag = (PgpPacketTag)(firstByte & 0x3F);
        body = default;

        // Read length byte
        int lenByte = stream.ReadByte();
        if (lenByte < 0)
        {
            throw new InvalidDataException("Unexpected end of stream reading packet length.");
        }

        if (lenByte < 192)
        {
            // One-octet length
            ValidatePacketSize(lenByte);
            body = ReadExactly(lenByte);
            return true;
        }
        else if (lenByte < 224)
        {
            // Two-octet length
            int secondByte = stream.ReadByte();
            if (secondByte < 0)
            {
                throw new InvalidDataException("Unexpected end of stream reading packet length.");
            }

            int length = ((lenByte - 192) << 8) + secondByte + 192;
            ValidatePacketSize(length);
            body = ReadExactly(length);
            return true;
        }
        else if (lenByte == 255)
        {
            // Five-octet length
            byte[] lenBytes = new byte[4];
            ReadExactlyInto(lenBytes);
            int length = (lenBytes[0] << 24) | (lenBytes[1] << 16) | (lenBytes[2] << 8) | lenBytes[3];
            ValidatePacketSize(length);
            body = ReadExactly(length);
            return true;
        }
        else
        {
            // Partial body length (chunked)
            body = ReadPartialBodyPacket(lenByte);
            return true;
        }
    }

    private ReadOnlyMemory<byte> ReadPartialBodyPacket(int firstLenByte)
    {
        using var bodyStream = new MemoryStream();
        long totalSize = 0;

        int currentLenByte = firstLenByte;

        while (true)
        {
            if (currentLenByte >= 224 && currentLenByte < 255)
            {
                // Partial body length: 2^(lenByte & 0x1F)
                int chunkSize = 1 << (currentLenByte & 0x1F);
                totalSize += chunkSize;
                ValidatePartialBodySize(totalSize);
                CopyExactly(chunkSize, bodyStream);

                // Read next length byte
                int nextLenByte = stream.ReadByte();
                if (nextLenByte < 0)
                {
                    throw new InvalidDataException("Unexpected end of stream in partial body packet.");
                }

                currentLenByte = nextLenByte;
            }
            else if (currentLenByte < 192)
            {
                // Final chunk with one-octet length
                totalSize += currentLenByte;
                ValidatePartialBodySize(totalSize);
                CopyExactly(currentLenByte, bodyStream);
                break;
            }
            else if (currentLenByte < 224)
            {
                // Final chunk with two-octet length
                int secondByte = stream.ReadByte();
                if (secondByte < 0)
                {
                    throw new InvalidDataException("Unexpected end of stream reading final chunk length.");
                }

                int length = ((currentLenByte - 192) << 8) + secondByte + 192;
                totalSize += length;
                ValidatePartialBodySize(totalSize);
                CopyExactly(length, bodyStream);
                break;
            }
            else // currentLenByte == 255
            {
                // Final chunk with five-octet length
                byte[] lenBytes = new byte[4];
                ReadExactlyInto(lenBytes);
                int length = (lenBytes[0] << 24) | (lenBytes[1] << 16) | (lenBytes[2] << 8) | lenBytes[3];
                totalSize += length;
                ValidatePartialBodySize(totalSize);
                CopyExactly(length, bodyStream);
                break;
            }
        }

        return bodyStream.ToArray();
    }

    private void ValidatePartialBodySize(long totalSize)
    {
        if (MaxPacketSize > 0 && totalSize > MaxPacketSize)
        {
            throw new InvalidDataException($"Partial body packet size ({totalSize} bytes) exceeds maximum allowed ({MaxPacketSize} bytes).");
        }
    }

    private bool ReadOldFormatPacket(byte firstByte, out PgpPacketTag tag, out ReadOnlyMemory<byte> body)
    {
        tag = (PgpPacketTag)((firstByte & 0x3C) >> 2);
        int lengthType = firstByte & 0x03;
        body = default;

        long length;

        switch (lengthType)
        {
            case 0:
                // One-octet length
                int len1 = stream.ReadByte();
                if (len1 < 0)
                {
                    throw new InvalidDataException("Unexpected end of stream reading packet length.");
                }

                length = len1;
                break;

            case 1:
                // Two-octet length
                byte[] len2Bytes = new byte[2];
                ReadExactlyInto(len2Bytes);
                length = (len2Bytes[0] << 8) | len2Bytes[1];
                break;

            case 2:
                // Four-octet length
                byte[] len4Bytes = new byte[4];
                ReadExactlyInto(len4Bytes);
                length = (len4Bytes[0] << 24) | (len4Bytes[1] << 16) | (len4Bytes[2] << 8) | len4Bytes[3];
                break;

            case 3:
                // Indeterminate length - read until EOF
                body = ReadToEnd();
                return true;

            default:
                throw new InvalidDataException($"Invalid old format length type: {lengthType}");
        }

        if (length > int.MaxValue)
        {
            throw new InvalidDataException("Packet size exceeds maximum allowed.");
        }

        ValidatePacketSize((int)length);
        body = ReadExactly((int)length);
        return true;
    }

    private byte[] ReadExactly(int count)
    {
        byte[] buffer = new byte[count];
        ReadExactlyInto(buffer);
        return buffer;
    }

    private void ReadExactlyInto(byte[] buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = stream.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read == 0)
            {
                throw new InvalidDataException("Unexpected end of stream while reading data.");
            }

            totalRead += read;
        }
    }

    private void CopyExactly(int count, Stream destination)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(count, 81920));
        try
        {
            int remaining = count;
            while (remaining > 0)
            {
                int toRead = Math.Min(remaining, buffer.Length);
                int read = stream.Read(buffer, 0, toRead);
                if (read == 0)
                {
                    throw new InvalidDataException($"Unexpected end of stream. Expected {count} more bytes.");
                }

                destination.Write(buffer, 0, read);
                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private byte[] ReadToEnd()
    {
        using var ms = new MemoryStream();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long totalRead = 0;
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                totalRead += read;
                if (MaxPacketSize > 0 && totalRead > MaxPacketSize)
                {
                    throw new InvalidDataException($"Indeterminate length packet exceeds maximum allowed ({MaxPacketSize} bytes).");
                }

                ms.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return ms.ToArray();
    }

    private void ValidatePacketSize(int size)
    {
        if (MaxPacketSize > 0 && size > MaxPacketSize)
        {
            throw new InvalidDataException($"Packet size ({size} bytes) exceeds maximum allowed ({MaxPacketSize} bytes).");
        }
    }

    private void ThrowIfDisposed()
    {
#if NET7_0_OR_GREATER
        ObjectDisposedException.ThrowIf(disposed, this);
#else
        if (disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }
#endif
    }

    /// <summary>
    /// Disposes the reader and optionally the underlying stream.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
            if (!leaveOpen)
            {
                stream.Dispose();
            }
        }
    }
}
