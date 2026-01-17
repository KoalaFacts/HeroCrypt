using System.Buffers;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Writes OpenPGP packets to a stream.
/// </summary>
/// <remarks>
/// <para>
/// This class provides methods to write OpenPGP packets in both old and new formats.
/// New format is recommended for all new implementations per RFC 9580.
/// </para>
/// <para>
/// <b>Usage:</b>
/// <code>
/// using var writer = new PgpPacketWriter(stream);
/// writer.WritePacket(PgpPacketTag.LiteralData, literalDataBytes);
/// writer.WritePacket(PgpPacketTag.Signature, signatureBytes);
/// </code>
/// </para>
/// </remarks>
public sealed class PgpPacketWriter : IDisposable
{
    private readonly Stream stream;
    private readonly bool leaveOpen;
    private readonly byte[] headerBuffer;
    private bool disposed;

    /// <summary>
    /// Default chunk size for partial body length encoding (64KB).
    /// </summary>
    public const int DefaultChunkSize = 65536;

    /// <summary>
    /// Initializes a new packet writer for the given stream.
    /// </summary>
    /// <param name="stream">The stream to write packets to.</param>
    /// <param name="leaveOpen">Whether to leave the stream open when disposed.</param>
    public PgpPacketWriter(Stream stream, bool leaveOpen = false)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
        this.leaveOpen = leaveOpen;
        this.headerBuffer = new byte[6]; // Maximum header size
    }

    /// <summary>
    /// Writes a packet with the given tag and body using new format.
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="body">The packet body.</param>
    public void WritePacket(PgpPacketTag tag, ReadOnlySpan<byte> body)
    {
        WritePacket(tag, body, PgpPacketFormat.New);
    }

    /// <summary>
    /// Writes a packet with the given tag and body.
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="body">The packet body.</param>
    /// <param name="format">The packet format to use.</param>
    public void WritePacket(PgpPacketTag tag, ReadOnlySpan<byte> body, PgpPacketFormat format)
    {
        ThrowIfDisposed();

        int headerLength;
        if (format == PgpPacketFormat.New)
        {
            headerLength = PgpPacketHeader.WriteNewFormat(tag, body.Length, headerBuffer);
        }
        else
        {
            headerLength = PgpPacketHeader.WriteOldFormat(tag, body.Length, headerBuffer);
        }

        stream.Write(headerBuffer, 0, headerLength);
#if NET5_0_OR_GREATER
        stream.Write(body);
#else
        stream.Write(body.ToArray(), 0, body.Length);
#endif
    }

    /// <summary>
    /// Writes a packet with the given tag and body from a stream using new format.
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="bodyStream">The stream containing the packet body.</param>
    /// <param name="bodyLength">The body length (must be known in advance).</param>
    public void WritePacket(PgpPacketTag tag, Stream bodyStream, long bodyLength)
    {
        WritePacket(tag, bodyStream, bodyLength, PgpPacketFormat.New);
    }

    /// <summary>
    /// Writes a packet with the given tag and body from a stream.
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="bodyStream">The stream containing the packet body.</param>
    /// <param name="bodyLength">The body length.</param>
    /// <param name="format">The packet format to use.</param>
    public void WritePacket(PgpPacketTag tag, Stream bodyStream, long bodyLength, PgpPacketFormat format)
    {
        ThrowIfDisposed();

        int headerLength;
        if (format == PgpPacketFormat.New)
        {
            headerLength = PgpPacketHeader.WriteNewFormat(tag, bodyLength, headerBuffer);
        }
        else
        {
            headerLength = PgpPacketHeader.WriteOldFormat(tag, bodyLength, headerBuffer);
        }

        stream.Write(headerBuffer, 0, headerLength);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long remaining = bodyLength;
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(remaining, buffer.Length);
                int read = bodyStream.Read(buffer, 0, toRead);
                if (read == 0)
                {
                    throw new InvalidOperationException($"Body stream ended prematurely. Expected {remaining} more bytes.");
                }

                stream.Write(buffer, 0, read);
                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Writes a packet using partial body length encoding (streaming/chunked).
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <param name="bodyStream">The stream containing the packet body.</param>
    /// <param name="chunkSize">The chunk size (must be a power of 2, 1 to 1GB).</param>
    /// <remarks>
    /// <para>
    /// Use this method when the body length is unknown in advance.
    /// Data is written in chunks with partial length headers.
    /// </para>
    /// </remarks>
    public void WritePacketStreaming(PgpPacketTag tag, Stream bodyStream, int chunkSize = DefaultChunkSize)
    {
        ThrowIfDisposed();

        if (chunkSize <= 0 || (chunkSize & (chunkSize - 1)) != 0)
        {
            throw new ArgumentException("Chunk size must be a power of 2.", nameof(chunkSize));
        }

        int chunkPower = BitOperations.Log2(chunkSize);
        if (chunkPower < 0 || chunkPower > 30)
        {
            throw new ArgumentException("Chunk size must be between 1 and 1GB.", nameof(chunkSize));
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        try
        {
            bool isFirst = true;

            while (true)
            {
                int read = ReadFully(bodyStream, buffer, 0, chunkSize);

                if (read == 0)
                {
                    if (isFirst)
                    {
                        // Empty body - write with zero length
                        WritePacket(tag, []);
                    }

                    break;
                }

                if (read < chunkSize)
                {
                    // Final partial chunk - write with definite length
                    if (isFirst)
                    {
                        // Only chunk - write as normal packet
                        int headerLen = PgpPacketHeader.WriteNewFormat(tag, read, headerBuffer);
                        stream.Write(headerBuffer, 0, headerLen);
                    }
                    else
                    {
                        // Final chunk after partial chunks - write final length
                        WriteFinalChunkLength(read);
                    }

                    stream.Write(buffer, 0, read);
                    break;
                }
                else
                {
                    // Full chunk - write with partial length header
                    int headerLen = PgpPacketHeader.WriteNewFormatPartial(tag, chunkPower, isFirst, headerBuffer);
                    stream.Write(headerBuffer, 0, headerLen);
                    stream.Write(buffer, 0, chunkSize);
                    isFirst = false;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Begins writing a packet with streaming body (for manual chunk control).
    /// </summary>
    /// <param name="tag">The packet tag.</param>
    /// <returns>A stream writer for the packet body.</returns>
    public PgpPacketBodyStream BeginPacket(PgpPacketTag tag)
    {
        ThrowIfDisposed();
        return new PgpPacketBodyStream(this, tag);
    }

    private void WriteFinalChunkLength(int length)
    {
        if (length < 192)
        {
            stream.WriteByte((byte)length);
        }
        else if (length < 8384)
        {
            int adjusted = length - 192;
            stream.WriteByte((byte)((adjusted >> 8) + 192));
            stream.WriteByte((byte)(adjusted & 0xFF));
        }
        else
        {
            stream.WriteByte(255);
            stream.WriteByte((byte)(length >> 24));
            stream.WriteByte((byte)(length >> 16));
            stream.WriteByte((byte)(length >> 8));
            stream.WriteByte((byte)length);
        }
    }

    private static int ReadFully(Stream stream, byte[] buffer, int offset, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = stream.Read(buffer, offset + totalRead, count - totalRead);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
        }

        return totalRead;
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
    /// Disposes the writer and optionally the underlying stream.
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

/// <summary>
/// Provides streaming write access to a packet body.
/// </summary>
/// <remarks>
/// <para>
/// This class buffers packet body data and writes it with proper headers
/// when disposed. Use for packets where the body is built incrementally.
/// </para>
/// </remarks>
public sealed class PgpPacketBodyStream : Stream
{
    private readonly PgpPacketWriter writer;
    private readonly PgpPacketTag tag;
    private readonly MemoryStream buffer;
    private bool disposed;

    internal PgpPacketBodyStream(PgpPacketWriter writer, PgpPacketTag tag)
    {
        this.writer = writer;
        this.tag = tag;
        this.buffer = new MemoryStream();
    }

    /// <inheritdoc />
    public override bool CanRead => false;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => !disposed;

    /// <inheritdoc />
    public override long Length => buffer.Length;

    /// <inheritdoc />
    public override long Position
    {
        get => buffer.Position;
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Flush() => buffer.Flush();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) =>
        throw new NotSupportedException();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        ThrowIfDisposed();
        this.buffer.Write(buffer, offset, count);
    }

#if NET5_0_OR_GREATER
    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ThrowIfDisposed();
        this.buffer.Write(buffer);
    }
#endif

    /// <inheritdoc />
    public override void WriteByte(byte value)
    {
        ThrowIfDisposed();
        buffer.WriteByte(value);
    }

    /// <summary>
    /// Writes an MPI value to the packet body.
    /// </summary>
    /// <param name="value">The MPI value bytes (big-endian).</param>
    public void WriteMpi(ReadOnlySpan<byte> value)
    {
        ThrowIfDisposed();

        byte[] mpiBuffer = new byte[2 + value.Length];
        int written = Mpi.Write(value, mpiBuffer);
        buffer.Write(mpiBuffer, 0, written);
    }

    /// <summary>
    /// Writes an MPI value to the packet body.
    /// </summary>
    /// <param name="value">The MPI value as BigInteger.</param>
    public void WriteMpi(System.Numerics.BigInteger value)
    {
        ThrowIfDisposed();

        int encodedLen = Mpi.GetEncodedLength(value);
        byte[] mpiBuffer = new byte[encodedLen];
        Mpi.Write(value, mpiBuffer);
        buffer.Write(mpiBuffer, 0, encodedLen);
    }

    /// <summary>
    /// Finishes writing and flushes the packet to the underlying stream.
    /// </summary>
    public void Finish()
    {
        if (disposed)
        {
            return;
        }

        writer.WritePacket(tag, buffer.ToArray());
        disposed = true;
        buffer.Dispose();
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing && !disposed)
        {
            Finish();
        }

        base.Dispose(disposing);
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
}
