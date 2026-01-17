using System.Buffers.Binary;
using System.Numerics;
using CryptoBitOps = HeroCrypt.Security.BitOperations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Multi-Precision Integer (MPI) encoding as defined in RFC 4880 Section 3.2.
/// </summary>
/// <remarks>
/// <para>
/// An MPI consists of two pieces: a two-octet scalar that is the length of the MPI
/// in bits followed by a string of octets that contain the actual integer.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +--+--+--+--+--+--+--+--+
/// | Bit count (2 octets)  |   MPI data (variable length)
/// +--+--+--+--+--+--+--+--+--+--+--+-- ... --+
/// </code>
/// </para>
/// <para>
/// The bit count is the actual number of significant bits in the MPI.
/// For example, the value 511 (0x01FF) has 9 significant bits.
/// </para>
/// </remarks>
public static class Mpi
{
    /// <summary>
    /// Reads an MPI from a span, returning the value as a BigInteger.
    /// </summary>
    /// <param name="source">The source span containing MPI data.</param>
    /// <param name="bytesConsumed">The total bytes consumed (2 + data length).</param>
    /// <returns>The MPI value as a BigInteger.</returns>
    /// <exception cref="ArgumentException">If the source is too short.</exception>
    public static BigInteger Read(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (source.Length < 2)
        {
            throw new ArgumentException("Source too short for MPI bit count.", nameof(source));
        }

        int bitCount = BinaryPrimitives.ReadUInt16BigEndian(source);
        int byteCount = (bitCount + 7) / 8;

        if (source.Length < 2 + byteCount)
        {
            throw new ArgumentException($"Source too short for MPI data. Expected {2 + byteCount} bytes, got {source.Length}.", nameof(source));
        }

        bytesConsumed = 2 + byteCount;

        if (byteCount == 0)
        {
            return BigInteger.Zero;
        }

        // BigInteger expects little-endian, but MPI is big-endian, so reverse
        byte[] reversed = new byte[byteCount];
        for (int i = 0; i < byteCount; i++)
        {
            reversed[i] = source[2 + byteCount - 1 - i];
        }

        // Ensure unsigned interpretation by adding a zero byte if high bit is set
        if ((reversed[byteCount - 1] & 0x80) != 0)
        {
            byte[] withSign = new byte[byteCount + 1];
            Array.Copy(reversed, withSign, byteCount);
            withSign[byteCount] = 0;
            return new BigInteger(withSign);
        }

        return new BigInteger(reversed);
    }

    /// <summary>
    /// Reads an MPI from a span, returning the raw bytes (without bit count prefix).
    /// </summary>
    /// <param name="source">The source span containing MPI data.</param>
    /// <param name="bytesConsumed">The total bytes consumed (2 + data length).</param>
    /// <returns>The MPI value as raw bytes (big-endian, no leading zeros).</returns>
    /// <exception cref="ArgumentException">If the source is too short.</exception>
    public static byte[] ReadBytes(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (source.Length < 2)
        {
            throw new ArgumentException("Source too short for MPI bit count.", nameof(source));
        }

        int bitCount = BinaryPrimitives.ReadUInt16BigEndian(source);
        int byteCount = (bitCount + 7) / 8;

        if (source.Length < 2 + byteCount)
        {
            throw new ArgumentException($"Source too short for MPI data. Expected {2 + byteCount} bytes, got {source.Length}.", nameof(source));
        }

        bytesConsumed = 2 + byteCount;

        if (byteCount == 0)
        {
            return [];
        }

        return source.Slice(2, byteCount).ToArray();
    }

    /// <summary>
    /// Tries to read an MPI from a span.
    /// </summary>
    /// <param name="source">The source span containing MPI data.</param>
    /// <param name="value">The MPI value if successful.</param>
    /// <param name="bytesConsumed">The total bytes consumed.</param>
    /// <returns>True if the MPI was read successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out BigInteger value, out int bytesConsumed)
    {
        value = BigInteger.Zero;
        bytesConsumed = 0;

        if (source.Length < 2)
        {
            return false;
        }

        int bitCount = BinaryPrimitives.ReadUInt16BigEndian(source);
        int byteCount = (bitCount + 7) / 8;

        if (source.Length < 2 + byteCount)
        {
            return false;
        }

        bytesConsumed = 2 + byteCount;

        if (byteCount == 0)
        {
            return true;
        }

        // BigInteger expects little-endian, but MPI is big-endian, so reverse
        byte[] reversed = new byte[byteCount];
        for (int i = 0; i < byteCount; i++)
        {
            reversed[i] = source[2 + byteCount - 1 - i];
        }

        // Ensure unsigned interpretation by adding a zero byte if high bit is set
        if ((reversed[byteCount - 1] & 0x80) != 0)
        {
            byte[] withSign = new byte[byteCount + 1];
            Array.Copy(reversed, withSign, byteCount);
            withSign[byteCount] = 0;
            value = new BigInteger(withSign);
        }
        else
        {
            value = new BigInteger(reversed);
        }

        return true;
    }

    /// <summary>
    /// Writes a BigInteger as an MPI to a span.
    /// </summary>
    /// <param name="value">The value to write.</param>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    /// <exception cref="ArgumentOutOfRangeException">If the value is negative.</exception>
    public static int Write(BigInteger value, Span<byte> destination)
    {
        if (value < BigInteger.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "MPI values must be non-negative.");
        }

        if (value.IsZero)
        {
            if (destination.Length < 2)
            {
                throw new ArgumentException("Destination too small.", nameof(destination));
            }

            destination[0] = 0;
            destination[1] = 0;
            return 2;
        }

        // Get byte representation (little-endian)
        byte[] bytes = value.ToByteArray(); // Little-endian, may have sign byte

        // Remove sign byte if present
        int length = bytes.Length;
        if (bytes[length - 1] == 0 && length > 1)
        {
            length--;
        }

        // Calculate bit count: bits in last byte (which is MSB in little-endian)
        int bitCount = (length - 1) * 8 + (32 - CryptoBitOps.LeadingZeroCount(bytes[length - 1]));

        int totalLength = 2 + length;
        if (destination.Length < totalLength)
        {
            throw new ArgumentException($"Destination too small. Need {totalLength} bytes.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)bitCount);

        // Write bytes in big-endian order (reverse of ToByteArray)
        for (int i = 0; i < length; i++)
        {
            destination[2 + i] = bytes[length - 1 - i];
        }

        return totalLength;
    }

    /// <summary>
    /// Writes raw bytes as an MPI to a span.
    /// </summary>
    /// <param name="value">The value bytes (big-endian, may have leading zeros).</param>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public static int Write(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        // Skip leading zeros
        int offset = 0;
        while (offset < value.Length && value[offset] == 0)
        {
            offset++;
        }

        if (offset == value.Length)
        {
            // All zeros or empty
            if (destination.Length < 2)
            {
                throw new ArgumentException("Destination too small.", nameof(destination));
            }

            destination[0] = 0;
            destination[1] = 0;
            return 2;
        }

        ReadOnlySpan<byte> trimmed = value.Slice(offset);
        int bitCount = CalculateBitCount(trimmed);
        int dataLength = (bitCount + 7) / 8;

        int totalLength = 2 + dataLength;
        if (destination.Length < totalLength)
        {
            throw new ArgumentException($"Destination too small. Need {totalLength} bytes.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)bitCount);
        trimmed.Slice(trimmed.Length - dataLength, dataLength).CopyTo(destination.Slice(2));

        return totalLength;
    }

    /// <summary>
    /// Gets the encoded length of a BigInteger as an MPI.
    /// </summary>
    /// <param name="value">The value to measure.</param>
    /// <returns>The total encoded length in bytes (2 + data length).</returns>
    public static int GetEncodedLength(BigInteger value)
    {
        if (value <= BigInteger.Zero)
        {
            return 2;
        }

        byte[] bytes = value.ToByteArray();
        int length = bytes.Length;
        if (bytes[length - 1] == 0 && length > 1)
        {
            length--;
        }

        return 2 + length;
    }

    /// <summary>
    /// Gets the encoded length of raw bytes as an MPI.
    /// </summary>
    /// <param name="value">The value bytes (big-endian).</param>
    /// <returns>The total encoded length in bytes (2 + data length without leading zeros).</returns>
    public static int GetEncodedLength(ReadOnlySpan<byte> value)
    {
        // Skip leading zeros
        int offset = 0;
        while (offset < value.Length && value[offset] == 0)
        {
            offset++;
        }

        if (offset == value.Length)
        {
            return 2;
        }

        int bitCount = CalculateBitCount(value.Slice(offset));
        return 2 + (bitCount + 7) / 8;
    }

    /// <summary>
    /// Calculates the bit count for MPI encoding.
    /// </summary>
    private static int CalculateBitCount(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return 0;
        }

        // Find position of highest set bit in first byte
        // LeadingZeroCount on a uint with byte in low bits returns 24 + leading zeros in byte
        // So significant bits = 32 - LeadingZeroCount(byte as uint)
        byte firstByte = bytes[0];
        int bitsInFirstByte = 32 - CryptoBitOps.LeadingZeroCount(firstByte);

        return bitsInFirstByte + (bytes.Length - 1) * 8;
    }
}
