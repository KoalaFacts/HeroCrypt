using System.Runtime.CompilerServices;

namespace HeroCrypt.Polyfills;

/// <summary>
/// Provides binary read/write helper methods for little-endian operations.
/// On .NET 8+ these delegate to BinaryPrimitives; on .NET Standard 2.0 they use manual implementations.
/// </summary>
internal static class BinaryHelpers
{
    #region WriteUInt64LittleEndian

    /// <summary>
    /// Writes a 64-bit unsigned integer in little-endian format to a span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteUInt64LittleEndian(Span<byte> destination, ulong value)
    {
#if NETSTANDARD2_0
        destination[0] = (byte)value;
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)(value >> 16);
        destination[3] = (byte)(value >> 24);
        destination[4] = (byte)(value >> 32);
        destination[5] = (byte)(value >> 40);
        destination[6] = (byte)(value >> 48);
        destination[7] = (byte)(value >> 56);
#else
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
#endif
    }

    /// <summary>
    /// Writes a 64-bit unsigned integer in little-endian format to a byte array at the specified offset.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteUInt64LittleEndian(byte[] destination, int offset, ulong value)
    {
#if NETSTANDARD2_0
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
        destination[offset + 4] = (byte)(value >> 32);
        destination[offset + 5] = (byte)(value >> 40);
        destination[offset + 6] = (byte)(value >> 48);
        destination[offset + 7] = (byte)(value >> 56);
#else
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination.AsSpan(offset), value);
#endif
    }

    #endregion

    #region ReadUInt64LittleEndian

    /// <summary>
    /// Reads a 64-bit unsigned integer in little-endian format from a span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> source)
    {
#if NETSTANDARD2_0
        return source[0] |
               ((ulong)source[1] << 8) |
               ((ulong)source[2] << 16) |
               ((ulong)source[3] << 24) |
               ((ulong)source[4] << 32) |
               ((ulong)source[5] << 40) |
               ((ulong)source[6] << 48) |
               ((ulong)source[7] << 56);
#else
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(source);
#endif
    }

    /// <summary>
    /// Reads a 64-bit unsigned integer in little-endian format from a byte array at the specified offset.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong ReadUInt64LittleEndian(byte[] source, int offset)
    {
#if NETSTANDARD2_0
        return source[offset] |
               ((ulong)source[offset + 1] << 8) |
               ((ulong)source[offset + 2] << 16) |
               ((ulong)source[offset + 3] << 24) |
               ((ulong)source[offset + 4] << 32) |
               ((ulong)source[offset + 5] << 40) |
               ((ulong)source[offset + 6] << 48) |
               ((ulong)source[offset + 7] << 56);
#else
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(source.AsSpan(offset));
#endif
    }

    #endregion

    #region WriteUInt32LittleEndian

    /// <summary>
    /// Writes a 32-bit unsigned integer in little-endian format to a span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteUInt32LittleEndian(Span<byte> destination, uint value)
    {
#if NETSTANDARD2_0
        destination[0] = (byte)value;
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)(value >> 16);
        destination[3] = (byte)(value >> 24);
#else
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination, value);
#endif
    }

    /// <summary>
    /// Writes a 32-bit unsigned integer in little-endian format to a byte array at the specified offset.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteUInt32LittleEndian(byte[] destination, int offset, uint value)
    {
#if NETSTANDARD2_0
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
#else
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination.AsSpan(offset), value);
#endif
    }

    #endregion

    #region WriteInt32LittleEndian

    /// <summary>
    /// Writes a 32-bit signed integer in little-endian format to a span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteInt32LittleEndian(Span<byte> destination, int value)
    {
#if NETSTANDARD2_0
        destination[0] = (byte)value;
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)(value >> 16);
        destination[3] = (byte)(value >> 24);
#else
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(destination, value);
#endif
    }

    /// <summary>
    /// Writes a 32-bit signed integer in little-endian format to a byte array at the specified offset.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteInt32LittleEndian(byte[] destination, int offset, int value)
    {
#if NETSTANDARD2_0
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
#else
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(destination.AsSpan(offset), value);
#endif
    }

    #endregion

    #region ReadUInt32LittleEndian

    /// <summary>
    /// Reads a 32-bit unsigned integer in little-endian format from a span.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> source)
    {
#if NETSTANDARD2_0
        return (uint)(source[0] | (source[1] << 8) | (source[2] << 16) | (source[3] << 24));
#else
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(source);
#endif
    }

    /// <summary>
    /// Reads a 32-bit unsigned integer in little-endian format from a byte array at the specified offset.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ReadUInt32LittleEndian(byte[] source, int offset)
    {
#if NETSTANDARD2_0
        return (uint)(source[offset] | (source[offset + 1] << 8) | (source[offset + 2] << 16) | (source[offset + 3] << 24));
#else
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(offset));
#endif
    }

    #endregion
}
