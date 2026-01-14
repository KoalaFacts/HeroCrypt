using System.Runtime.CompilerServices;

namespace HeroCrypt.Security;

/// <summary>
/// Provides bit manipulation operations for cryptographic primitives.
/// These operations are used by ChaCha20, Blake2b, Argon2, and other algorithms.
/// </summary>
public static class BitOperations
{
    /// <summary>
    /// Rotates a 32-bit unsigned integer left by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate</param>
    /// <param name="bits">The number of bits to rotate (0-31)</param>
    /// <returns>The rotated value</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateLeft(uint value, int bits)
    {
#if NET5_0_OR_GREATER
        return System.Numerics.BitOperations.RotateLeft(value, bits);
#else
        return (value << bits) | (value >> (32 - bits));
#endif
    }

    /// <summary>
    /// Rotates a 32-bit unsigned integer right by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate</param>
    /// <param name="bits">The number of bits to rotate (0-31)</param>
    /// <returns>The rotated value</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateRight(uint value, int bits)
    {
#if NET5_0_OR_GREATER
        return System.Numerics.BitOperations.RotateRight(value, bits);
#else
        return (value >> bits) | (value << (32 - bits));
#endif
    }

    /// <summary>
    /// Rotates a 64-bit unsigned integer left by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate</param>
    /// <param name="bits">The number of bits to rotate (0-63)</param>
    /// <returns>The rotated value</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateLeft(ulong value, int bits)
    {
#if NET5_0_OR_GREATER
        return System.Numerics.BitOperations.RotateLeft(value, bits);
#else
        return (value << bits) | (value >> (64 - bits));
#endif
    }

    /// <summary>
    /// Rotates a 64-bit unsigned integer right by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate</param>
    /// <param name="bits">The number of bits to rotate (0-63)</param>
    /// <returns>The rotated value</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateRight(ulong value, int bits)
    {
#if NET5_0_OR_GREATER
        return System.Numerics.BitOperations.RotateRight(value, bits);
#else
        return (value >> bits) | (value << (64 - bits));
#endif
    }

    /// <summary>
    /// Checks if a value is a power of two.
    /// </summary>
    /// <param name="value">The value to check</param>
    /// <returns>True if value is a power of two, false otherwise</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsPowerOfTwo(int value)
    {
        return value > 0 && (value & (value - 1)) == 0;
    }

    /// <summary>
    /// Checks if a value is a power of two.
    /// </summary>
    /// <param name="value">The value to check</param>
    /// <returns>True if value is a power of two, false otherwise</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsPowerOfTwo(long value)
    {
        return value > 0 && (value & (value - 1)) == 0;
    }
}
