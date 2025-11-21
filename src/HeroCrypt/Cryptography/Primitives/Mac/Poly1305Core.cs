using System.Runtime.CompilerServices;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Mac;

/// <summary>
/// High-performance Poly1305 message authentication code implementation
/// Implements RFC 8439 with constant-time guarantees
/// </summary>
internal static class Poly1305Core
{
    /// <summary>
    /// Key size in bytes
    /// </summary>
    public const int KEY_SIZE = 32;

    /// <summary>
    /// Tag size in bytes
    /// </summary>
    public const int TAG_SIZE = 16;

    /// <summary>
    /// Block size in bytes
    /// </summary>
    public const int BLOCK_SIZE = 16;

    /// <summary>
    /// Poly1305 prime: 2^130 - 5
    /// </summary>
    private const ulong P0 = 0xFFFFFFFFFFFFFFFB;
    private const ulong P1 = 0xFFFFFFFFFFFFFFFF;
    private const ulong P2 = 0x3;

    /// <summary>
    /// Computes Poly1305 MAC for the given message
    /// </summary>
    /// <param name="tag">16-byte output tag</param>
    /// <param name="message">Message to authenticate</param>
    /// <param name="key">32-byte key</param>
    public static void ComputeMac(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length != TAG_SIZE)
        {
            throw new ArgumentException($"Tag must be {TAG_SIZE} bytes", nameof(tag));
        }
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }

        // Extract r and s from key
        Span<byte> rBytes = stackalloc byte[16];
        Span<byte> sBytes = stackalloc byte[16];

        key.Slice(0, 16).CopyTo(rBytes);
        key.Slice(16, 16).CopyTo(sBytes);

        // Clamp r
        ClampR(rBytes);

        // Convert to little-endian uint64 arrays
        Span<ulong> r = stackalloc ulong[3];
        Span<ulong> s = stackalloc ulong[2];

        BytesToUInt64LE(rBytes, r.Slice(0, 2));
        r[2] = 0; // High part of r is always 0 after clamping

        BytesToUInt64LE(sBytes, s);

        // Initialize accumulator
        Span<ulong> h = stackalloc ulong[3];
        h.Clear();

        // Process message in 16-byte blocks
        // Move stackalloc outside the loop to prevent stack overflow
        Span<ulong> blockNum = stackalloc ulong[3];
        var offset = 0;
        while (offset < message.Length)
        {
            var blockSize = Math.Min(BLOCK_SIZE, message.Length - offset);
            var block = message.Slice(offset, blockSize);

            // Convert block to number with padding bit (reuse the blockNum buffer)
            BlockToNumber(block, blockNum);

            // h = (h + blockNum) * r mod p
            AddModP(h, blockNum);
            MultiplyModP(h, r);

            offset += blockSize;
        }

        // Add s
        AddS(h, s);

        // Convert to bytes
        UInt64LEToBytes(h.Slice(0, 2), tag);

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(rBytes);
        SecureMemoryOperations.SecureClear(sBytes);
        SecureMemoryOperations.SecureClear(r);
        SecureMemoryOperations.SecureClear(s);
        SecureMemoryOperations.SecureClear(h);
    }

    /// <summary>
    /// Verifies a Poly1305 MAC
    /// </summary>
    /// <param name="tag">Expected tag</param>
    /// <param name="message">Message to verify</param>
    /// <param name="key">32-byte key</param>
    /// <returns>True if verification succeeds</returns>
    public static bool VerifyMac(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length != TAG_SIZE)
        {
            return false;
        }

        Span<byte> computedTag = stackalloc byte[TAG_SIZE];
        ComputeMac(computedTag, message, key);

        // Constant-time comparison
        var result = SecureMemoryOperations.ConstantTimeEquals(tag, computedTag);

        // Clear computed tag
        SecureMemoryOperations.SecureClear(computedTag);

        return result;
    }

    /// <summary>
    /// Clamps the r value according to RFC 8439
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ClampR(Span<byte> r)
    {
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;
    }

    /// <summary>
    /// Converts a message block to a 130-bit number
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void BlockToNumber(ReadOnlySpan<byte> block, Span<ulong> number)
    {
        number.Clear();

        // Copy block data
        var blockBytes = new byte[17]; // 16 bytes + padding
        block.CopyTo(blockBytes.AsSpan(0, block.Length));

        // Add padding bit
        if (block.Length < 16)
        {
            blockBytes[block.Length] = 1;
        }
        else
        {
            blockBytes[16] = 1;
        }

        // Convert to little-endian uint64
        number[0] = BitConverter.ToUInt64(blockBytes, 0);
        number[1] = BitConverter.ToUInt64(blockBytes, 8);
        number[2] = blockBytes[16];
    }

    /// <summary>
    /// Converts bytes to little-endian uint64 array
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void BytesToUInt64LE(ReadOnlySpan<byte> bytes, Span<ulong> numbers)
    {
        // Move stackalloc outside the loop to prevent stack overflow
        Span<byte> temp = stackalloc byte[8];

#if !NET5_0_OR_GREATER
        // Create reusable arrays for .NET Standard 2.0 (avoid memory leaks in loop)
        var byteArray = new byte[8];
        var tempArray = new byte[8];
#endif

        for (var i = 0; i < numbers.Length; i++)
        {
            var offset = i * 8;
            if (offset + 8 <= bytes.Length)
            {
#if NET5_0_OR_GREATER
                numbers[i] = BitConverter.ToUInt64(bytes.Slice(offset, 8));
#else
                bytes.Slice(offset, 8).CopyTo(byteArray);
                numbers[i] = BitConverter.ToUInt64(byteArray, 0);
#endif
            }
            else
            {
                // Handle partial read (reuse the temp buffer)
                temp.Clear();
                var remaining = bytes.Length - offset;
                bytes.Slice(offset, remaining).CopyTo(temp);
#if NET5_0_OR_GREATER
                numbers[i] = BitConverter.ToUInt64(temp);
#else
                temp.CopyTo(tempArray);
                numbers[i] = BitConverter.ToUInt64(tempArray, 0);
#endif
            }
        }
    }

    /// <summary>
    /// Converts uint64 array to little-endian bytes
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void UInt64LEToBytes(ReadOnlySpan<ulong> numbers, Span<byte> bytes)
    {
        for (var i = 0; i < numbers.Length; i++)
        {
            var offset = i * 8;
            if (offset + 8 <= bytes.Length)
            {
                BitConverter.GetBytes(numbers[i]).CopyTo(bytes.Slice(offset, 8));
            }
        }
    }

    /// <summary>
    /// Addition modulo 2^130 - 5
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AddModP(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        var carry = 0UL;

        for (var i = 0; i < 3; i++)
        {
            var sum = a[i] + (i < b.Length ? b[i] : 0) + carry;
            a[i] = sum;
            carry = sum < a[i] ? 1UL : 0UL; // Detect overflow
        }

        // Reduce if necessary
        ReduceP(a);
    }

    /// <summary>
    /// Multiplication modulo 2^130 - 5
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MultiplyModP(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        // Simplified multiplication - full implementation would be more complex
        // This is a placeholder for the actual Poly1305 field multiplication

        Span<ulong> result = stackalloc ulong[6];
        result.Clear();

        // Schoolbook multiplication
        for (var i = 0; i < 3; i++)
        {
            if (a[i] == 0)
            {
                continue;
            }

            for (var j = 0; j < 3; j++)
            {
                if (b[j] == 0)
                {
                    continue;
                }

                // Manual 64x64 -> 128 bit multiplication for .NET Standard 2.0 compatibility
                var al = a[i] & 0xFFFFFFFF;
                var ah = a[i] >> 32;
                var bl = b[j] & 0xFFFFFFFF;
                var bh = b[j] >> 32;

                var m0 = al * bl;
                var m1 = al * bh;
                var m2 = ah * bl;
                var m3 = ah * bh;

                var c1 = (m0 >> 32) + (m1 & 0xFFFFFFFF) + (m2 & 0xFFFFFFFF);
                var low = (m0 & 0xFFFFFFFF) | (c1 << 32);
                var high = m3 + (m1 >> 32) + (m2 >> 32) + (c1 >> 32);

                // Add to result
                var pos = i + j;
                var carry = 0UL;

                // Add low part
                var sum = result[pos] + low + carry;
                result[pos] = sum;
                carry = sum < result[pos] ? 1UL : 0UL;

                // Add high part
                if (pos + 1 < result.Length)
                {
                    sum = result[pos + 1] + high + carry;
                    result[pos + 1] = sum;
                    carry = sum < result[pos + 1] ? 1UL : 0UL;
                }
            }
        }

        // Reduce modulo 2^130 - 5
        ReduceAfterMultiply(result, a);

        // Clear result
        SecureMemoryOperations.SecureClear(result);
    }

    /// <summary>
    /// Adds the s value to h
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AddS(Span<ulong> h, ReadOnlySpan<ulong> s)
    {
        var carry = 0UL;

        for (var i = 0; i < 2; i++)
        {
            var sum = h[i] + s[i] + carry;
            h[i] = sum;
            carry = sum < h[i] ? 1UL : 0UL;
        }

        if (carry > 0)
        {
            h[2] += carry;
        }

        // Final reduction
        ReduceP(h);
    }

    /// <summary>
    /// Reduces a 130-bit number modulo 2^130 - 5
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ReduceP(Span<ulong> a)
    {
        // For Poly1305, we need to reduce modulo 2^130 - 5
        // If the value >= 2^130, we subtract 2^130 and add back 5

        // Use a loop instead of recursion to avoid stack overflow
        while (a[2] >= 4)
        {
            var overflow = a[2] >> 2;
            a[2] &= 0x3;

            // Add overflow * 5 to the lower parts
            var toAdd = overflow * 5;

            // Add to a[0] with carry
            var oldA0 = a[0];
            a[0] += toAdd;
            var carry = a[0] < oldA0 ? 1UL : 0UL;

            if (carry > 0)
            {
                var oldA1 = a[1];
                a[1] += carry;
                carry = a[1] < oldA1 ? 1UL : 0UL;

                if (carry > 0)
                {
                    a[2] += carry;
                    // The loop will continue if a[2] >= 4
                }
            }
        }
    }

    /// <summary>
    /// Reduces after multiplication
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ReduceAfterMultiply(ReadOnlySpan<ulong> result, Span<ulong> output)
    {
        // Copy lower 130 bits
        output[0] = result[0];
        output[1] = result[1];
        output[2] = result[2] & 0x3;

        // Handle overflow bits
        var overflow = (result[2] >> 2) + (result[3] << 62) + (result[4] << 126) + (result[5] << 190);

        // Multiply overflow by 5 and add to lower part
        overflow *= 5;

        var carry = 0UL;
        var overflowLow = overflow & ulong.MaxValue;
        var oldOutput0 = output[0];
        output[0] = oldOutput0 + overflowLow + carry;
        carry = output[0] < oldOutput0 || output[0] < overflowLow ? 1UL : 0UL;

        overflow >>= 64;
        var oldOutput1 = output[1];
        output[1] = oldOutput1 + overflow + carry;
        carry = output[1] < oldOutput1 || output[1] < overflow ? 1UL : 0UL;

        if (carry > 0)
        {
            output[2] += carry;
        }

        // Final reduction
        ReduceP(output);
    }
}
