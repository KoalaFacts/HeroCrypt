using System.Numerics;
using System.Runtime.CompilerServices;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Poly1305;

/// <summary>
/// High-performance Poly1305 message authentication code implementation.
/// Implements RFC 8439.
/// Uses BigInteger for correctness (replacing previous buggy 64-bit limb implementation).
/// </summary>
/// <remarks>
/// <para>
/// <b>Security Note - Memory Persistence:</b>
/// This implementation uses <see cref="BigInteger"/> for the 'r', 's', and accumulator values.
/// Because <see cref="BigInteger"/> is immutable, these values containing key material
/// cannot be securely cleared from memory after use. The values may persist in managed
/// memory until garbage collection occurs.
/// </para>
/// <para>
/// <b>Mitigation:</b>
/// <list type="bullet">
///   <item>The byte array copies of r and s on the stack are cleared via SecureMemoryOperations.SecureClear</item>
///   <item>For sensitive applications, consider running in a process with minimal memory exposure</item>
///   <item>The risk is limited to memory dump scenarios (cold boot attacks, hibernation files, crash dumps)</item>
/// </list>
/// </para>
/// <para>
/// <b>Future Consideration:</b>
/// A limb-based implementation using mutable arrays could address this limitation,
/// but would require careful implementation to avoid timing side channels.
/// </para>
/// </remarks>
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
    private static readonly BigInteger P = (BigInteger.One << 130) - 5;

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

        key[..16].CopyTo(rBytes);
        key.Slice(16, 16).CopyTo(sBytes);

        // Clamp r
        ClampR(rBytes);

        // Convert r and s to BigInteger
        // Append 0 byte to ensure positive (unsigned) interpretation
        var rPos = new byte[17];
        rBytes.CopyTo(rPos);
        var r = new BigInteger(rPos);

        var sPos = new byte[17];
        sBytes.CopyTo(sPos);
        var s = new BigInteger(sPos);

        BigInteger acc = BigInteger.Zero;

        try
        {
            var offset = 0;
            while (offset < message.Length)
            {
                var blockSize = Math.Min(BLOCK_SIZE, message.Length - offset);
                var block = message.Slice(offset, blockSize);

                // Convert block to number
                // Rule: add 0x01 byte after block
                var blockNumBytes = new byte[blockSize + 2]; // +1 for 0x01, +1 for sign (0)
                block.CopyTo(blockNumBytes);
                blockNumBytes[blockSize] = 1;

                var n = new BigInteger(blockNumBytes);

                // acc += n
                acc += n;

                // acc = (acc * r) % P
                acc = (acc * r) % P;

                offset += blockSize;
            }

            // acc += s
            acc += s;

            // tag = acc % 2^128
            // Effectively take lower 16 bytes
            var finalBytes = acc.ToByteArray();
            var resultTag = new byte[16]; // Zeros

            // Copy bytes up to 16
            var loopLen = Math.Min(16, finalBytes.Length);
            Array.Copy(finalBytes, resultTag, loopLen);

            resultTag.CopyTo(tag);
        }
        finally
        {
            // Clean up stack buffers
            SecureMemoryOperations.SecureClear(rBytes);
            SecureMemoryOperations.SecureClear(sBytes);
        }
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

        var result = SecureMemoryOperations.ConstantTimeEquals(tag, computedTag);
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
}
