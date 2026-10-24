using System.Numerics;
using System.Runtime.CompilerServices;
using HeroCrypt.Polyfills;
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
internal sealed class Poly1305Core
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

    private readonly SecurityPolicyOptions policy;

    /// <summary>
    /// Initializes a new instance of the <see cref="Poly1305Core"/> class with the specified security policy.
    /// </summary>
    /// <param name="policy">The security policy to use for validation. If null, uses <see cref="SecurityPolicy.CurrentPolicy"/>.</param>
    public Poly1305Core(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
    }

    /// <summary>
    /// Computes Poly1305 MAC for the given message
    /// </summary>
    /// <param name="tag">16-byte output tag</param>
    /// <param name="message">Message to authenticate</param>
    /// <param name="key">32-byte key</param>
    public void ComputeMac(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        => ComputeMacCore(tag, message, [], key, isAead: false);

    /// <summary>
    /// Computes the RFC 8439 AEAD Poly1305 tag without concatenating AAD,
    /// ciphertext, padding and lengths into a message-sized temporary buffer.
    /// Each partial AAD/ciphertext block is zero-padded to a full 16-byte
    /// Poly1305 block before appending the full-block Poly1305 high bit.
    /// </summary>
    internal void ComputeAeadMac(Span<byte> tag, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key)
        => ComputeMacCore(tag, associatedData, ciphertext, key, isAead: true);

    private void ComputeMacCore(Span<byte> tag, ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second, ReadOnlySpan<byte> key, bool isAead)
    {
        policy.ValidateSignature("POLY1305");
        if (tag.Length != TAG_SIZE)
        {
            throw new ArgumentException($"Tag must be {TAG_SIZE} bytes", nameof(tag));
        }

        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }

        Span<byte> rBytes = stackalloc byte[16];
        Span<byte> sBytes = stackalloc byte[16];
        byte[] rPos = new byte[17];
        byte[] sPos = new byte[17];

        try
        {
            key[..16].CopyTo(rBytes);
            key.Slice(16, 16).CopyTo(sBytes);
            ClampR(rBytes);

            // Preserve the existing unsigned little-endian BigInteger treatment.
            rBytes.CopyTo(rPos);
            sBytes.CopyTo(sPos);
            var r = new BigInteger(rPos);
            var s = new BigInteger(sPos);

            BigInteger acc = AccumulateBlocks(BigInteger.Zero, first, r, padFinalBlock: isAead);
            if (isAead)
            {
                acc = AccumulateBlocks(acc, second, r, padFinalBlock: true);

                // RFC 8439 length block: two unsigned little-endian 64-bit lengths.
                // This is also a complete Poly1305 block and requires no padding.
                Span<byte> lengths = stackalloc byte[16];
                try
                {
                    BinaryHelpers.WriteUInt64LittleEndian(lengths[..8], (ulong)first.Length);
                    BinaryHelpers.WriteUInt64LittleEndian(lengths[8..], (ulong)second.Length);
                    acc = AccumulateBlocks(acc, lengths, r, padFinalBlock: false);
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(lengths);
                }
            }

            acc += s;
            var finalBytes = acc.ToByteArray();
            var resultTag = new byte[TAG_SIZE];
            Array.Copy(finalBytes, resultTag, Math.Min(TAG_SIZE, finalBytes.Length));
            resultTag.CopyTo(tag);
        }
        finally
        {
            // Best effort only: BigInteger is immutable and can retain key-derived
            // values in managed/JIT/native copies outside these owned buffers.
            SecureMemoryOperations.SecureClear(rBytes);
            SecureMemoryOperations.SecureClear(sBytes);
            SecureMemoryOperations.SecureClear(rPos.AsSpan());
            SecureMemoryOperations.SecureClear(sPos.AsSpan());
        }
    }

    private static BigInteger AccumulateBlocks(BigInteger accumulator, ReadOnlySpan<byte> input,
        BigInteger r, bool padFinalBlock)
    {
        int offset = 0;
        while (offset < input.Length)
        {
            int actualLength = Math.Min(BLOCK_SIZE, input.Length - offset);
            int authenticatedLength = padFinalBlock ? BLOCK_SIZE : actualLength;
            byte[] blockBytes = new byte[authenticatedLength + 2];
            input.Slice(offset, actualLength).CopyTo(blockBytes);
            blockBytes[authenticatedLength] = 1;
            var n = new BigInteger(blockBytes);
            accumulator = ((accumulator + n) * r) % P;
            offset += actualLength;
        }

        return accumulator;
    }

    /// <summary>
    /// Verifies a Poly1305 MAC
    /// </summary>
    /// <param name="tag">Expected tag</param>
    /// <param name="message">Message to verify</param>
    /// <param name="key">32-byte key</param>
    /// <returns>True if verification succeeds</returns>
    public bool VerifyMac(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        policy.ValidateSignature("POLY1305");
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
