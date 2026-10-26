using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.ChaCha20;

/// <summary>
/// ChaCha cipher variants with configurable round counts.
/// Supports ChaCha8, ChaCha12, and ChaCha20.
/// </summary>
/// <remarks>
/// <para>
/// The ChaCha family has 8-, 12-, and 20-round variants. Fewer rounds change the security
/// margin, but no fixed bit-strength or throughput ratio follows from the round count:
/// </para>
/// <list type="table">
///   <listheader>
///     <term>Variant</term>
///     <description>Use Case</description>
///   </listheader>
///   <item>
///     <term>ChaCha20</term>
///     <description><b>Default</b> - 20-round stream cipher specified in RFC 8439</description>
///   </item>
///   <item>
///     <term>ChaCha12</term>
///     <description>Reduced-round variant; RFC 8439 does not define its security strength</description>
///   </item>
///   <item>
///     <term>ChaCha8</term>
///     <description>Reduced-round variant; requires a separate security assessment</description>
///   </item>
/// </list>
/// <para>
/// <b>Recommendation:</b> Prefer the standardized ChaCha20 variant. This raw stream
/// cipher provides no authentication; choose ChaCha20-Poly1305 when authenticated
/// encryption is required. Do not select reduced-round variants using the legacy
/// numeric security or speed estimates without independent analysis and benchmarking.
/// </para>
/// </remarks>
public static class ChaChaVariants
{
    /// <summary>
    /// ChaCha constants "expand 32-byte k"
    /// </summary>
    private static readonly uint[] Constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// <summary>
    /// Key size in bytes (same for all variants)
    /// </summary>
    public const int KEY_SIZE = 32;

    /// <summary>
    /// Nonce size in bytes (same for all variants)
    /// </summary>
    public const int NONCE_SIZE = 12;

    /// <summary>
    /// Block size in bytes (same for all variants)
    /// </summary>
    public const int BLOCK_SIZE = 64;

    /// <summary>
    /// ChaCha variant types with different security/performance tradeoffs.
    /// </summary>
    /// <remarks>
    /// The numeric value represents the number of rounds in the cipher.
    /// Reduced-round variants have different security margins; neither bit-security nor
    /// elapsed-time ratios can be inferred directly from the number of rounds.
    /// </remarks>
    public enum ChaChaVariant
    {
        /// <summary>
        /// ChaCha8 - 8 rounds (4 double rounds).
        /// </summary>
        /// <remarks>
        /// Reduced-round variant not specified for IETF protocols by RFC 8439.
        /// No audited bit-security level or cross-platform speedup is established here.
        /// <b>Warning:</b> Avoid for security-sensitive applications without expert review.
        /// </remarks>
        ChaCha8 = 8,

        /// <summary>
        /// ChaCha12 - 12 rounds (6 double rounds).
        /// </summary>
        /// <remarks>
        /// Reduced-round variant not specified for IETF protocols by RFC 8439.
        /// No audited bit-security level or cross-platform speedup is established here.
        /// Use only after an explicit security assessment and workload benchmark.
        /// </remarks>
        ChaCha12 = 12,

        /// <summary>
        /// ChaCha20 - 20 rounds (10 double rounds).
        /// </summary>
        /// <remarks>
        /// RFC 8439 specifies this 20-round variant with a 256-bit key and 96-bit nonce.
        /// This raw stream cipher does not authenticate ciphertext. <b>Use this by default</b>
        /// among the variants, and use an authenticated construction where appropriate.
        /// </remarks>
        ChaCha20 = 20
    }

    /// <summary>
    /// Encrypts or decrypts data using the specified ChaCha variant
    /// </summary>
    /// <param name="output">Output buffer</param>
    /// <param name="input">Input buffer</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">12-byte nonce</param>
    /// <param name="counter">Initial counter value</param>
    /// <param name="variant">ChaCha variant to use</param>
    public static void Transform(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce, uint counter, ChaChaVariant variant)
    {
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes", nameof(nonce));
        }
        if (output.Length < input.Length)
        {
            throw new ArgumentException($"Output buffer must be at least {input.Length} bytes, but was {output.Length} bytes", nameof(output));
        }

        // Refuse unsupported round counts before processing any caller data.
        ValidateVariant(variant);

        // Compute the count without int overflow, and reject counter wrapping
        // before modifying any part of the caller-provided output buffer.
        int blocks = input.IsEmpty ? 0 : 1 + ((input.Length - 1) / BLOCK_SIZE);
        ValidateCounterRange(counter, blocks);

        Span<uint> state = stackalloc uint[16];

        // Move stackalloc outside the loop to prevent stack overflow
        Span<byte> keystream = stackalloc byte[BLOCK_SIZE];

        try
        {
            for (int blockIndex = 0; blockIndex < blocks; blockIndex++)
            {
                int blockStart = blockIndex * BLOCK_SIZE;
                int blockSize = Math.Min(BLOCK_SIZE, input.Length - blockStart);

                ReadOnlySpan<byte> inputBlock = input.Slice(blockStart, blockSize);
                Span<byte> outputBlock = output.Slice(blockStart, blockSize);

                // Initialize state for this block
                InitializeState(state, key, nonce, counter + (uint)blockIndex);

                // Generate keystream block (reuse the keystream buffer)
                GenerateKeystreamBlock(keystream, state, (int)variant);

                // XOR with input
                for (int i = 0; i < blockSize; i++)
                {
                    outputBlock[i] = (byte)(inputBlock[i] ^ keystream[i]);
                }

                // Clear keystream
                SecureMemoryOperations.SecureClear(keystream);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(keystream);
            SecureMemoryOperations.SecureClear(state);
        }
    }

    /// <summary>
    /// Generates keystream for the specified ChaCha variant
    /// </summary>
    /// <param name="keystream">Output keystream buffer</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">12-byte nonce</param>
    /// <param name="counter">Counter value</param>
    /// <param name="variant">ChaCha variant to use</param>
    public static void GenerateKeystream(Span<byte> keystream, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce, uint counter, ChaChaVariant variant)
    {
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes", nameof(nonce));
        }
        if (keystream.Length % BLOCK_SIZE != 0)
        {
            throw new ArgumentException("Keystream length must be multiple of block size", nameof(keystream));
        }

        ValidateVariant(variant);

        int blocks = keystream.Length / BLOCK_SIZE;
        ValidateCounterRange(counter, blocks);

        Span<uint> state = stackalloc uint[16];

        try
        {
            for (int blockIndex = 0; blockIndex < blocks; blockIndex++)
            {
                int blockStart = blockIndex * BLOCK_SIZE;
                Span<byte> keystreamBlock = keystream.Slice(blockStart, BLOCK_SIZE);

                // Initialize state for this block
                InitializeState(state, key, nonce, counter + (uint)blockIndex);

                // Generate keystream block
                GenerateKeystreamBlock(keystreamBlock, state, (int)variant);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(state);
        }
    }

    /// <summary>
    /// Allows only the three defined ChaCha round counts.
    /// </summary>
    private static void ValidateVariant(ChaChaVariant variant)
    {
        if (!Enum.IsDefined(variant))
        {
            throw new ArgumentException("Invalid ChaCha variant", nameof(variant));
        }
    }

    /// <summary>
    /// Rejects requests that would reuse a block counter under the same key and nonce.
    /// </summary>
    private static void ValidateCounterRange(uint counter, int blockCount)
    {
        // The last uint.MaxValue block is legal. Only crossing into counter 0
        // would repeat an earlier keystream block for the same key and nonce.
        if (blockCount > 0 && counter + (ulong)(blockCount - 1) > uint.MaxValue)
        {
            throw new CryptographicException(
                "ChaCha counter overflow: requested input exceeds the remaining 32-bit counter space.");
        }
    }

    /// <summary>
    /// Initializes ChaCha state
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitializeState(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
    {
        // constants
        state[0] = Constants[0];
        state[1] = Constants[1];
        state[2] = Constants[2];
        state[3] = Constants[3];

        // Key
        for (int i = 0; i < 8; i++)
        {
            state[4 + i] =
                key[i * 4] |
                ((uint)key[(i * 4) + 1] << 8) |
                ((uint)key[(i * 4) + 2] << 16) |
                ((uint)key[(i * 4) + 3] << 24);
        }

        // Counter
        state[12] = counter;

        // Nonce
        state[13] =
            nonce[0] |
            ((uint)nonce[1] << 8) |
            ((uint)nonce[2] << 16) |
            ((uint)nonce[3] << 24);

        state[14] =
            nonce[4] |
            ((uint)nonce[5] << 8) |
            ((uint)nonce[6] << 16) |
            ((uint)nonce[7] << 24);

        state[15] =
            nonce[8] |
            ((uint)nonce[9] << 8) |
            ((uint)nonce[10] << 16) |
            ((uint)nonce[11] << 24);
    }

    /// <summary>
    /// Generates a single keystream block using the specified number of rounds
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateKeystreamBlock(Span<byte> keystream, ReadOnlySpan<uint> state, int rounds)
    {
        // Create working copy
        Span<uint> workingState = stackalloc uint[16];
        try
        {
            state.CopyTo(workingState);

            // Perform the specified number of rounds
            int doubleRounds = rounds / 2;
            for (int i = 0; i < doubleRounds; i++)
            {
                // Odd round - column rounds
                QuarterRound(workingState, 0, 4, 8, 12);
                QuarterRound(workingState, 1, 5, 9, 13);
                QuarterRound(workingState, 2, 6, 10, 14);
                QuarterRound(workingState, 3, 7, 11, 15);

                // Even round - diagonal rounds
                QuarterRound(workingState, 0, 5, 10, 15);
                QuarterRound(workingState, 1, 6, 11, 12);
                QuarterRound(workingState, 2, 7, 8, 13);
                QuarterRound(workingState, 3, 4, 9, 14);
            }

            // Add original state to working state
            for (int i = 0; i < 16; i++)
            {
                workingState[i] += state[i];
            }

            // Convert to bytes (little-endian)
            for (int i = 0; i < 16; i++)
            {
                uint value = workingState[i];
                keystream[i * 4] = (byte)value;
                keystream[(i * 4) + 1] = (byte)(value >> 8);
                keystream[(i * 4) + 2] = (byte)(value >> 16);
                keystream[(i * 4) + 3] = (byte)(value >> 24);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(workingState);
        }
    }

    /// <summary>
    /// ChaCha quarter round function
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = RotateLeft(state[d], 16);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = RotateLeft(state[b], 12);

        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = RotateLeft(state[d], 8);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = RotateLeft(state[b], 7);
    }

    /// <summary>
    /// Left rotation
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateLeft(uint value, int bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    /// <summary>
    /// Gets legacy numeric security labels retained for API compatibility.
    /// </summary>
    /// <remarks>
    /// The returned 64/96/128 values are historical labels, not proven security-bit
    /// bounds or independently verified cryptanalytic estimates. Do not use them
    /// to approve algorithms, choose key sizes, or make compliance claims.
    /// Prefer the RFC 8439 ChaCha20 variant and obtain an independent security
    /// assessment before choosing a reduced-round alternative.
    /// </remarks>
    /// <param name="variant">ChaCha variant</param>
    /// <returns>Legacy numeric label, not a verified bit-security measurement.</returns>
    public static int GetSecurityBits(ChaChaVariant variant)
    {
        return variant switch
        {
            ChaChaVariant.ChaCha8 => 64,    // Historical, unverified label; kept for compatibility
            ChaChaVariant.ChaCha12 => 96,   // Historical, unverified label; kept for compatibility
            ChaChaVariant.ChaCha20 => 128,  // Historical, unverified label; kept for compatibility
            _ => throw new ArgumentException("Unknown ChaCha variant", nameof(variant))
        };
    }

    /// <summary>
    /// Gets legacy illustrative performance ratios retained for API compatibility.
    /// </summary>
    /// <remarks>
    /// The 2.5/1.7/1.0 ratios are not measured HeroCrypt throughput or latency
    /// results. Performance depends on message size, target framework, CPU, JIT,
    /// operating system and the exact operation. Do not use these constants for
    /// capacity planning or advertised speedups; measure the actual workload.
    /// </remarks>
    /// <param name="variant">ChaCha variant</param>
    /// <returns>Legacy, unmeasured ratio relative to ChaCha20.</returns>
    public static double GetPerformanceMultiplier(ChaChaVariant variant)
    {
        return variant switch
        {
            ChaChaVariant.ChaCha8 => 2.5,   // Historical placeholder, not a benchmark
            ChaChaVariant.ChaCha12 => 1.7,  // Historical placeholder, not a benchmark
            ChaChaVariant.ChaCha20 => 1.0,  // Historical reference value
            _ => throw new ArgumentException("Unknown ChaCha variant", nameof(variant))
        };
    }

    /// <summary>
    /// Validates parameters for ChaCha variants
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ChaChaVariant variant)
    {
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes", nameof(nonce));
        }
        ValidateVariant(variant);
    }
}
