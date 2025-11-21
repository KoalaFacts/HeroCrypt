using System.Runtime.CompilerServices;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// ChaCha cipher variants with configurable round counts
/// Supports ChaCha8, ChaCha12, and ChaCha20
/// </summary>
public static class ChaChaVariants
{
    /// <summary>
    /// ChaCha constants "expand 32-byte k"
    /// </summary>
    private static readonly uint[] constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

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
    /// ChaCha variant types with different security/performance tradeoffs
    /// </summary>
    public enum ChaChaVariant
    {
        /// <summary>ChaCha8 - 8 rounds (4 double rounds) - Fast, lower security</summary>
        ChaCha8 = 8,

        /// <summary>ChaCha12 - 12 rounds (6 double rounds) - Balanced security/performance</summary>
        ChaCha12 = 12,

        /// <summary>ChaCha20 - 20 rounds (10 double rounds) - Full security</summary>
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
            throw new ArgumentException("Output buffer too small", nameof(output));
        }

        Span<uint> state = stackalloc uint[16];
        int blocks = (input.Length + BLOCK_SIZE - 1) / BLOCK_SIZE;

        // Move stackalloc outside the loop to prevent stack overflow
        Span<byte> keystream = stackalloc byte[BLOCK_SIZE];

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

        // Clear state
        SecureMemoryOperations.SecureClear(state);
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

        Span<uint> state = stackalloc uint[16];
        int blocks = keystream.Length / BLOCK_SIZE;

        for (int blockIndex = 0; blockIndex < blocks; blockIndex++)
        {
            int blockStart = blockIndex * BLOCK_SIZE;
            Span<byte> keystreamBlock = keystream.Slice(blockStart, BLOCK_SIZE);

            // Initialize state for this block
            InitializeState(state, key, nonce, counter + (uint)blockIndex);

            // Generate keystream block
            GenerateKeystreamBlock(keystreamBlock, state, (int)variant);
        }

        // Clear state
        SecureMemoryOperations.SecureClear(state);
    }

    /// <summary>
    /// Initializes ChaCha state
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitializeState(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
    {
        // constants
        state[0] = constants[0];
        state[1] = constants[1];
        state[2] = constants[2];
        state[3] = constants[3];

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
    private static void GenerateKeystreamBlock(Span<byte> keystream, Span<uint> state, int rounds)
    {
        // Create working copy
        Span<uint> workingState = stackalloc uint[16];
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

        // Clear working state
        SecureMemoryOperations.SecureClear(workingState);
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
    /// Gets the recommended security level for each variant
    /// </summary>
    /// <param name="variant">ChaCha variant</param>
    /// <returns>Estimated security bits</returns>
    public static int GetSecurityBits(ChaChaVariant variant)
    {
        return variant switch
        {
            ChaChaVariant.ChaCha8 => 64,    // Reduced security - use only for performance-critical scenarios
            ChaChaVariant.ChaCha12 => 96,   // Good balance of security and performance
            ChaChaVariant.ChaCha20 => 128,  // Full security
            _ => throw new ArgumentException("Unknown ChaCha variant", nameof(variant))
        };
    }

    /// <summary>
    /// Gets the performance characteristics for each variant (relative to ChaCha20)
    /// </summary>
    /// <param name="variant">ChaCha variant</param>
    /// <returns>Performance multiplier relative to ChaCha20</returns>
    public static double GetPerformanceMultiplier(ChaChaVariant variant)
    {
        return variant switch
        {
            ChaChaVariant.ChaCha8 => 2.5,   // ~2.5x faster than ChaCha20
            ChaChaVariant.ChaCha12 => 1.7,  // ~1.7x faster than ChaCha20
            ChaChaVariant.ChaCha20 => 1.0,  // Baseline
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
        if (!Enum.IsDefined(variant))
        {
            throw new ArgumentException("Invalid ChaCha variant", nameof(variant));
        }
    }
}
