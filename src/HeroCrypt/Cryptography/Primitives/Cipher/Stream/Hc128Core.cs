using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// HC-128 stream cipher implementation
/// Part of the eSTREAM portfolio (Profile 1: Software)
/// Designed by Hongjun Wu
/// </summary>
internal static class Hc128Core
{
    /// <summary>
    /// Key size in bytes (128 bits)
    /// </summary>
    public const int KEY_SIZE = 16;

    /// <summary>
    /// IV size in bytes (128 bits)
    /// </summary>
    public const int IV_SIZE = 16;

    /// <summary>
    /// HC-128 cipher state container.
    /// </summary>
    private class Hc128State
    {
        /// <summary>
        /// P-table containing 512 32-bit words used in keystream generation.
        /// </summary>
        public uint[] P = new uint[512];

        /// <summary>
        /// Q-table containing 512 32-bit words used in keystream generation.
        /// </summary>
        public uint[] Q = new uint[512];

        /// <summary>
        /// Step counter tracking the current position in the cipher's internal state.
        /// </summary>
        public uint Counter;
    }

    /// <summary>
    /// Encrypts or decrypts data using HC-128 stream cipher
    /// </summary>
    /// <param name="output">Output buffer</param>
    /// <param name="input">Input buffer</param>
    /// <param name="key">16-byte key</param>
    /// <param name="iv">16-byte initialization vector</param>
    public static void Transform(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }
        if (iv.Length != IV_SIZE)
        {
            throw new ArgumentException($"IV must be {IV_SIZE} bytes", nameof(iv));
        }
        if (output.Length < input.Length)
        {
            throw new ArgumentException("Output buffer too small", nameof(output));
        }

        var state = new Hc128State();

        try
        {
            // Initialize state
            Initialize(state, key, iv);

            // Generate keystream and XOR with input
            var words = (input.Length + 3) / 4; // Number of 32-bit words
            var inputOffset = 0;
            var outputOffset = 0;

            for (var i = 0; i < words; i++)
            {
                var keystreamWord = GenerateKeystream(state);

                // XOR with input (handle partial words at the end)
                var remaining = input.Length - inputOffset;
                var bytesToProcess = Math.Min(4, remaining);

                for (var j = 0; j < bytesToProcess; j++)
                {
                    output[outputOffset++] = (byte)(input[inputOffset++] ^ (keystreamWord >> (j * 8)));
                }
            }
        }
        finally
        {
            // Clear state
            if (state?.P != null)
            {
                SecureMemoryOperations.SecureClear(state.P.AsSpan());
            }
            if (state?.Q != null)
            {
                SecureMemoryOperations.SecureClear(state.Q.AsSpan());
            }
        }
    }

    /// <summary>
    /// Initializes the HC-128 state with key and IV
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Initialize(Hc128State state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        // Initialize expanded key and IV arrays
        Span<uint> w = stackalloc uint[1280]; // 1280 = 256 + 1024 initialization words

        try
        {
            // Expand key into first 4 words (128 bits)
            for (var i = 0; i < 4; i++)
            {
                w[i] = ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            }

            // Expand IV into next 4 words (128 bits)
            for (var i = 0; i < 4; i++)
            {
                w[i + 4] = ReadUInt32LittleEndian(iv.Slice(i * 4, 4));
            }

            // Fill rest with copies of key and IV
            for (var i = 8; i < 16; i++)
            {
                w[i] = w[i - 8];
            }

            // Generate expanded key using message expansion
            for (var i = 16; i < 1280; i++)
            {
                w[i] = F2(w[i - 2]) + w[i - 7] + F1(w[i - 15]) + w[i - 16] + (uint)i;
            }

            // Initialize P and Q tables
            for (var i = 0; i < 512; i++)
            {
                state.P[i] = w[i + 256];
            }

            for (var i = 0; i < 512; i++)
            {
                state.Q[i] = w[i + 768];
            }

            // Run cipher 1024 steps to mix the state
            for (var i = 0; i < 1024; i++)
            {
                GenerateKeystream(state);
            }

            // Reset counter
            state.Counter = 0;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(MemoryMarshal.AsBytes(w));
        }
    }

    /// <summary>
    /// Generates one keystream word (32 bits)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint GenerateKeystream(Hc128State state)
    {
        var j = state.Counter & 0x1FF; // mod 512
        uint s;

        if (state.Counter < 512)
        {
            // Use P table
            state.P[j] = state.P[j] + G1(state.P[(j - 3) & 0x1FF], state.P[(j - 10) & 0x1FF], state.P[(j - 511) & 0x1FF]);
            s = H1(state.P[(j - 12) & 0x1FF], state.Q) ^ state.P[j];
        }
        else
        {
            // Use Q table
            state.Q[j] = state.Q[j] + G2(state.Q[(j - 3) & 0x1FF], state.Q[(j - 10) & 0x1FF], state.Q[(j - 511) & 0x1FF]);
            s = H2(state.Q[(j - 12) & 0x1FF], state.P) ^ state.Q[j];
        }

        state.Counter = (state.Counter + 1) & 0x3FF; // mod 1024

        return s;
    }

    /// <summary>
    /// G1 function: feedback for P table
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint G1(uint x, uint y, uint z)
    {
        return (RotateRight(x, 10) ^ RotateRight(z, 23)) + RotateRight(y, 8);
    }

    /// <summary>
    /// G2 function: feedback for Q table
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint G2(uint x, uint y, uint z)
    {
        return (RotateLeft(x, 10) ^ RotateLeft(z, 23)) + RotateLeft(y, 8);
    }

    /// <summary>
    /// H1 function: output filter for P table
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint H1(uint x, uint[] q)
    {
        return q[(byte)x] + q[256 + ((byte)(x >> 16))];
    }

    /// <summary>
    /// H2 function: output filter for Q table
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint H2(uint x, uint[] p)
    {
        return p[(byte)x] + p[256 + ((byte)(x >> 16))];
    }

    /// <summary>
    /// F1 function: used in key expansion
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint F1(uint x)
    {
        return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
    }

    /// <summary>
    /// F2 function: used in key expansion
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint F2(uint x)
    {
        return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
    }

    /// <summary>
    /// Right rotation
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateRight(uint value, int bits)
    {
        return (value >> bits) | (value << (32 - bits));
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
    /// Reads a uint32 value in little-endian format
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> buffer)
    {
        return (uint)(buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24));
    }

    /// <summary>
    /// Validates parameters for HC-128
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes", nameof(key));
        }
        if (iv.Length != IV_SIZE)
        {
            throw new ArgumentException($"IV must be {IV_SIZE} bytes", nameof(iv));
        }
    }

    /// <summary>
    /// Gets the maximum plaintext length
    /// </summary>
    public static long GetMaxPlaintextLength()
    {
        // HC-128 can encrypt up to 2^64 bytes (theoretical limit)
        return long.MaxValue;
    }
}
