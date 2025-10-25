using HeroCrypt.Security;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HeroCrypt.Cryptography.Symmetric.Rabbit;

/// <summary>
/// Rabbit stream cipher implementation (RFC 4503)
/// High-speed stream cipher designed for software performance
/// Part of the eSTREAM portfolio (software profile)
/// </summary>
internal static class RabbitCore
{
    /// <summary>
    /// Key size in bytes (128 bits)
    /// </summary>
    public const int KeySize = 16;

    /// <summary>
    /// IV size in bytes (64 bits)
    /// </summary>
    public const int IvSize = 8;

    /// <summary>
    /// Block size in bytes (128 bits of output per iteration)
    /// </summary>
    public const int BlockSize = 16;

    /// <summary>
    /// Rabbit cipher state
    /// </summary>
    private struct RabbitState
    {
        public uint[] X;  // 8 state variables (32-bit each)
        public uint[] C;  // 8 counter variables (32-bit each)
        public uint Carry; // Carry bit for counter system

        public RabbitState()
        {
            X = new uint[8];
            C = new uint[8];
            Carry = 0;
        }
    }

    /// <summary>
    /// Encrypts or decrypts data using Rabbit stream cipher
    /// </summary>
    /// <param name="output">Output buffer</param>
    /// <param name="input">Input buffer</param>
    /// <param name="key">16-byte key</param>
    /// <param name="iv">8-byte initialization vector (or empty for key-only mode)</param>
    public static void Transform(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        if (iv.Length != 0 && iv.Length != IvSize)
            throw new ArgumentException($"IV must be {IvSize} bytes or empty for key-only mode", nameof(iv));
        if (output.Length < input.Length)
            throw new ArgumentException("Output buffer too small", nameof(output));

        var state = new RabbitState();

        try
        {
            // Initialize state with key
            KeySetup(ref state, key);

            // Setup IV (only if provided)
            if (iv.Length == IvSize)
            {
                IvSetup(ref state, iv);
            }

            // Generate keystream and XOR with input
            var blocks = (input.Length + BlockSize - 1) / BlockSize;
            Span<byte> keystream = stackalloc byte[BlockSize];

            for (var blockIndex = 0; blockIndex < blocks; blockIndex++)
            {
                var blockStart = blockIndex * BlockSize;
                var blockSize = Math.Min(BlockSize, input.Length - blockStart);

                var inputBlock = input.Slice(blockStart, blockSize);
                var outputBlock = output.Slice(blockStart, blockSize);

                // Extract keystream block
                ExtractKeystream(ref state, keystream);

                // XOR with input
                for (var i = 0; i < blockSize; i++)
                {
                    outputBlock[i] = (byte)(inputBlock[i] ^ keystream[i]);
                }

                // Clear keystream
                SecureMemoryOperations.SecureClear(keystream);
            }
        }
        finally
        {
            // Clear state
            if (state.X != null)
                SecureMemoryOperations.SecureClear(state.X.AsSpan());
            if (state.C != null)
                SecureMemoryOperations.SecureClear(state.C.AsSpan());
        }
    }

    /// <summary>
    /// Key setup - initializes the state with the key
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void KeySetup(ref RabbitState state, ReadOnlySpan<byte> key)
    {
        // Convert key to 16-bit words (RFC 4503 / Mozilla implementation)
        // Read bytes in reverse order: k[0] from bytes 14-15, k[1] from bytes 12-13, etc.
        Span<ushort> k = stackalloc ushort[8];
        for (var j = 0; j < 8; j++)
        {
            var i = 14 - (j * 2);  // 14, 12, 10, 8, 6, 4, 2, 0
            k[j] = (ushort)(key[i + 1] | (key[i] << 8));
        }

        try
        {
            // Initialize state variables (RFC 4503 Section 2.3)
            // Even j: Xj = K(j+1 mod 8) || Kj, Cj = K(j+4 mod 8) || K(j+5 mod 8)
            // Odd j:  Xj = K(j+5 mod 8) || K(j+4 mod 8), Cj = Kj || K(j+1 mod 8)
            for (var j = 0; j < 8; j++)
            {
                if (j % 2 == 0)
                {
                    state.X[j] = (uint)((k[(j + 1) % 8] << 16) | k[j]);
                    state.C[j] = (uint)((k[(j + 4) % 8] << 16) | k[(j + 5) % 8]);
                }
                else
                {
                    state.X[j] = (uint)((k[(j + 5) % 8] << 16) | k[(j + 4) % 8]);
                    state.C[j] = (uint)((k[j] << 16) | k[(j + 1) % 8]);
                }
            }

            state.Carry = 0;

            // Iterate system 4 times
            for (var i = 0; i < 4; i++)
            {
                NextState(ref state);
            }

            // Modify counters
            for (var i = 0; i < 8; i++)
            {
                state.C[i] ^= state.X[(i + 4) % 8];
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(MemoryMarshal.AsBytes(k));
        }
    }

    /// <summary>
    /// IV setup - reinitializes the state with an IV
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void IvSetup(ref RabbitState state, ReadOnlySpan<byte> iv)
    {
        // Convert IV to 32-bit words (RFC 4503 / Mozilla implementation)
        // i0 = lower 32 bits, i2 = upper 32 bits (little-endian)
        var i0 = (uint)(iv[0] | (iv[1] << 8) | (iv[2] << 16) | (iv[3] << 24));
        var i2 = (uint)(iv[4] | (iv[5] << 8) | (iv[6] << 16) | (iv[7] << 24));

        // Derive intermediate values
        var i1 = (i0 >> 16) | (i2 & 0xFFFF0000);
        var i3 = ((i2 & 0xFFFF) << 16) | (i0 & 0xFFFF);

        // Modify counters with IV (RFC 4503 Section 2.4)
        state.C[0] ^= i0;
        state.C[1] ^= i1;
        state.C[2] ^= i2;
        state.C[3] ^= i3;
        state.C[4] ^= i0;
        state.C[5] ^= i1;
        state.C[6] ^= i2;
        state.C[7] ^= i3;

        // Iterate system 4 times
        for (var i = 0; i < 4; i++)
        {
            NextState(ref state);
        }
    }

    /// <summary>
    /// Computes the next internal state
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void NextState(ref RabbitState state)
    {
        // Counter update constants (Fibonacci-like)
        ReadOnlySpan<uint> A = stackalloc uint[8]
        {
            0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
            0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3
        };

        // Save old counter values
        Span<uint> c_old = stackalloc uint[8];
        state.C.CopyTo(c_old);

        // Update counters
        for (var i = 0; i < 8; i++)
        {
            var temp = (ulong)state.C[i] + A[i] + state.Carry;
            state.Carry = (uint)(temp >> 32);
            state.C[i] = (uint)temp;
        }

        // Calculate g-functions
        Span<uint> g = stackalloc uint[8];
        for (var i = 0; i < 8; i++)
        {
            g[i] = GFunc(state.X[i], state.C[i]);
        }

        // Update state variables
        state.X[0] = (uint)(g[0] + RotateLeft(g[7], 16) + RotateLeft(g[6], 16));
        state.X[1] = (uint)(g[1] + RotateLeft(g[0], 8) + g[7]);
        state.X[2] = (uint)(g[2] + RotateLeft(g[1], 16) + RotateLeft(g[0], 16));
        state.X[3] = (uint)(g[3] + RotateLeft(g[2], 8) + g[1]);
        state.X[4] = (uint)(g[4] + RotateLeft(g[3], 16) + RotateLeft(g[2], 16));
        state.X[5] = (uint)(g[5] + RotateLeft(g[4], 8) + g[3]);
        state.X[6] = (uint)(g[6] + RotateLeft(g[5], 16) + RotateLeft(g[4], 16));
        state.X[7] = (uint)(g[7] + RotateLeft(g[6], 8) + g[5]);
    }

    /// <summary>
    /// G-function: non-linear state transition
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint GFunc(uint x, uint c)
    {
        // Square the sum
        var sum = (ulong)x + c;
        var square = sum * sum;

        // XOR high and low parts
        return (uint)(square ^ (square >> 32));
    }

    /// <summary>
    /// Extracts keystream from current state
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtractKeystream(ref RabbitState state, Span<byte> output)
    {
        // Update state
        NextState(ref state);

        // Extract 128 bits of keystream
        Span<ushort> s = stackalloc ushort[8];

        s[0] = (ushort)(state.X[0] ^ (state.X[5] >> 16));
        s[1] = (ushort)((state.X[0] >> 16) ^ (state.X[3] & 0xFFFF));
        s[2] = (ushort)(state.X[2] ^ (state.X[7] >> 16));
        s[3] = (ushort)((state.X[2] >> 16) ^ (state.X[5] & 0xFFFF));
        s[4] = (ushort)(state.X[4] ^ (state.X[1] >> 16));
        s[5] = (ushort)((state.X[4] >> 16) ^ (state.X[7] & 0xFFFF));
        s[6] = (ushort)(state.X[6] ^ (state.X[3] >> 16));
        s[7] = (ushort)((state.X[6] >> 16) ^ (state.X[1] & 0xFFFF));

        // Convert to bytes (little-endian)
        for (var i = 0; i < 8; i++)
        {
            output[i * 2] = (byte)s[i];
            output[i * 2 + 1] = (byte)(s[i] >> 8);
        }

        SecureMemoryOperations.SecureClear(MemoryMarshal.AsBytes(s));
    }

    /// <summary>
    /// Left rotation (circular shift)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateLeft(uint value, int bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    /// <summary>
    /// Validates parameters for Rabbit
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        if (iv.Length != 0 && iv.Length != IvSize)
            throw new ArgumentException($"IV must be {IvSize} bytes or empty for key-only mode", nameof(iv));
    }

    /// <summary>
    /// Gets the maximum plaintext length
    /// </summary>
    public static long GetMaxPlaintextLength()
    {
        // Rabbit can encrypt up to 2^64 blocks (theoretical limit)
        // Practical limit is much smaller for security
        return long.MaxValue;
    }
}
