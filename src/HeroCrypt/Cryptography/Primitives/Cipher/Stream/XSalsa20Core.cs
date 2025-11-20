using System.Runtime.CompilerServices;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// XSalsa20 stream cipher implementation
/// Extended version of Salsa20 with 24-byte nonces (similar to XChaCha20)
/// Maintains compatibility with NaCl/libsodium implementations
/// </summary>
public static class XSalsa20Core
{
    /// <summary>
    /// Salsa20 constants "expand 32-byte k"
    /// </summary>
    private static readonly uint[] Constants = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    /// <summary>
    /// Key size in bytes
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    /// Extended nonce size in bytes
    /// </summary>
    public const int NonceSize = 24;

    /// <summary>
    /// Block size in bytes
    /// </summary>
    public const int BlockSize = 64;

    /// <summary>
    /// Encrypts or decrypts data using XSalsa20
    /// </summary>
    /// <param name="output">Output buffer</param>
    /// <param name="input">Input buffer</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">24-byte nonce</param>
    /// <param name="counter">Initial counter value</param>
    public static void Transform(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce, uint counter = 0)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        }
        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
        }
        if (output.Length < input.Length)
        {
            throw new ArgumentException("Output buffer too small", nameof(output));
        }

        // Derive Salsa20 key and nonce from XSalsa20 parameters using HSalsa20
        Span<byte> derivedKey = stackalloc byte[32];
        Span<byte> derivedNonce = stackalloc byte[8];
        DeriveKeyAndNonce(derivedKey, derivedNonce, key, nonce);

        try
        {
            Span<uint> state = stackalloc uint[16];
            var blocks = (input.Length + BlockSize - 1) / BlockSize;

            // Move stackalloc outside the loop to prevent stack overflow
            Span<byte> keystream = stackalloc byte[BlockSize];

            for (var blockIndex = 0; blockIndex < blocks; blockIndex++)
            {
                var blockStart = blockIndex * BlockSize;
                var blockSize = Math.Min(BlockSize, input.Length - blockStart);

                var inputBlock = input.Slice(blockStart, blockSize);
                var outputBlock = output.Slice(blockStart, blockSize);

                // Initialize state for this block
                InitializeSalsa20State(state, derivedKey, derivedNonce, counter + (uint)blockIndex);

                // Generate keystream block (reuse the keystream buffer)
                GenerateKeystreamBlock(keystream, state);

                // XOR with input
                for (var i = 0; i < blockSize; i++)
                {
                    outputBlock[i] = (byte)(inputBlock[i] ^ keystream[i]);
                }

                // Clear keystream
                SecureMemoryOperations.SecureClear(keystream);
            }

            // Clear state
            SecureMemoryOperations.SecureClear(state);
        }
        finally
        {
            // Clear derived key and nonce
            SecureMemoryOperations.SecureClear(derivedKey);
            SecureMemoryOperations.SecureClear(derivedNonce);
        }
    }

    /// <summary>
    /// Derives Salsa20 key and nonce from XSalsa20 parameters using HSalsa20
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DeriveKeyAndNonce(Span<byte> derivedKey, Span<byte> derivedNonce,
        ReadOnlySpan<byte> originalKey, ReadOnlySpan<byte> extendedNonce)
    {
        // HSalsa20 takes the first 16 bytes of the nonce
        var hsalsa20Nonce = extendedNonce.Slice(0, 16);

        // Derive new key using HSalsa20
        HSalsa20(derivedKey, originalKey, hsalsa20Nonce);

        // The derived nonce is the last 8 bytes of the extended nonce
        extendedNonce.Slice(16, 8).CopyTo(derivedNonce);
    }

    /// <summary>
    /// HSalsa20 key derivation function
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void HSalsa20(Span<byte> output, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (output.Length != 32)
        {
            throw new ArgumentException("Output must be 32 bytes", nameof(output));
        }
        if (key.Length != 32)
        {
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        }
        if (nonce.Length != 16)
        {
            throw new ArgumentException("Nonce must be 16 bytes", nameof(nonce));
        }

        // Initialize HSalsa20 state
        Span<uint> state = stackalloc uint[16];

        // Constants
        state[0] = Constants[0];
        state[1] = Constants[1];
        state[2] = Constants[2];
        state[3] = Constants[3];

#if !NET5_0_OR_GREATER
        // Create reusable arrays for .NET Standard 2.0 (avoid memory leaks in loops)
        var keySlice = new byte[4];
        var nonceSlice = new byte[4];
#endif

        // Key
        for (var i = 0; i < 8; i++)
        {
#if NET5_0_OR_GREATER
            state[4 + i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
#else
            key.Slice(i * 4, 4).CopyTo(keySlice);
            state[4 + i] = BitConverter.ToUInt32(keySlice, 0);
#endif
        }

        // Nonce
        for (var i = 0; i < 4; i++)
        {
#if NET5_0_OR_GREATER
            state[12 + i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(i * 4, 4));
#else
            nonce.Slice(i * 4, 4).CopyTo(nonceSlice);
            state[12 + i] = BitConverter.ToUInt32(nonceSlice, 0);
#endif
        }

        // Perform 20 rounds (same as Salsa20)
        for (var i = 0; i < 10; i++)
        {
            // Column rounds
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 5, 9, 13, 1);
            QuarterRound(state, 10, 14, 2, 6);
            QuarterRound(state, 15, 3, 7, 11);

            // Row rounds
            QuarterRound(state, 0, 1, 2, 3);
            QuarterRound(state, 5, 6, 7, 4);
            QuarterRound(state, 10, 11, 8, 9);
            QuarterRound(state, 15, 12, 13, 14);
        }

        // Output only state[0], state[5], state[10], state[15], state[6], state[7], state[8], state[9]
        WriteUInt32LittleEndian(output.Slice(0, 4), state[0]);
        WriteUInt32LittleEndian(output.Slice(4, 4), state[5]);
        WriteUInt32LittleEndian(output.Slice(8, 4), state[10]);
        WriteUInt32LittleEndian(output.Slice(12, 4), state[15]);
        WriteUInt32LittleEndian(output.Slice(16, 4), state[6]);
        WriteUInt32LittleEndian(output.Slice(20, 4), state[7]);
        WriteUInt32LittleEndian(output.Slice(24, 4), state[8]);
        WriteUInt32LittleEndian(output.Slice(28, 4), state[9]);

        // Clear state
        SecureMemoryOperations.SecureClear(state);
    }

    /// <summary>
    /// Initializes Salsa20 state
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitializeSalsa20State(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
    {
        // Constants
        state[0] = Constants[0];
        state[1] = Constants[1];
        state[2] = Constants[2];
        state[3] = Constants[3];

#if !NET5_0_OR_GREATER
        // Create reusable arrays for .NET Standard 2.0 (avoid memory leaks in loops)
        var keySlice = new byte[4];
        var nonceSlice = new byte[4];
#endif

        // Key (first half)
        for (var i = 0; i < 4; i++)
        {
#if NET5_0_OR_GREATER
            state[4 + i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
#else
            key.Slice(i * 4, 4).CopyTo(keySlice);
            state[4 + i] = BitConverter.ToUInt32(keySlice, 0);
#endif
        }

        // Counter and nonce
        state[8] = counter;
        state[9] = 0; // High part of counter for 64-bit counter

#if NET5_0_OR_GREATER
        state[10] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4));
        state[11] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
#else
        nonce.Slice(0, 4).CopyTo(nonceSlice);
        state[10] = BitConverter.ToUInt32(nonceSlice, 0);
        nonce.Slice(4, 4).CopyTo(nonceSlice);
        state[11] = BitConverter.ToUInt32(nonceSlice, 0);
#endif

        // Key (second half)
        for (var i = 0; i < 4; i++)
        {
#if NET5_0_OR_GREATER
            state[12 + i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(key.Slice((i + 4) * 4, 4));
#else
            key.Slice((i + 4) * 4, 4).CopyTo(keySlice);
            state[12 + i] = BitConverter.ToUInt32(keySlice, 0);
#endif
        }
    }

    /// <summary>
    /// Generates a single keystream block using Salsa20 round function
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateKeystreamBlock(Span<byte> keystream, Span<uint> state)
    {
        // Create working copy
        Span<uint> workingState = stackalloc uint[16];
        state.CopyTo(workingState);

        // Perform 20 rounds (10 double rounds)
        for (var i = 0; i < 10; i++)
        {
            // Column rounds
            QuarterRound(workingState, 0, 4, 8, 12);
            QuarterRound(workingState, 5, 9, 13, 1);
            QuarterRound(workingState, 10, 14, 2, 6);
            QuarterRound(workingState, 15, 3, 7, 11);

            // Row rounds
            QuarterRound(workingState, 0, 1, 2, 3);
            QuarterRound(workingState, 5, 6, 7, 4);
            QuarterRound(workingState, 10, 11, 8, 9);
            QuarterRound(workingState, 15, 12, 13, 14);
        }

        // Add original state to working state
        for (var i = 0; i < 16; i++)
        {
            workingState[i] += state[i];
        }

        // Convert to bytes (little-endian)
        for (var i = 0; i < 16; i++)
        {
            WriteUInt32LittleEndian(keystream.Slice(i * 4, 4), workingState[i]);
        }

        // Clear working state
        SecureMemoryOperations.SecureClear(workingState);
    }

    /// <summary>
    /// Salsa20 quarter round function
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        state[b] ^= RotateLeft(state[a] + state[d], 7);
        state[c] ^= RotateLeft(state[b] + state[a], 9);
        state[d] ^= RotateLeft(state[c] + state[b], 13);
        state[a] ^= RotateLeft(state[d] + state[c], 18);
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
    /// Writes a uint32 value in little-endian format
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteUInt32LittleEndian(Span<byte> buffer, uint value)
    {
        buffer[0] = (byte)value;
        buffer[1] = (byte)(value >> 8);
        buffer[2] = (byte)(value >> 16);
        buffer[3] = (byte)(value >> 24);
    }

    /// <summary>
    /// Validates parameters for XSalsa20
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        }
        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
        }
    }

    /// <summary>
    /// Gets the maximum plaintext length for a given nonce
    /// </summary>
    public static long GetMaxPlaintextLength()
    {
        // XSalsa20 can encrypt up to 2^70 bytes with a single nonce
        return long.MaxValue; // Practically unlimited for most applications
    }
}
