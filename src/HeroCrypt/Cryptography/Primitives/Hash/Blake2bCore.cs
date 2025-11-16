#if NETSTANDARD2_0
using System;
#else
using System.Buffers.Binary;
#endif
using System.Runtime.CompilerServices;

namespace HeroCrypt.Cryptography.Primitives.Hash;

/// <summary>
/// Blake2b cryptographic hash function implementation.
/// Implements RFC 7693 specification.
/// </summary>
public static class Blake2bCore
{
    /// <summary>
    /// Blake2b initialization vectors (first 64 bits of the fractional parts of the square roots of the first 8 primes).
    /// </summary>
    private static readonly ulong[] Blake2bIv =
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    /// <summary>
    /// Blake2b message schedule permutation table.
    /// </summary>
    private static readonly byte[,] Blake2bSigma = new byte[10, 16]
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
    };

    /// <summary>
    /// Blake2b parameter block structure.
    /// </summary>
    /// <summary>
    /// Blake2b parameter block structure containing algorithm configuration
    /// </summary>
    public struct Blake2bParams
    {
        /// <summary>
        /// Digest length in bytes (1-64)
        /// </summary>
        public byte DigestSize;

        /// <summary>
        /// Key length in bytes (0-64, 0 for no key)
        /// </summary>
        public byte KeyLength;

        /// <summary>
        /// Fanout (0-255, 1 for sequential hashing)
        /// </summary>
        public byte FanOut;

        /// <summary>
        /// Depth (0-255, 1 for sequential hashing)
        /// </summary>
        public byte Depth;

        /// <summary>
        /// Leaf length (0 means unlimited)
        /// </summary>
        public uint LeafLength;

        /// <summary>
        /// Node offset for tree hashing
        /// </summary>
        public ulong NodeOffset;

        /// <summary>
        /// Node depth for tree hashing
        /// </summary>
        public byte NodeDepth;

        /// <summary>
        /// Inner hash length for tree hashing
        /// </summary>
        public byte InnerLength;

        /// <summary>
        /// Reserved bytes (must be zero)
        /// </summary>
        public byte[] Reserved;

        /// <summary>
        /// Salt value (16 bytes)
        /// </summary>
        public byte[] Salt;

        /// <summary>
        /// Personalization value (16 bytes)
        /// </summary>
        public byte[] Personalization;

        /// <summary>
        /// Creates default Blake2b parameters for sequential hashing
        /// </summary>
        /// <param name="outputLength">Output hash length in bytes (default: 64)</param>
        /// <returns>Default Blake2b parameters</returns>
        public static Blake2bParams Default(int outputLength = 64)
        {
            return new Blake2bParams
            {
                DigestSize = (byte)outputLength,
                KeyLength = 0,
                FanOut = 1,
                Depth = 1,
                LeafLength = 0,
                NodeOffset = 0,
                NodeDepth = 0,
                InnerLength = 0,
                Reserved = new byte[14],
                Salt = new byte[16],
                Personalization = new byte[16]
            };
        }

        /// <summary>
        /// Converts the parameter block to an array of 64-bit words
        /// </summary>
        /// <returns>Parameter block as 8 x 64-bit words</returns>
        public ulong[] ToWords()
        {
            var words = new ulong[8];
            var paramBytes = new byte[64];

            paramBytes[0] = DigestSize;
            paramBytes[1] = KeyLength;
            paramBytes[2] = FanOut;
            paramBytes[3] = Depth;

#if NETSTANDARD2_0
            WriteUInt32LittleEndian(paramBytes, 4, LeafLength);
            WriteUInt64LittleEndian(paramBytes, 8, NodeOffset);
#else
            BinaryPrimitives.WriteUInt32LittleEndian(paramBytes.AsSpan(4), LeafLength);
            BinaryPrimitives.WriteUInt64LittleEndian(paramBytes.AsSpan(8), NodeOffset);
#endif

            paramBytes[16] = NodeDepth;
            paramBytes[17] = InnerLength;

            if (Reserved != null)
                Array.Copy(Reserved, 0, paramBytes, 18, Math.Min(14, Reserved.Length));
            if (Salt != null)
                Array.Copy(Salt, 0, paramBytes, 32, Math.Min(16, Salt.Length));
            if (Personalization != null)
                Array.Copy(Personalization, 0, paramBytes, 48, Math.Min(16, Personalization.Length));

            for (var i = 0; i < 8; i++)
            {
#if NETSTANDARD2_0
                words[i] = ReadUInt64LittleEndian(paramBytes, i * 8);
#else
                words[i] = BinaryPrimitives.ReadUInt64LittleEndian(paramBytes.AsSpan(i * 8));
#endif
            }

            return words;
        }
    }

    /// <summary>
    /// Computes a Blake2b hash with the specified parameters
    /// </summary>
    /// <param name="input">Input data to hash</param>
    /// <param name="outputLength">Output hash length in bytes (1-64, default: 64)</param>
    /// <param name="key">Optional key for keyed hashing (max 64 bytes)</param>
    /// <param name="salt">Optional salt value (must be exactly 16 bytes)</param>
    /// <param name="personalization">Optional personalization value (must be exactly 16 bytes)</param>
    /// <returns>Blake2b hash as byte array</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[] ComputeHash(
        byte[] input,
        int outputLength = 64,
        byte[]? key = null,
        byte[]? salt = null,
        byte[]? personalization = null)
    {
        if (outputLength < 1 || outputLength > 64)
            throw new ArgumentException("Output length must be between 1 and 64 bytes", nameof(outputLength));

        if (key != null && key.Length > 64)
            throw new ArgumentException("Key length must not exceed 64 bytes", nameof(key));

        var parameters = Blake2bParams.Default(outputLength);
        parameters.KeyLength = (byte)(key?.Length ?? 0);

        if (salt != null)
        {
            if (salt.Length != 16)
                throw new ArgumentException("Salt must be exactly 16 bytes", nameof(salt));
            parameters.Salt = salt;
        }

        if (personalization != null)
        {
            if (personalization.Length != 16)
                throw new ArgumentException("Personalization must be exactly 16 bytes", nameof(personalization));
            parameters.Personalization = personalization;
        }

        return ComputeHashInternal(input, parameters, key);
    }

    /// <summary>
    /// Computes a Blake2b hash with arbitrary output length using the long hash construction
    /// Used for Argon2 where hash outputs can exceed 64 bytes (H' as per Argon2 specification)
    /// </summary>
    /// <param name="input">Input data to hash</param>
    /// <param name="outputLength">Desired output length in bytes</param>
    /// <returns>Blake2b long hash as byte array</returns>
    /// <exception cref="ArgumentException">Thrown when output length is not positive</exception>
    public static byte[] ComputeLongHash(byte[] input, int outputLength)
    {
        if (outputLength < 1)
            throw new ArgumentException("Output length must be positive", nameof(outputLength));

        // Create input with prepended length: LE32(T) || A
        var inputWithLength = new byte[4 + input.Length];
#if NETSTANDARD2_0
        WriteInt32LittleEndian(inputWithLength, 0, outputLength);
#else
        BinaryPrimitives.WriteInt32LittleEndian(inputWithLength.AsSpan(0), outputLength);
#endif
        Array.Copy(input, 0, inputWithLength, 4, input.Length);

        if (outputLength <= 64)
        {
            // For T <= 64: H'(A) = H^T(LE32(T) || A)
            return ComputeHash(inputWithLength, outputLength);
        }
        else
        {
            // For T > 64: Use multi-stage approach
            var output = new byte[outputLength];
            var r = (outputLength + 31) / 32 - 2;

            // V_1 = H^(64)(LE32(T) || A)
            var v = ComputeHash(inputWithLength, 64);

            // W_1: first 32 bytes of V_1
            Array.Copy(v, 0, output, 0, 32);
            var position = 32;

            // Generate V_2, V_3, ..., V_r
            for (var i = 1; i < r; i++)
            {
                v = ComputeHash(v, 64);
                Array.Copy(v, 0, output, position, 32);
                position += 32;
            }

            // Final block V_{r+1} with reduced length
            var finalLength = outputLength - 32 * r;
            if (finalLength > 0)
            {
                var finalBlock = ComputeHash(v, finalLength);
                Array.Copy(finalBlock, 0, output, position, finalLength);
            }

            return output;
        }
    }

    private static byte[] ComputeHashInternal(byte[] input, Blake2bParams parameters, byte[]? key)
    {
        // Initialize hash state with parameter block
        var h = new ulong[8];
        Array.Copy(Blake2bIv, h, 8);
        var paramWords = parameters.ToWords();
        for (var i = 0; i < 8; i++)
        {
            h[i] ^= paramWords[i];
        }

        var bytesCompressed = 0;
        var buffer = new byte[128];
        var bufferLength = 0;

        // If keyed, process the key as the first block
        if (key != null && key.Length > 0)
        {
            Array.Copy(key, buffer, key.Length);
            bufferLength = 128; // Key block is always padded to 128 bytes
        }

        // Process input
        for (var i = 0; i < input.Length; i++)
        {
            if (bufferLength == 128)
            {
                bytesCompressed += 128;
                Compress(h, buffer, bytesCompressed, false);
                bufferLength = 0;
                Array.Clear(buffer, 0, 128);
            }
            buffer[bufferLength++] = input[i];
        }

        // Process final block
        bytesCompressed += bufferLength;
        Compress(h, buffer, bytesCompressed, true);

        // Output hash bytes
        var output = new byte[parameters.DigestSize];
        for (var i = 0; i < parameters.DigestSize / 8; i++)
        {
#if NETSTANDARD2_0
            WriteUInt64LittleEndian(output, i * 8, h[i]);
#else
            BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(i * 8), h[i]);
#endif
        }

        // Handle remaining bytes
        if (parameters.DigestSize % 8 != 0)
        {
            var lastBytes = new byte[8];
#if NETSTANDARD2_0
            WriteUInt64LittleEndian(lastBytes, 0, h[parameters.DigestSize / 8]);
#else
            BinaryPrimitives.WriteUInt64LittleEndian(lastBytes, h[parameters.DigestSize / 8]);
#endif
            Array.Copy(lastBytes, 0, output, (parameters.DigestSize / 8) * 8, parameters.DigestSize % 8);
        }

        return output;
    }

    private static void Compress(ulong[] h, byte[] messageBlock, int bytesCompressed, bool isLastBlock)
    {
        // Convert message block to 16 64-bit words
        var m = new ulong[16];
        for (var i = 0; i < 16; i++)
        {
#if NETSTANDARD2_0
            m[i] = ReadUInt64LittleEndian(messageBlock, i * 8);
#else
            m[i] = BinaryPrimitives.ReadUInt64LittleEndian(messageBlock.AsSpan(i * 8));
#endif
        }

        // Initialize working vector
        var v = new ulong[16];
        Array.Copy(h, v, 8);
        Array.Copy(Blake2bIv, 0, v, 8, 8);

        // XOR in counter and final block flag
        v[12] ^= (ulong)bytesCompressed;
        v[13] ^= 0; // High 64 bits of counter
        if (isLastBlock)
        {
            v[14] ^= 0xFFFFFFFFFFFFFFFFUL;
        }

        // 12 rounds of mixing
        for (var round = 0; round < 12; round++)
        {
            // Column step
            G(v, 0, 4, 8, 12, m[Blake2bSigma[round % 10, 0]], m[Blake2bSigma[round % 10, 1]]);
            G(v, 1, 5, 9, 13, m[Blake2bSigma[round % 10, 2]], m[Blake2bSigma[round % 10, 3]]);
            G(v, 2, 6, 10, 14, m[Blake2bSigma[round % 10, 4]], m[Blake2bSigma[round % 10, 5]]);
            G(v, 3, 7, 11, 15, m[Blake2bSigma[round % 10, 6]], m[Blake2bSigma[round % 10, 7]]);

            // Diagonal step
            G(v, 0, 5, 10, 15, m[Blake2bSigma[round % 10, 8]], m[Blake2bSigma[round % 10, 9]]);
            G(v, 1, 6, 11, 12, m[Blake2bSigma[round % 10, 10]], m[Blake2bSigma[round % 10, 11]]);
            G(v, 2, 7, 8, 13, m[Blake2bSigma[round % 10, 12]], m[Blake2bSigma[round % 10, 13]]);
            G(v, 3, 4, 9, 14, m[Blake2bSigma[round % 10, 14]], m[Blake2bSigma[round % 10, 15]]);
        }

        // Finalize hash value
        for (var i = 0; i < 8; i++)
        {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 63);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong RotateRight(ulong value, int bits)
    {
        return (value >> bits) | (value << (64 - bits));
    }

#if NETSTANDARD2_0
    // Helper methods for .NET Standard 2.0 compatibility
    private static void WriteInt32LittleEndian(byte[] destination, int offset, int value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt32LittleEndian(byte[] destination, int offset, uint value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt64LittleEndian(byte[] destination, int offset, ulong value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
        destination[offset + 4] = (byte)(value >> 32);
        destination[offset + 5] = (byte)(value >> 40);
        destination[offset + 6] = (byte)(value >> 48);
        destination[offset + 7] = (byte)(value >> 56);
    }

    private static ulong ReadUInt64LittleEndian(byte[] source, int offset)
    {
        return (ulong)source[offset] |
               ((ulong)source[offset + 1] << 8) |
               ((ulong)source[offset + 2] << 16) |
               ((ulong)source[offset + 3] << 24) |
               ((ulong)source[offset + 4] << 32) |
               ((ulong)source[offset + 5] << 40) |
               ((ulong)source[offset + 6] << 48) |
               ((ulong)source[offset + 7] << 56);
    }
#endif
}