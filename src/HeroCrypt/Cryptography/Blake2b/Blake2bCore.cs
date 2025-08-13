#if NETSTANDARD2_0
using BinaryPrimitives = HeroCrypt.Compatibility.BinaryPrimitivesCompat;
#else
using System.Buffers.Binary;
#endif
using System.Runtime.CompilerServices;

namespace HeroCrypt.Cryptography.Blake2b;

/// <summary>
/// Blake2b cryptographic hash function implementation according to RFC 7693
/// </summary>
public static class Blake2bCore
{
    private const int BlockSize = 128;
    private const int MaxHashSize = 64;
    private const int MaxKeySize = 64;
    
    // Blake2b initialization vectors (same as SHA-512)
    private static readonly ulong[] IV = 
    [
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    ];
    
    // Permutation for message word selection
    private static readonly int[][] Sigma = 
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
    ];
    
    /// <summary>
    /// Compute Blake2b hash
    /// </summary>
    public static byte[] ComputeHash(byte[] data, int hashSize = 64, byte[]? key = null)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (hashSize < 1 || hashSize > MaxHashSize)
            throw new ArgumentOutOfRangeException(nameof(hashSize), $"Hash size must be between 1 and {MaxHashSize}");
        if (key != null && key.Length > MaxKeySize)
            throw new ArgumentException($"Key size must not exceed {MaxKeySize} bytes", nameof(key));
        
        var ctx = new Blake2bContext();
        Initialize(ctx, hashSize, key);
        Update(ctx, data, 0, data.Length);
        return Final(ctx);
    }
    
    /// <summary>
    /// Compute Blake2b hash with variable output length (Blake2b-Long)
    /// </summary>
    public static byte[] ComputeHashLong(byte[] data, int outputLength, byte[]? key = null)
    {
        if (outputLength <= MaxHashSize)
        {
            return ComputeHash(data, outputLength, key);
        }
        
        var result = new byte[outputLength];
        
        // Prepend output length as 32-bit little-endian integer
        var inputWithLength = new byte[4 + data.Length];
        BinaryPrimitives.WriteInt32LittleEndian(inputWithLength.AsSpan(0), outputLength);
        Array.Copy(data, 0, inputWithLength, 4, data.Length);
        
        // Generate first block with full 64-byte output
        var outBuffer = ComputeHash(inputWithLength, 64, key);
        Array.Copy(outBuffer, 0, result, 0, Math.Min(32, outputLength));
        
        var remaining = outputLength - 32;
        var position = 32;
        
        // Generate subsequent blocks
        while (remaining > 64)
        {
            outBuffer = ComputeHash(outBuffer, 64, null);
            Array.Copy(outBuffer, 0, result, position, 32);
            position += 32;
            remaining -= 32;
        }
        
        // Generate final block
        if (remaining > 0)
        {
            outBuffer = ComputeHash(outBuffer, 64, null);
            Array.Copy(outBuffer, 0, result, position, remaining);
        }
        
        return result;
    }
    
    private static void Initialize(Blake2bContext ctx, int hashSize, byte[]? key)
    {
        ctx.HashSize = hashSize;
        ctx.KeyLength = key?.Length ?? 0;
        
        // Initialize state with IV
        for (var i = 0; i < 8; i++)
        {
            ctx.H[i] = IV[i];
        }
        
        // Set parameters in H[0]
        ctx.H[0] ^= 0x01010000UL | ((ulong)(byte)ctx.KeyLength << 8) | (ulong)ctx.HashSize;
        
        // If we have a key, pad it to BlockSize and treat it as the first block
        if (key != null && key.Length > 0)
        {
            var keyBlock = new byte[BlockSize];
            Array.Copy(key, keyBlock, key.Length);
            Update(ctx, keyBlock, 0, BlockSize);
        }
    }
    
    private static void Update(Blake2bContext ctx, byte[] data, int offset, int length)
    {
        var dataPos = offset;
        var dataEnd = offset + length;
        
        while (dataPos < dataEnd)
        {
            var bytesToCopy = Math.Min(dataEnd - dataPos, BlockSize - ctx.BufferLength);
            Array.Copy(data, dataPos, ctx.Buffer, ctx.BufferLength, bytesToCopy);
            
            ctx.BufferLength += bytesToCopy;
            dataPos += bytesToCopy;
            
            if (ctx.BufferLength == BlockSize)
            {
                ctx.Counter += BlockSize;
                Compress(ctx, false);
                ctx.BufferLength = 0;
            }
        }
    }
    
    private static byte[] Final(Blake2bContext ctx)
    {
        // Pad final block with zeros
        if (ctx.BufferLength < BlockSize)
        {
            Array.Clear(ctx.Buffer, ctx.BufferLength, BlockSize - ctx.BufferLength);
        }
        
        ctx.Counter += (ulong)ctx.BufferLength;
        ctx.CounterHigh = 0; // Not used in our implementation
        
        // Final block flag
        Compress(ctx, true);
        
        // Extract hash
        var hash = new byte[ctx.HashSize];
        for (var i = 0; i < ctx.HashSize; i++)
        {
            hash[i] = (byte)(ctx.H[i / 8] >> (8 * (i % 8)));
        }
        
        return hash;
    }
    
    private static void Compress(Blake2bContext ctx, bool isFinal)
    {
        // Initialize working vector
        var v = new ulong[16];
        for (var i = 0; i < 8; i++)
        {
            v[i] = ctx.H[i];
            v[i + 8] = IV[i];
        }
        
        v[12] ^= ctx.Counter;
        v[13] ^= ctx.CounterHigh;
        
        if (isFinal)
        {
            v[14] ^= 0xFFFFFFFFFFFFFFFFUL;
        }
        
        // Parse message block into 16 64-bit words
        var m = new ulong[16];
        for (var i = 0; i < 16; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt64LittleEndian(ctx.Buffer.AsSpan(i * 8));
        }
        
        // 12 rounds of mixing
        for (var round = 0; round < 12; round++)
        {
            var s = Sigma[round % 10];
            
            // Column step
            G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            
            // Diagonal step
            G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        
        // Update hash state
        for (var i = 0; i < 8; i++)
        {
            ctx.H[i] ^= v[i] ^ v[i + 8];
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
    
    private sealed class Blake2bContext
    {
        public readonly ulong[] H = new ulong[8];
        public readonly byte[] Buffer = new byte[BlockSize];
        public int BufferLength;
        public ulong Counter;
        public ulong CounterHigh;
        public int HashSize;
        public int KeyLength;
    }
}