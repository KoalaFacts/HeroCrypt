using System;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Scrypt;

/// <summary>
/// Core Scrypt implementation following RFC 7914
/// </summary>
internal static class ScryptCore
{
    /// <summary>
    /// Derives a key using the Scrypt algorithm
    /// </summary>
    /// <param name="password">The password to derive from</param>
    /// <param name="salt">The salt value</param>
    /// <param name="n">CPU/memory cost parameter (must be power of 2)</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="keyLength">Length of the derived key in bytes</param>
    /// <returns>The derived key</returns>
    public static byte[] DeriveKey(byte[] password, byte[] salt, int n, int r, int p, int keyLength)
    {
        // Allow empty password and salt for RFC test vectors
        if (password == null) password = Array.Empty<byte>();
        if (salt == null) salt = Array.Empty<byte>();

        if (n <= 0 || (n & (n - 1)) != 0) throw new ArgumentException("N must be a power of 2 greater than 0");
        if (r <= 0) throw new ArgumentException("r must be greater than 0");
        if (p <= 0) throw new ArgumentException("p must be greater than 0");
        if (keyLength <= 0) throw new ArgumentException("keyLength must be greater than 0");

        // Step 1: Generate initial hash using PBKDF2-HMAC-SHA256
        var blockSize = 128 * r;
        var b = new byte[p * blockSize];

#if NETSTANDARD2_0
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1))
        {
            b = pbkdf2.GetBytes(p * blockSize);
        }
#else
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1, HashAlgorithmName.SHA256))
        {
            b = pbkdf2.GetBytes(p * blockSize);
        }
#endif

        // Step 2: Apply Scrypt mixing function to each block
        for (var i = 0; i < p; i++)
        {
            var blockOffset = i * blockSize;
            var block = new Span<byte>(b, blockOffset, blockSize);
            ROMix(block, n, r);
        }

        // Step 3: Final PBKDF2 to produce output
#if NETSTANDARD2_0
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, b, 1))
        {
            return pbkdf2.GetBytes(keyLength);
        }
#else
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, b, 1, HashAlgorithmName.SHA256))
        {
            return pbkdf2.GetBytes(keyLength);
        }
#endif
    }

    private static void ROMix(Span<byte> block, int n, int r)
    {
        var blockSize = 128 * r;
        var v = new byte[n * blockSize];
        var x = new byte[blockSize];
        var y = new byte[blockSize];

        // Step 1: Fill V array
        block.CopyTo(x);
        for (var i = 0; i < n; i++)
        {
            x.CopyTo(v.AsSpan(i * blockSize, blockSize));
            BlockMix(x, y, r);
            y.AsSpan().CopyTo(x.AsSpan());
        }

        // Step 2: Second loop with random access
        for (var i = 0; i < n; i++)
        {
            var j = Integerify(x, r) & (n - 1);
            Xor(x, v.AsSpan(j * blockSize, blockSize));
            BlockMix(x, y, r);
            y.AsSpan().CopyTo(x.AsSpan());
        }

        x.CopyTo(block);
    }

    private static void BlockMix(Span<byte> input, Span<byte> output, int r)
    {
        var x = new byte[64];
        var temp = new byte[64];

        // X = B[2r-1]
        input.Slice((2 * r - 1) * 64, 64).CopyTo(x);

        // Process each 64-byte block
        for (var i = 0; i < 2 * r; i++)
        {
            // X = Salsa(X XOR B[i])
            Xor(x, input.Slice(i * 64, 64));
            Salsa20_8(x, temp);
            temp.AsSpan().CopyTo(x.AsSpan());

            // Store result according to RFC pattern
            if (i % 2 == 0)
            {
                x.CopyTo(output.Slice((i / 2) * 64, 64));
            }
            else
            {
                x.CopyTo(output.Slice((r + i / 2) * 64, 64));
            }
        }
    }

    private static void Salsa20_8(Span<byte> input, Span<byte> output)
    {
        Span<uint> x = stackalloc uint[16];

        // Convert bytes to words (little-endian)
        for (var i = 0; i < 16; i++)
        {
            var offset = i * 4;
            x[i] = (uint)(input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16) | (input[offset + 3] << 24));
        }

        // Save original for addition later
        Span<uint> original = stackalloc uint[16];
        x.CopyTo(original);

        // 8 rounds (4 double rounds)
        for (var i = 0; i < 4; i++)
        {
            // Column rounds
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 5, 9, 13, 1);
            QuarterRound(x, 10, 14, 2, 6);
            QuarterRound(x, 15, 3, 7, 11);

            // Row rounds
            QuarterRound(x, 0, 1, 2, 3);
            QuarterRound(x, 5, 6, 7, 4);
            QuarterRound(x, 10, 11, 8, 9);
            QuarterRound(x, 15, 12, 13, 14);
        }

        // Add original
        for (var i = 0; i < 16; i++)
        {
            x[i] += original[i];
        }

        // Convert words back to bytes (little-endian)
        for (var i = 0; i < 16; i++)
        {
            var offset = i * 4;
            var value = x[i];
            output[offset] = (byte)value;
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);
        }
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[b] ^= RotateLeft(x[a] + x[d], 7);
        x[c] ^= RotateLeft(x[b] + x[a], 9);
        x[d] ^= RotateLeft(x[c] + x[b], 13);
        x[a] ^= RotateLeft(x[d] + x[c], 18);
    }

    private static uint RotateLeft(uint value, int shift)
    {
        return (value << shift) | (value >> (32 - shift));
    }

    private static int Integerify(Span<byte> block, int r)
    {
        var offset = (2 * r - 1) * 64;
        return (int)(block[offset] | (block[offset + 1] << 8) | (block[offset + 2] << 16) | (block[offset + 3] << 24));
    }

    private static void Xor(Span<byte> a, ReadOnlySpan<byte> b)
    {
        for (var i = 0; i < a.Length; i++)
        {
            a[i] ^= b[i];
        }
    }
}