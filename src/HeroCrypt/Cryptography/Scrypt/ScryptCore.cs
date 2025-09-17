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
        // Validate parameters according to RFC 7914
        ValidateParameters(password, salt, n, r, p, keyLength);

        // Step 1: Generate initial hash using PBKDF2-HMAC-SHA256
        var blockSize = 128 * r;
        var b = DeriveInitialHash(password, salt, p * blockSize);

        // Step 2: Apply Scrypt mixing function to each block
        for (var i = 0; i < p; i++)
        {
            var blockOffset = i * blockSize;
            var block = new byte[blockSize];
            Array.Copy(b, blockOffset, block, 0, blockSize);

            var mixed = ScryptMixingFunction(block, n, r);
            Array.Copy(mixed, 0, b, blockOffset, blockSize);
        }

        // Step 3: Final PBKDF2 to produce output
        return DeriveOutput(password, b, keyLength);
    }

    private static void ValidateParameters(byte[] password, byte[] salt, int n, int r, int p, int keyLength)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));
        if (salt == null)
            throw new ArgumentNullException(nameof(salt));
        if (n < 2 || (n & (n - 1)) != 0)
            throw new ArgumentException("N must be a power of 2 greater than 1", nameof(n));
        if (r < 1)
            throw new ArgumentException("R must be positive", nameof(r));
        if (p < 1)
            throw new ArgumentException("P must be positive", nameof(p));
        if (keyLength < 1 || keyLength > int.MaxValue)
            throw new ArgumentException("Key length must be positive", nameof(keyLength));

        // Check for potential overflow conditions
        var maxMemory = (long)128 * r * n;
        if (maxMemory > int.MaxValue)
            throw new ArgumentException("Parameters would require too much memory");

        var maxOperations = (long)32 * r * (n + p);
        if (maxOperations > int.MaxValue)
            throw new ArgumentException("Parameters would require too many operations");
    }

    private static byte[] DeriveInitialHash(byte[] password, byte[] salt, int outputLength)
    {
#if NET5_0_OR_GREATER
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 1, HashAlgorithmName.SHA256, outputLength);
#else
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1);
        return pbkdf2.GetBytes(outputLength);
#endif
    }

    private static byte[] DeriveOutput(byte[] password, byte[] salt, int keyLength)
    {
#if NET5_0_OR_GREATER
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 1, HashAlgorithmName.SHA256, keyLength);
#else
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1);
        return pbkdf2.GetBytes(keyLength);
#endif
    }

    private static byte[] ScryptMixingFunction(byte[] block, int n, int r)
    {
        var blockSize = 128 * r;
        var v = new uint[32 * r * n]; // Working memory
        var x = new uint[32 * r];     // Working block

        // Convert input block to uint32 array (little-endian)
        BytesToUInt32(block, x);

        // Step 1: Fill V array
        Array.Copy(x, 0, v, 0, 32 * r);

        for (var i = 1; i < n; i++)
        {
            ScryptBlockMix(x, r);
            Array.Copy(x, 0, v, i * 32 * r, 32 * r);
        }

        // Step 2: Perform mixing operations
        for (var i = 0; i < n; i++)
        {
            var j = (int)(x[32 * r - 16] & (n - 1));
            for (var k = 0; k < 32 * r; k++)
            {
                x[k] ^= v[j * 32 * r + k];
            }
            ScryptBlockMix(x, r);
        }

        // Convert back to bytes
        var result = new byte[blockSize];
        UInt32ToBytes(x, result);
        return result;
    }

    private static void ScryptBlockMix(uint[] x, int r)
    {
        var y = new uint[32 * r];
        var t = new uint[16];

        // Extract the last 64-byte block
        Array.Copy(x, 32 * r - 16, t, 0, 16);

        // Process each 64-byte block
        for (var i = 0; i < 2 * r; i++)
        {
            // XOR with current block
            var blockOffset = i * 16;
            for (var j = 0; j < 16; j++)
            {
                t[j] ^= x[blockOffset + j];
            }

            // Apply Salsa20/8 core
            Salsa208Core(t);

            // Store result
            var outputOffset = (i % 2) * r + (i / 2);
            Array.Copy(t, 0, y, outputOffset * 16, 16);
        }

        Array.Copy(y, x, 32 * r);
    }

    private static void Salsa208Core(uint[] x)
    {
        var w = new uint[16];
        Array.Copy(x, w, 16);

        for (var i = 0; i < 8; i += 2)
        {
            // Column rounds
            w[4] ^= RotateLeft(w[0] + w[12], 7);
            w[8] ^= RotateLeft(w[4] + w[0], 9);
            w[12] ^= RotateLeft(w[8] + w[4], 13);
            w[0] ^= RotateLeft(w[12] + w[8], 18);

            w[9] ^= RotateLeft(w[5] + w[1], 7);
            w[13] ^= RotateLeft(w[9] + w[5], 9);
            w[1] ^= RotateLeft(w[13] + w[9], 13);
            w[5] ^= RotateLeft(w[1] + w[13], 18);

            w[14] ^= RotateLeft(w[10] + w[6], 7);
            w[2] ^= RotateLeft(w[14] + w[10], 9);
            w[6] ^= RotateLeft(w[2] + w[14], 13);
            w[10] ^= RotateLeft(w[6] + w[2], 18);

            w[3] ^= RotateLeft(w[15] + w[11], 7);
            w[7] ^= RotateLeft(w[3] + w[15], 9);
            w[11] ^= RotateLeft(w[7] + w[3], 13);
            w[15] ^= RotateLeft(w[11] + w[7], 18);

            // Row rounds
            w[1] ^= RotateLeft(w[0] + w[3], 7);
            w[2] ^= RotateLeft(w[1] + w[0], 9);
            w[3] ^= RotateLeft(w[2] + w[1], 13);
            w[0] ^= RotateLeft(w[3] + w[2], 18);

            w[6] ^= RotateLeft(w[5] + w[4], 7);
            w[7] ^= RotateLeft(w[6] + w[5], 9);
            w[4] ^= RotateLeft(w[7] + w[6], 13);
            w[5] ^= RotateLeft(w[4] + w[7], 18);

            w[11] ^= RotateLeft(w[10] + w[9], 7);
            w[8] ^= RotateLeft(w[11] + w[10], 9);
            w[9] ^= RotateLeft(w[8] + w[11], 13);
            w[10] ^= RotateLeft(w[9] + w[8], 18);

            w[12] ^= RotateLeft(w[15] + w[14], 7);
            w[13] ^= RotateLeft(w[12] + w[15], 9);
            w[14] ^= RotateLeft(w[13] + w[12], 13);
            w[15] ^= RotateLeft(w[14] + w[13], 18);
        }

        for (var i = 0; i < 16; i++)
        {
            x[i] += w[i];
        }
    }

    private static uint RotateLeft(uint value, int shift)
    {
        return (value << shift) | (value >> (32 - shift));
    }

    private static void BytesToUInt32(byte[] input, uint[] output)
    {
        for (var i = 0; i < output.Length; i++)
        {
            var byteIndex = i * 4;
            output[i] = (uint)(input[byteIndex] |
                               (input[byteIndex + 1] << 8) |
                               (input[byteIndex + 2] << 16) |
                               (input[byteIndex + 3] << 24));
        }
    }

    private static void UInt32ToBytes(uint[] input, byte[] output)
    {
        for (var i = 0; i < input.Length; i++)
        {
            var byteIndex = i * 4;
            var value = input[i];
            output[byteIndex] = (byte)value;
            output[byteIndex + 1] = (byte)(value >> 8);
            output[byteIndex + 2] = (byte)(value >> 16);
            output[byteIndex + 3] = (byte)(value >> 24);
        }
    }
}