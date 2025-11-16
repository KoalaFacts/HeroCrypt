using HeroCrypt.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Primitives.Mac;

/// <summary>
/// AES-CMAC (Cipher-based Message Authentication Code) implementation
/// RFC 4493 compliant
/// Required component for AES-SIV (RFC 5297)
/// </summary>
internal static class AesCmacCore
{
    /// <summary>
    /// AES block size in bytes
    /// </summary>
    private const int BlockSize = 16;

    /// <summary>
    /// Supported key sizes in bytes
    /// </summary>
    public static readonly int[] SupportedKeySizes = { 16, 24, 32 }; // AES-128, AES-192, AES-256

    /// <summary>
    /// Computes AES-CMAC tag for given data
    /// </summary>
    /// <param name="tag">Output tag buffer (16 bytes)</param>
    /// <param name="data">Input data</param>
    /// <param name="key">AES key (16, 24, or 32 bytes)</param>
    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        if (tag.Length < BlockSize)
            throw new ArgumentException($"Tag must be at least {BlockSize} bytes", nameof(tag));

        if (!SupportedKeySizes.Contains(key.Length))
            throw new ArgumentException($"Key must be 16, 24, or 32 bytes (AES-128/192/256)", nameof(key));

        // Create key array once and clear it at end (avoid memory leak)
        var keyArray = key.ToArray();

        try
        {
            using var aes = Aes.Create();
            aes.Key = keyArray;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();

            // Generate subkeys K1 and K2
            Span<byte> k1 = stackalloc byte[BlockSize];
            Span<byte> k2 = stackalloc byte[BlockSize];
            GenerateSubkeys(k1, k2, encryptor);

            // Compute CMAC
            ComputeCmac(tag, data, k1, k2, encryptor);

            // Clear sensitive data
            SecureMemoryOperations.SecureClear(k1);
            SecureMemoryOperations.SecureClear(k2);
        }
        finally
        {
            Array.Clear(keyArray, 0, keyArray.Length);
        }
    }

    /// <summary>
    /// Generates subkeys K1 and K2 for CMAC (RFC 4493 Section 2.3)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateSubkeys(Span<byte> k1, Span<byte> k2, ICryptoTransform aes)
    {
        // Step 1: L := AES-128(K, 0^128)
        Span<byte> l = stackalloc byte[BlockSize];
        var zeroArray = new byte[BlockSize];  // All zeros by default
        var lArray = new byte[BlockSize];

        aes.TransformBlock(zeroArray, 0, BlockSize, lArray, 0);
        lArray.CopyTo(l);

        // Step 2: K1 := L << 1 (if MSB(L) = 0) or (L << 1) XOR Rb (if MSB(L) = 1)
        LeftShiftOneBit(k1, l);
        if ((l[0] & 0x80) != 0) // MSB is 1
        {
            k1[BlockSize - 1] ^= 0x87; // Rb constant for 128-bit block
        }

        // Step 3: K2 := K1 << 1 (if MSB(K1) = 0) or (K1 << 1) XOR Rb (if MSB(K1) = 1)
        LeftShiftOneBit(k2, k1);
        if ((k1[0] & 0x80) != 0) // MSB is 1
        {
            k2[BlockSize - 1] ^= 0x87; // Rb constant for 128-bit block
        }

        // Clear L
        SecureMemoryOperations.SecureClear(l);
    }

    /// <summary>
    /// Computes CMAC using the CBC-MAC algorithm with subkeys
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ComputeCmac(Span<byte> tag, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> k1, ReadOnlySpan<byte> k2, ICryptoTransform aes)
    {
        var n = (data.Length + BlockSize - 1) / BlockSize; // Number of blocks (ceiling division)

        if (n == 0)
        {
            n = 1; // Handle empty message
        }

        var lastBlockComplete = (data.Length > 0) && (data.Length % BlockSize == 0);

        // Initialize MAC to zero
        Span<byte> mac = stackalloc byte[BlockSize];
        mac.Clear();

        Span<byte> block = stackalloc byte[BlockSize];
        var macArray = new byte[BlockSize];

        // Process all blocks except the last
        for (var i = 0; i < n - 1; i++)
        {
            var blockStart = i * BlockSize;
            data.Slice(blockStart, BlockSize).CopyTo(block);

            // XOR with previous MAC
            XorBlock(mac, block);

            // Encrypt
            mac.CopyTo(macArray);
            aes.TransformBlock(macArray, 0, BlockSize, macArray, 0);
            macArray.CopyTo(mac);
        }

        // Process last block
        block.Clear();
        var lastBlockStart = (n - 1) * BlockSize;
        var lastBlockLength = data.Length - lastBlockStart;

        if (lastBlockLength > 0)
        {
            data.Slice(lastBlockStart, lastBlockLength).CopyTo(block);
        }

        if (lastBlockComplete)
        {
            // Last block is complete: M_last := M_n XOR K1
            XorBlock(block, k1);
        }
        else
        {
            // Last block is incomplete: M_last := padding(M_n) XOR K2
            // Padding: append single '1' bit followed by zeros
            if (lastBlockLength < BlockSize)
            {
                block[lastBlockLength] = 0x80; // Padding: 10000000
            }
            XorBlock(block, k2);
        }

        // Final XOR and encryption
        XorBlock(mac, block);
        mac.CopyTo(macArray);
        aes.TransformBlock(macArray, 0, BlockSize, macArray, 0);
        macArray.CopyTo(mac);

        // Output tag
        mac.CopyTo(tag);
    }

    /// <summary>
    /// Left shift by one bit (big-endian)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void LeftShiftOneBit(Span<byte> output, ReadOnlySpan<byte> input)
    {
        byte overflow = 0;

        for (var i = BlockSize - 1; i >= 0; i--)
        {
            output[i] = (byte)((input[i] << 1) | overflow);
            overflow = (byte)((input[i] & 0x80) >> 7);
        }
    }

    /// <summary>
    /// XORs two blocks
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorBlock(Span<byte> a, ReadOnlySpan<byte> b)
    {
        for (var i = 0; i < BlockSize; i++)
        {
            a[i] ^= b[i];
        }
    }

    /// <summary>
    /// Verifies a CMAC tag in constant time
    /// </summary>
    /// <param name="tag">Expected tag</param>
    /// <param name="data">Data that was authenticated</param>
    /// <param name="key">AES key</param>
    /// <returns>True if tag is valid</returns>
    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        if (tag.Length != BlockSize)
            throw new ArgumentException($"Tag must be {BlockSize} bytes", nameof(tag));

        Span<byte> computedTag = stackalloc byte[BlockSize];
        ComputeTag(computedTag, data, key);

        var result = SecureMemoryOperations.ConstantTimeEquals(tag, computedTag);

        // Clear computed tag
        SecureMemoryOperations.SecureClear(computedTag);

        return result;
    }
}
