using HeroCrypt.Cryptography.Symmetric.AesCmac;
using HeroCrypt.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Symmetric.AesSiv;

/// <summary>
/// AES-SIV (Synthetic IV) implementation
/// RFC 5297 compliant nonce-misuse resistant AEAD
/// Provides deterministic authenticated encryption
/// </summary>
internal static class AesSivCore
{
    /// <summary>
    /// AES block size in bytes
    /// </summary>
    private const int BlockSize = 16;

    /// <summary>
    /// SIV (Synthetic IV) size in bytes
    /// </summary>
    public const int SivSize = 16;

    /// <summary>
    /// Supported key sizes in bytes (doubled because SIV uses two keys)
    /// </summary>
    public static readonly int[] SupportedKeySizes = { 32, 48, 64 }; // AES-SIV-128, AES-SIV-192, AES-SIV-256

    /// <summary>
    /// Encrypts plaintext using AES-SIV
    /// </summary>
    /// <param name="ciphertext">Output buffer for SIV + ciphertext</param>
    /// <param name="plaintext">Input plaintext</param>
    /// <param name="key">AES-SIV key (32, 48, or 64 bytes for AES-128/192/256)</param>
    /// <param name="nonce">Nonce (can be any length, including empty)</param>
    /// <param name="associatedData">Associated data (can be empty)</param>
    /// <returns>Total bytes written (SivSize + plaintext.Length)</returns>
    public static int Encrypt(
        Span<byte> ciphertext,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData)
    {
        ValidateParameters(key, ciphertext.Length, plaintext.Length);

        if (ciphertext.Length < SivSize + plaintext.Length)
            throw new ArgumentException("Ciphertext buffer too small", nameof(ciphertext));

        // Split key into K1 (MAC key) and K2 (CTR key)
        var keyLength = key.Length / 2;
        var k1 = key.Slice(0, keyLength);
        var k2 = key.Slice(keyLength, keyLength);

        // Compute SIV = S2V(K1, AD, plaintext, nonce)
        Span<byte> siv = stackalloc byte[SivSize];
        S2V(siv, k1, associatedData, plaintext, nonce);

        // Store SIV at beginning of output
        siv.CopyTo(ciphertext);

        // Encrypt plaintext using CTR mode with SIV as IV
        if (plaintext.Length > 0)
        {
            var ciphertextOnly = ciphertext.Slice(SivSize, plaintext.Length);
            EncryptCtr(ciphertextOnly, plaintext, k2, siv);
        }

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(siv);

        return SivSize + plaintext.Length;
    }

    /// <summary>
    /// Decrypts ciphertext using AES-SIV
    /// </summary>
    /// <param name="plaintext">Output buffer for plaintext</param>
    /// <param name="ciphertext">Input SIV + ciphertext</param>
    /// <param name="key">AES-SIV key (32, 48, or 64 bytes)</param>
    /// <param name="nonce">Nonce used during encryption</param>
    /// <param name="associatedData">Associated data used during encryption</param>
    /// <returns>Plaintext length on success, -1 on authentication failure</returns>
    public static int Decrypt(
        Span<byte> plaintext,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData)
    {
        if (ciphertext.Length < SivSize)
            throw new ArgumentException("Ciphertext too short", nameof(ciphertext));

        var plaintextLength = ciphertext.Length - SivSize;
        ValidateParameters(key, ciphertext.Length, plaintextLength);

        if (plaintext.Length < plaintextLength)
            throw new ArgumentException("Plaintext buffer too small", nameof(plaintext));

        // Split key into K1 (MAC key) and K2 (CTR key)
        var keyLength = key.Length / 2;
        var k1 = key.Slice(0, keyLength);
        var k2 = key.Slice(keyLength, keyLength);

        // Extract SIV from ciphertext
        var receivedSiv = ciphertext.Slice(0, SivSize);
        var ciphertextOnly = ciphertext.Slice(SivSize);

        // Decrypt ciphertext using CTR mode
        if (plaintextLength > 0)
        {
            DecryptCtr(plaintext.Slice(0, plaintextLength), ciphertextOnly, k2, receivedSiv);
        }

        // Compute expected SIV = S2V(K1, AD, plaintext, nonce)
        Span<byte> expectedSiv = stackalloc byte[SivSize];
        S2V(expectedSiv, k1, associatedData, plaintext.Slice(0, plaintextLength), nonce);

        // Verify SIV in constant time
        var sivMatch = ConstantTimeOperations.ConstantTimeEquals(receivedSiv, expectedSiv);

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(expectedSiv);

        if (!sivMatch)
        {
            // Clear plaintext on authentication failure
            SecureMemoryOperations.SecureClear(plaintext.Slice(0, plaintextLength));
            return -1;
        }

        return plaintextLength;
    }

    /// <summary>
    /// S2V function (RFC 5297 Section 2.4)
    /// Creates synthetic IV from multiple input strings using AES-CMAC
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void S2V(Span<byte> output, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce)
    {
        // D = AES-CMAC(K, <zero>)
        Span<byte> d = stackalloc byte[BlockSize];
        Span<byte> zero = stackalloc byte[BlockSize];
        zero.Clear();
        AesCmacCore.ComputeTag(d, zero, key);

        // Process associated data if present
        if (associatedData.Length > 0)
        {
            Span<byte> cmac = stackalloc byte[BlockSize];
            AesCmacCore.ComputeTag(cmac, associatedData, key);
            Dbl(d);
            XorBlock(d, cmac);
            SecureMemoryOperations.SecureClear(cmac);
        }

        // Process nonce if present
        if (nonce.Length > 0)
        {
            Span<byte> cmac = stackalloc byte[BlockSize];
            AesCmacCore.ComputeTag(cmac, nonce, key);
            Dbl(d);
            XorBlock(d, cmac);
            SecureMemoryOperations.SecureClear(cmac);
        }

        // Process plaintext (final input)
        Span<byte> t = stackalloc byte[BlockSize];

        if (plaintext.Length >= BlockSize)
        {
            // T = plaintext[0..n-16] || (plaintext[n-16..n] XOR D)
            var xorLen = plaintext.Length - BlockSize;
            var lastBlock = plaintext.Slice(xorLen, BlockSize);

            d.CopyTo(t);
            XorBlock(t, lastBlock);

            // Create combined input
            var combined = new byte[xorLen + BlockSize];
            plaintext.Slice(0, xorLen).CopyTo(combined);
            t.CopyTo(combined.AsSpan(xorLen));

            AesCmacCore.ComputeTag(output, combined, key);
            Array.Clear(combined);
        }
        else
        {
            // T = dbl(D) XOR pad(plaintext)
            Dbl(d);

            // Pad plaintext: plaintext || 10000000...
            t.Clear();
            plaintext.CopyTo(t);
            if (plaintext.Length < BlockSize)
            {
                t[plaintext.Length] = 0x80;
            }

            XorBlock(t, d);
            AesCmacCore.ComputeTag(output, t, key);
        }

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(d);
        SecureMemoryOperations.SecureClear(t);
        SecureMemoryOperations.SecureClear(zero);
    }

    /// <summary>
    /// Encrypts plaintext using AES-CTR mode
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncryptCtr(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();

        // Clear bit 63 and bit 31 of IV for CTR mode (RFC 5297 Section 2.6)
        Span<byte> counter = stackalloc byte[BlockSize];
        iv.CopyTo(counter);
        counter[8] &= 0x7F;  // Clear bit 63
        counter[12] &= 0x7F; // Clear bit 31

        var remaining = plaintext;
        var outputOffset = 0;

        Span<byte> keystream = stackalloc byte[BlockSize];
        var keystreamArray = new byte[BlockSize];

        while (remaining.Length > 0)
        {
            // Generate keystream block
            aes.TransformBlock(counter.ToArray(), 0, BlockSize, keystreamArray, 0);
            keystreamArray.CopyTo(keystream);

            // XOR with plaintext
            var blockSize = Math.Min(BlockSize, remaining.Length);
            for (var i = 0; i < blockSize; i++)
            {
                ciphertext[outputOffset + i] = (byte)(remaining[i] ^ keystream[i]);
            }

            // Increment counter (big-endian)
            IncrementCounter(counter);

            remaining = remaining.Slice(blockSize);
            outputOffset += blockSize;
        }

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(counter);
        SecureMemoryOperations.SecureClear(keystream);
    }

    /// <summary>
    /// Decrypts ciphertext using AES-CTR mode (same as encryption)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecryptCtr(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        // CTR mode decryption is the same as encryption
        EncryptCtr(plaintext, ciphertext, key, iv);
    }

    /// <summary>
    /// Doubles a value in GF(2^128) (dbl operation from RFC 5297)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Dbl(Span<byte> value)
    {
        byte overflow = 0;

        for (var i = BlockSize - 1; i >= 0; i--)
        {
            var newOverflow = (byte)((value[i] & 0x80) >> 7);
            value[i] = (byte)((value[i] << 1) | overflow);
            overflow = newOverflow;
        }

        // If original MSB was 1, XOR with R_128
        if (overflow != 0)
        {
            value[BlockSize - 1] ^= 0x87;
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
    /// Increments counter in big-endian format
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void IncrementCounter(Span<byte> counter)
    {
        for (var i = BlockSize - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }

    /// <summary>
    /// Validates AES-SIV parameters
    /// </summary>
    private static void ValidateParameters(ReadOnlySpan<byte> key, int ciphertextLength, int plaintextLength)
    {
        if (!SupportedKeySizes.Contains(key.Length))
            throw new ArgumentException($"Key must be 32, 48, or 64 bytes (AES-SIV-128/192/256)", nameof(key));

        if (plaintextLength < 0)
            throw new ArgumentException("Invalid plaintext length", nameof(plaintextLength));
    }
}
