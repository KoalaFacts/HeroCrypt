using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Cryptography.Primitives.Mac;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Aead;

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
    private const int BLOCK_SIZE = 16;

    /// <summary>
    /// SIV (Synthetic IV) size in bytes
    /// </summary>
    public const int SIV_SIZE = 16;

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
    /// <returns>Total bytes written (SIV_SIZE + plaintext.Length)</returns>
    public static int Encrypt(
        Span<byte> ciphertext,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData)
    {
        ValidateParameters(key, ciphertext.Length, plaintext.Length);

        if (ciphertext.Length < SIV_SIZE + plaintext.Length)
        {
            throw new ArgumentException("Ciphertext buffer too small", nameof(ciphertext));
        }

        // Split key into K1 (MAC key) and K2 (CTR key)
        var keyLength = key.Length / 2;
        var k1 = key.Slice(0, keyLength);
        var k2 = key.Slice(keyLength, keyLength);

        // Compute SIV = S2V(K1, AD, plaintext, nonce)
        Span<byte> siv = stackalloc byte[SIV_SIZE];
        S2V(siv, k1, associatedData, plaintext, nonce);

        // Store SIV at beginning of output
        siv.CopyTo(ciphertext);

        // Encrypt plaintext using CTR mode with SIV as IV
        if (plaintext.Length > 0)
        {
            var ciphertextOnly = ciphertext.Slice(SIV_SIZE, plaintext.Length);
            EncryptCtr(ciphertextOnly, plaintext, k2, siv);
        }

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(siv);

        return SIV_SIZE + plaintext.Length;
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
        if (ciphertext.Length < SIV_SIZE)
        {
            throw new ArgumentException("Ciphertext too short", nameof(ciphertext));
        }

        var plaintextLength = ciphertext.Length - SIV_SIZE;
        ValidateParameters(key, ciphertext.Length, plaintextLength);

        if (plaintext.Length < plaintextLength)
        {
            throw new ArgumentException("Plaintext buffer too small", nameof(plaintext));
        }

        // Split key into K1 (MAC key) and K2 (CTR key)
        var keyLength = key.Length / 2;
        var k1 = key.Slice(0, keyLength);
        var k2 = key.Slice(keyLength, keyLength);

        // Extract SIV from ciphertext
        var receivedSiv = ciphertext.Slice(0, SIV_SIZE);
        var ciphertextOnly = ciphertext.Slice(SIV_SIZE);

        // Decrypt ciphertext using CTR mode
        if (plaintextLength > 0)
        {
            DecryptCtr(plaintext.Slice(0, plaintextLength), ciphertextOnly, k2, receivedSiv);
        }

        // Compute expected SIV = S2V(K1, AD, plaintext, nonce)
        Span<byte> expectedSiv = stackalloc byte[SIV_SIZE];
        S2V(expectedSiv, k1, associatedData, plaintext.Slice(0, plaintextLength), nonce);

        // Verify SIV in constant time
        var sivMatch = SecureMemoryOperations.ConstantTimeEquals(receivedSiv, expectedSiv);

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
        Span<byte> d = stackalloc byte[BLOCK_SIZE];
        Span<byte> zero = stackalloc byte[BLOCK_SIZE];
        zero.Clear();
        AesCmacCore.ComputeTag(d, zero, key);

        // Process associated data if present
        if (associatedData.Length > 0)
        {
            Span<byte> cmac = stackalloc byte[BLOCK_SIZE];
            AesCmacCore.ComputeTag(cmac, associatedData, key);
            Dbl(d);
            XorBlock(d, cmac);
            SecureMemoryOperations.SecureClear(cmac);
        }

        // Process nonce if present
        if (nonce.Length > 0)
        {
            Span<byte> cmac = stackalloc byte[BLOCK_SIZE];
            AesCmacCore.ComputeTag(cmac, nonce, key);
            Dbl(d);
            XorBlock(d, cmac);
            SecureMemoryOperations.SecureClear(cmac);
        }

        // Process plaintext (final input)
        Span<byte> t = stackalloc byte[BLOCK_SIZE];

        if (plaintext.Length >= BLOCK_SIZE)
        {
            // T = plaintext[0..n-16] || (plaintext[n-16..n] XOR D)
            var xorLen = plaintext.Length - BLOCK_SIZE;
            var lastBlock = plaintext.Slice(xorLen, BLOCK_SIZE);

            d.CopyTo(t);
            XorBlock(t, lastBlock);

            // Create combined input using ArrayPool to avoid heap allocation
            var combinedLength = xorLen + BLOCK_SIZE;
            var combined = ArrayPool<byte>.Shared.Rent(combinedLength);
            try
            {
                plaintext.Slice(0, xorLen).CopyTo(combined);
                t.CopyTo(combined.AsSpan(xorLen, BLOCK_SIZE));

                AesCmacCore.ComputeTag(output, combined.AsSpan(0, combinedLength), key);
            }
            finally
            {
                Array.Clear(combined, 0, combinedLength);
                ArrayPool<byte>.Shared.Return(combined);
            }
        }
        else
        {
            // T = dbl(D) XOR pad(plaintext)
            Dbl(d);

            // Pad plaintext: plaintext || 10000000...
            t.Clear();
            plaintext.CopyTo(t);
            if (plaintext.Length < BLOCK_SIZE)
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
        // Create key array once and clear it in finally block
        var keyArray = key.ToArray();

        using var aes = Aes.Create();
        aes.Key = keyArray;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();

        // Clear bit 63 and bit 31 of IV for CTR mode (RFC 5297 Section 2.6)
        var counterArray = new byte[BLOCK_SIZE];
        iv.CopyTo(counterArray);
        counterArray[8] &= 0x7F;  // Clear bit 63
        counterArray[12] &= 0x7F; // Clear bit 31

        var remaining = plaintext;
        var outputOffset = 0;

        var keystreamArray = new byte[BLOCK_SIZE];

        try
        {
            while (remaining.Length > 0)
            {
                // Generate keystream block
                encryptor.TransformBlock(counterArray, 0, BLOCK_SIZE, keystreamArray, 0);

                // XOR with plaintext
                var blockSize = Math.Min(BLOCK_SIZE, remaining.Length);
                for (var i = 0; i < blockSize; i++)
                {
                    ciphertext[outputOffset + i] = (byte)(remaining[i] ^ keystreamArray[i]);
                }

                // Increment counter (big-endian)
                IncrementCounter(counterArray);

                remaining = remaining.Slice(blockSize);
                outputOffset += blockSize;
            }
        }
        finally
        {
            // Clear sensitive data
            Array.Clear(keyArray, 0, keyArray.Length);
            Array.Clear(counterArray, 0, counterArray.Length);
            Array.Clear(keystreamArray, 0, keystreamArray.Length);
        }
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

        for (var i = BLOCK_SIZE - 1; i >= 0; i--)
        {
            var newOverflow = (byte)((value[i] & 0x80) >> 7);
            value[i] = (byte)((value[i] << 1) | overflow);
            overflow = newOverflow;
        }

        // If original MSB was 1, XOR with R_128
        if (overflow != 0)
        {
            value[BLOCK_SIZE - 1] ^= 0x87;
        }
    }

    /// <summary>
    /// XORs two blocks
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorBlock(Span<byte> a, ReadOnlySpan<byte> b)
    {
        for (var i = 0; i < BLOCK_SIZE; i++)
        {
            a[i] ^= b[i];
        }
    }

    /// <summary>
    /// Increments counter in big-endian format
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void IncrementCounter(byte[] counter)
    {
        for (var i = BLOCK_SIZE - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Validates AES-SIV parameters
    /// </summary>
    private static void ValidateParameters(ReadOnlySpan<byte> key, int ciphertextLength, int plaintextLength)
    {
        _ = ciphertextLength;

        if (!SupportedKeySizes.Contains(key.Length))
        {
            throw new ArgumentException($"Key must be 32, 48, or 64 bytes (AES-SIV-128/192/256)", nameof(key));
        }

        if (plaintextLength < 0)
        {
            throw new ArgumentException("Invalid plaintext length", nameof(plaintextLength));
        }
    }

    /// <summary>
    /// Validates AES-SIV key and nonce parameters (public for testing)
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        _ = nonce;

        if (!SupportedKeySizes.Contains(key.Length))
        {
            throw new ArgumentException($"Key must be 32, 48, or 64 bytes (AES-SIV-128/192/256)", nameof(key));
        }

        // Nonce can be any length in AES-SIV (it's flexible)
        // No specific validation needed for nonce
    }
}
