using HeroCrypt.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Symmetric.AesOcb;

/// <summary>
/// AES-OCB (Offset Codebook Mode) implementation
/// RFC 7253 compliant Authenticated Encryption with Associated Data (AEAD)
/// Provides high-performance authenticated encryption with parallelizable encryption
///
/// NOTE: OCB is patented. While patents are royalty-free for open-source software,
/// commercial use may require licensing. See RFC 7253 Section 1.5 for details.
/// </summary>
internal static class AesOcbCore
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
    /// Supported nonce sizes in bytes (1-15 bytes per RFC 7253)
    /// </summary>
    public const int MinNonceSize = 1;
    public const int MaxNonceSize = 15;

    /// <summary>
    /// Tag size in bytes (authenticator)
    /// </summary>
    public const int TagSize = 16;

    /// <summary>
    /// Encrypts plaintext using AES-OCB
    /// </summary>
    /// <param name="ciphertext">Output buffer for ciphertext + tag</param>
    /// <param name="plaintext">Input plaintext</param>
    /// <param name="key">AES key (16, 24, or 32 bytes)</param>
    /// <param name="nonce">Nonce (1-15 bytes, 12 bytes recommended)</param>
    /// <param name="associatedData">Associated data (can be empty)</param>
    /// <returns>Total bytes written (plaintext.Length + TagSize)</returns>
    public static int Encrypt(
        Span<byte> ciphertext,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData)
    {
        ValidateParameters(key, nonce, ciphertext.Length, plaintext.Length);

        if (ciphertext.Length < plaintext.Length + TagSize)
            throw new ArgumentException("Ciphertext buffer too small", nameof(ciphertext));

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();

        // Generate OCB state
        Span<byte> l_star = stackalloc byte[BlockSize];
        Span<byte> l_dollar = stackalloc byte[BlockSize];
        Span<byte> offset = stackalloc byte[BlockSize];
        Span<byte> checksum = stackalloc byte[BlockSize];

        try
        {
            // Initialize L_* = ENCIPHER(K, zeros(128))
            Span<byte> zeros = stackalloc byte[BlockSize];
            zeros.Clear();
            EncryptBlock(encryptor, l_star, zeros);

            // Compute L_$ = double(L_*)
            Double(l_dollar, l_star);

            // Initialize offset from nonce
            InitializeOffset(encryptor, offset, nonce, l_dollar);

            // Process plaintext blocks
            var fullBlocks = plaintext.Length / BlockSize;
            var ciphertextOnly = ciphertext.Slice(0, plaintext.Length);

            Span<byte> offsetXor = stackalloc byte[BlockSize];
            Span<byte> tempBlock = stackalloc byte[BlockSize];

            for (var i = 0; i < fullBlocks; i++)
            {
                var plaintextBlock = plaintext.Slice(i * BlockSize, BlockSize);
                var ciphertextBlock = ciphertextOnly.Slice(i * BlockSize, BlockSize);

                // Offset = Offset xor L_i
                var l_i = GetL(encryptor, l_star, i + 1);
                XorBlock(offset, offset, l_i);

                // Checksum = Checksum xor Plaintext_i
                XorBlock(checksum, checksum, plaintextBlock);

                // C_i = Offset xor ENCIPHER(K, Plaintext_i xor Offset)
                XorBlock(tempBlock, plaintextBlock, offset);
                EncryptBlock(encryptor, offsetXor, tempBlock);
                XorBlock(ciphertextBlock, offsetXor, offset);

                SecureMemoryOperations.SecureClear(l_i);
            }

            // Process final partial block if any
            var remaining = plaintext.Length - (fullBlocks * BlockSize);
            if (remaining > 0)
            {
                var plaintextFinal = plaintext.Slice(fullBlocks * BlockSize, remaining);
                var ciphertextFinal = ciphertextOnly.Slice(fullBlocks * BlockSize, remaining);

                // Offset = Offset xor L_*
                XorBlock(offset, offset, l_star);

                // Pad = ENCIPHER(K, Offset)
                Span<byte> pad = stackalloc byte[BlockSize];
                EncryptBlock(encryptor, pad, offset);

                // C_* = Plaintext_* xor Pad[1..bitlen(Plaintext_*)]
                for (var i = 0; i < remaining; i++)
                {
                    ciphertextFinal[i] = (byte)(plaintextFinal[i] ^ pad[i]);
                    checksum[i] ^= plaintextFinal[i];
                }
                checksum[remaining] ^= 0x80; // Padding

                SecureMemoryOperations.SecureClear(pad);
            }

            // Compute authentication tag
            Span<byte> tag = ciphertext.Slice(plaintext.Length, TagSize);
            ComputeTag(encryptor, tag, offset, checksum, l_dollar, associatedData);

            return plaintext.Length + TagSize;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(l_star);
            SecureMemoryOperations.SecureClear(l_dollar);
            SecureMemoryOperations.SecureClear(offset);
            SecureMemoryOperations.SecureClear(checksum);
            SecureMemoryOperations.SecureClear(offsetXor);
            SecureMemoryOperations.SecureClear(tempBlock);
        }
    }

    /// <summary>
    /// Decrypts ciphertext using AES-OCB
    /// </summary>
    /// <param name="plaintext">Output buffer for plaintext</param>
    /// <param name="ciphertext">Input ciphertext + tag</param>
    /// <param name="key">AES key (16, 24, or 32 bytes)</param>
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
        if (ciphertext.Length < TagSize)
            throw new ArgumentException("Ciphertext too short", nameof(ciphertext));

        var plaintextLength = ciphertext.Length - TagSize;
        ValidateParameters(key, nonce, ciphertext.Length, plaintextLength);

        if (plaintext.Length < plaintextLength)
            throw new ArgumentException("Plaintext buffer too small", nameof(plaintext));

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();

        // Generate OCB state
        Span<byte> l_star = stackalloc byte[BlockSize];
        Span<byte> l_dollar = stackalloc byte[BlockSize];
        Span<byte> offset = stackalloc byte[BlockSize];
        Span<byte> checksum = stackalloc byte[BlockSize];

        try
        {
            // Initialize L_* = ENCIPHER(K, zeros(128))
            Span<byte> zeros = stackalloc byte[BlockSize];
            zeros.Clear();
            EncryptBlock(encryptor, l_star, zeros);

            // Compute L_$ = double(L_*)
            Double(l_dollar, l_star);

            // Initialize offset from nonce
            InitializeOffset(encryptor, offset, nonce, l_dollar);

            // Process ciphertext blocks
            var ciphertextOnly = ciphertext.Slice(0, plaintextLength);
            var fullBlocks = plaintextLength / BlockSize;

            Span<byte> offsetXor = stackalloc byte[BlockSize];
            Span<byte> tempBlock = stackalloc byte[BlockSize];

            for (var i = 0; i < fullBlocks; i++)
            {
                var ciphertextBlock = ciphertextOnly.Slice(i * BlockSize, BlockSize);
                var plaintextBlock = plaintext.Slice(i * BlockSize, BlockSize);

                // Offset = Offset xor L_i
                var l_i = GetL(encryptor, l_star, i + 1);
                XorBlock(offset, offset, l_i);

                // P_i = Offset xor DECIPHER(K, C_i xor Offset)
                XorBlock(tempBlock, ciphertextBlock, offset);
                EncryptBlock(encryptor, offsetXor, tempBlock);
                XorBlock(plaintextBlock, offsetXor, offset);

                // Checksum = Checksum xor Plaintext_i
                XorBlock(checksum, checksum, plaintextBlock);

                SecureMemoryOperations.SecureClear(l_i);
            }

            // Process final partial block if any
            var remaining = plaintextLength - (fullBlocks * BlockSize);
            if (remaining > 0)
            {
                var ciphertextFinal = ciphertextOnly.Slice(fullBlocks * BlockSize, remaining);
                var plaintextFinal = plaintext.Slice(fullBlocks * BlockSize, remaining);

                // Offset = Offset xor L_*
                XorBlock(offset, offset, l_star);

                // Pad = ENCIPHER(K, Offset)
                Span<byte> pad = stackalloc byte[BlockSize];
                EncryptBlock(encryptor, pad, offset);

                // P_* = C_* xor Pad[1..bitlen(C_*)]
                for (var i = 0; i < remaining; i++)
                {
                    plaintextFinal[i] = (byte)(ciphertextFinal[i] ^ pad[i]);
                    checksum[i] ^= plaintextFinal[i];
                }
                checksum[remaining] ^= 0x80; // Padding

                SecureMemoryOperations.SecureClear(pad);
            }

            // Verify authentication tag
            Span<byte> expectedTag = stackalloc byte[TagSize];
            ComputeTag(encryptor, expectedTag, offset, checksum, l_dollar, associatedData);

            var receivedTag = ciphertext.Slice(plaintextLength, TagSize);
            if (!SecureMemoryOperations.ConstantTimeEquals(expectedTag, receivedTag))
            {
                // Clear plaintext on authentication failure
                SecureMemoryOperations.SecureClear(plaintext.Slice(0, plaintextLength));
                SecureMemoryOperations.SecureClear(expectedTag);
                return -1;
            }

            SecureMemoryOperations.SecureClear(expectedTag);
            return plaintextLength;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(l_star);
            SecureMemoryOperations.SecureClear(l_dollar);
            SecureMemoryOperations.SecureClear(offset);
            SecureMemoryOperations.SecureClear(checksum);
            SecureMemoryOperations.SecureClear(offsetXor);
            SecureMemoryOperations.SecureClear(tempBlock);
        }
    }

    /// <summary>
    /// Initializes the offset from nonce per RFC 7253
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitializeOffset(ICryptoTransform encryptor, Span<byte> offset, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> l_dollar)
    {
        // Nonce = num2str(TAGLEN mod 128, 7) || zeros(120 - bitlen(N)) || 1 || N
        Span<byte> nonceBlock = stackalloc byte[BlockSize];
        nonceBlock.Clear();

        // First byte: TAGLEN mod 128 (in bits) = 128 mod 128 = 0, shifted
        var tagBits = (TagSize * 8) % 128;
        nonceBlock[0] = (byte)((tagBits << 1) | 0); // High bit reserved

        // Last bytes: nonce
        var nonceStart = BlockSize - nonce.Length;
        nonceBlock[nonceStart - 1] |= 0x01; // Set separator bit
        nonce.CopyTo(nonceBlock.Slice(nonceStart));

        // bottom = str2num(Nonce) mod 64
        var bottom = nonceBlock[BlockSize - 1] & 0x3F;

        // Nonce with bottom bits cleared
        nonceBlock[BlockSize - 1] &= 0xC0;

        // Ktop = ENCIPHER(K, Nonce with bottom bits cleared)
        Span<byte> ktop = stackalloc byte[BlockSize];
        EncryptBlock(encryptor, ktop, nonceBlock);

        // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
        Span<byte> stretch = stackalloc byte[24];
        ktop.CopyTo(stretch.Slice(0, BlockSize));
        for (var i = 0; i < 8; i++)
        {
            stretch[BlockSize + i] = (byte)(ktop[i] ^ ktop[i + 1]);
        }

        // Offset = Stretch[1 + bottom .. 128 + bottom]
        var bitOffset = bottom;
        var byteOffset = bitOffset / 8;
        var bitShift = bitOffset % 8;

        for (var i = 0; i < BlockSize; i++)
        {
            offset[i] = (byte)((stretch[byteOffset + i] << bitShift) | (stretch[byteOffset + i + 1] >> (8 - bitShift)));
        }

        // Offset = Offset xor L_$
        XorBlock(offset, offset, l_dollar);

        SecureMemoryOperations.SecureClear(nonceBlock);
        SecureMemoryOperations.SecureClear(ktop);
        SecureMemoryOperations.SecureClear(stretch);
    }

    /// <summary>
    /// Computes the authentication tag per RFC 7253
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ComputeTag(ICryptoTransform encryptor, Span<byte> tag, ReadOnlySpan<byte> offset,
        ReadOnlySpan<byte> checksum, ReadOnlySpan<byte> l_dollar, ReadOnlySpan<byte> associatedData)
    {
        // Process associated data
        Span<byte> auth = stackalloc byte[BlockSize];
        ProcessAssociatedData(encryptor, auth, associatedData, l_dollar);

        // Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor Auth
        Span<byte> temp = stackalloc byte[BlockSize];
        XorBlock(temp, checksum, offset);
        XorBlock(temp, temp, l_dollar);

        EncryptBlock(encryptor, tag, temp);
        XorBlock(tag, tag, auth);

        SecureMemoryOperations.SecureClear(auth);
        SecureMemoryOperations.SecureClear(temp);
    }

    /// <summary>
    /// Process associated data for authentication
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ProcessAssociatedData(ICryptoTransform encryptor, Span<byte> auth, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> l_dollar)
    {
        if (associatedData.IsEmpty)
        {
            auth.Clear();
            return;
        }

        Span<byte> offset = stackalloc byte[BlockSize];
        Span<byte> sum = stackalloc byte[BlockSize];
        Span<byte> l_star = stackalloc byte[BlockSize];

        try
        {
            // Compute L_* for associated data
            Span<byte> zeros = stackalloc byte[BlockSize];
            zeros.Clear();
            EncryptBlock(encryptor, l_star, zeros);

            var fullBlocks = associatedData.Length / BlockSize;
            Span<byte> tempBlock = stackalloc byte[BlockSize];

            for (var i = 0; i < fullBlocks; i++)
            {
                var adBlock = associatedData.Slice(i * BlockSize, BlockSize);

                // Offset = Offset xor L_i
                var l_i = GetL(encryptor, l_star, i + 1);
                XorBlock(offset, offset, l_i);

                // Sum = Sum xor ENCIPHER(K, A_i xor Offset)
                XorBlock(tempBlock, adBlock, offset);
                Span<byte> encrypted = stackalloc byte[BlockSize];
                EncryptBlock(encryptor, encrypted, tempBlock);
                XorBlock(sum, sum, encrypted);

                SecureMemoryOperations.SecureClear(l_i);
                SecureMemoryOperations.SecureClear(encrypted);
            }

            // Process final partial block if any
            var remaining = associatedData.Length - (fullBlocks * BlockSize);
            if (remaining > 0)
            {
                var adFinal = associatedData.Slice(fullBlocks * BlockSize, remaining);

                // Offset = Offset xor L_*
                XorBlock(offset, offset, l_star);

                // CipherInput = (A_* || 1 || zeros(127 - bitlen(A_*))) xor Offset
                tempBlock.Clear();
                adFinal.CopyTo(tempBlock);
                tempBlock[remaining] = 0x80; // Padding
                XorBlock(tempBlock, tempBlock, offset);

                Span<byte> encrypted = stackalloc byte[BlockSize];
                EncryptBlock(encryptor, encrypted, tempBlock);
                XorBlock(sum, sum, encrypted);

                SecureMemoryOperations.SecureClear(encrypted);
            }

            sum.CopyTo(auth);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(offset);
            SecureMemoryOperations.SecureClear(sum);
            SecureMemoryOperations.SecureClear(l_star);
            SecureMemoryOperations.SecureClear(tempBlock);
        }
    }

    /// <summary>
    /// Gets L_i value per RFC 7253
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Span<byte> GetL(ICryptoTransform encryptor, ReadOnlySpan<byte> l_star, int i)
    {
        // ntz(i) = number of trailing zeros in binary representation of i
        var ntz = 0;
        var temp = i;
        while ((temp & 1) == 0)
        {
            ntz++;
            temp >>= 1;
        }

        // L_i = double^ntz(L_*)
        var l_i = new byte[BlockSize];
        l_star.CopyTo(l_i);

        for (var j = 0; j < ntz; j++)
        {
            Double(l_i, l_i);
        }

        return l_i;
    }

    /// <summary>
    /// Doubles a block in GF(2^128) per RFC 7253
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Double(Span<byte> output, ReadOnlySpan<byte> input)
    {
        var carry = 0;
        for (var i = BlockSize - 1; i >= 0; i--)
        {
            var newCarry = (input[i] & 0x80) >> 7;
            output[i] = (byte)((input[i] << 1) | carry);
            carry = newCarry;
        }

        // If the first bit was 1, XOR with 0x87 (reduction polynomial for GF(2^128))
        if (carry != 0)
        {
            output[BlockSize - 1] ^= 0x87;
        }
    }

    /// <summary>
    /// XORs two blocks
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorBlock(Span<byte> output, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for (var i = 0; i < BlockSize; i++)
        {
            output[i] = (byte)(a[i] ^ b[i]);
        }
    }

    /// <summary>
    /// Encrypts a single block using AES-ECB
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncryptBlock(ICryptoTransform encryptor, Span<byte> output, ReadOnlySpan<byte> input)
    {
        var inputArray = input.ToArray();
        var outputArray = new byte[BlockSize];
        encryptor.TransformBlock(inputArray, 0, BlockSize, outputArray, 0);
        outputArray.CopyTo(output);
        Array.Clear(inputArray, 0, inputArray.Length);
        Array.Clear(outputArray, 0, outputArray.Length);
    }

    /// <summary>
    /// Validates parameters for AES-OCB
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int ciphertextLength, int plaintextLength)
    {
        if (!SupportedKeySizes.Contains(key.Length))
            throw new ArgumentException($"Key must be 16, 24, or 32 bytes, got {key.Length}", nameof(key));
        if (nonce.Length < MinNonceSize || nonce.Length > MaxNonceSize)
            throw new ArgumentException($"Nonce must be between {MinNonceSize} and {MaxNonceSize} bytes", nameof(nonce));
        if (plaintextLength < 0)
            throw new ArgumentException("Plaintext length cannot be negative", nameof(plaintextLength));
    }

    /// <summary>
    /// Gets maximum plaintext length supported
    /// </summary>
    public static long GetMaxPlaintextLength()
    {
        // OCB mode can handle up to 2^36 blocks (theoretical limit)
        return (1L << 36) * BlockSize;
    }
}
