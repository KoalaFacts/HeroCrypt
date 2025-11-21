using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// AES-CCM (Counter with CBC-MAC) implementation
/// RFC 3610 compliant AEAD cipher
/// Widely used in IoT protocols (Bluetooth LE, Zigbee, Thread, 802.15.4)
/// </summary>
internal static class AesCcmCore
{
    /// <summary>
    /// Supported key sizes in bytes
    /// </summary>
    public static readonly int[] SupportedKeySizes = [16, 24, 32]; // AES-128, AES-192, AES-256

    /// <summary>
    /// Minimum nonce size in bytes (RFC 3610: 7-13 bytes)
    /// </summary>
    public const int MIN_NONCE_SIZE = 7;

    /// <summary>
    /// Maximum nonce size in bytes (RFC 3610: 7-13 bytes)
    /// </summary>
    public const int MAX_NONCE_SIZE = 13;

    /// <summary>
    /// Default nonce size in bytes (commonly used in IoT)
    /// </summary>
    public const int DEFAULT_NONCE_SIZE = 13;

    /// <summary>
    /// Minimum tag size in bytes (RFC 3610: 4, 6, 8, 10, 12, 14, 16)
    /// </summary>
    public const int MIN_TAG_SIZE = 4;

    /// <summary>
    /// Maximum tag size in bytes (RFC 3610: 4, 6, 8, 10, 12, 14, 16)
    /// </summary>
    public const int MAX_TAG_SIZE = 16;

    /// <summary>
    /// Default tag size in bytes (most common)
    /// </summary>
    public const int DEFAULT_TAG_SIZE = 16;

    /// <summary>
    /// AES block size in bytes
    /// </summary>
    private const int BLOCK_SIZE = 16;

    /// <summary>
    /// Encrypts plaintext using AES-CCM
    /// </summary>
    /// <param name="ciphertext">Output buffer for ciphertext + tag</param>
    /// <param name="plaintext">Input plaintext</param>
    /// <param name="key">AES key (16, 24, or 32 bytes)</param>
    /// <param name="nonce">Nonce (7-13 bytes, typically 13)</param>
    /// <param name="associatedData">Additional authenticated data (can be empty)</param>
    /// <param name="tagSize">Authentication tag size in bytes (4-16, even numbers)</param>
    /// <returns>Total bytes written (plaintext.Length + tagSize)</returns>
    public static int Encrypt(
        Span<byte> ciphertext,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        int tagSize = DEFAULT_TAG_SIZE)
    {
        ValidateParameters(key, nonce, tagSize, plaintext.Length);

        if (ciphertext.Length < plaintext.Length + tagSize)
        {
            throw new ArgumentException("Ciphertext buffer too small", nameof(ciphertext));
        }

        // Create key array once and clear it in finally block (avoid memory leak)
        var keyArray = key.ToArray();

        try
        {
            using var aes = Aes.Create();
            aes.Key = keyArray;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();

            // Split output: ciphertext | tag
            var ciphertextOnly = ciphertext[..plaintext.Length];
            var tag = ciphertext.Slice(plaintext.Length, tagSize);

            // Compute authentication tag using CBC-MAC
            Span<byte> fullTag = stackalloc byte[BLOCK_SIZE];
            ComputeTag(fullTag, plaintext, associatedData, nonce, encryptor, tagSize);

            // Encrypt plaintext using CTR mode and encrypt tag
            EncryptCtr(ciphertextOnly, tag, plaintext, fullTag[..tagSize], nonce, encryptor);

            // Clear sensitive data
            SecureMemoryOperations.SecureClear(fullTag);

            return plaintext.Length + tagSize;
        }
        finally
        {
            Array.Clear(keyArray, 0, keyArray.Length);
        }
    }

    /// <summary>
    /// Decrypts ciphertext using AES-CCM
    /// </summary>
    /// <param name="plaintext">Output buffer for plaintext</param>
    /// <param name="ciphertext">Input ciphertext + tag</param>
    /// <param name="key">AES key (16, 24, or 32 bytes)</param>
    /// <param name="nonce">Nonce (7-13 bytes, typically 13)</param>
    /// <param name="associatedData">Additional authenticated data (can be empty)</param>
    /// <param name="tagSize">Authentication tag size in bytes (4-16, even numbers)</param>
    /// <returns>Plaintext length on success, -1 on authentication failure</returns>
    public static int Decrypt(
        Span<byte> plaintext,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        int tagSize = DEFAULT_TAG_SIZE)
    {
        if (ciphertext.Length < tagSize)
        {
            throw new ArgumentException("Ciphertext too short", nameof(ciphertext));
        }

        var plaintextLength = ciphertext.Length - tagSize;
        ValidateParameters(key, nonce, tagSize, plaintextLength);

        if (plaintext.Length < plaintextLength)
        {
            throw new ArgumentException("Plaintext buffer too small", nameof(plaintext));
        }

        // Create key array once and clear it in finally block (avoid memory leak)
        var keyArray = key.ToArray();

        try
        {
            using var aes = Aes.Create();
            aes.Key = keyArray;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();

            // Split input: ciphertext | tag
            var ciphertextOnly = ciphertext[..plaintextLength];
            var receivedTag = ciphertext.Slice(plaintextLength, tagSize);

            // Decrypt ciphertext using CTR mode
            Span<byte> decryptedTag = stackalloc byte[tagSize];
            DecryptCtr(plaintext[..plaintextLength], decryptedTag, ciphertextOnly, receivedTag, nonce, encryptor);

            // Compute expected tag
            Span<byte> expectedTag = stackalloc byte[BLOCK_SIZE];
            ComputeTag(expectedTag, plaintext[..plaintextLength], associatedData, nonce, encryptor, tagSize);

            // Verify tag in constant time
            var tagMatch = SecureMemoryOperations.ConstantTimeEquals(
                decryptedTag,
                expectedTag[..tagSize]);

            // Clear sensitive data
            SecureMemoryOperations.SecureClear(expectedTag);
            SecureMemoryOperations.SecureClear(decryptedTag);

            if (!tagMatch)
            {
                // Clear plaintext on authentication failure
                SecureMemoryOperations.SecureClear(plaintext[..plaintextLength]);
                return -1;
            }

            return plaintextLength;
        }
        finally
        {
            Array.Clear(keyArray, 0, keyArray.Length);
        }
    }

    /// <summary>
    /// Computes the CBC-MAC authentication tag
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ComputeTag(
        Span<byte> tag,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> nonce,
        ICryptoTransform aes,
        int tagSize)
    {
        var L = 15 - nonce.Length; // L parameter (counter size)
        var M = tagSize; // M parameter (tag size)

        // B_0 = flags | nonce | plaintext_length
        Span<byte> block = stackalloc byte[BLOCK_SIZE];
        block.Clear();

        // Flags byte: Reserved(1) | Adata(1) | M'(3) | L'(3)
        // M' = (M - 2) / 2
        // L' = L - 1
        var flags = (byte)((associatedData.Length > 0 ? 0x40 : 0x00) | (((M - 2) / 2) << 3) | (L - 1));
        block[0] = flags;

        // Nonce
        nonce.CopyTo(block.Slice(1, nonce.Length));

        // Plaintext length (big-endian, L bytes)
        WriteLength(block.Slice(BLOCK_SIZE - L, L), plaintext.Length);

        // Initialize CBC-MAC with B_0
        Span<byte> mac = stackalloc byte[BLOCK_SIZE];
        var macArray = new byte[BLOCK_SIZE];
        var blockArray = new byte[BLOCK_SIZE];
        block.CopyTo(blockArray);
        aes.TransformBlock(blockArray, 0, BLOCK_SIZE, macArray, 0);
        macArray.CopyTo(mac);

        // Process associated data if present
        if (associatedData.Length > 0)
        {
            // Encode AAD length
            Span<byte> aadBlock = stackalloc byte[BLOCK_SIZE];
            int aadOffset;

            if (associatedData.Length < 0xFF00)
            {
                // Short form: 2 bytes
                aadBlock[0] = (byte)(associatedData.Length >> 8);
                aadBlock[1] = (byte)associatedData.Length;
                aadOffset = 2;
            }
            else
            {
                // Long form: 6 bytes (0xFFFE followed by 4-byte length)
                aadBlock[0] = 0xFF;
                aadBlock[1] = 0xFE;
                aadBlock[2] = (byte)(associatedData.Length >> 24);
                aadBlock[3] = (byte)(associatedData.Length >> 16);
                aadBlock[4] = (byte)(associatedData.Length >> 8);
                aadBlock[5] = (byte)associatedData.Length;
                aadOffset = 6;
            }

            // Copy AAD data and process blocks
            var aadRemaining = associatedData;
            var firstBlockSpace = BLOCK_SIZE - aadOffset;

            if (aadRemaining.Length <= firstBlockSpace)
            {
                // AAD fits in first block
                aadRemaining.CopyTo(aadBlock[aadOffset..]);
                XorBlock(mac, aadBlock);
                mac.CopyTo(macArray);
                aes.TransformBlock(macArray, 0, BLOCK_SIZE, macArray, 0);
                macArray.CopyTo(mac);
            }
            else
            {
                // First block
                aadRemaining[..firstBlockSpace].CopyTo(aadBlock[aadOffset..]);
                XorBlock(mac, aadBlock);
                mac.CopyTo(macArray);
                aes.TransformBlock(macArray, 0, BLOCK_SIZE, macArray, 0);
                macArray.CopyTo(mac);
                aadRemaining = aadRemaining[firstBlockSpace..];

                // Remaining AAD blocks
                while (aadRemaining.Length > 0)
                {
                    aadBlock.Clear();
                    var copyLen = Math.Min(BLOCK_SIZE, aadRemaining.Length);
                    aadRemaining[..copyLen].CopyTo(aadBlock);
                    XorBlock(mac, aadBlock);
                    mac.CopyTo(macArray);
                    aes.TransformBlock(macArray, 0, BLOCK_SIZE, macArray, 0);
                    macArray.CopyTo(mac);
                    aadRemaining = aadRemaining[copyLen..];
                }
            }
        }

        // Process plaintext blocks
        var remaining = plaintext;
        while (remaining.Length > 0)
        {
            block.Clear();
            var copyLen = Math.Min(BLOCK_SIZE, remaining.Length);
            remaining[..copyLen].CopyTo(block);
            XorBlock(mac, block);
            mac.CopyTo(macArray);
            aes.TransformBlock(macArray, 0, BLOCK_SIZE, macArray, 0);
            macArray.CopyTo(mac);
            remaining = remaining[copyLen..];
        }

        // Final MAC is the tag
        mac.CopyTo(tag);
    }

    /// <summary>
    /// Encrypts plaintext and tag using CTR mode
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncryptCtr(
        Span<byte> ciphertext,
        Span<byte> encryptedTag,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> nonce,
        ICryptoTransform aes)
    {
        var L = 15 - nonce.Length;

        // A_i = flags | nonce | counter
        Span<byte> counter = stackalloc byte[BLOCK_SIZE];
        Span<byte> keystream = stackalloc byte[BLOCK_SIZE];

        // Flags for CTR mode: L' = L - 1
        var flags = (byte)(L - 1);

        // Reusable arrays for AES transform (avoid memory leaks in loops)
        var keystreamArray = new byte[BLOCK_SIZE];
        var counterArray = new byte[BLOCK_SIZE];

        // Encrypt tag with A_0 (counter = 0)
        counter.Clear();
        counter[0] = flags;
        nonce.CopyTo(counter.Slice(1, nonce.Length));
        // Counter bytes already 0
        counter.CopyTo(counterArray);
        aes.TransformBlock(counterArray, 0, BLOCK_SIZE, keystreamArray, 0);
        keystreamArray.CopyTo(keystream);

        for (var i = 0; i < tag.Length; i++)
        {
            encryptedTag[i] = (byte)(tag[i] ^ keystream[i]);
        }

        // Encrypt plaintext with A_1, A_2, ...
        var remaining = plaintext;
        var outputOffset = 0;
        var ctrValue = 1;

        while (remaining.Length > 0)
        {
            // Build counter block
            counter.Clear();
            counter[0] = flags;
            nonce.CopyTo(counter.Slice(1, nonce.Length));
            WriteLength(counter.Slice(BLOCK_SIZE - L, L), ctrValue);

            // Generate keystream
            counter.CopyTo(counterArray);
            aes.TransformBlock(counterArray, 0, BLOCK_SIZE, keystreamArray, 0);
            keystreamArray.CopyTo(keystream);

            // XOR with plaintext
            var blockSize = Math.Min(BLOCK_SIZE, remaining.Length);
            for (var i = 0; i < blockSize; i++)
            {
                ciphertext[outputOffset + i] = (byte)(remaining[i] ^ keystream[i]);
            }

            remaining = remaining[blockSize..];
            outputOffset += blockSize;
            ctrValue++;
        }

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(counter);
        SecureMemoryOperations.SecureClear(keystream);
    }

    /// <summary>
    /// Decrypts ciphertext and tag using CTR mode
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecryptCtr(
        Span<byte> plaintext,
        Span<byte> decryptedTag,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> encryptedTag,
        ReadOnlySpan<byte> nonce,
        ICryptoTransform aes)
    {
        var L = 15 - nonce.Length;

        // A_i = flags | nonce | counter
        Span<byte> counter = stackalloc byte[BLOCK_SIZE];
        Span<byte> keystream = stackalloc byte[BLOCK_SIZE];

        // Flags for CTR mode: L' = L - 1
        var flags = (byte)(L - 1);

        // Reusable arrays for AES transform (avoid memory leaks in loops)
        var keystreamArray = new byte[BLOCK_SIZE];
        var counterArray = new byte[BLOCK_SIZE];

        // Decrypt tag with A_0 (counter = 0)
        counter.Clear();
        counter[0] = flags;
        nonce.CopyTo(counter.Slice(1, nonce.Length));
        counter.CopyTo(counterArray);
        aes.TransformBlock(counterArray, 0, BLOCK_SIZE, keystreamArray, 0);
        keystreamArray.CopyTo(keystream);

        for (var i = 0; i < encryptedTag.Length; i++)
        {
            decryptedTag[i] = (byte)(encryptedTag[i] ^ keystream[i]);
        }

        // Decrypt ciphertext with A_1, A_2, ... (same as encryption)
        var remaining = ciphertext;
        var outputOffset = 0;
        var ctrValue = 1;

        while (remaining.Length > 0)
        {
            // Build counter block
            counter.Clear();
            counter[0] = flags;
            nonce.CopyTo(counter.Slice(1, nonce.Length));
            WriteLength(counter.Slice(BLOCK_SIZE - L, L), ctrValue);

            // Generate keystream
            counter.CopyTo(counterArray);
            aes.TransformBlock(counterArray, 0, BLOCK_SIZE, keystreamArray, 0);
            keystreamArray.CopyTo(keystream);

            // XOR with ciphertext
            var blockSize = Math.Min(BLOCK_SIZE, remaining.Length);
            for (var i = 0; i < blockSize; i++)
            {
                plaintext[outputOffset + i] = (byte)(remaining[i] ^ keystream[i]);
            }

            remaining = remaining[blockSize..];
            outputOffset += blockSize;
            ctrValue++;
        }

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(counter);
        SecureMemoryOperations.SecureClear(keystream);
    }

    /// <summary>
    /// Writes a length value in big-endian format
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteLength(Span<byte> buffer, long value)
    {
        for (var i = buffer.Length - 1; i >= 0; i--)
        {
            buffer[i] = (byte)value;
            value >>= 8;
        }
    }

    /// <summary>
    /// XORs a block into the MAC
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorBlock(Span<byte> mac, ReadOnlySpan<byte> block)
    {
        for (var i = 0; i < BLOCK_SIZE; i++)
        {
            mac[i] ^= block[i];
        }
    }

    /// <summary>
    /// Validates AES-CCM parameters
    /// </summary>
    private static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, int tagSize, int plaintextLength)
    {
        if (!SupportedKeySizes.Contains(key.Length))
        {
            throw new ArgumentException($"Key must be 16, 24, or 32 bytes (AES-128/192/256)", nameof(key));
        }

        if (nonce.Length < MIN_NONCE_SIZE || nonce.Length > MAX_NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {MIN_NONCE_SIZE}-{MAX_NONCE_SIZE} bytes", nameof(nonce));
        }

        if (tagSize < MIN_TAG_SIZE || tagSize > MAX_TAG_SIZE || tagSize % 2 != 0)
        {
            throw new ArgumentException($"Tag size must be an even number between {MIN_TAG_SIZE} and {MAX_TAG_SIZE} bytes", nameof(tagSize));
        }

        var L = 15 - nonce.Length;
        var maxPlaintextLength = (1L << (L * 8)) - 1;

        if (plaintextLength > maxPlaintextLength)
        {
            throw new ArgumentException($"Plaintext too long for nonce size (max {maxPlaintextLength} bytes)", nameof(plaintextLength));
        }
    }

    /// <summary>
    /// Gets the maximum plaintext length for a given nonce size
    /// </summary>
    public static long GetMaxPlaintextLength(int nonceSize)
    {
        if (nonceSize < MIN_NONCE_SIZE || nonceSize > MAX_NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce size must be {MIN_NONCE_SIZE}-{MAX_NONCE_SIZE} bytes");
        }

        var L = 15 - nonceSize;
        return (1L << (L * 8)) - 1;
    }
}
