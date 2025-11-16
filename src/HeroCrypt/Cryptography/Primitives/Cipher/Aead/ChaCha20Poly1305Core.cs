using HeroCrypt.Cryptography.Primitives.Cipher.Stream;
using HeroCrypt.Cryptography.Primitives.Mac;
using HeroCrypt.Security;
using System.Runtime.CompilerServices;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// ChaCha20-Poly1305 AEAD implementation according to RFC 8439
/// Provides authenticated encryption with associated data
/// </summary>
internal static class ChaCha20Poly1305Core
{
    /// <summary>
    /// Key size in bytes
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    /// Nonce size in bytes
    /// </summary>
    public const int NonceSize = 12;

    /// <summary>
    /// Authentication tag size in bytes
    /// </summary>
    public const int TagSize = 16;

    /// <summary>
    /// Encrypts plaintext and computes authentication tag
    /// </summary>
    /// <param name="ciphertext">Output buffer for ciphertext (must include space for tag)</param>
    /// <param name="plaintext">Input plaintext</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">12-byte nonce</param>
    /// <param name="associatedData">Optional associated data to authenticate</param>
    /// <returns>Total length including tag</returns>
    public static int Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
        if (ciphertext.Length < plaintext.Length + TagSize)
            throw new ArgumentException("Ciphertext buffer too small", nameof(ciphertext));

        var ciphertextWithoutTag = ciphertext.Slice(0, plaintext.Length);
        var tag = ciphertext.Slice(plaintext.Length, TagSize);

        // Generate Poly1305 key using ChaCha20 with counter=0
        Span<byte> poly1305Key = stackalloc byte[32];
        Span<byte> zeroBlock = stackalloc byte[32];
        ChaCha20Core.Transform(poly1305Key, zeroBlock, key, nonce, 0);

        // Encrypt plaintext using ChaCha20 with counter=1
        ChaCha20Core.Transform(ciphertextWithoutTag, plaintext, key, nonce, 1);

        // Compute authentication tag
        ComputeTag(tag, associatedData, ciphertextWithoutTag, poly1305Key);

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(poly1305Key);
        SecureMemoryOperations.SecureClear(zeroBlock);

        return plaintext.Length + TagSize;
    }

    /// <summary>
    /// Decrypts ciphertext and verifies authentication tag
    /// </summary>
    /// <param name="plaintext">Output buffer for plaintext</param>
    /// <param name="ciphertext">Input ciphertext with tag</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">12-byte nonce</param>
    /// <param name="associatedData">Optional associated data to authenticate</param>
    /// <returns>Plaintext length, or -1 if authentication fails</returns>
    public static int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
        if (ciphertext.Length < TagSize)
            throw new ArgumentException("Ciphertext too short", nameof(ciphertext));

        var ciphertextLength = ciphertext.Length - TagSize;
        if (plaintext.Length < ciphertextLength)
            throw new ArgumentException("Plaintext buffer too small", nameof(plaintext));

        var ciphertextWithoutTag = ciphertext.Slice(0, ciphertextLength);
        var receivedTag = ciphertext.Slice(ciphertextLength, TagSize);

        // Generate Poly1305 key using ChaCha20 with counter=0
        Span<byte> poly1305Key = stackalloc byte[32];
        Span<byte> zeroBlock = stackalloc byte[32];
        ChaCha20Core.Transform(poly1305Key, zeroBlock, key, nonce, 0);

        // Compute expected authentication tag
        Span<byte> expectedTag = stackalloc byte[TagSize];
        ComputeTag(expectedTag, associatedData, ciphertextWithoutTag, poly1305Key);

        // Verify tag in constant time
        var tagValid = SecureMemoryOperations.ConstantTimeEquals(receivedTag, expectedTag);

        // Clear computed tag
        SecureMemoryOperations.SecureClear(expectedTag);

        if (!tagValid)
        {
            // Clear sensitive data and return failure
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);
            return -1;
        }

        // Decrypt ciphertext using ChaCha20 with counter=1
        var plaintextSlice = plaintext.Slice(0, ciphertextLength);
        ChaCha20Core.Transform(plaintextSlice, ciphertextWithoutTag, key, nonce, 1);

        // Clear sensitive data
        SecureMemoryOperations.SecureClear(poly1305Key);
        SecureMemoryOperations.SecureClear(zeroBlock);

        return ciphertextLength;
    }

    /// <summary>
    /// Computes the Poly1305 authentication tag
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> poly1305Key)
    {
        // Calculate lengths
        var aadLength = associatedData.Length;
        var ciphertextLength = ciphertext.Length;

        // Calculate padding
        var aadPadding = (16 - (aadLength % 16)) % 16;
        var ciphertextPadding = (16 - (ciphertextLength % 16)) % 16;

        // Total message length for Poly1305
        var totalLength = aadLength + aadPadding + ciphertextLength + ciphertextPadding + 16;

        // Build message for Poly1305
        Span<byte> message = totalLength <= 1024 ? stackalloc byte[totalLength] : new byte[totalLength];
        var offset = 0;

        // Copy associated data
        if (aadLength > 0)
        {
            associatedData.CopyTo(message.Slice(offset, aadLength));
            offset += aadLength;
        }

        // Add AAD padding
        if (aadPadding > 0)
        {
            message.Slice(offset, aadPadding).Clear();
            offset += aadPadding;
        }

        // Copy ciphertext
        if (ciphertextLength > 0)
        {
            ciphertext.CopyTo(message.Slice(offset, ciphertextLength));
            offset += ciphertextLength;
        }

        // Add ciphertext padding
        if (ciphertextPadding > 0)
        {
            message.Slice(offset, ciphertextPadding).Clear();
            offset += ciphertextPadding;
        }

        // Add lengths in little-endian format
        var lengthBytes = message.Slice(offset, 16);
        WriteUInt64LittleEndian(lengthBytes.Slice(0, 8), (ulong)aadLength);
        WriteUInt64LittleEndian(lengthBytes.Slice(8, 8), (ulong)ciphertextLength);

        // Compute Poly1305 MAC
        Poly1305Core.ComputeMac(tag, message, poly1305Key);

        // Clear message if allocated on heap
        if (totalLength > 1024)
        {
            SecureMemoryOperations.SecureClear(message);
        }
        else
        {
            SecureMemoryOperations.SecureClear(message);
        }
    }

    /// <summary>
    /// Writes a uint64 value in little-endian format
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteUInt64LittleEndian(Span<byte> buffer, ulong value)
    {
        buffer[0] = (byte)value;
        buffer[1] = (byte)(value >> 8);
        buffer[2] = (byte)(value >> 16);
        buffer[3] = (byte)(value >> 24);
        buffer[4] = (byte)(value >> 32);
        buffer[5] = (byte)(value >> 40);
        buffer[6] = (byte)(value >> 48);
        buffer[7] = (byte)(value >> 56);
    }

    /// <summary>
    /// Generates a Poly1305 key using ChaCha20
    /// </summary>
    /// <param name="poly1305Key">Output 32-byte key</param>
    /// <param name="chachaKey">ChaCha20 key</param>
    /// <param name="nonce">ChaCha20 nonce</param>
    public static void GeneratePoly1305Key(Span<byte> poly1305Key, ReadOnlySpan<byte> chachaKey, ReadOnlySpan<byte> nonce)
    {
        if (poly1305Key.Length != 32)
            throw new ArgumentException("Poly1305 key must be 32 bytes", nameof(poly1305Key));

        Span<byte> zeroBlock = stackalloc byte[32];
        ChaCha20Core.Transform(poly1305Key, zeroBlock, chachaKey, nonce, 0);

        // Clear zero block
        SecureMemoryOperations.SecureClear(zeroBlock);
    }

    /// <summary>
    /// Validates key and nonce sizes
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
    }

    /// <summary>
    /// Gets the maximum ciphertext length for a given plaintext length
    /// </summary>
    public static int GetCiphertextLength(int plaintextLength)
    {
        if (plaintextLength < 0)
            throw new ArgumentOutOfRangeException(nameof(plaintextLength));

        return plaintextLength + TagSize;
    }

    /// <summary>
    /// Gets the maximum plaintext length for a given ciphertext length
    /// </summary>
    public static int GetPlaintextLength(int ciphertextLength)
    {
        if (ciphertextLength < TagSize)
            return -1; // Invalid ciphertext

        return ciphertextLength - TagSize;
    }
}