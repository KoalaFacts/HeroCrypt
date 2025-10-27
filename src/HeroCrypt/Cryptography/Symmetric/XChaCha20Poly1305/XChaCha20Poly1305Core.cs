using HeroCrypt.Cryptography.Symmetric.ChaCha20;
using HeroCrypt.Cryptography.Symmetric.Poly1305;
using HeroCrypt.Security;
using System.Runtime.CompilerServices;

namespace HeroCrypt.Cryptography.Symmetric.XChaCha20Poly1305;

/// <summary>
/// XChaCha20-Poly1305 AEAD implementation with extended 24-byte nonces
/// Provides the same security as ChaCha20-Poly1305 but with larger nonce space
/// </summary>
internal static class XChaCha20Poly1305Core
{
    /// <summary>
    /// Key size in bytes
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    /// Extended nonce size in bytes
    /// </summary>
    public const int NonceSize = 24;

    /// <summary>
    /// Authentication tag size in bytes
    /// </summary>
    public const int TagSize = 16;

    /// <summary>
    /// HChaCha20 constants
    /// </summary>
    private static readonly uint[] HChaCha20Constants = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    /// <summary>
    /// Encrypts plaintext using XChaCha20-Poly1305
    /// </summary>
    /// <param name="ciphertext">Output buffer (must include space for tag)</param>
    /// <param name="plaintext">Input plaintext</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">24-byte nonce</param>
    /// <param name="associatedData">Optional associated data</param>
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

        // Derive ChaCha20 key and nonce from XChaCha20 parameters
        Span<byte> derivedKey = stackalloc byte[32];
        Span<byte> derivedNonce = stackalloc byte[12];
        DeriveKeyAndNonce(derivedKey, derivedNonce, key, nonce);

        try
        {
            var ciphertextWithoutTag = ciphertext.Slice(0, plaintext.Length);
            var tag = ciphertext.Slice(plaintext.Length, TagSize);

            // Generate Poly1305 key using the derived ChaCha20 key
            Span<byte> poly1305Key = stackalloc byte[32];
            Span<byte> zeroBlock = stackalloc byte[32];
            ChaCha20Core.Transform(poly1305Key, zeroBlock, derivedKey, derivedNonce, 0);

            // Encrypt plaintext using ChaCha20 with counter=1
            ChaCha20Core.Transform(ciphertextWithoutTag, plaintext, derivedKey, derivedNonce, 1);

            // Compute authentication tag
            ComputeTag(tag, associatedData, ciphertextWithoutTag, poly1305Key);

            // Clear sensitive data
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);

            return plaintext.Length + TagSize;
        }
        finally
        {
            // Clear derived key and nonce
            SecureMemoryOperations.SecureClear(derivedKey);
            SecureMemoryOperations.SecureClear(derivedNonce);
        }
    }

    /// <summary>
    /// Decrypts ciphertext using XChaCha20-Poly1305
    /// </summary>
    /// <param name="plaintext">Output buffer for plaintext</param>
    /// <param name="ciphertext">Input ciphertext with tag</param>
    /// <param name="key">32-byte key</param>
    /// <param name="nonce">24-byte nonce</param>
    /// <param name="associatedData">Optional associated data</param>
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

        // Derive ChaCha20 key and nonce from XChaCha20 parameters
        Span<byte> derivedKey = stackalloc byte[32];
        Span<byte> derivedNonce = stackalloc byte[12];
        DeriveKeyAndNonce(derivedKey, derivedNonce, key, nonce);

        try
        {
            var ciphertextWithoutTag = ciphertext.Slice(0, ciphertextLength);
            var receivedTag = ciphertext.Slice(ciphertextLength, TagSize);

            // Generate Poly1305 key using the derived ChaCha20 key
            Span<byte> poly1305Key = stackalloc byte[32];
            Span<byte> zeroBlock = stackalloc byte[32];
            ChaCha20Core.Transform(poly1305Key, zeroBlock, derivedKey, derivedNonce, 0);

            // Compute expected authentication tag
            Span<byte> expectedTag = stackalloc byte[TagSize];
            ComputeTag(expectedTag, associatedData, ciphertextWithoutTag, poly1305Key);

            // Verify tag in constant time
            var tagValid = SecureMemoryOperations.ConstantTimeEquals(receivedTag, expectedTag);

            // Clear computed tag and Poly1305 key
            SecureMemoryOperations.SecureClear(expectedTag);
            SecureMemoryOperations.SecureClear(poly1305Key);
            SecureMemoryOperations.SecureClear(zeroBlock);

            if (!tagValid)
            {
                return -1;
            }

            // Decrypt ciphertext using ChaCha20 with counter=1
            var plaintextSlice = plaintext.Slice(0, ciphertextLength);
            ChaCha20Core.Transform(plaintextSlice, ciphertextWithoutTag, derivedKey, derivedNonce, 1);

            return ciphertextLength;
        }
        finally
        {
            // Clear derived key and nonce
            SecureMemoryOperations.SecureClear(derivedKey);
            SecureMemoryOperations.SecureClear(derivedNonce);
        }
    }

    /// <summary>
    /// Derives ChaCha20 key and nonce from XChaCha20 parameters using HChaCha20
    /// </summary>
    /// <param name="derivedKey">Output 32-byte derived key</param>
    /// <param name="derivedNonce">Output 12-byte derived nonce</param>
    /// <param name="originalKey">Input 32-byte original key</param>
    /// <param name="extendedNonce">Input 24-byte extended nonce</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DeriveKeyAndNonce(Span<byte> derivedKey, Span<byte> derivedNonce,
        ReadOnlySpan<byte> originalKey, ReadOnlySpan<byte> extendedNonce)
    {
        // HChaCha20 takes the first 16 bytes of the nonce
        var hchacha20Nonce = extendedNonce.Slice(0, 16);

        // Derive new key using HChaCha20
        HChaCha20(derivedKey, originalKey, hchacha20Nonce);

        // The derived nonce is the last 8 bytes of the extended nonce + 4 zero bytes
        derivedNonce.Clear();
        extendedNonce.Slice(16, 8).CopyTo(derivedNonce.Slice(4, 8));
    }

    /// <summary>
    /// HChaCha20 key derivation function
    /// </summary>
    /// <param name="output">32-byte output key</param>
    /// <param name="key">32-byte input key</param>
    /// <param name="nonce">16-byte nonce</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void HChaCha20(Span<byte> output, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (output.Length != 32)
            throw new ArgumentException("Output must be 32 bytes", nameof(output));
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 16)
            throw new ArgumentException("Nonce must be 16 bytes", nameof(nonce));

        // Initialize HChaCha20 state
        Span<uint> state = stackalloc uint[16];

        // Constants
        state[0] = HChaCha20Constants[0];
        state[1] = HChaCha20Constants[1];
        state[2] = HChaCha20Constants[2];
        state[3] = HChaCha20Constants[3];

#if !NET5_0_OR_GREATER
        // Create reusable arrays for .NET Standard 2.0 (avoid memory leaks in loops)
        var keyBytes = new byte[4];
        var nonceBytes = new byte[4];
#endif

        // Key
        for (var i = 0; i < 8; i++)
        {
#if NET5_0_OR_GREATER
            state[4 + i] = BitConverter.ToUInt32(key.Slice(i * 4, 4));
#else
            key.Slice(i * 4, 4).CopyTo(keyBytes);
            state[4 + i] = BitConverter.ToUInt32(keyBytes, 0);
#endif
        }

        // Nonce
        for (var i = 0; i < 4; i++)
        {
#if NET5_0_OR_GREATER
            state[12 + i] = BitConverter.ToUInt32(nonce.Slice(i * 4, 4));
#else
            nonce.Slice(i * 4, 4).CopyTo(nonceBytes);
            state[12 + i] = BitConverter.ToUInt32(nonceBytes, 0);
#endif
        }

        // Perform 20 rounds (same as ChaCha20)
        for (var i = 0; i < 10; i++)
        {
            // Odd round - column rounds
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 1, 5, 9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);

            // Even round - diagonal rounds
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7, 8, 13);
            QuarterRound(state, 3, 4, 9, 14);
        }

        // Output only state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15]
        BitConverter.GetBytes(state[0]).CopyTo(output.Slice(0, 4));
        BitConverter.GetBytes(state[1]).CopyTo(output.Slice(4, 4));
        BitConverter.GetBytes(state[2]).CopyTo(output.Slice(8, 4));
        BitConverter.GetBytes(state[3]).CopyTo(output.Slice(12, 4));
        BitConverter.GetBytes(state[12]).CopyTo(output.Slice(16, 4));
        BitConverter.GetBytes(state[13]).CopyTo(output.Slice(20, 4));
        BitConverter.GetBytes(state[14]).CopyTo(output.Slice(24, 4));
        BitConverter.GetBytes(state[15]).CopyTo(output.Slice(28, 4));

        // Clear state
        SecureMemoryOperations.SecureClear(state);
    }

    /// <summary>
    /// ChaCha20 quarter round function
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = RotateLeft(state[d], 16);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = RotateLeft(state[b], 12);

        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = RotateLeft(state[d], 8);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = RotateLeft(state[b], 7);
    }

    /// <summary>
    /// Left rotation with constant time guarantee
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateLeft(uint value, int bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    /// <summary>
    /// Computes the Poly1305 authentication tag (same as ChaCha20-Poly1305)
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