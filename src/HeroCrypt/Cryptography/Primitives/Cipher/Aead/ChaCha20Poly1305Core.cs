using System.Runtime.CompilerServices;
using HeroCrypt.Cryptography.Primitives.Cipher.Stream;
#if NETSTANDARD2_0
using HeroCrypt.Polyfills;
#endif
using HeroCrypt.Security;

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
    public const int KEY_SIZE = 32;

    /// <summary>
    /// Nonce size in bytes
    /// </summary>
    public const int NONCE_SIZE = 12;

    /// <summary>
    /// Authentication tag size in bytes
    /// </summary>
    public const int TAG_SIZE = 16;

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
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes, but was {key.Length} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes, but was {nonce.Length} bytes", nameof(nonce));
        }
        if (ciphertext.Length < plaintext.Length + TAG_SIZE)
        {
            throw new ArgumentException($"Ciphertext buffer must be at least {plaintext.Length + TAG_SIZE} bytes, but was {ciphertext.Length} bytes", nameof(ciphertext));
        }

        var ciphertextWithoutTag = ciphertext[..plaintext.Length];
        var tag = ciphertext.Slice(plaintext.Length, TAG_SIZE);

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

        return plaintext.Length + TAG_SIZE;
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
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes, but was {key.Length} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes, but was {nonce.Length} bytes", nameof(nonce));
        }
        if (ciphertext.Length < TAG_SIZE)
        {
            throw new ArgumentException($"Ciphertext must be at least {TAG_SIZE} bytes, but was {ciphertext.Length} bytes", nameof(ciphertext));
        }

        var ciphertextLength = ciphertext.Length - TAG_SIZE;
        if (plaintext.Length < ciphertextLength)
        {
            throw new ArgumentException($"Plaintext buffer must be at least {ciphertextLength} bytes, but was {plaintext.Length} bytes", nameof(plaintext));
        }

        var ciphertextWithoutTag = ciphertext[..ciphertextLength];
        var receivedTag = ciphertext.Slice(ciphertextLength, TAG_SIZE);

        // Generate Poly1305 key using ChaCha20 with counter=0
        Span<byte> poly1305Key = stackalloc byte[32];
        Span<byte> zeroBlock = stackalloc byte[32];
        ChaCha20Core.Transform(poly1305Key, zeroBlock, key, nonce, 0);

        // Compute expected authentication tag
        Span<byte> expectedTag = stackalloc byte[TAG_SIZE];
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
        var plaintextSlice = plaintext[..ciphertextLength];
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
        Poly1305TagComputation.ComputeTag(tag, associatedData, ciphertext, poly1305Key);
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
        {
            throw new ArgumentException($"Poly1305 key must be 32 bytes, but was {poly1305Key.Length} bytes", nameof(poly1305Key));
        }

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
        if (key.Length != KEY_SIZE)
        {
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes, but was {key.Length} bytes", nameof(key));
        }
        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException($"Nonce must be {NONCE_SIZE} bytes, but was {nonce.Length} bytes", nameof(nonce));
        }
    }

    /// <summary>
    /// Gets the maximum ciphertext length for a given plaintext length
    /// </summary>
    public static int GetCiphertextLength(int plaintextLength)
    {
#if NETSTANDARD2_0
        if (plaintextLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintextLength));
        }
#else
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);
#endif

        return plaintextLength + TAG_SIZE;
    }

    /// <summary>
    /// Gets the maximum plaintext length for a given ciphertext length
    /// </summary>
    public static int GetPlaintextLength(int ciphertextLength)
    {
        if (ciphertextLength < TAG_SIZE)
        {
            return -1; // Invalid ciphertext
        }

        return ciphertextLength - TAG_SIZE;
    }
}
