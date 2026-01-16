using System.Security.Cryptography;
using HeroCrypt.Primitives.Common;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.AesGcm;

/// <summary>
/// Result of an AES-GCM encryption operation.
/// </summary>
public readonly struct AesGcmEncryptionResult
{
    /// <summary>The encrypted ciphertext including authentication tag.</summary>
    public readonly byte[] Ciphertext { get; init; }

    /// <summary>The nonce used for encryption (needed for decryption).</summary>
    public readonly byte[] Nonce { get; init; }

    /// <summary>Size of the authentication tag in bytes (always 16).</summary>
    public readonly int TagSize { get; init; }

    /// <summary>Length of the ciphertext portion (excluding tag).</summary>
    public readonly int CiphertextLength => Ciphertext.Length - TagSize;
}

/// <summary>
/// AES-GCM (Galois/Counter Mode) implementation.
/// NIST SP 800-38D compliant AEAD cipher.
/// </summary>
/// <remarks>
/// AES-GCM is not supported on .NET Standard 2.0. Use ChaCha20-Poly1305 as an alternative.
/// </remarks>
internal static class AesGcmCore
{
#if NETSTANDARD2_0
    /// <summary>
    /// Encrypts plaintext using AES-GCM.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">AES-GCM is not supported on .NET Standard 2.0.</exception>
    public static AesGcmEncryptionResult Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce = default,
        ReadOnlySpan<byte> associatedData = default,
        bool deterministicMode = false)
    {
        _ = plaintext;
        _ = key;
        _ = nonce;
        _ = associatedData;
        _ = deterministicMode;
        throw new PlatformNotSupportedException("AES-GCM is not supported on .NET Standard 2.0. Use ChaCha20-Poly1305 or XChaCha20-Poly1305 as an alternative.");
    }

    /// <summary>
    /// Decrypts ciphertext using AES-GCM.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">AES-GCM is not supported on .NET Standard 2.0.</exception>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        throw new PlatformNotSupportedException("AES-GCM is not supported on .NET Standard 2.0. Use ChaCha20-Poly1305 or XChaCha20-Poly1305 as an alternative.");
    }
#else
    private const int NONCE_SIZE = 12;
    private const int TAG_SIZE = 16;
    private static readonly int[] SupportedKeySizes = AesConstants.StandardKeySizes;
    /// <summary>
    /// Encrypts plaintext using AES-GCM.
    /// </summary>
    /// <param name="plaintext">Input plaintext.</param>
    /// <param name="key">AES key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <param name="nonce">Nonce (12 bytes). Default: auto-generated random nonce.</param>
    /// <param name="associatedData">Additional authenticated data. Default: empty.</param>
    /// <param name="deterministicMode">When true and nonce is empty, uses zero nonce (dangerous - only for testing). Default: false.</param>
    /// <returns>Encryption result containing ciphertext, nonce, and metadata.</returns>
    public static AesGcmEncryptionResult Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce = default,
        ReadOnlySpan<byte> associatedData = default,
        bool deterministicMode = false)
    {
        // Generate random nonce if not provided and not in deterministic mode
        byte[] nonceArray;
        if (nonce.IsEmpty)
        {
            if (deterministicMode)
            {
                // Deterministic mode: use zero nonce (WARNING: dangerous for production)
                nonceArray = new byte[NONCE_SIZE];
            }
            else
            {
                // Secure default: auto-generate random nonce
                nonceArray = new byte[NONCE_SIZE];
                SecureRandomNumberGenerator.Fill(nonceArray);
            }
        }
        else
        {
            nonceArray = nonce.ToArray();
        }

        ValidateParameters(key, nonceArray);

        // Allocate ciphertext buffer
        var ciphertext = new byte[plaintext.Length + TAG_SIZE];

        var ciphertextOnly = ciphertext.AsSpan(0, plaintext.Length);
        var tag = ciphertext.AsSpan(plaintext.Length, TAG_SIZE);

        using var aesGcm = new System.Security.Cryptography.AesGcm(key, TAG_SIZE);
        aesGcm.Encrypt(nonceArray, plaintext, ciphertextOnly, tag, associatedData);

        return new AesGcmEncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = nonceArray,
            TagSize = TAG_SIZE
        };
    }

    /// <summary>
    /// Decrypts ciphertext using AES-GCM.
    /// </summary>
    /// <param name="ciphertext">Input ciphertext including authentication tag.</param>
    /// <param name="key">AES key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <param name="nonce">Nonce used during encryption (12 bytes).</param>
    /// <param name="associatedData">Additional authenticated data used during encryption. Default: empty.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown when authentication fails.</exception>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < TAG_SIZE)
        {
            throw new ArgumentException($"Ciphertext must be at least {TAG_SIZE} bytes, but was {ciphertext.Length} bytes", nameof(ciphertext));
        }

        ValidateParameters(key, nonce);

        var plaintextLength = ciphertext.Length - TAG_SIZE;
        var plaintext = new byte[plaintextLength];

        var ciphertextOnly = ciphertext[..plaintextLength];
        var tag = ciphertext.Slice(plaintextLength, TAG_SIZE);

        try
        {
            using var aesGcm = new System.Security.Cryptography.AesGcm(key, TAG_SIZE);
            aesGcm.Decrypt(nonce, ciphertextOnly, tag, plaintext, associatedData);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            SecureMemoryOperations.SecureClear(plaintext);
            throw new CryptographicException("AES-GCM decryption failed: authentication tag mismatch.");
        }
        catch (CryptographicException)
        {
            SecureMemoryOperations.SecureClear(plaintext);
            throw;
        }
    }

    /// <summary>
    /// Validates AES-GCM parameters.
    /// </summary>
    private static void ValidateParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (!SupportedKeySizes.Contains(key.Length))
        {
            throw new ArgumentException(
                $"Key must be 16, 24, or 32 bytes (AES-128/192/256), but was {key.Length} bytes",
                nameof(key));
        }

        if (nonce.Length != NONCE_SIZE)
        {
            throw new ArgumentException(
                $"Nonce must be {NONCE_SIZE} bytes, but was {nonce.Length} bytes",
                nameof(nonce));
        }
    }
#endif
}
