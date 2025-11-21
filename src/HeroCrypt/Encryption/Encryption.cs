using System.Security.Cryptography;
using HeroCrypt.Cryptography.Primitives.Cipher.Aead;
using Primitives = HeroCrypt.Cryptography.Primitives;

namespace HeroCrypt.Encryption;

/// <summary>
/// Result of an encryption operation
/// </summary>
public readonly struct EncryptionResult
{
    /// <summary>
    /// The ciphertext (encrypted data)
    /// </summary>
    public byte[] Ciphertext { get; init; }

    /// <summary>
    /// The nonce/IV used for encryption (needed for decryption)
    /// </summary>
    public byte[] Nonce { get; init; }

    /// <summary>
    /// Optional: Ciphertext for the encapsulated key (for hybrid encryption)
    /// </summary>
    public byte[]? KeyCiphertext { get; init; }
}

/// <summary>
/// Unified encryption and decryption operations for various algorithms
/// </summary>
internal static class Encryption
{
#if NETSTANDARD2_0
    // Polyfill for RandomNumberGenerator.Fill on .NET Standard 2.0
    private static void FillRandomBytes(byte[] buffer)
    {
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
    }
#endif

    /// <summary>
    /// Encrypts data using the specified algorithm
    /// </summary>
    /// <param name="plaintext">The data to encrypt</param>
    /// <param name="key">The encryption key (format and size depends on algorithm)</param>
    /// <param name="algorithm">The encryption algorithm to use</param>
    /// <param name="associatedData">Optional authenticated associated data (for AEAD ciphers)</param>
    /// <returns>Encryption result containing ciphertext and nonce</returns>
    /// <exception cref="ArgumentNullException">Thrown when plaintext or key is null</exception>
    /// <exception cref="NotSupportedException">Thrown when algorithm is not supported on this platform</exception>
    public static EncryptionResult Encrypt(byte[] plaintext, byte[] key, EncryptionAlgorithm algorithm, byte[]? associatedData = null)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key);
#else
        if (plaintext == null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }
#endif

        return algorithm switch
        {
            EncryptionAlgorithm.AesGcm => EncryptAesGcm(plaintext, key, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.AesCcm => EncryptAesCcm(plaintext, key, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.ChaCha20Poly1305 => EncryptChaCha20Poly1305(plaintext, key, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.XChaCha20Poly1305 => EncryptXChaCha20Poly1305(plaintext, key, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.RsaOaepSha256 => EncryptRsaOaep(plaintext, key),
#if NET10_0_OR_GREATER
            EncryptionAlgorithm.MLKem768AesGcm => EncryptMLKemHybrid(plaintext, key, 768, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.MLKem1024AesGcm => EncryptMLKemHybrid(plaintext, key, 1024, associatedData ?? Array.Empty<byte>()),
#else
            EncryptionAlgorithm.MLKem768AesGcm or EncryptionAlgorithm.MLKem1024AesGcm =>
                throw new NotSupportedException("ML-KEM algorithms require .NET 10 or greater"),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Decrypts data using the specified algorithm
    /// </summary>
    /// <param name="ciphertext">The encrypted data</param>
    /// <param name="key">The decryption key (format and size depends on algorithm)</param>
    /// <param name="nonce">The nonce/IV used during encryption</param>
    /// <param name="algorithm">The encryption algorithm used</param>
    /// <param name="associatedData">Optional authenticated associated data (for AEAD ciphers)</param>
    /// <param name="keyCiphertext">Optional key ciphertext (for hybrid encryption)</param>
    /// <returns>The decrypted plaintext</returns>
    /// <exception cref="ArgumentNullException">Thrown when ciphertext, key, or nonce is null</exception>
    /// <exception cref="CryptographicException">Thrown when decryption or authentication fails</exception>
    /// <exception cref="NotSupportedException">Thrown when algorithm is not supported on this platform</exception>
    public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] nonce, EncryptionAlgorithm algorithm,
        byte[]? associatedData = null, byte[]? keyCiphertext = null)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);
#else
        if (ciphertext == null)
        {
            throw new ArgumentNullException(nameof(ciphertext));
        }
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }
        if (nonce == null)
        {
            throw new ArgumentNullException(nameof(nonce));
        }
#endif

        return algorithm switch
        {
            EncryptionAlgorithm.AesGcm => DecryptAesGcm(ciphertext, key, nonce, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.AesCcm => DecryptAesCcm(ciphertext, key, nonce, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.ChaCha20Poly1305 => DecryptChaCha20Poly1305(ciphertext, key, nonce, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.XChaCha20Poly1305 => DecryptXChaCha20Poly1305(ciphertext, key, nonce, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.RsaOaepSha256 => DecryptRsaOaep(ciphertext, key),
#if NET10_0_OR_GREATER
            EncryptionAlgorithm.MLKem768AesGcm => DecryptMLKemHybrid(ciphertext, key, nonce, keyCiphertext!, 768, associatedData ?? Array.Empty<byte>()),
            EncryptionAlgorithm.MLKem1024AesGcm => DecryptMLKemHybrid(ciphertext, key, nonce, keyCiphertext!, 1024, associatedData ?? Array.Empty<byte>()),
#else
            EncryptionAlgorithm.MLKem768AesGcm or EncryptionAlgorithm.MLKem1024AesGcm =>
                throw new NotSupportedException("ML-KEM algorithms require .NET 10 or greater"),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    #region AES-GCM

#if !NETSTANDARD2_0
    private static EncryptionResult EncryptAesGcm(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int NonceSize = 12;
        const int TagSize = 16;

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length + TagSize];
        var tag = ciphertext.AsSpan(plaintext.Length, TagSize);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), tag, associatedData);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = nonce
        };
    }

    private static byte[] DecryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        const int TagSize = 16;

        if (ciphertext.Length < TagSize)
        {
            throw new CryptographicException("Ciphertext too short");
        }

        var plaintextLength = ciphertext.Length - TagSize;
        var plaintext = new byte[plaintextLength];
        var tag = ciphertext.AsSpan(plaintextLength, TagSize);

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext.AsSpan(0, plaintextLength), tag, plaintext, associatedData);

        return plaintext;
    }
#else
    private static EncryptionResult EncryptAesGcm(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        throw new NotSupportedException("AES-GCM is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }

    private static byte[] DecryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        throw new NotSupportedException("AES-GCM is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }
#endif

    #endregion

    #region AES-CCM

#if !NETSTANDARD2_0
    private static EncryptionResult EncryptAesCcm(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int NonceSize = 13;
        const int TagSize = 16;

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length + TagSize];
        var tag = ciphertext.AsSpan(plaintext.Length, TagSize);

        using var aes = new AesCcm(key);
        aes.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), tag, associatedData);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = nonce
        };
    }

    private static byte[] DecryptAesCcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        const int TagSize = 16;

        if (ciphertext.Length < TagSize)
        {
            throw new CryptographicException("Ciphertext too short");
        }

        var plaintextLength = ciphertext.Length - TagSize;
        var plaintext = new byte[plaintextLength];
        var tag = ciphertext.AsSpan(plaintextLength, TagSize);

        using var aes = new AesCcm(key);
        aes.Decrypt(nonce, ciphertext.AsSpan(0, plaintextLength), tag, plaintext, associatedData);

        return plaintext;
    }
#else
    private static EncryptionResult EncryptAesCcm(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        throw new NotSupportedException("AES-CCM is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }

    private static byte[] DecryptAesCcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        throw new NotSupportedException("AES-CCM is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }
#endif

    #endregion

    #region ChaCha20-Poly1305

    private static EncryptionResult EncryptChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int nonceSize = 12;
        const int tagSize = 16;

        var nonce = new byte[nonceSize];
#if NETSTANDARD2_0
        FillRandomBytes(nonce);
#else
        RandomNumberGenerator.Fill(nonce);
#endif

        var ciphertext = new byte[plaintext.Length + tagSize];

        ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = nonce
        };
    }

    private static byte[] DecryptChaCha20Poly1305(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        const int tagSize = 16;

        if (ciphertext.Length < tagSize)
        {
            throw new CryptographicException("Ciphertext too short");
        }

        var plaintext = new byte[ciphertext.Length - tagSize];

        var result = ChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData);
        if (result < 0)
        {
            throw new CryptographicException("Decryption failed: authentication tag mismatch");
        }

        return plaintext;
    }

    #endregion

    #region XChaCha20-Poly1305

    private static EncryptionResult EncryptXChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int nonceSize = 24;
        const int tagSize = 16;

        var nonce = new byte[nonceSize];
#if NETSTANDARD2_0
        FillRandomBytes(nonce);
#else
        RandomNumberGenerator.Fill(nonce);
#endif

        var ciphertext = new byte[plaintext.Length + tagSize];

        XChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = nonce
        };
    }

    private static byte[] DecryptXChaCha20Poly1305(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        const int tagSize = 16;

        if (ciphertext.Length < tagSize)
        {
            throw new CryptographicException("Ciphertext too short");
        }

        var plaintext = new byte[ciphertext.Length - tagSize];

        var result = XChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData);
        if (result < 0)
        {
            throw new CryptographicException("Decryption failed: authentication tag mismatch");
        }

        return plaintext;
    }

    #endregion

    #region RSA-OAEP

#if !NETSTANDARD2_0
    private static EncryptionResult EncryptRsaOaep(byte[] plaintext, byte[] publicKey)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);

        var ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = Array.Empty<byte>() // RSA doesn't use nonce
        };
    }

    private static byte[] DecryptRsaOaep(byte[] ciphertext, byte[] privateKey)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);

        return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }
#else
    private static EncryptionResult EncryptRsaOaep(byte[] plaintext, byte[] publicKey)
    {
        throw new NotSupportedException("RSA-OAEP encryption is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }

    private static byte[] DecryptRsaOaep(byte[] ciphertext, byte[] privateKey)
    {
        throw new NotSupportedException("RSA-OAEP decryption is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }
#endif

    #endregion

    #region ML-KEM Hybrid Encryption

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006 // Experimental feature warnings
    private static EncryptionResult EncryptMLKemHybrid(byte[] plaintext, byte[] publicKeyPem, int securityBits, byte[] associatedData)
    {
        _ = securityBits;

        var pem = System.Text.Encoding.UTF8.GetString(publicKeyPem);

        // Encapsulate shared secret using ML-KEM
        using var encapsulation = Primitives.PostQuantum.Kyber.MLKemWrapper.Encapsulate(pem);
        var sharedSecret = encapsulation.SharedSecret;

        // Use first 32 bytes of shared secret as AES-GCM key
        var aesKey = new byte[32];
        Array.Copy(sharedSecret, aesKey, 32);

        // Encrypt with AES-GCM
        var result = EncryptAesGcm(plaintext, aesKey, associatedData);

        // Include the ML-KEM ciphertext (encapsulated key) in result
        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce,
            KeyCiphertext = encapsulation.Ciphertext
        };
    }

    private static byte[] DecryptMLKemHybrid(byte[] ciphertext, byte[] privateKeyPem, byte[] nonce, byte[] keyCiphertext, int securityBits, byte[] associatedData)
    {
        _ = securityBits;

        if (keyCiphertext == null)
        {
            throw new ArgumentNullException(nameof(keyCiphertext), "ML-KEM decryption requires keyCiphertext");
        }

        var pem = System.Text.Encoding.UTF8.GetString(privateKeyPem);

        // Import private key and decapsulate shared secret
        using var key = System.Security.Cryptography.MLKem.ImportFromPem(pem);
        var sharedSecret = key.Decapsulate(keyCiphertext);

        // Use first 32 bytes of shared secret as AES-GCM key
        var aesKey = new byte[32];
        Array.Copy(sharedSecret, aesKey, 32);

        // Decrypt with AES-GCM
        return DecryptAesGcm(ciphertext, aesKey, nonce, associatedData);
    }
#endif

    #endregion
}
