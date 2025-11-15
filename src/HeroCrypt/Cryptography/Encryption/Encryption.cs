using System.Security.Cryptography;
using HeroCrypt.Cryptography.Symmetric.ChaCha20Poly1305;
using HeroCrypt.Cryptography.Symmetric.XChaCha20Poly1305;

namespace HeroCrypt.Cryptography.Encryption;

/// <summary>
/// Unified encryption and decryption operations for various algorithms
/// </summary>
internal static class Encryption
{
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
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));
        if (key == null)
            throw new ArgumentNullException(nameof(key));

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
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (nonce == null)
            throw new ArgumentNullException(nameof(nonce));

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

    private static EncryptionResult EncryptAesGcm(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int nonceSize = 12;
        const int tagSize = 16;

        var nonce = new byte[nonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length + tagSize];
        var tag = ciphertext.AsSpan(plaintext.Length, tagSize);

        using var aes = new AesGcm(key, tagSize);
        aes.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), tag, associatedData);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = nonce
        };
    }

    private static byte[] DecryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] associatedData)
    {
        const int tagSize = 16;

        if (ciphertext.Length < tagSize)
            throw new CryptographicException("Ciphertext too short");

        var plaintextLength = ciphertext.Length - tagSize;
        var plaintext = new byte[plaintextLength];
        var tag = ciphertext.AsSpan(plaintextLength, tagSize);

        using var aes = new AesGcm(key, tagSize);
        aes.Decrypt(nonce, ciphertext.AsSpan(0, plaintextLength), tag, plaintext, associatedData);

        return plaintext;
    }

    #endregion

    #region AES-CCM

    private static EncryptionResult EncryptAesCcm(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int nonceSize = 13;
        const int tagSize = 16;

        var nonce = new byte[nonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length + tagSize];
        var tag = ciphertext.AsSpan(plaintext.Length, tagSize);

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
        const int tagSize = 16;

        if (ciphertext.Length < tagSize)
            throw new CryptographicException("Ciphertext too short");

        var plaintextLength = ciphertext.Length - tagSize;
        var plaintext = new byte[plaintextLength];
        var tag = ciphertext.AsSpan(plaintextLength, tagSize);

        using var aes = new AesCcm(key);
        aes.Decrypt(nonce, ciphertext.AsSpan(0, plaintextLength), tag, plaintext, associatedData);

        return plaintext;
    }

    #endregion

    #region ChaCha20-Poly1305

    private static EncryptionResult EncryptChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int nonceSize = 12;
        const int tagSize = 16;

        var nonce = new byte[nonceSize];
        RandomNumberGenerator.Fill(nonce);

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
            throw new CryptographicException("Ciphertext too short");

        var plaintext = new byte[ciphertext.Length - tagSize];

        var result = ChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData);
        if (result < 0)
            throw new CryptographicException("Decryption failed: authentication tag mismatch");

        return plaintext;
    }

    #endregion

    #region XChaCha20-Poly1305

    private static EncryptionResult EncryptXChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        const int nonceSize = 24;
        const int tagSize = 16;

        var nonce = new byte[nonceSize];
        RandomNumberGenerator.Fill(nonce);

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
            throw new CryptographicException("Ciphertext too short");

        var plaintext = new byte[ciphertext.Length - tagSize];

        var result = XChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData);
        if (result < 0)
            throw new CryptographicException("Decryption failed: authentication tag mismatch");

        return plaintext;
    }

    #endregion

    #region RSA-OAEP

    private static EncryptionResult EncryptRsaOaep(byte[] plaintext, byte[] publicKey)
    {
        using var rsa = RSA.Create();
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
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);

        return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }

    #endregion

    #region ML-KEM Hybrid Encryption

#if NET10_0_OR_GREATER
    private static EncryptionResult EncryptMLKemHybrid(byte[] plaintext, byte[] publicKeyPem, int securityBits, byte[] associatedData)
    {
        var pem = System.Text.Encoding.UTF8.GetString(publicKeyPem);

        // Encapsulate shared secret using ML-KEM
        using var encapsulation = PostQuantum.Kyber.MLKemWrapper.Encapsulate(pem, securityBits);
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
        if (keyCiphertext == null)
            throw new ArgumentNullException(nameof(keyCiphertext), "ML-KEM decryption requires keyCiphertext");

        var pem = System.Text.Encoding.UTF8.GetString(privateKeyPem);

        // Decapsulate shared secret using ML-KEM
        using var decapsulation = PostQuantum.Kyber.MLKemWrapper.Decapsulate(pem, keyCiphertext, securityBits);
        var sharedSecret = decapsulation.SharedSecret;

        // Use first 32 bytes of shared secret as AES-GCM key
        var aesKey = new byte[32];
        Array.Copy(sharedSecret, aesKey, 32);

        // Decrypt with AES-GCM
        return DecryptAesGcm(ciphertext, aesKey, nonce, associatedData);
    }
#endif

    #endregion
}
