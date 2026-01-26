using System.Security.Cryptography;
using HeroCrypt.Primitives.AesCcm;
using HeroCrypt.Primitives.AesGcm;
using HeroCrypt.Primitives.AesOcb;
using HeroCrypt.Primitives.AesSiv;
using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Primitives.XChaCha20Poly1305;
using HeroCrypt.Security;
#if NET10_OR_GREATER
using HeroCrypt.Primitives.MLKem;
#endif

namespace HeroCrypt.Operations;

/// <summary>
/// Fluent builder for decryption operations.
/// </summary>
/// <remarks>
/// <para>
/// This builder implements <see cref="IDisposable"/> to securely clear sensitive key material
/// from memory when the builder is no longer needed. It is recommended to use this builder
/// within a <c>using</c> statement.
/// </para>
/// </remarks>
public sealed class DecryptionBuilder : IDisposable
{
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private byte[]? encapsulatedKey;
    private bool disposed;

    private void ThrowIfDisposed()
    {
#if NETSTANDARD2_0
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(DecryptionBuilder));
        }
#else
        ObjectDisposedException.ThrowIf(disposed, this);
#endif
    }

    private void ClearKey()
    {
        if (key == null) return;
        SecureMemoryOperations.SecureClear(key);
        key = null;
    }

    private void ClearNonce()
    {
        if (nonce == null) return;
        SecureMemoryOperations.SecureClear(nonce);
        nonce = null;
    }

    private void ClearAssociatedData()
    {
        if (associatedData == null) return;
        SecureMemoryOperations.SecureClear(associatedData);
        associatedData = null;
    }

    private void ClearEncapsulatedKey()
    {
        if (encapsulatedKey == null) return;
        SecureMemoryOperations.SecureClear(encapsulatedKey);
        encapsulatedKey = null;
    }

    /// <summary>
    /// Releases all resources used by this builder and securely clears sensitive key material.
    /// </summary>
    public void Dispose()
    {
        if (disposed) return;
        ClearKey();
        ClearNonce();
        ClearAssociatedData();
        ClearEncapsulatedKey();
        disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Sets the encryption algorithm to use.
    /// </summary>
    public DecryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        ThrowIfDisposed();
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Use AES-GCM for decryption.
    /// </summary>
    public DecryptionBuilder WithAesGcm() => WithAlgorithm(EncryptionAlgorithm.AesGcm);

    /// <summary>
    /// Use AES-CCM for decryption.
    /// </summary>
    public DecryptionBuilder WithAesCcm() => WithAlgorithm(EncryptionAlgorithm.AesCcm);

    /// <summary>
    /// Use AES-OCB for decryption (high-performance AEAD).
    /// </summary>
    public DecryptionBuilder WithAesOcb() => WithAlgorithm(EncryptionAlgorithm.AesOcb);

    /// <summary>
    /// Use AES-SIV for decryption (nonce-misuse resistant).
    /// </summary>
    public DecryptionBuilder WithAesSiv() => WithAlgorithm(EncryptionAlgorithm.AesSiv);

    /// <summary>
    /// Use ChaCha20-Poly1305 for decryption.
    /// </summary>
    public DecryptionBuilder WithChaCha20Poly1305() => WithAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305);

    /// <summary>
    /// Use XChaCha20-Poly1305 for decryption.
    /// </summary>
    public DecryptionBuilder WithXChaCha20Poly1305() => WithAlgorithm(EncryptionAlgorithm.XChaCha20Poly1305);

    /// <summary>
    /// Use RSA-OAEP with SHA-256 for decryption.
    /// </summary>
    public DecryptionBuilder WithRsaOaep() => WithAlgorithm(EncryptionAlgorithm.RsaOaepSha256);

    /// <summary>
    /// Sets the decryption key.
    /// </summary>
    public DecryptionBuilder WithKey(byte[] key)
    {
        ThrowIfDisposed();
        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the nonce used during encryption.
    /// </summary>
    public DecryptionBuilder WithNonce(byte[] nonce)
    {
        ThrowIfDisposed();
        ClearNonce();
        this.nonce = [.. nonce];
        return this;
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD).
    /// </summary>
    public DecryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        ThrowIfDisposed();
        ClearAssociatedData();
        this.associatedData = [.. associatedData];
        return this;
    }

    /// <summary>
    /// Sets the encapsulated key for hybrid encryption.
    /// </summary>
    public DecryptionBuilder WithEncapsulatedKey(byte[] encapsulatedKey)
    {
        ThrowIfDisposed();
        ClearEncapsulatedKey();
        this.encapsulatedKey = [.. encapsulatedKey];
        return this;
    }

    /// <summary>
    /// Configures the decryption builder from an encryption result.
    /// </summary>
    /// <param name="result">The encryption result containing the nonce and optional encapsulated key.</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// <para>
    /// This method sets the nonce and encapsulated key (if present) from the encryption result,
    /// simplifying the decryption workflow. You still need to:
    /// </para>
    /// <list type="bullet">
    /// <item>Set the algorithm using <see cref="WithAlgorithm"/> (or use the default AES-GCM)</item>
    /// <item>Set the decryption key using <see cref="WithKey"/></item>
    /// <item>Set associated data if any was used during encryption</item>
    /// </list>
    /// <para>
    /// Example usage:
    /// </para>
    /// <code>
    /// var decrypted = HeroCryptBuilder.Decrypt()
    ///     .FromEncryptionResult(result)
    ///     .WithAlgorithm(algorithm)
    ///     .WithKey(key)
    ///     .Decrypt(result.Ciphertext);
    /// </code>
    /// </remarks>
    public DecryptionBuilder FromEncryptionResult(EncryptionResult result)
    {
        ThrowIfDisposed();

        // Set nonce
        ClearNonce();
        nonce = [.. result.Nonce];

        // Set encapsulated key if present (for hybrid encryption)
        if (result.EncapsulatedKey != null)
        {
            ClearEncapsulatedKey();
            encapsulatedKey = [.. result.EncapsulatedKey];
        }

        return this;
    }

    /// <summary>
    /// Decrypts the ciphertext and returns the plaintext.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown when authentication fails.</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ThrowIfDisposed();

        if (key == null)
            throw new InvalidOperationException("Decryption key must be set using WithKey()");

        InputValidator.ValidateByteArray(ciphertext, nameof(ciphertext));
        InputValidator.ValidateByteArray(key, nameof(key));

        var isRsaAlgorithm = algorithm is EncryptionAlgorithm.RsaOaepSha256
            or EncryptionAlgorithm.RsaOaepSha384
            or EncryptionAlgorithm.RsaOaepSha512
            or EncryptionAlgorithm.RsaPkcs1v15;

        if (!isRsaAlgorithm)
        {
            if (nonce == null)
                throw new InvalidOperationException("Nonce must be set using WithNonce()");

            InputValidator.ValidateByteArray(nonce, nameof(nonce));
        }

        if (associatedData != null)
            InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);

        if (encapsulatedKey != null)
            InputValidator.ValidateByteArray(encapsulatedKey, nameof(encapsulatedKey));

        var aad = associatedData ?? [];

        return algorithm switch
        {
            EncryptionAlgorithm.AesGcm => DecryptAesGcm(ciphertext, key, nonce!, aad),
            EncryptionAlgorithm.AesCcm => DecryptAesCcm(ciphertext, key, nonce!, aad),
            EncryptionAlgorithm.AesOcb => DecryptAesOcb(ciphertext, key, nonce!, aad),
            EncryptionAlgorithm.AesSiv => DecryptAesSiv(ciphertext, key, nonce!, aad),
            EncryptionAlgorithm.ChaCha20Poly1305 => DecryptChaCha20Poly1305(ciphertext, key, nonce!, aad),
            EncryptionAlgorithm.XChaCha20Poly1305 => DecryptXChaCha20Poly1305(ciphertext, key, nonce!, aad),
            EncryptionAlgorithm.RsaOaepSha256 => DecryptRsa(ciphertext, key, RSAEncryptionPadding.OaepSHA256),
            EncryptionAlgorithm.RsaOaepSha384 => DecryptRsa(ciphertext, key, RSAEncryptionPadding.OaepSHA384),
            EncryptionAlgorithm.RsaOaepSha512 => DecryptRsa(ciphertext, key, RSAEncryptionPadding.OaepSHA512),
            EncryptionAlgorithm.RsaPkcs1v15 => DecryptRsa(ciphertext, key, RSAEncryptionPadding.Pkcs1),
            EncryptionAlgorithm.X25519ChaCha20Poly1305 => DecryptX25519ChaCha20Poly1305(ciphertext, key, nonce!, aad, encapsulatedKey),
            EncryptionAlgorithm.X25519XChaCha20Poly1305 => DecryptX25519XChaCha20Poly1305(ciphertext, key, nonce!, aad, encapsulatedKey),
            EncryptionAlgorithm.X25519AesGcm => DecryptX25519AesGcm(ciphertext, key, nonce!, aad, encapsulatedKey),
            EncryptionAlgorithm.AesGcmSiv => throw new NotImplementedException(),
            EncryptionAlgorithm.Ascon128 => throw new NotImplementedException(),
            EncryptionAlgorithm.Ascon128a => throw new NotImplementedException(),
            EncryptionAlgorithm.EciesP256 => throw new NotImplementedException(),
            EncryptionAlgorithm.EciesP384 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeX25519ChaCha20Poly1305 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeX25519AesGcm128 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeX25519AesGcm256 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeP256AesGcm128 => throw new NotImplementedException(),
            EncryptionAlgorithm.AesCbcHmacSha256 => throw new NotImplementedException(),
#if NET10_OR_GREATER
            EncryptionAlgorithm.MLKem768AesGcm => DecryptMLKemAesGcm(ciphertext, key, nonce!, aad, encapsulatedKey),
            EncryptionAlgorithm.MLKem1024AesGcm => DecryptMLKemAesGcm(ciphertext, key, nonce!, aad, encapsulatedKey),
            EncryptionAlgorithm.MLKem768ChaCha20Poly1305 => DecryptMLKemChaCha20Poly1305(ciphertext, key, nonce!, aad, encapsulatedKey),
            EncryptionAlgorithm.MLKem1024ChaCha20Poly1305 => DecryptMLKemChaCha20Poly1305(ciphertext, key, nonce!, aad, encapsulatedKey),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    private static byte[] DecryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
    {
        return AesGcmCore.Decrypt(ciphertext, key, nonce, aad);
    }

    private static byte[] DecryptAesCcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
    {
        return AesCcmCore.Decrypt(ciphertext, key, nonce, aad);
    }

    private static byte[] DecryptAesOcb(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
    {
        return AesOcbCore.Decrypt(ciphertext, key, nonce, aad);
    }

    private static byte[] DecryptAesSiv(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
    {
        return AesSivCore.Decrypt(ciphertext, key, nonce, aad);
    }

    private static byte[] DecryptChaCha20Poly1305(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
    {
        return ChaCha20Poly1305Core.Decrypt(ciphertext, key, nonce, aad);
    }

    private static byte[] DecryptXChaCha20Poly1305(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
    {
        return XChaCha20Poly1305Core.Decrypt(ciphertext, key, nonce, aad);
    }

#if NETSTANDARD2_0
    private static byte[] DecryptRsa(byte[] ciphertext, byte[] privateKeyBytes, RSAEncryptionPadding padding)
    {
        _ = ciphertext;
        _ = privateKeyBytes;
        _ = padding;
        throw new PlatformNotSupportedException("RSA key import is not supported on .NET Standard 2.0.");
    }

    private static byte[] DecryptX25519ChaCha20Poly1305(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, X25519AeadCipher.ChaCha20Poly1305);
    }

    private static byte[] DecryptX25519XChaCha20Poly1305(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, X25519AeadCipher.XChaCha20Poly1305);
    }

    private static byte[] DecryptX25519AesGcm(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, X25519AeadCipher.AesGcm);
    }

    private static byte[] DecryptX25519Hybrid(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey, X25519AeadCipher cipher)
    {
        _ = ciphertext;
        _ = privateKey;
        _ = nonce;
        _ = aad;
        _ = ephemeralPublicKey;
        _ = cipher;
        throw new PlatformNotSupportedException("X25519 hybrid decryption is not supported on .NET Standard 2.0.");
    }
#else
    private static byte[] DecryptRsa(byte[] ciphertext, byte[] privateKeyBytes, RSAEncryptionPadding padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

        return rsa.Decrypt(ciphertext, padding);
    }

    private static byte[] DecryptX25519ChaCha20Poly1305(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, X25519AeadCipher.ChaCha20Poly1305);
    }

    private static byte[] DecryptX25519XChaCha20Poly1305(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, X25519AeadCipher.XChaCha20Poly1305);
    }

    private static byte[] DecryptX25519AesGcm(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, X25519AeadCipher.AesGcm);
    }

    private static byte[] DecryptX25519Hybrid(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey, X25519AeadCipher cipher)
    {
        if (ephemeralPublicKey == null)
            throw new InvalidOperationException("Encapsulated key (ephemeral public key) must be set using WithEncapsulatedKey() for X25519 hybrid decryption");

        // Compute shared secret via X25519 key agreement
        var sharedSecret = Curve25519Core.ComputeSharedSecret(privateKey, ephemeralPublicKey);

        try
        {
            // Derive symmetric key using HKDF
            var symmetricKey = HkdfCore.DeriveKey(
                sharedSecret,
                salt: [],
                info: System.Text.Encoding.UTF8.GetBytes("X25519-Hybrid-Encryption"),
                length: 32,
                HashAlgorithmName.SHA256);

            try
            {
                // Decrypt with the selected AEAD cipher
                return cipher switch
                {
                    X25519AeadCipher.ChaCha20Poly1305 => ChaCha20Poly1305Core.Decrypt(ciphertext, symmetricKey, nonce, aad),
                    X25519AeadCipher.XChaCha20Poly1305 => XChaCha20Poly1305Core.Decrypt(ciphertext, symmetricKey, nonce, aad),
                    X25519AeadCipher.AesGcm => AesGcmCore.Decrypt(ciphertext, symmetricKey, nonce, aad),
                    _ => throw new NotSupportedException($"Cipher {cipher} is not supported")
                };
            }
            finally
            {
                SecureMemoryOperations.SecureClear(symmetricKey);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(sharedSecret);
        }
    }
#endif

    private enum X25519AeadCipher
    {
        ChaCha20Poly1305,
        XChaCha20Poly1305,
        AesGcm
    }

#if NET10_OR_GREATER
#pragma warning disable SYSLIB5006
    private static byte[] DecryptMLKemAesGcm(byte[] ciphertext, byte[] secretKeyPemBytes, byte[] nonce, byte[] aad, byte[]? encapsulatedKey)
    {
        if (encapsulatedKey == null)
            throw new InvalidOperationException("Encapsulated key must be set using WithEncapsulatedKey() for ML-KEM hybrid decryption");

        var secretKeyPem = System.Text.Encoding.UTF8.GetString(secretKeyPemBytes);

        using var importedKey = System.Security.Cryptography.MLKem.ImportFromPem(secretKeyPem);
        var sharedSecret = importedKey.Decapsulate(encapsulatedKey);

        try
        {
            return AesGcmCore.Decrypt(ciphertext, sharedSecret, nonce, aad);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(sharedSecret);
        }
    }

    private static byte[] DecryptMLKemChaCha20Poly1305(byte[] ciphertext, byte[] secretKeyPemBytes, byte[] nonce, byte[] aad, byte[]? encapsulatedKey)
    {
        if (encapsulatedKey == null)
            throw new InvalidOperationException("Encapsulated key must be set using WithEncapsulatedKey() for ML-KEM hybrid decryption");

        var secretKeyPem = System.Text.Encoding.UTF8.GetString(secretKeyPemBytes);

        using var importedKey = System.Security.Cryptography.MLKem.ImportFromPem(secretKeyPem);
        var sharedSecret = importedKey.Decapsulate(encapsulatedKey);

        try
        {
            return ChaCha20Poly1305Core.Decrypt(ciphertext, sharedSecret, nonce, aad);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(sharedSecret);
        }
    }
#pragma warning restore SYSLIB5006
#endif
}
