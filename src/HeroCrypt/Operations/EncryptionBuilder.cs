using System.Security.Cryptography;
using HeroCrypt.Operations.Internal;
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
/// Result of an encryption operation.
/// </summary>
public readonly struct EncryptionResult
{
    /// <summary>
    /// The ciphertext (encrypted data).
    /// </summary>
    public readonly byte[] Ciphertext { get; init; }

    /// <summary>
    /// The nonce/IV used for encryption (needed for decryption).
    /// </summary>
    public readonly byte[] Nonce { get; init; }

    /// <summary>
    /// Optional: Ciphertext for the encapsulated key (for hybrid encryption).
    /// </summary>
    public readonly byte[]? EncapsulatedKey { get; init; }

    /// <summary>
    /// Gets the ciphertext as a lowercase hexadecimal string.
    /// </summary>
    public string CiphertextAsHex => TextEncodings.ToHexLower(Ciphertext);

    /// <summary>
    /// Gets the ciphertext as a Base64-encoded string.
    /// </summary>
    public string CiphertextAsBase64 => Convert.ToBase64String(Ciphertext);

    /// <summary>
    /// Gets the ciphertext as a URL-safe Base64-encoded string (no padding).
    /// </summary>
    public string CiphertextAsBase64Url => TextEncodings.ToBase64Url(Ciphertext);

    /// <summary>
    /// Gets the nonce as a lowercase hexadecimal string.
    /// </summary>
    public string NonceAsHex => TextEncodings.ToHexLower(Nonce);

    /// <summary>
    /// Gets the nonce as a Base64-encoded string.
    /// </summary>
    public string NonceAsBase64 => Convert.ToBase64String(Nonce);

    /// <summary>
    /// Gets the nonce as a URL-safe Base64-encoded string (no padding).
    /// </summary>
    public string NonceAsBase64Url => TextEncodings.ToBase64Url(Nonce);

    /// <summary>
    /// Gets the encapsulated key as a lowercase hexadecimal string (for hybrid encryption).
    /// Returns null if no encapsulated key is present.
    /// </summary>
    public string? EncapsulatedKeyAsHex => EncapsulatedKey != null
        ? TextEncodings.ToHexLower(EncapsulatedKey)
        : null;

    /// <summary>
    /// Gets the encapsulated key as a Base64-encoded string (for hybrid encryption).
    /// Returns null if no encapsulated key is present.
    /// </summary>
    public string? EncapsulatedKeyAsBase64 => EncapsulatedKey != null
        ? Convert.ToBase64String(EncapsulatedKey)
        : null;

    /// <summary>
    /// Gets the encapsulated key as a URL-safe Base64-encoded string (for hybrid encryption).
    /// Returns null if no encapsulated key is present.
    /// </summary>
    public string? EncapsulatedKeyAsBase64Url => EncapsulatedKey != null
        ? TextEncodings.ToBase64Url(EncapsulatedKey)
        : null;
}

/// <summary>
/// Fluent builder for encryption operations.
/// </summary>
/// <remarks>
/// <para>
/// This builder implements <see cref="IDisposable"/> to securely clear sensitive key material
/// from memory when the builder is no longer needed. It is recommended to use this builder
/// within a <c>using</c> statement.
/// </para>
/// <para>
/// This class is thread-safe. All public methods can be safely called from multiple threads concurrently.
/// </para>
/// <example>
/// <para><b>Basic encryption:</b></para>
/// <code>
/// using var builder = HeroCryptBuilder.Encrypt()
///     .WithAesGcm()
///     .WithKey(key);
/// var result = builder.Encrypt(plaintext);
/// </code>
/// </example>
/// <example>
/// <para><b>Encryption with text encoding (for storage/transmission):</b></para>
/// <code>
/// using var builder = HeroCryptBuilder.Encrypt()
///     .WithChaCha20Poly1305()
///     .WithRandomKey();
/// var result = builder.Encrypt("secret message");
///
/// // Get values as text for storage
/// string keyBase64 = builder.GetKeyAsBase64();
/// string ciphertextBase64 = result.CiphertextAsBase64;
/// string nonceBase64 = result.NonceAsBase64;
/// </code>
/// </example>
/// </remarks>
public sealed class EncryptionBuilder : IDisposable
{
    private readonly SyncLock syncLock = new();
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private bool deterministicMode;
    private bool disposed;

    /// <summary>
    /// Sets the encryption algorithm to use.
    /// </summary>
    /// <param name="algorithm">The encryption algorithm.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public EncryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            this.algorithm = algorithm;
            return this;
        }
    }

    /// <summary>
    /// Use AES-GCM for encryption (default).
    /// </summary>
    public EncryptionBuilder WithAesGcm() => WithAlgorithm(EncryptionAlgorithm.AesGcm);

    /// <summary>
    /// Use AES-CCM for encryption.
    /// </summary>
    public EncryptionBuilder WithAesCcm() => WithAlgorithm(EncryptionAlgorithm.AesCcm);

    /// <summary>
    /// Use AES-OCB for encryption (high-performance AEAD).
    /// </summary>
    public EncryptionBuilder WithAesOcb() => WithAlgorithm(EncryptionAlgorithm.AesOcb);

    /// <summary>
    /// Use AES-SIV for encryption (nonce-misuse resistant).
    /// </summary>
    public EncryptionBuilder WithAesSiv() => WithAlgorithm(EncryptionAlgorithm.AesSiv);

    /// <summary>
    /// Use ChaCha20-Poly1305 for encryption.
    /// </summary>
    public EncryptionBuilder WithChaCha20Poly1305() => WithAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305);

    /// <summary>
    /// Use XChaCha20-Poly1305 for encryption.
    /// </summary>
    public EncryptionBuilder WithXChaCha20Poly1305() => WithAlgorithm(EncryptionAlgorithm.XChaCha20Poly1305);

    /// <summary>
    /// Use RSA-OAEP with SHA-256 for encryption.
    /// </summary>
    public EncryptionBuilder WithRsaOaep() => WithAlgorithm(EncryptionAlgorithm.RsaOaepSha256);

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The encryption key. A copy is made internally.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public EncryptionBuilder WithKey(byte[] key)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            ClearKey();
            this.key = [.. key];
            return this;
        }
    }

    /// <summary>
    /// Sets the encryption key from a hexadecimal string.
    /// </summary>
    /// <param name="hexKey">The key as a hexadecimal string (case-insensitive).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">If the string is not a valid hexadecimal string.</exception>
    /// <example>
    /// <code>
    /// // Load a 256-bit key from hex (64 hex chars = 32 bytes)
    /// using var builder = HeroCryptBuilder.Encrypt()
    ///     .WithAesGcm()
    ///     .WithKeyFromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    /// </code>
    /// </example>
    /// <seealso cref="WithKeyFromBase64"/>
    /// <seealso cref="WithKeyFromBase64Url"/>
    public EncryptionBuilder WithKeyFromHex(string hexKey)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromHexString(hexKey);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the encryption key from a Base64-encoded string.
    /// </summary>
    /// <param name="base64Key">The key as a Base64-encoded string.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">If the string is not valid Base64.</exception>
    /// <example>
    /// <code>
    /// // Load a key from standard Base64 (with padding)
    /// using var builder = HeroCryptBuilder.Encrypt()
    ///     .WithAesGcm()
    ///     .WithKeyFromBase64("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");
    /// </code>
    /// </example>
    /// <seealso cref="WithKeyFromHex"/>
    /// <seealso cref="WithKeyFromBase64Url"/>
    public EncryptionBuilder WithKeyFromBase64(string base64Key)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromBase64String(base64Key);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the encryption key from a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="base64UrlKey">The key as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">If the string is not valid URL-safe Base64.</exception>
    /// <remarks>
    /// URL-safe Base64 uses '-' instead of '+', '_' instead of '/', and may omit padding '=' characters.
    /// This method accepts both padded and unpadded URL-safe Base64 strings.
    /// </remarks>
    /// <example>
    /// <code>
    /// // Load a key from URL-safe Base64 (ideal for query strings and URLs)
    /// using var builder = HeroCryptBuilder.Encrypt()
    ///     .WithAesGcm()
    ///     .WithKeyFromBase64Url("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    /// </code>
    /// </example>
    /// <seealso cref="WithKeyFromHex"/>
    /// <seealso cref="WithKeyFromBase64"/>
    public EncryptionBuilder WithKeyFromBase64Url(string base64UrlKey)
    {
        ThrowIfDisposed();
        var keyBytes = TextEncodings.FromBase64Url(base64UrlKey);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Generates a cryptographically secure random key of the default size for the selected algorithm.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="NotSupportedException">If the algorithm does not support symmetric key generation (e.g., RSA, X25519, ML-KEM).</exception>
    /// <remarks>
    /// <para>Default key sizes:</para>
    /// <list type="bullet">
    /// <item>AES-GCM, AES-CCM, AES-OCB: 32 bytes (256-bit)</item>
    /// <item>ChaCha20-Poly1305, XChaCha20-Poly1305: 32 bytes</item>
    /// <item>AES-SIV: 64 bytes (two 256-bit keys)</item>
    /// </list>
    /// <para>Use <see cref="GetKey()"/> to retrieve the generated key for storage.</para>
    /// </remarks>
    public EncryptionBuilder WithRandomKey()
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            var keySize = GetDefaultKeySize(algorithm);
            return WithRandomKeyCore(keySize);
        }
    }

    /// <summary>
    /// Generates a cryptographically secure random key of the specified size.
    /// </summary>
    /// <param name="keySize">The key size in bytes.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">If the key size is not valid.</exception>
    public EncryptionBuilder WithRandomKey(int keySize)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            return WithRandomKeyCore(keySize);
        }
    }

    private EncryptionBuilder WithRandomKeyCore(int keySize)
    {
        if (keySize <= 0)
            throw new ArgumentOutOfRangeException(nameof(keySize), "Key size must be positive");

        ClearKey();
        key = RandomNumberGenerator.GetBytes(keySize);
        return this;
    }

    /// <summary>
    /// Gets the current encryption key.
    /// </summary>
    /// <returns>A copy of the encryption key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If the key has not been set.</exception>
    /// <remarks>
    /// Returns a copy of the key to prevent external modification.
    /// Useful after calling <see cref="WithRandomKey()"/> to store the generated key.
    /// </remarks>
    public byte[] GetKey()
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            return GetKeyCore();
        }
    }

    private byte[] GetKeyCore()
    {
        if (key == null)
            throw new InvalidOperationException("Key must be set using WithKey() or WithRandomKey()");
        return [.. key];
    }

    /// <summary>
    /// Gets the current encryption key as a lowercase hexadecimal string.
    /// </summary>
    /// <returns>The encryption key as a hex string.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If the key has not been set.</exception>
    /// <seealso cref="GetKeyAsBase64"/>
    /// <seealso cref="GetKeyAsBase64Url"/>
    public string GetKeyAsHex()
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            var keyBytes = GetKeyCore();
            return TextEncodings.ToHexLower(keyBytes);
        }
    }

    /// <summary>
    /// Gets the current encryption key as a Base64-encoded string.
    /// </summary>
    /// <returns>The encryption key as a Base64 string.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If the key has not been set.</exception>
    /// <seealso cref="GetKeyAsHex"/>
    /// <seealso cref="GetKeyAsBase64Url"/>
    public string GetKeyAsBase64()
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            var keyBytes = GetKeyCore();
            return Convert.ToBase64String(keyBytes);
        }
    }

    /// <summary>
    /// Gets the current encryption key as a URL-safe Base64-encoded string (no padding).
    /// </summary>
    /// <returns>The encryption key as a URL-safe Base64 string.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If the key has not been set.</exception>
    /// <seealso cref="GetKeyAsHex"/>
    /// <seealso cref="GetKeyAsBase64"/>
    public string GetKeyAsBase64Url()
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            var keyBytes = GetKeyCore();
            return TextEncodings.ToBase64Url(keyBytes);
        }
    }

    private static int GetDefaultKeySize(EncryptionAlgorithm algorithm)
    {
        return algorithm switch
        {
            EncryptionAlgorithm.AesGcm => 32,
            EncryptionAlgorithm.AesCcm => 32,
            EncryptionAlgorithm.AesOcb => 32,
            EncryptionAlgorithm.ChaCha20Poly1305 => 32,
            EncryptionAlgorithm.XChaCha20Poly1305 => 32,
            EncryptionAlgorithm.AesSiv => 64,
            EncryptionAlgorithm.RsaOaepSha256 or
            EncryptionAlgorithm.RsaOaepSha384 or
            EncryptionAlgorithm.RsaOaepSha512 or
            EncryptionAlgorithm.RsaPkcs1v15 =>
                throw new NotSupportedException("RSA encryption uses public keys, not symmetric keys. Use WithKey() with an RSA public key."),
            EncryptionAlgorithm.X25519ChaCha20Poly1305 or
            EncryptionAlgorithm.X25519XChaCha20Poly1305 or
            EncryptionAlgorithm.X25519AesGcm =>
                throw new NotSupportedException("X25519 hybrid encryption uses recipient public keys. Use WithKey() with the recipient's public key."),
#if NET10_OR_GREATER
            EncryptionAlgorithm.MLKem768AesGcm or
            EncryptionAlgorithm.MLKem1024AesGcm or
            EncryptionAlgorithm.MLKem768ChaCha20Poly1305 or
            EncryptionAlgorithm.MLKem1024ChaCha20Poly1305 =>
                throw new NotSupportedException("ML-KEM hybrid encryption uses recipient public keys. Use WithKey() with the recipient's public key."),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} does not support random key generation")
        };
    }

    /// <summary>
    /// Sets a specific nonce/IV for encryption.
    /// When not set, a secure random nonce is auto-generated (recommended).
    /// </summary>
    /// <param name="nonce">The nonce/IV. A copy is made internally.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <remarks>
    /// WARNING: Nonce reuse with the same key is catastrophic for most AEAD algorithms
    /// (AES-GCM, ChaCha20-Poly1305, etc.). Only use this if you have a specific requirement
    /// and understand the security implications. AES-SIV is the only algorithm that is
    /// nonce-misuse resistant.
    /// </remarks>
    public EncryptionBuilder WithNonce(byte[] nonce)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            ClearNonce();
            this.nonce = [.. nonce];
            return this;
        }
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD).
    /// </summary>
    /// <param name="associatedData">The associated data. A copy is made internally.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public EncryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            ClearAssociatedData();
            this.associatedData = [.. associatedData];
            return this;
        }
    }

    /// <summary>
    /// Sets optional authenticated associated data from a string (UTF-8 encoded).
    /// </summary>
    /// <param name="associatedData">The associated data as a string (will be UTF-8 encoded).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <remarks>
    /// Common use case: authenticate metadata like file names, user IDs, or context strings
    /// that should be verified during decryption but don't need to be encrypted.
    /// </remarks>
    public EncryptionBuilder WithAssociatedData(string associatedData)
    {
        return WithAssociatedData(System.Text.Encoding.UTF8.GetBytes(associatedData));
    }

    /// <summary>
    /// Enables deterministic encryption mode.
    /// When enabled and no nonce is provided, uses empty nonce for RFC-compliant deterministic encryption.
    /// </summary>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <remarks>
    /// <para>WARNING: Deterministic encryption has security implications:</para>
    /// <list type="bullet">
    /// <item>Same plaintext + key produces identical ciphertext (reveals duplicate messages)</item>
    /// <item>For AES-SIV: Safe, designed for nonce-misuse resistance</item>
    /// <item>For other algorithms (AES-GCM, ChaCha20-Poly1305): Dangerous, only use for testing or specific protocols</item>
    /// </list>
    /// </remarks>
    public EncryptionBuilder WithDeterministicMode()
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            deterministicMode = true;
            return this;
        }
    }

    /// <summary>
    /// Encrypts the plaintext and returns the result containing ciphertext and nonce.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The encryption result containing ciphertext and nonce.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If the key has not been set.</exception>
    public EncryptionResult Encrypt(byte[] plaintext)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();

            if (key == null)
                throw new InvalidOperationException("Encryption key must be set using WithKey()");

            InputValidator.ValidateByteArray(plaintext, nameof(plaintext), allowEmpty: true);
            InputValidator.ValidateByteArray(key, nameof(key));

            if (associatedData != null)
                InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);

            if (nonce != null)
                InputValidator.ValidateByteArray(nonce, nameof(nonce), allowEmpty: true);

            var aad = associatedData ?? [];
            ReadOnlySpan<byte> nonceSpan = nonce ?? default;

            return algorithm switch
            {
                EncryptionAlgorithm.AesGcm => EncryptAesGcm(plaintext, key, nonceSpan, aad, deterministicMode),
                EncryptionAlgorithm.AesCcm => EncryptAesCcm(plaintext, key, nonceSpan, aad, deterministicMode),
                EncryptionAlgorithm.AesOcb => EncryptAesOcb(plaintext, key, nonceSpan, aad, deterministicMode),
                EncryptionAlgorithm.AesSiv => EncryptAesSiv(plaintext, key, nonceSpan, aad, deterministicMode),
                EncryptionAlgorithm.ChaCha20Poly1305 => EncryptChaCha20Poly1305(plaintext, key, nonceSpan, aad, deterministicMode),
                EncryptionAlgorithm.XChaCha20Poly1305 => EncryptXChaCha20Poly1305(plaintext, key, nonceSpan, aad, deterministicMode),
                EncryptionAlgorithm.RsaOaepSha256 => EncryptRsa(plaintext, key, RSAEncryptionPadding.OaepSHA256),
                EncryptionAlgorithm.RsaOaepSha384 => EncryptRsa(plaintext, key, RSAEncryptionPadding.OaepSHA384),
                EncryptionAlgorithm.RsaOaepSha512 => EncryptRsa(plaintext, key, RSAEncryptionPadding.OaepSHA512),
                EncryptionAlgorithm.RsaPkcs1v15 => EncryptRsa(plaintext, key, RSAEncryptionPadding.Pkcs1),
                EncryptionAlgorithm.X25519ChaCha20Poly1305 => EncryptX25519ChaCha20Poly1305(plaintext, key, aad),
                EncryptionAlgorithm.X25519XChaCha20Poly1305 => EncryptX25519XChaCha20Poly1305(plaintext, key, aad),
                EncryptionAlgorithm.X25519AesGcm => EncryptX25519AesGcm(plaintext, key, aad),
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
                EncryptionAlgorithm.MLKem768AesGcm => EncryptMLKemAesGcm(plaintext, key, aad),
                EncryptionAlgorithm.MLKem1024AesGcm => EncryptMLKemAesGcm(plaintext, key, aad),
                EncryptionAlgorithm.MLKem768ChaCha20Poly1305 => EncryptMLKemChaCha20Poly1305(plaintext, key, aad),
                EncryptionAlgorithm.MLKem1024ChaCha20Poly1305 => EncryptMLKemChaCha20Poly1305(plaintext, key, aad),
#endif
                _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
            };
        }
    }

    /// <summary>
    /// Encrypts the plaintext string (UTF-8 encoded) and returns the result containing ciphertext and nonce.
    /// </summary>
    /// <param name="plaintext">The string data to encrypt (will be UTF-8 encoded).</param>
    /// <returns>The encryption result containing ciphertext and nonce.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If the key has not been set.</exception>
    public EncryptionResult Encrypt(string plaintext)
    {
        return Encrypt(System.Text.Encoding.UTF8.GetBytes(plaintext));
    }

    private static EncryptionResult EncryptAesGcm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesGcmCore.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptAesCcm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesCcmCore.Encrypt(plaintext, key, nonce, aad, deterministicMode: deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptAesOcb(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesOcbCore.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptAesSiv(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesSivCore.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptChaCha20Poly1305(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptXChaCha20Poly1305(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

#if NETSTANDARD2_0
    private static EncryptionResult EncryptRsa(byte[] plaintext, byte[] publicKeyBytes, RSAEncryptionPadding padding)
    {
        _ = plaintext;
        _ = publicKeyBytes;
        _ = padding;
        throw new PlatformNotSupportedException("RSA key import is not supported on .NET Standard 2.0.");
    }

    private static EncryptionResult EncryptX25519ChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, HybridCipherType.ChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519XChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, HybridCipherType.XChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519AesGcm(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, HybridCipherType.AesGcm);
    }

    private static EncryptionResult EncryptX25519Hybrid(byte[] plaintext, byte[] recipientPublicKey, byte[] aad, HybridCipherType cipher)
    {
        _ = plaintext;
        _ = recipientPublicKey;
        _ = aad;
        _ = cipher;
        throw new PlatformNotSupportedException("X25519 hybrid encryption is not supported on .NET Standard 2.0.");
    }
#else
    private static EncryptionResult EncryptRsa(byte[] plaintext, byte[] publicKeyBytes, RSAEncryptionPadding padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        var ciphertext = rsa.Encrypt(plaintext, padding);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = []
        };
    }

    private static EncryptionResult EncryptX25519ChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, HybridCipherType.ChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519XChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, HybridCipherType.XChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519AesGcm(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, HybridCipherType.AesGcm);
    }

    private static EncryptionResult EncryptX25519Hybrid(byte[] plaintext, byte[] recipientPublicKey, byte[] aad, HybridCipherType cipher)
    {
        // Generate ephemeral key pair
        var ephemeralPrivateKey = Curve25519Core.GeneratePrivateKey();
        var ephemeralPublicKey = Curve25519Core.DerivePublicKey(ephemeralPrivateKey);

        try
        {
            // Compute shared secret via X25519 key agreement
            var sharedSecret = Curve25519Core.ComputeSharedSecret(ephemeralPrivateKey, recipientPublicKey);

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
                    // Encrypt with the selected AEAD cipher
                    var (ciphertext, nonce) = cipher switch
                    {
                        HybridCipherType.ChaCha20Poly1305 => EncryptWithChaCha20Poly1305(plaintext, symmetricKey, aad),
                        HybridCipherType.XChaCha20Poly1305 => EncryptWithXChaCha20Poly1305(plaintext, symmetricKey, aad),
                        HybridCipherType.AesGcm => EncryptWithAesGcm(plaintext, symmetricKey, aad),
                        _ => throw new NotSupportedException($"Cipher {cipher} is not supported")
                    };

                    return new EncryptionResult
                    {
                        Ciphertext = ciphertext,
                        Nonce = nonce,
                        EncapsulatedKey = ephemeralPublicKey
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
        finally
        {
            SecureMemoryOperations.SecureClear(ephemeralPrivateKey);
        }
    }

    private static (byte[] Ciphertext, byte[] Nonce) EncryptWithChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] aad)
    {
        var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, associatedData: aad);
        return (result.Ciphertext, result.Nonce);
    }

    private static (byte[] Ciphertext, byte[] Nonce) EncryptWithXChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] aad)
    {
        var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, associatedData: aad);
        return (result.Ciphertext, result.Nonce);
    }

    private static (byte[] Ciphertext, byte[] Nonce) EncryptWithAesGcm(byte[] plaintext, byte[] key, byte[] aad)
    {
        var result = AesGcmCore.Encrypt(plaintext, key, associatedData: aad);
        return (result.Ciphertext, result.Nonce);
    }
#endif

    private void ThrowIfDisposed()
    {
#if NETSTANDARD2_0
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(EncryptionBuilder));
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

    /// <summary>
    /// Securely clears all sensitive data (key, nonce, associated data) from memory.
    /// </summary>
    public void Dispose()
    {
        using (syncLock.EnterScope())
        {
            if (disposed) return;
            ClearKey();
            ClearNonce();
            ClearAssociatedData();
            disposed = true;
        }
        GC.SuppressFinalize(this);
    }

#if NET10_OR_GREATER
#pragma warning disable SYSLIB5006
    private static EncryptionResult EncryptMLKemAesGcm(byte[] plaintext, byte[] publicKeyPemBytes, byte[] aad)
    {
        var publicKeyPem = System.Text.Encoding.UTF8.GetString(publicKeyPemBytes);

        using var encapsulation = MLKemCore.Encapsulate(publicKeyPem);

        var result = AesGcmCore.Encrypt(plaintext, encapsulation.SharedSecret, associatedData: aad);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce,
            EncapsulatedKey = encapsulation.Ciphertext
        };
    }

    private static EncryptionResult EncryptMLKemChaCha20Poly1305(byte[] plaintext, byte[] publicKeyPemBytes, byte[] aad)
    {
        var publicKeyPem = System.Text.Encoding.UTF8.GetString(publicKeyPemBytes);

        using var encapsulation = MLKemCore.Encapsulate(publicKeyPem);

        var result = ChaCha20Poly1305Core.Encrypt(plaintext, encapsulation.SharedSecret, associatedData: aad);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce,
            EncapsulatedKey = encapsulation.Ciphertext
        };
    }
#pragma warning restore SYSLIB5006
#endif
}
