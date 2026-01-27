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
/// Fluent builder for decryption operations.
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
/// <para><b>Basic decryption with AES-GCM:</b></para>
/// <code>
/// using var builder = HeroCryptBuilder.Decrypt()
///     .WithAesGcm()
///     .WithKey(key)
///     .WithNonce(encryptionResult.Nonce);
/// byte[] plaintext = builder.Decrypt(encryptionResult.Ciphertext);
/// </code>
/// </example>
/// <example>
/// <para><b>Using FromEncryptionResult for simplified workflow:</b></para>
/// <code>
/// using var builder = HeroCryptBuilder.Decrypt()
///     .FromEncryptionResult(result)
///     .WithAesGcm()
///     .WithKey(key);
/// string message = builder.DecryptToString(result.Ciphertext);
/// </code>
/// </example>
/// </remarks>
public sealed class DecryptionBuilder : IDisposable
{
    private readonly SyncLock syncLock = new();
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
        using (syncLock.EnterScope())
        {
            if (disposed) return;
            ClearKey();
            ClearNonce();
            ClearAssociatedData();
            ClearEncapsulatedKey();
            disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Sets the encryption algorithm to use.
    /// </summary>
    public DecryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            this.algorithm = algorithm;
            return this;
        }
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
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            ClearKey();
            this.key = [.. key];
            return this;
        }
    }

    /// <summary>
    /// Sets the decryption key from a hexadecimal string.
    /// </summary>
    /// <param name="hexKey">The key as a hexadecimal string (case-insensitive).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid hexadecimal.</exception>
    /// <remarks>
    /// This is a convenience method for using keys that have been stored as hex strings.
    /// Commonly used with keys retrieved from <c>EncryptionBuilder.GetKeyAsHex()</c>.
    /// </remarks>
    public DecryptionBuilder WithKeyFromHex(string hexKey)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromHexString(hexKey);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the decryption key from a Base64-encoded string.
    /// </summary>
    /// <param name="base64Key">The key as a Base64-encoded string.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid Base64.</exception>
    /// <remarks>
    /// This is a convenience method for using keys that have been stored as Base64 strings.
    /// Commonly used with keys retrieved from <c>EncryptionBuilder.GetKeyAsBase64()</c>.
    /// </remarks>
    public DecryptionBuilder WithKeyFromBase64(string base64Key)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromBase64String(base64Key);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the decryption key from a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="base64UrlKey">The key as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid URL-safe Base64.</exception>
    /// <remarks>
    /// <para>
    /// This is a convenience method for using keys that have been stored as URL-safe Base64 strings.
    /// Commonly used with keys retrieved from <c>EncryptionBuilder.GetKeyAsBase64Url()</c>.
    /// </para>
    /// <para>
    /// URL-safe Base64 uses '-' instead of '+', '_' instead of '/', and may omit padding '=' characters.
    /// </para>
    /// </remarks>
    public DecryptionBuilder WithKeyFromBase64Url(string base64UrlKey)
    {
        ThrowIfDisposed();
        var keyBytes = TextEncodings.FromBase64Url(base64UrlKey);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the nonce used during encryption.
    /// </summary>
    public DecryptionBuilder WithNonce(byte[] nonce)
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
    /// Sets the nonce from a hexadecimal string.
    /// </summary>
    /// <param name="hexNonce">The nonce as a hexadecimal string (case-insensitive).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid hexadecimal.</exception>
    /// <remarks>
    /// This is a convenience method for using nonces that have been stored as hex strings.
    /// </remarks>
    public DecryptionBuilder WithNonceFromHex(string hexNonce)
    {
        ThrowIfDisposed();
        var nonceBytes = Convert.FromHexString(hexNonce);
        return WithNonce(nonceBytes);
    }

    /// <summary>
    /// Sets the nonce from a Base64-encoded string.
    /// </summary>
    /// <param name="base64Nonce">The nonce as a Base64-encoded string.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid Base64.</exception>
    /// <remarks>
    /// This is a convenience method for using nonces that have been stored as Base64 strings.
    /// </remarks>
    public DecryptionBuilder WithNonceFromBase64(string base64Nonce)
    {
        ThrowIfDisposed();
        var nonceBytes = Convert.FromBase64String(base64Nonce);
        return WithNonce(nonceBytes);
    }

    /// <summary>
    /// Sets the nonce from a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="base64UrlNonce">The nonce as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid URL-safe Base64.</exception>
    /// <remarks>
    /// <para>
    /// This is a convenience method for using nonces that have been stored as URL-safe Base64 strings.
    /// </para>
    /// <para>
    /// URL-safe Base64 uses '-' instead of '+', '_' instead of '/', and may omit padding '=' characters.
    /// </para>
    /// </remarks>
    public DecryptionBuilder WithNonceFromBase64Url(string base64UrlNonce)
    {
        ThrowIfDisposed();
        var nonceBytes = TextEncodings.FromBase64Url(base64UrlNonce);
        return WithNonce(nonceBytes);
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD).
    /// </summary>
    public DecryptionBuilder WithAssociatedData(byte[] associatedData)
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
    /// Use the same string value that was used during encryption to authenticate the data.
    /// </remarks>
    public DecryptionBuilder WithAssociatedData(string associatedData)
    {
        return WithAssociatedData(System.Text.Encoding.UTF8.GetBytes(associatedData));
    }

    /// <summary>
    /// Sets the encapsulated key for hybrid encryption.
    /// </summary>
    public DecryptionBuilder WithEncapsulatedKey(byte[] encapsulatedKey)
    {
        using (syncLock.EnterScope())
        {
            ThrowIfDisposed();
            ClearEncapsulatedKey();
            this.encapsulatedKey = [.. encapsulatedKey];
            return this;
        }
    }

    /// <summary>
    /// Sets the encapsulated key for hybrid encryption from a hexadecimal string.
    /// </summary>
    /// <param name="hexEncapsulatedKey">The encapsulated key as a hexadecimal string (case-insensitive).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid hexadecimal.</exception>
    /// <remarks>
    /// This is a convenience method for using encapsulated keys that have been stored as hex strings.
    /// Commonly used with keys from <c>EncryptionResult.EncapsulatedKeyAsHex</c>.
    /// </remarks>
    public DecryptionBuilder WithEncapsulatedKeyFromHex(string hexEncapsulatedKey)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromHexString(hexEncapsulatedKey);
        return WithEncapsulatedKey(keyBytes);
    }

    /// <summary>
    /// Sets the encapsulated key for hybrid encryption from a Base64-encoded string.
    /// </summary>
    /// <param name="base64EncapsulatedKey">The encapsulated key as a Base64-encoded string.</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid Base64.</exception>
    /// <remarks>
    /// This is a convenience method for using encapsulated keys that have been stored as Base64 strings.
    /// Commonly used with keys from <c>EncryptionResult.EncapsulatedKeyAsBase64</c>.
    /// </remarks>
    public DecryptionBuilder WithEncapsulatedKeyFromBase64(string base64EncapsulatedKey)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromBase64String(base64EncapsulatedKey);
        return WithEncapsulatedKey(keyBytes);
    }

    /// <summary>
    /// Sets the encapsulated key for hybrid encryption from a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="base64UrlEncapsulatedKey">The encapsulated key as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>This builder for method chaining.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="FormatException">Thrown if the string is not valid URL-safe Base64.</exception>
    /// <remarks>
    /// <para>
    /// This is a convenience method for using encapsulated keys that have been stored as URL-safe Base64 strings.
    /// Commonly used with keys from <c>EncryptionResult.EncapsulatedKeyAsBase64Url</c>.
    /// </para>
    /// <para>
    /// URL-safe Base64 uses '-' instead of '+', '_' instead of '/', and may omit padding '=' characters.
    /// </para>
    /// </remarks>
    public DecryptionBuilder WithEncapsulatedKeyFromBase64Url(string base64UrlEncapsulatedKey)
    {
        ThrowIfDisposed();
        var keyBytes = TextEncodings.FromBase64Url(base64UrlEncapsulatedKey);
        return WithEncapsulatedKey(keyBytes);
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
        using (syncLock.EnterScope())
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
    }

    /// <summary>
    /// Decrypts the ciphertext and returns the plaintext.
    /// </summary>
    /// <exception cref="CryptographicException">Thrown when authentication fails.</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        using (syncLock.EnterScope())
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
    }

    /// <summary>
    /// Decrypts the ciphertext and returns the plaintext as a UTF-8 string.
    /// </summary>
    /// <param name="ciphertext">The encrypted data to decrypt.</param>
    /// <returns>The decrypted plaintext as a UTF-8 string.</returns>
    /// <exception cref="CryptographicException">Thrown when authentication fails.</exception>
    /// <exception cref="System.Text.DecoderFallbackException">Thrown if the decrypted bytes are not valid UTF-8.</exception>
    /// <remarks>
    /// This is a convenience method for decrypting data that was originally encrypted as a UTF-8 string.
    /// The decrypted bytes are converted to a string using UTF-8 encoding.
    /// </remarks>
    public string DecryptToString(byte[] ciphertext)
    {
        var plaintext = Decrypt(ciphertext);
        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Decrypts ciphertext provided as a hexadecimal string.
    /// </summary>
    /// <param name="hexCiphertext">The ciphertext as a hexadecimal string (case-insensitive).</param>
    /// <returns>The decrypted plaintext as bytes.</returns>
    /// <exception cref="FormatException">Thrown if the string is not valid hexadecimal.</exception>
    /// <remarks>
    /// This is a convenience method for decrypting ciphertext that has been encoded as hex.
    /// Use this when receiving ciphertext from APIs or databases that store data as hex strings.
    /// </remarks>
    public byte[] DecryptFromHex(string hexCiphertext)
    {
        var ciphertext = Convert.FromHexString(hexCiphertext);
        return Decrypt(ciphertext);
    }

    /// <summary>
    /// Decrypts ciphertext provided as a hexadecimal string and returns the result as a UTF-8 string.
    /// </summary>
    /// <param name="hexCiphertext">The ciphertext as a hexadecimal string (case-insensitive).</param>
    /// <returns>The decrypted plaintext as a UTF-8 string.</returns>
    /// <exception cref="FormatException">Thrown if the input is not valid hexadecimal.</exception>
    /// <exception cref="System.Text.DecoderFallbackException">Thrown if the decrypted bytes are not valid UTF-8.</exception>
    public string DecryptFromHexToString(string hexCiphertext)
    {
        var plaintext = DecryptFromHex(hexCiphertext);
        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Decrypts ciphertext provided as a Base64-encoded string.
    /// </summary>
    /// <param name="base64Ciphertext">The ciphertext as a Base64-encoded string.</param>
    /// <returns>The decrypted plaintext as bytes.</returns>
    /// <exception cref="FormatException">Thrown if the string is not valid Base64.</exception>
    /// <remarks>
    /// This is a convenience method for decrypting ciphertext that has been encoded as Base64.
    /// Use this when receiving ciphertext from APIs or storage that use Base64 encoding.
    /// </remarks>
    public byte[] DecryptFromBase64(string base64Ciphertext)
    {
        var ciphertext = Convert.FromBase64String(base64Ciphertext);
        return Decrypt(ciphertext);
    }

    /// <summary>
    /// Decrypts ciphertext provided as a Base64-encoded string and returns the result as a UTF-8 string.
    /// </summary>
    /// <param name="base64Ciphertext">The ciphertext as a Base64-encoded string.</param>
    /// <returns>The decrypted plaintext as a UTF-8 string.</returns>
    /// <exception cref="FormatException">Thrown if the input is not valid Base64.</exception>
    /// <exception cref="System.Text.DecoderFallbackException">Thrown if the decrypted bytes are not valid UTF-8.</exception>
    public string DecryptFromBase64ToString(string base64Ciphertext)
    {
        var plaintext = DecryptFromBase64(base64Ciphertext);
        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Decrypts ciphertext provided as a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="base64UrlCiphertext">The ciphertext as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>The decrypted plaintext as bytes.</returns>
    /// <exception cref="FormatException">Thrown if the string is not valid URL-safe Base64.</exception>
    /// <remarks>
    /// <para>
    /// This is a convenience method for decrypting ciphertext that has been encoded as URL-safe Base64.
    /// </para>
    /// <para>
    /// URL-safe Base64 uses '-' instead of '+', '_' instead of '/', and may omit padding '=' characters.
    /// </para>
    /// </remarks>
    public byte[] DecryptFromBase64Url(string base64UrlCiphertext)
    {
        var ciphertext = TextEncodings.FromBase64Url(base64UrlCiphertext);
        return Decrypt(ciphertext);
    }

    /// <summary>
    /// Decrypts ciphertext provided as a URL-safe Base64-encoded string and returns the result as a UTF-8 string.
    /// </summary>
    /// <param name="base64UrlCiphertext">The ciphertext as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>The decrypted plaintext as a UTF-8 string.</returns>
    /// <exception cref="FormatException">Thrown if the input is not valid URL-safe Base64.</exception>
    /// <exception cref="System.Text.DecoderFallbackException">Thrown if the decrypted bytes are not valid UTF-8.</exception>
    /// <example>
    /// <para><b>Complete round-trip workflow with URL-safe Base64:</b></para>
    /// <code>
    /// // Encryption
    /// using var encryptor = HeroCryptBuilder.Encrypt()
    ///     .WithAesGcm()
    ///     .WithRandomKey();
    ///
    /// var result = encryptor.Encrypt("Hello, World!");
    /// var keyHex = encryptor.GetKeyAsHex();
    ///
    /// // Store/transmit as URL-safe strings (ideal for APIs)
    /// var payload = new { c = result.CiphertextAsBase64Url, n = result.NonceAsBase64Url };
    ///
    /// // Decryption
    /// var plaintext = HeroCryptBuilder.Decrypt()
    ///     .WithAesGcm()
    ///     .WithKeyFromHex(keyHex)
    ///     .WithNonceFromBase64Url(payload.n)
    ///     .DecryptFromBase64UrlToString(payload.c);
    /// </code>
    /// </example>
    public string DecryptFromBase64UrlToString(string base64UrlCiphertext)
    {
        var plaintext = DecryptFromBase64Url(base64UrlCiphertext);
        return System.Text.Encoding.UTF8.GetString(plaintext);
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
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, HybridCipherType.ChaCha20Poly1305);
    }

    private static byte[] DecryptX25519XChaCha20Poly1305(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, HybridCipherType.XChaCha20Poly1305);
    }

    private static byte[] DecryptX25519AesGcm(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, HybridCipherType.AesGcm);
    }

    private static byte[] DecryptX25519Hybrid(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey, HybridCipherType cipher)
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
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, HybridCipherType.ChaCha20Poly1305);
    }

    private static byte[] DecryptX25519XChaCha20Poly1305(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, HybridCipherType.XChaCha20Poly1305);
    }

    private static byte[] DecryptX25519AesGcm(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey)
    {
        return DecryptX25519Hybrid(ciphertext, privateKey, nonce, aad, ephemeralPublicKey, HybridCipherType.AesGcm);
    }

    private static byte[] DecryptX25519Hybrid(byte[] ciphertext, byte[] privateKey, byte[] nonce, byte[] aad, byte[]? ephemeralPublicKey, HybridCipherType cipher)
    {
        if (ephemeralPublicKey == null)
            throw new InvalidOperationException("Encapsulated key must be set using WithEncapsulatedKey() or FromEncryptionResult()");

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
                    HybridCipherType.ChaCha20Poly1305 => ChaCha20Poly1305Core.Decrypt(ciphertext, symmetricKey, nonce, aad),
                    HybridCipherType.XChaCha20Poly1305 => XChaCha20Poly1305Core.Decrypt(ciphertext, symmetricKey, nonce, aad),
                    HybridCipherType.AesGcm => AesGcmCore.Decrypt(ciphertext, symmetricKey, nonce, aad),
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

#if NET10_OR_GREATER
#pragma warning disable SYSLIB5006
    private static byte[] DecryptMLKemAesGcm(byte[] ciphertext, byte[] secretKeyPemBytes, byte[] nonce, byte[] aad, byte[]? encapsulatedKey)
    {
        if (encapsulatedKey == null)
            throw new InvalidOperationException("Encapsulated key must be set using WithEncapsulatedKey() or FromEncryptionResult()");

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
            throw new InvalidOperationException("Encapsulated key must be set using WithEncapsulatedKey() or FromEncryptionResult()");

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
