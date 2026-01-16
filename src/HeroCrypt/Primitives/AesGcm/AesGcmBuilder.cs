using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.AesGcm;

/// <summary>
/// Fluent builder for AES-GCM AEAD encryption operations.
/// Provides authenticated encryption according to NIST SP 800-38D.
/// </summary>
/// <remarks>
/// <para>
/// AES-GCM is the most widely used AEAD cipher, supported by TLS 1.2/1.3,
/// IPsec, and many other protocols.
/// </para>
/// <para>
/// <b>Platform Support:</b> AES-GCM is not supported on .NET Standard 2.0.
/// Use ChaCha20-Poly1305 or XChaCha20-Poly1305 as alternatives.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Encrypt data
/// using var builder = AesGcmBuilder.Create()
///     .WithKey(key)
///     .WithRandomNonce()
///     .WithAssociatedData(aad);
/// var ciphertext = builder.Encrypt(plaintext);
/// var nonce = builder.GetNonce();
///
/// // Decrypt data
/// using var decryptor = AesGcmBuilder.Create()
///     .WithKey(key)
///     .WithNonce(nonce)
///     .WithAssociatedData(aad);
/// var plaintext = decryptor.Decrypt(ciphertext);
/// </code>
/// </example>
public sealed class AesGcmBuilder : IDisposable
{
    private const int DefaultNonceSize = 12;

    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private bool disposed;

    private AesGcmBuilder() { }

    /// <summary>
    /// Creates a new AES-GCM builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static AesGcmBuilder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The encryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    public AesGcmBuilder WithKey(byte[] key)
    {
        ArgumentHelper.ThrowIfNull(key);
        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The encryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesGcmBuilder WithKey(ReadOnlySpan<byte> key)
    {
        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The nonce (12 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If nonce is null.</exception>
    public AesGcmBuilder WithNonce(byte[] nonce)
    {
        ArgumentHelper.ThrowIfNull(nonce);
        ClearNonce();
        this.nonce = [.. nonce];
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The nonce (12 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesGcmBuilder WithNonce(ReadOnlySpan<byte> nonce)
    {
        ClearNonce();
        this.nonce = nonce.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random nonce and sets it.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public AesGcmBuilder WithRandomNonce()
    {
        ClearNonce();
        nonce = new byte[DefaultNonceSize];
        SecureRandomNumberGenerator.Fill(nonce);
        return this;
    }

    /// <summary>
    /// Sets the associated data for authentication.
    /// </summary>
    /// <param name="associatedData">The associated data to authenticate (not encrypted).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesGcmBuilder WithAssociatedData(byte[]? associatedData)
    {
        ClearAssociatedData();
        this.associatedData = associatedData != null ? [.. associatedData] : null;
        return this;
    }

    /// <summary>
    /// Sets the associated data for authentication.
    /// </summary>
    /// <param name="associatedData">The associated data to authenticate (not encrypted).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesGcmBuilder WithAssociatedData(ReadOnlySpan<byte> associatedData)
    {
        ClearAssociatedData();
        this.associatedData = associatedData.IsEmpty ? null : associatedData.ToArray();
        return this;
    }

    /// <summary>
    /// Encrypts the plaintext and returns the ciphertext with authentication tag.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The ciphertext including authentication tag.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    /// <exception cref="ArgumentNullException">If plaintext is null.</exception>
    /// <exception cref="PlatformNotSupportedException">On .NET Standard 2.0.</exception>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentHelper.ThrowIfNull(plaintext);
        return Encrypt(plaintext.AsSpan());
    }

    /// <summary>
    /// Encrypts the plaintext and returns the ciphertext with authentication tag.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The ciphertext including authentication tag.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    /// <exception cref="PlatformNotSupportedException">On .NET Standard 2.0.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var result = AesGcmCore.Encrypt(plaintext, key, nonce, associatedData ?? ReadOnlySpan<byte>.Empty);
        return result.Ciphertext;
    }

    /// <summary>
    /// Decrypts the ciphertext and verifies the authentication tag.
    /// </summary>
    /// <param name="ciphertext">The ciphertext including authentication tag.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    /// <exception cref="ArgumentNullException">If ciphertext is null.</exception>
    /// <exception cref="CryptographicException">If authentication fails.</exception>
    /// <exception cref="PlatformNotSupportedException">On .NET Standard 2.0.</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentHelper.ThrowIfNull(ciphertext);
        return Decrypt(ciphertext.AsSpan());
    }

    /// <summary>
    /// Decrypts the ciphertext and verifies the authentication tag.
    /// </summary>
    /// <param name="ciphertext">The ciphertext including authentication tag.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    /// <exception cref="CryptographicException">If authentication fails.</exception>
    /// <exception cref="PlatformNotSupportedException">On .NET Standard 2.0.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return AesGcmCore.Decrypt(ciphertext, key, nonce, associatedData ?? ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Gets the nonce that was set or generated.
    /// </summary>
    /// <returns>A copy of the nonce bytes.</returns>
    /// <exception cref="InvalidOperationException">If nonce is not set.</exception>
    public byte[] GetNonce()
    {
        if (nonce == null)
        {
            throw new InvalidOperationException("Nonce has not been set. Use WithNonce() or WithRandomNonce() first.");
        }

        return [.. nonce];
    }

    private void ValidateState()
    {
        if (key == null)
        {
            throw new InvalidOperationException("Key has not been set. Use WithKey() first.");
        }

        if (nonce == null)
        {
            throw new InvalidOperationException("Nonce has not been set. Use WithNonce() or WithRandomNonce() first.");
        }
    }

    private void ClearKey()
    {
        if (key == null)
            return;

        SecureMemoryOperations.SecureClear(key);
        key = null;
    }

    private void ClearNonce()
    {
        if (nonce == null)
            return;

        SecureMemoryOperations.SecureClear(nonce);
        nonce = null;
    }

    private void ClearAssociatedData()
    {
        if (associatedData == null)
            return;

        SecureMemoryOperations.SecureClear(associatedData);
        associatedData = null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (disposed)
            return;

        ClearKey();
        ClearNonce();
        ClearAssociatedData();
        disposed = true;
        GC.SuppressFinalize(this);
    }
}
