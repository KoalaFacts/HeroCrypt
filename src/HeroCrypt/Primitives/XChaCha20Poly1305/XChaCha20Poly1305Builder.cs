using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.XChaCha20Poly1305;

/// <summary>
/// Fluent builder for XChaCha20-Poly1305 AEAD encryption operations.
/// Provides authenticated encryption with extended 24-byte nonces.
/// </summary>
/// <example>
/// <code>
/// // Encrypt data with extended nonce
/// using var builder = XChaCha20Poly1305Builder.Create()
///     .WithKey(key)
///     .WithRandomNonce()
///     .WithAssociatedData(aad);
/// var ciphertext = builder.Encrypt(plaintext);
/// var nonce = builder.GetNonce();
///
/// // Decrypt data
/// using var decryptor = XChaCha20Poly1305Builder.Create()
///     .WithKey(key)
///     .WithNonce(nonce)
///     .WithAssociatedData(aad);
/// var plaintext = decryptor.Decrypt(ciphertext);
/// </code>
/// </example>
public sealed class XChaCha20Poly1305Builder : IDisposable
{
    private const int DefaultNonceSize = 24;

    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private bool disposed;

    private XChaCha20Poly1305Builder() { }

    /// <summary>
    /// Creates a new XChaCha20-Poly1305 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static XChaCha20Poly1305Builder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The 32-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    public XChaCha20Poly1305Builder WithKey(byte[] key)
    {
        ArgumentHelper.ThrowIfNull(key);
        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The 32-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public XChaCha20Poly1305Builder WithKey(ReadOnlySpan<byte> key)
    {
        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the extended nonce (number used once).
    /// </summary>
    /// <param name="nonce">The 24-byte nonce.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If nonce is null.</exception>
    public XChaCha20Poly1305Builder WithNonce(byte[] nonce)
    {
        ArgumentHelper.ThrowIfNull(nonce);
        ClearNonce();
        this.nonce = [.. nonce];
        return this;
    }

    /// <summary>
    /// Sets the extended nonce (number used once).
    /// </summary>
    /// <param name="nonce">The 24-byte nonce.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public XChaCha20Poly1305Builder WithNonce(ReadOnlySpan<byte> nonce)
    {
        ClearNonce();
        this.nonce = nonce.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random nonce and sets it.
    /// The 24-byte nonce allows safe random generation without collision concerns.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public XChaCha20Poly1305Builder WithRandomNonce()
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
    public XChaCha20Poly1305Builder WithAssociatedData(byte[]? associatedData)
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
    public XChaCha20Poly1305Builder WithAssociatedData(ReadOnlySpan<byte> associatedData)
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
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var result = XChaCha20Poly1305Core.Encrypt(plaintext, key!, nonce!, associatedData ?? ReadOnlySpan<byte>.Empty);
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
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return XChaCha20Poly1305Core.Decrypt(ciphertext, key!, nonce!, associatedData ?? ReadOnlySpan<byte>.Empty);
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
        if (key != null)
        {
            SecureMemoryOperations.SecureClear(key);
            key = null;
        }
    }

    private void ClearNonce()
    {
        if (nonce != null)
        {
            SecureMemoryOperations.SecureClear(nonce);
            nonce = null;
        }
    }

    private void ClearAssociatedData()
    {
        if (associatedData != null)
        {
            SecureMemoryOperations.SecureClear(associatedData);
            associatedData = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearKey();
            ClearNonce();
            ClearAssociatedData();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
