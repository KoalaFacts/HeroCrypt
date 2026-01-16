using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.AesSiv;

/// <summary>
/// Fluent builder for AES-SIV AEAD encryption operations.
/// Provides deterministic authenticated encryption according to RFC 5297.
/// </summary>
/// <remarks>
/// <para>
/// AES-SIV is a nonce-misuse resistant AEAD cipher that provides deterministic
/// authenticated encryption. This makes it suitable for scenarios where nonce
/// uniqueness cannot be guaranteed or where deterministic encryption is required.
/// </para>
/// <para>
/// Unlike other AEAD modes, AES-SIV can safely handle repeated nonces and
/// provides the best possible security even when nonces are reused.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Encrypt data with nonce
/// using var builder = AesSivBuilder.Create()
///     .WithKey(key)
///     .WithNonce(nonce)
///     .WithAssociatedData(aad);
/// var ciphertext = builder.Encrypt(plaintext);
///
/// // Decrypt data
/// using var decryptor = AesSivBuilder.Create()
///     .WithKey(key)
///     .WithNonce(nonce)
///     .WithAssociatedData(aad);
/// var plaintext = decryptor.Decrypt(ciphertext);
///
/// // Deterministic encryption (same plaintext always produces same ciphertext)
/// using var deterministicBuilder = AesSivBuilder.Create()
///     .WithKey(key)
///     .WithAssociatedData(aad);
/// var ciphertext1 = deterministicBuilder.Encrypt(plaintext);
/// var ciphertext2 = deterministicBuilder.Encrypt(plaintext);
/// // ciphertext1 equals ciphertext2
/// </code>
/// </example>
public sealed class AesSivBuilder : IDisposable
{
    private const int DefaultNonceSize = 16;

    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private bool disposed;

    private AesSivBuilder() { }

    /// <summary>
    /// Creates a new AES-SIV builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static AesSivBuilder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The encryption key (32, 48, or 64 bytes for AES-SIV-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    public AesSivBuilder WithKey(byte[] key)
    {
        ArgumentHelper.ThrowIfNull(key);
        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The encryption key (32, 48, or 64 bytes for AES-SIV-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesSivBuilder WithKey(ReadOnlySpan<byte> key)
    {
        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The nonce (can be any length, including empty for deterministic encryption).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <remarks>
    /// Unlike other AEAD modes, AES-SIV is nonce-misuse resistant and can safely
    /// handle repeated or empty nonces. An empty nonce produces deterministic encryption
    /// where the same plaintext always produces the same ciphertext.
    /// </remarks>
    public AesSivBuilder WithNonce(byte[]? nonce)
    {
        ClearNonce();
        this.nonce = nonce != null ? [.. nonce] : null;
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The nonce (can be any length, including empty for deterministic encryption).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <remarks>
    /// Unlike other AEAD modes, AES-SIV is nonce-misuse resistant and can safely
    /// handle repeated or empty nonces. An empty nonce produces deterministic encryption
    /// where the same plaintext always produces the same ciphertext.
    /// </remarks>
    public AesSivBuilder WithNonce(ReadOnlySpan<byte> nonce)
    {
        ClearNonce();
        this.nonce = nonce.IsEmpty ? null : nonce.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random nonce and sets it.
    /// </summary>
    /// <param name="nonceSize">The nonce size in bytes (default is 16).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesSivBuilder WithRandomNonce(int nonceSize = DefaultNonceSize)
    {
        ArgumentHelper.ThrowIfNegative(nonceSize);
        ClearNonce();
        nonce = new byte[nonceSize];
        SecureRandomNumberGenerator.Fill(nonce);
        return this;
    }

    /// <summary>
    /// Sets the associated data for authentication.
    /// </summary>
    /// <param name="associatedData">The associated data to authenticate (not encrypted).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesSivBuilder WithAssociatedData(byte[]? associatedData)
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
    public AesSivBuilder WithAssociatedData(ReadOnlySpan<byte> associatedData)
    {
        ClearAssociatedData();
        this.associatedData = associatedData.IsEmpty ? null : associatedData.ToArray();
        return this;
    }

    /// <summary>
    /// Encrypts the plaintext and returns the ciphertext with SIV.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The SIV followed by ciphertext.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If plaintext is null.</exception>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentHelper.ThrowIfNull(plaintext);
        return Encrypt(plaintext.AsSpan());
    }

    /// <summary>
    /// Encrypts the plaintext and returns the ciphertext with SIV.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The SIV followed by ciphertext.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var result = AesSivCore.Encrypt(plaintext, key!, nonce ?? ReadOnlySpan<byte>.Empty, associatedData ?? ReadOnlySpan<byte>.Empty);
        return result.Ciphertext;
    }

    /// <summary>
    /// Decrypts the ciphertext and verifies the SIV.
    /// </summary>
    /// <param name="ciphertext">The SIV followed by ciphertext.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If ciphertext is null.</exception>
    /// <exception cref="CryptographicException">If authentication fails.</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ArgumentHelper.ThrowIfNull(ciphertext);
        return Decrypt(ciphertext.AsSpan());
    }

    /// <summary>
    /// Decrypts the ciphertext and verifies the SIV.
    /// </summary>
    /// <param name="ciphertext">The SIV followed by ciphertext.</param>
    /// <returns>The decrypted plaintext.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="CryptographicException">If authentication fails.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return AesSivCore.Decrypt(ciphertext, key!, nonce ?? ReadOnlySpan<byte>.Empty, associatedData ?? ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Gets the nonce that was set or generated.
    /// </summary>
    /// <returns>A copy of the nonce bytes, or null if no nonce was set.</returns>
    public byte[]? GetNonce()
    {
        if (nonce == null)
        {
            return null;
        }

        return [.. nonce];
    }

    private void ValidateState()
    {
        if (key == null)
        {
            throw new InvalidOperationException("Key has not been set. Use WithKey() first.");
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
