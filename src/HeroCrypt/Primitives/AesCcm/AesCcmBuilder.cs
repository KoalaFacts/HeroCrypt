using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.AesCcm;

/// <summary>
/// Fluent builder for AES-CCM AEAD encryption operations.
/// Provides authenticated encryption according to RFC 3610 and NIST SP 800-38C.
/// </summary>
/// <remarks>
/// <para>
/// AES-CCM is widely used in IoT protocols including Bluetooth LE, Zigbee, Thread, and 802.15.4.
/// </para>
/// <para><b>Platform Support:</b></para>
/// <list type="bullet">
///   <item>
///     <term>Windows</term>
///     <description>Fully supported via Windows CNG.</description>
///   </item>
///   <item>
///     <term>Linux</term>
///     <description>Fully supported via OpenSSL.</description>
///   </item>
///   <item>
///     <term>macOS</term>
///     <description>
///       Not supported. The macOS Security framework does not implement
///       the CCM mode. Operations will throw <see cref="PlatformNotSupportedException"/>.
///       Use AES-GCM as an alternative on macOS.
///     </description>
///   </item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// // Encrypt data with custom tag size
/// using var builder = AesCcmBuilder.Create()
///     .WithKey(key)
///     .WithNonce(nonce)
///     .WithAssociatedData(aad)
///     .WithTagSize(16);
/// var ciphertext = builder.Encrypt(plaintext);
///
/// // Decrypt data
/// using var decryptor = AesCcmBuilder.Create()
///     .WithKey(key)
///     .WithNonce(nonce)
///     .WithAssociatedData(aad)
///     .WithTagSize(16);
/// var plaintext = decryptor.Decrypt(ciphertext);
/// </code>
/// </example>
public sealed class AesCcmBuilder : IDisposable
{
    private const int DefaultNonceSize = 13;
    private const int DefaultTagSize = 16;

    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private int tagSize = DefaultTagSize;
    private bool disposed;

    private AesCcmBuilder() { }

    /// <summary>
    /// Creates a new AES-CCM builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static AesCcmBuilder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The encryption key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    public AesCcmBuilder WithKey(byte[] key)
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
    public AesCcmBuilder WithKey(ReadOnlySpan<byte> key)
    {
        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The nonce (7-13 bytes, typically 13).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If nonce is null.</exception>
    public AesCcmBuilder WithNonce(byte[] nonce)
    {
        ArgumentHelper.ThrowIfNull(nonce);
        ClearNonce();
        this.nonce = [.. nonce];
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The nonce (7-13 bytes, typically 13).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesCcmBuilder WithNonce(ReadOnlySpan<byte> nonce)
    {
        ClearNonce();
        this.nonce = nonce.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random nonce and sets it.
    /// </summary>
    /// <param name="nonceSize">The nonce size in bytes (default is 13).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesCcmBuilder WithRandomNonce(int nonceSize = DefaultNonceSize)
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
    public AesCcmBuilder WithAssociatedData(byte[]? associatedData)
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
    public AesCcmBuilder WithAssociatedData(ReadOnlySpan<byte> associatedData)
    {
        ClearAssociatedData();
        this.associatedData = associatedData.IsEmpty ? null : associatedData.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the authentication tag size.
    /// </summary>
    /// <param name="tagSize">The tag size in bytes (4-16 bytes, even numbers only per RFC 3610).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public AesCcmBuilder WithTagSize(int tagSize)
    {
        ArgumentHelper.ThrowIfNegative(tagSize);
        this.tagSize = tagSize;
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

        var result = AesCcmCore.Encrypt(plaintext, key, nonce, associatedData ?? ReadOnlySpan<byte>.Empty, tagSize);
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

        return AesCcmCore.Decrypt(ciphertext, key, nonce, associatedData ?? ReadOnlySpan<byte>.Empty, tagSize);
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

    /// <summary>
    /// Gets the ciphertext length for a given plaintext length.
    /// </summary>
    /// <param name="plaintextLength">The plaintext length.</param>
    /// <returns>The ciphertext length including authentication tag.</returns>
    public int GetCiphertextLength(int plaintextLength)
    {
        ArgumentHelper.ThrowIfNegative(plaintextLength);
        return plaintextLength + tagSize;
    }

    /// <summary>
    /// Gets the plaintext length for a given ciphertext length.
    /// </summary>
    /// <param name="ciphertextLength">The ciphertext length including authentication tag.</param>
    /// <returns>The plaintext length.</returns>
    public int GetPlaintextLength(int ciphertextLength)
    {
        if (ciphertextLength < tagSize)
        {
            throw new ArgumentException($"Ciphertext must be at least {tagSize} bytes.", nameof(ciphertextLength));
        }

        return ciphertextLength - tagSize;
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
