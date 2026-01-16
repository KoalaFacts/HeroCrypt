using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.AesCmac;

/// <summary>
/// Fluent builder for AES-CMAC message authentication code operations.
/// Provides authentication according to RFC 4493.
/// </summary>
/// <example>
/// <code>
/// // Compute CMAC with AES-128
/// using var builder = AesCmacBuilder.Create()
///     .WithKey(key128);
/// var tag = builder.ComputeTag(data);
///
/// // Compute CMAC with AES-256
/// using var builder = AesCmacBuilder.Create()
///     .WithKey(key256);
/// var tag = builder.ComputeTag(data);
///
/// // Generate random key
/// using var builder = AesCmacBuilder.Create()
///     .WithRandomKey(32); // AES-256
/// var key = builder.GetKey();
/// var tag = builder.ComputeTag(data);
/// </code>
/// </example>
public sealed class AesCmacBuilder : IDisposable
{
    private const int KeySize128 = 16;
    private const int KeySize192 = 24;
    private const int KeySize256 = 32;
    private const int TagSize = 16;

    private byte[]? key;
    private bool disposed;

    private AesCmacBuilder() { }

    /// <summary>
    /// Creates a new AES-CMAC builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static AesCmacBuilder Create() => new();

    /// <summary>
    /// Sets the AES key.
    /// </summary>
    /// <param name="key">The AES key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    /// <exception cref="ArgumentException">If key is not 16, 24, or 32 bytes.</exception>
    public AesCmacBuilder WithKey(byte[] key)
    {
        ArgumentHelper.ThrowIfNull(key);
        ValidateKeySize(key.Length);

        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the AES key.
    /// </summary>
    /// <param name="key">The AES key (16, 24, or 32 bytes for AES-128/192/256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If key is not 16, 24, or 32 bytes.</exception>
    public AesCmacBuilder WithKey(ReadOnlySpan<byte> key)
    {
        ValidateKeySize(key.Length);

        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random key and sets it.
    /// </summary>
    /// <param name="keySize">The key size in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256, default: 32).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If key size is not 16, 24, or 32 bytes.</exception>
    public AesCmacBuilder WithRandomKey(int keySize = KeySize256)
    {
        ValidateKeySize(keySize);

        ClearKey();
        key = new byte[keySize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return this;
    }

    /// <summary>
    /// Computes the AES-CMAC tag for the given data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The 16-byte authentication tag.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If data is null.</exception>
    public byte[] ComputeTag(byte[] data)
    {
        ArgumentHelper.ThrowIfNull(data);
        return ComputeTag(data.AsSpan());
    }

    /// <summary>
    /// Computes the AES-CMAC tag for the given data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The 16-byte authentication tag.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public byte[] ComputeTag(ReadOnlySpan<byte> data)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var tag = new byte[TagSize];
        AesCmacCore.ComputeTag(tag, data, key!);
        return tag;
    }

    /// <summary>
    /// Computes the AES-CMAC tag into the provided buffer.
    /// </summary>
    /// <param name="tag">The output buffer for the tag (must be at least 16 bytes).</param>
    /// <param name="data">The data to authenticate.</param>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentException">If tag is less than 16 bytes.</exception>
    public void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> data)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        AesCmacCore.ComputeTag(tag, data, key!);
    }

    /// <summary>
    /// Verifies an AES-CMAC tag for the given data.
    /// </summary>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="data">The data that was authenticated.</param>
    /// <returns>True if the tag is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If tag or data is null.</exception>
    public bool VerifyTag(byte[] tag, byte[] data)
    {
        ArgumentHelper.ThrowIfNull(tag);
        ArgumentHelper.ThrowIfNull(data);
        return VerifyTag(tag.AsSpan(), data.AsSpan());
    }

    /// <summary>
    /// Verifies an AES-CMAC tag for the given data.
    /// </summary>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="data">The data that was authenticated.</param>
    /// <returns>True if the tag is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> data)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return AesCmacCore.VerifyTag(tag, data, key!);
    }

    /// <summary>
    /// Gets the key that was set or generated.
    /// </summary>
    /// <returns>A copy of the key bytes.</returns>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public byte[] GetKey()
    {
        if (key == null)
        {
            throw new InvalidOperationException("Key has not been set. Use WithKey() or WithRandomKey() first.");
        }

        return [.. key];
    }

    private void ValidateKeySize(int keySize)
    {
        if (keySize is not KeySize128 and not KeySize192 and not KeySize256)
        {
            throw new ArgumentException(
                $"Key must be {KeySize128}, {KeySize192}, or {KeySize256} bytes (AES-128/192/256), but was {keySize} bytes.",
                nameof(keySize));
        }
    }

    private void ValidateState()
    {
        if (key == null)
        {
            throw new InvalidOperationException("Key has not been set. Use WithKey() or WithRandomKey() first.");
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

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearKey();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
