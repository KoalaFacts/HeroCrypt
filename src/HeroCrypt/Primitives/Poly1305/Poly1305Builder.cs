using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Poly1305;

/// <summary>
/// Fluent builder for Poly1305 message authentication code operations.
/// Provides authentication according to RFC 8439.
/// </summary>
/// <example>
/// <code>
/// // Compute MAC
/// using var builder = Poly1305Builder.Create()
///     .WithKey(key);
/// var mac = builder.ComputeMac(message);
///
/// // Verify MAC
/// using var verifier = Poly1305Builder.Create()
///     .WithKey(key);
/// bool isValid = verifier.VerifyMac(mac, message);
///
/// // Generate random key
/// using var builder = Poly1305Builder.Create()
///     .WithRandomKey();
/// var key = builder.GetKey();
/// var mac = builder.ComputeMac(message);
/// </code>
/// </example>
public sealed class Poly1305Builder : IDisposable
{
    private const int KeySize = Poly1305Core.KEY_SIZE;
    private const int TagSize = Poly1305Core.TAG_SIZE;

    private byte[]? key;
    private bool disposed;

    private Poly1305Builder() { }

    /// <summary>
    /// Creates a new Poly1305 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Poly1305Builder Create() => new();

    /// <summary>
    /// Sets the authentication key.
    /// </summary>
    /// <param name="key">The 32-byte key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    /// <exception cref="ArgumentException">If key is not 32 bytes.</exception>
    public Poly1305Builder WithKey(byte[] key)
    {
        ArgumentHelper.ThrowIfNull(key);
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes, but was {key.Length} bytes.", nameof(key));
        }

        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the authentication key.
    /// </summary>
    /// <param name="key">The 32-byte key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If key is not 32 bytes.</exception>
    public Poly1305Builder WithKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes, but was {key.Length} bytes.", nameof(key));
        }

        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random key and sets it.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Poly1305Builder WithRandomKey()
    {
        ClearKey();
        key = new byte[KeySize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return this;
    }

    /// <summary>
    /// Computes the Poly1305 MAC for the given message.
    /// </summary>
    /// <param name="message">The message to authenticate.</param>
    /// <returns>The 16-byte authentication tag.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If message is null.</exception>
    public byte[] ComputeMac(byte[] message)
    {
        ArgumentHelper.ThrowIfNull(message);
        return ComputeMac(message.AsSpan());
    }

    /// <summary>
    /// Computes the Poly1305 MAC for the given message.
    /// </summary>
    /// <param name="message">The message to authenticate.</param>
    /// <returns>The 16-byte authentication tag.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public byte[] ComputeMac(ReadOnlySpan<byte> message)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var tag = new byte[TagSize];
        Poly1305Core.ComputeMac(tag, message, key!);
        return tag;
    }

    /// <summary>
    /// Computes the Poly1305 MAC into the provided buffer.
    /// </summary>
    /// <param name="tag">The output buffer for the tag (must be 16 bytes).</param>
    /// <param name="message">The message to authenticate.</param>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentException">If tag is not 16 bytes.</exception>
    public void ComputeMac(Span<byte> tag, ReadOnlySpan<byte> message)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        Poly1305Core.ComputeMac(tag, message, key!);
    }

    /// <summary>
    /// Verifies a Poly1305 MAC for the given message.
    /// </summary>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="message">The message that was authenticated.</param>
    /// <returns>True if the MAC is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If tag or message is null.</exception>
    public bool VerifyMac(byte[] tag, byte[] message)
    {
        ArgumentHelper.ThrowIfNull(tag);
        ArgumentHelper.ThrowIfNull(message);
        return VerifyMac(tag.AsSpan(), message.AsSpan());
    }

    /// <summary>
    /// Verifies a Poly1305 MAC for the given message.
    /// </summary>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="message">The message that was authenticated.</param>
    /// <returns>True if the MAC is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public bool VerifyMac(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return Poly1305Core.VerifyMac(tag, message, key!);
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
