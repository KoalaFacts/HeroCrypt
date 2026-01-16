using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Rabbit;

/// <summary>
/// Fluent builder for Rabbit stream cipher operations.
/// High-speed stream cipher designed for software performance (RFC 4503).
/// Part of the eSTREAM portfolio (software profile).
/// </summary>
/// <example>
/// <code>
/// // Transform data with IV (encryption and decryption use the same operation)
/// using var builder = RabbitBuilder.Create()
///     .WithKey(key)
///     .WithIv(iv);
/// var ciphertext = builder.Transform(plaintext);
/// var decrypted = builder.Transform(ciphertext);
///
/// // Transform data without IV (key-only mode)
/// using var builder2 = RabbitBuilder.Create()
///     .WithKey(key);
/// var ciphertext2 = builder2.Transform(plaintext);
/// </code>
/// </example>
public sealed class RabbitBuilder : IDisposable
{
    private const int KeySize = RabbitCore.KEY_SIZE;
    private const int IvSize = RabbitCore.IV_SIZE;

    private byte[]? key;
    private byte[]? iv;
    private bool disposed;

    private RabbitBuilder() { }

    /// <summary>
    /// Creates a new Rabbit builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static RabbitBuilder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The 16-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    /// <exception cref="ArgumentException">If key is not 16 bytes.</exception>
    public RabbitBuilder WithKey(byte[] key)
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
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The 16-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If key is not 16 bytes.</exception>
    public RabbitBuilder WithKey(ReadOnlySpan<byte> key)
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
    /// Sets the initialization vector (optional for Rabbit).
    /// </summary>
    /// <param name="iv">The 8-byte initialization vector.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If iv is null.</exception>
    /// <exception cref="ArgumentException">If iv is not 8 bytes.</exception>
    public RabbitBuilder WithIv(byte[] iv)
    {
        ArgumentHelper.ThrowIfNull(iv);
        if (iv.Length != IvSize)
        {
            throw new ArgumentException($"IV must be {IvSize} bytes, but was {iv.Length} bytes.", nameof(iv));
        }

        ClearIv();
        this.iv = [.. iv];
        return this;
    }

    /// <summary>
    /// Sets the initialization vector (optional for Rabbit).
    /// </summary>
    /// <param name="iv">The 8-byte initialization vector.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If iv is not 8 bytes.</exception>
    public RabbitBuilder WithIv(ReadOnlySpan<byte> iv)
    {
        if (iv.Length != IvSize)
        {
            throw new ArgumentException($"IV must be {IvSize} bytes, but was {iv.Length} bytes.", nameof(iv));
        }

        ClearIv();
        this.iv = iv.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random IV and sets it.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public RabbitBuilder WithRandomIv()
    {
        ClearIv();
        iv = new byte[IvSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(iv);
        return this;
    }

    /// <summary>
    /// Transforms the input data using the Rabbit stream cipher.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <returns>The transformed data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    /// <exception cref="ArgumentNullException">If input is null.</exception>
    public byte[] Transform(byte[] input)
    {
        ArgumentHelper.ThrowIfNull(input);
        return Transform(input.AsSpan());
    }

    /// <summary>
    /// Transforms the input data using the Rabbit stream cipher.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <returns>The transformed data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public byte[] Transform(ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var output = new byte[input.Length];
        RabbitCore.Transform(output, input, key!, iv ?? ReadOnlySpan<byte>.Empty);
        return output;
    }

    /// <summary>
    /// Transforms the input data into the provided buffer.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="output">The output buffer (must be at least input.Length bytes).</param>
    /// <param name="input">The data to transform.</param>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key is not set.</exception>
    public void Transform(Span<byte> output, ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        RabbitCore.Transform(output, input, key!, iv ?? ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Gets the IV that was set or generated.
    /// </summary>
    /// <returns>A copy of the IV bytes, or null if no IV was set.</returns>
    public byte[]? GetIv()
    {
        return iv != null ? [.. iv] : null;
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

    private void ClearIv()
    {
        if (iv != null)
        {
            SecureMemoryOperations.SecureClear(iv);
            iv = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearKey();
            ClearIv();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
