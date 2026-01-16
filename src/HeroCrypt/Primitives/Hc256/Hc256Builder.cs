using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Hc256;

/// <summary>
/// Fluent builder for HC-256 stream cipher operations.
/// Part of the eSTREAM portfolio (Profile 1: Software).
/// Designed by Hongjun Wu - extension of HC-128 with 256-bit security.
/// </summary>
/// <example>
/// <code>
/// // Transform data (encryption and decryption use the same operation)
/// using var builder = Hc256Builder.Create()
///     .WithKey(key)
///     .WithIv(iv);
/// var ciphertext = builder.Transform(plaintext);
/// var decrypted = builder.Transform(ciphertext);
/// </code>
/// </example>
public sealed class Hc256Builder : IDisposable
{
    private const int KeySize = Hc256Core.KEY_SIZE;
    private const int IvSize = Hc256Core.IV_SIZE;

    private byte[]? key;
    private byte[]? iv;
    private bool disposed;

    private Hc256Builder() { }

    /// <summary>
    /// Creates a new HC-256 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Hc256Builder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The 32-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    /// <exception cref="ArgumentException">If key is not 32 bytes.</exception>
    public Hc256Builder WithKey(byte[] key)
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
    /// <param name="key">The 32-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If key is not 32 bytes.</exception>
    public Hc256Builder WithKey(ReadOnlySpan<byte> key)
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
    /// Sets the initialization vector.
    /// </summary>
    /// <param name="iv">The 32-byte initialization vector.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If iv is null.</exception>
    /// <exception cref="ArgumentException">If iv is not 32 bytes.</exception>
    public Hc256Builder WithIv(byte[] iv)
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
    /// Sets the initialization vector.
    /// </summary>
    /// <param name="iv">The 32-byte initialization vector.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If iv is not 32 bytes.</exception>
    public Hc256Builder WithIv(ReadOnlySpan<byte> iv)
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
    public Hc256Builder WithRandomIv()
    {
        ClearIv();
        iv = new byte[IvSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(iv);
        return this;
    }

    /// <summary>
    /// Transforms the input data using the HC-256 stream cipher.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <returns>The transformed data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or IV is not set.</exception>
    /// <exception cref="ArgumentNullException">If input is null.</exception>
    public byte[] Transform(byte[] input)
    {
        ArgumentHelper.ThrowIfNull(input);
        return Transform(input.AsSpan());
    }

    /// <summary>
    /// Transforms the input data using the HC-256 stream cipher.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <returns>The transformed data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or IV is not set.</exception>
    public byte[] Transform(ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var output = new byte[input.Length];
        Hc256Core.Transform(output, input, key!, iv!);
        return output;
    }

    /// <summary>
    /// Transforms the input data into the provided buffer.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="output">The output buffer (must be at least input.Length bytes).</param>
    /// <param name="input">The data to transform.</param>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or IV is not set.</exception>
    public void Transform(Span<byte> output, ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        Hc256Core.Transform(output, input, key!, iv!);
    }

    /// <summary>
    /// Gets the IV that was set or generated.
    /// </summary>
    /// <returns>A copy of the IV bytes.</returns>
    /// <exception cref="InvalidOperationException">If IV is not set.</exception>
    public byte[] GetIv()
    {
        if (iv == null)
        {
            throw new InvalidOperationException("IV has not been set. Use WithIv() or WithRandomIv() first.");
        }

        return [.. iv];
    }

    private void ValidateState()
    {
        if (key == null)
        {
            throw new InvalidOperationException("Key has not been set. Use WithKey() first.");
        }

        if (iv == null)
        {
            throw new InvalidOperationException("IV has not been set. Use WithIv() or WithRandomIv() first.");
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
