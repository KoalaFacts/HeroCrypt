using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.ChaCha20;

/// <summary>
/// Fluent builder for ChaCha20 stream cipher operations.
/// Provides symmetric encryption/decryption according to RFC 8439.
/// </summary>
/// <example>
/// <code>
/// // Transform data (encryption and decryption use the same operation)
/// using var builder = ChaCha20Builder.Create()
///     .WithKey(key)
///     .WithNonce(nonce);
/// var ciphertext = builder.Transform(plaintext);
/// var decrypted = builder.Transform(ciphertext);
/// </code>
/// </example>
public sealed class ChaCha20Builder : IDisposable
{
    private const int KeySize = ChaCha20Core.KEY_SIZE;
    private const int NonceSize = ChaCha20Core.NONCE_SIZE;

    private byte[]? key;
    private byte[]? nonce;
    private uint counter;
    private bool disposed;

    private ChaCha20Builder() { }

    /// <summary>
    /// Creates a new ChaCha20 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static ChaCha20Builder Create() => new();

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    /// <param name="key">The 32-byte encryption key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    /// <exception cref="ArgumentException">If key is not 32 bytes.</exception>
    public ChaCha20Builder WithKey(byte[] key)
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
    public ChaCha20Builder WithKey(ReadOnlySpan<byte> key)
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
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The 12-byte nonce.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If nonce is null.</exception>
    /// <exception cref="ArgumentException">If nonce is not 12 bytes.</exception>
    public ChaCha20Builder WithNonce(byte[] nonce)
    {
        ArgumentHelper.ThrowIfNull(nonce);
        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"Nonce must be {NonceSize} bytes, but was {nonce.Length} bytes.", nameof(nonce));
        }

        ClearNonce();
        this.nonce = [.. nonce];
        return this;
    }

    /// <summary>
    /// Sets the nonce (number used once).
    /// </summary>
    /// <param name="nonce">The 12-byte nonce.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If nonce is not 12 bytes.</exception>
    public ChaCha20Builder WithNonce(ReadOnlySpan<byte> nonce)
    {
        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"Nonce must be {NonceSize} bytes, but was {nonce.Length} bytes.", nameof(nonce));
        }

        ClearNonce();
        this.nonce = nonce.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random nonce and sets it.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public ChaCha20Builder WithRandomNonce()
    {
        ClearNonce();
        nonce = new byte[NonceSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(nonce);
        return this;
    }

    /// <summary>
    /// Sets the initial counter value for the ChaCha20 stream.
    /// </summary>
    /// <param name="counter">The initial counter value (default is 0).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public ChaCha20Builder WithCounter(uint counter)
    {
        this.counter = counter;
        return this;
    }

    /// <summary>
    /// Transforms the input data using the ChaCha20 stream cipher.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <returns>The transformed data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    /// <exception cref="ArgumentNullException">If input is null.</exception>
    public byte[] Transform(byte[] input)
    {
        ArgumentHelper.ThrowIfNull(input);
        return Transform(input.AsSpan());
    }

    /// <summary>
    /// Transforms the input data using the ChaCha20 stream cipher.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="input">The data to transform.</param>
    /// <returns>The transformed data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    public byte[] Transform(ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        var output = new byte[input.Length];
        ChaCha20Core.Transform(output, input, key!, nonce!, counter);
        return output;
    }

    /// <summary>
    /// Transforms the input data into the provided buffer.
    /// For stream ciphers, encryption and decryption use the same operation.
    /// </summary>
    /// <param name="output">The output buffer (must be at least input.Length bytes).</param>
    /// <param name="input">The data to transform.</param>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key or nonce is not set.</exception>
    public void Transform(Span<byte> output, ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        ChaCha20Core.Transform(output, input, key!, nonce!, counter);
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

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearKey();
            ClearNonce();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
