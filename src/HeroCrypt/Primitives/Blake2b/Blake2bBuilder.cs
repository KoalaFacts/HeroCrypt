using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Blake2b;

/// <summary>
/// Fluent builder for Blake2b cryptographic hash operations.
/// Provides hashing according to RFC 7693.
/// </summary>
/// <example>
/// <code>
/// // Basic hashing with default 64-byte output
/// using var builder = Blake2bBuilder.Create();
/// var hash = builder.ComputeHash(data);
///
/// // Custom output length
/// using var builder = Blake2bBuilder.Create()
///     .WithOutputLength(32);
/// var hash = builder.ComputeHash(data);
///
/// // Keyed hashing (MAC)
/// using var builder = Blake2bBuilder.Create()
///     .WithKey(key)
///     .WithOutputLength(32);
/// var mac = builder.ComputeHash(data);
///
/// // With salt and personalization
/// using var builder = Blake2bBuilder.Create()
///     .WithSalt(salt)
///     .WithPersonalization(personalization);
/// var hash = builder.ComputeHash(data);
/// </code>
/// </example>
public sealed class Blake2bBuilder : IDisposable
{
    private const int MinOutputLength = 1;
    private const int MaxOutputLength = 64;
    private const int DefaultOutputLength = 64;
    private const int MaxKeyLength = 64;
    private const int SaltSize = 16;
    private const int PersonalizationSize = 16;

    private int outputLength = DefaultOutputLength;
    private byte[]? key;
    private byte[]? salt;
    private byte[]? personalization;
    private bool disposed;

    private Blake2bBuilder() { }

    /// <summary>
    /// Creates a new Blake2b builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Blake2bBuilder Create() => new();

    /// <summary>
    /// Sets the output hash length.
    /// </summary>
    /// <param name="outputLength">The output length in bytes (1-64, default: 64).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If output length is not between 1 and 64 bytes.</exception>
    public Blake2bBuilder WithOutputLength(int outputLength)
    {
        if (outputLength is < MinOutputLength or > MaxOutputLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(outputLength),
                $"Output length must be between {MinOutputLength} and {MaxOutputLength} bytes, but was {outputLength} bytes.");
        }

        this.outputLength = outputLength;
        return this;
    }

    /// <summary>
    /// Sets the key for keyed hashing (MAC mode).
    /// </summary>
    /// <param name="key">The key (0-64 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key is null.</exception>
    /// <exception cref="ArgumentException">If key exceeds 64 bytes.</exception>
    public Blake2bBuilder WithKey(byte[] key)
    {
        ArgumentHelper.ThrowIfNull(key);
        if (key.Length > MaxKeyLength)
        {
            throw new ArgumentException($"Key must not exceed {MaxKeyLength} bytes, but was {key.Length} bytes.", nameof(key));
        }

        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the key for keyed hashing (MAC mode).
    /// </summary>
    /// <param name="key">The key (0-64 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If key exceeds 64 bytes.</exception>
    public Blake2bBuilder WithKey(ReadOnlySpan<byte> key)
    {
        if (key.Length > MaxKeyLength)
        {
            throw new ArgumentException($"Key must not exceed {MaxKeyLength} bytes, but was {key.Length} bytes.", nameof(key));
        }

        ClearKey();
        this.key = key.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random key and sets it.
    /// </summary>
    /// <param name="keyLength">The key length in bytes (default: 64).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If key length exceeds 64 bytes.</exception>
    public Blake2bBuilder WithRandomKey(int keyLength = MaxKeyLength)
    {
        if (keyLength is < 0 or > MaxKeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(keyLength),
                $"Key length must be between 0 and {MaxKeyLength} bytes, but was {keyLength} bytes.");
        }

        ClearKey();
        key = new byte[keyLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return this;
    }

    /// <summary>
    /// Sets the salt value.
    /// </summary>
    /// <param name="salt">The salt (must be exactly 16 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If salt is null.</exception>
    /// <exception cref="ArgumentException">If salt is not exactly 16 bytes.</exception>
    public Blake2bBuilder WithSalt(byte[] salt)
    {
        ArgumentHelper.ThrowIfNull(salt);
        if (salt.Length != SaltSize)
        {
            throw new ArgumentException($"Salt must be exactly {SaltSize} bytes, but was {salt.Length} bytes.", nameof(salt));
        }

        ClearSalt();
        this.salt = [.. salt];
        return this;
    }

    /// <summary>
    /// Sets the salt value.
    /// </summary>
    /// <param name="salt">The salt (must be exactly 16 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If salt is not exactly 16 bytes.</exception>
    public Blake2bBuilder WithSalt(ReadOnlySpan<byte> salt)
    {
        if (salt.Length != SaltSize)
        {
            throw new ArgumentException($"Salt must be exactly {SaltSize} bytes, but was {salt.Length} bytes.", nameof(salt));
        }

        ClearSalt();
        this.salt = salt.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a random salt and sets it.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Blake2bBuilder WithRandomSalt()
    {
        ClearSalt();
        salt = new byte[SaltSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return this;
    }

    /// <summary>
    /// Sets the personalization value.
    /// </summary>
    /// <param name="personalization">The personalization (must be exactly 16 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If personalization is null.</exception>
    /// <exception cref="ArgumentException">If personalization is not exactly 16 bytes.</exception>
    public Blake2bBuilder WithPersonalization(byte[] personalization)
    {
        ArgumentHelper.ThrowIfNull(personalization);
        if (personalization.Length != PersonalizationSize)
        {
            throw new ArgumentException(
                $"Personalization must be exactly {PersonalizationSize} bytes, but was {personalization.Length} bytes.",
                nameof(personalization));
        }

        ClearPersonalization();
        this.personalization = [.. personalization];
        return this;
    }

    /// <summary>
    /// Sets the personalization value.
    /// </summary>
    /// <param name="personalization">The personalization (must be exactly 16 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If personalization is not exactly 16 bytes.</exception>
    public Blake2bBuilder WithPersonalization(ReadOnlySpan<byte> personalization)
    {
        if (personalization.Length != PersonalizationSize)
        {
            throw new ArgumentException(
                $"Personalization must be exactly {PersonalizationSize} bytes, but was {personalization.Length} bytes.",
                nameof(personalization));
        }

        ClearPersonalization();
        this.personalization = personalization.ToArray();
        return this;
    }

    /// <summary>
    /// Computes the Blake2b hash of the input data.
    /// </summary>
    /// <param name="input">The data to hash.</param>
    /// <returns>The hash output.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="ArgumentNullException">If input is null.</exception>
    public byte[] ComputeHash(byte[] input)
    {
        ArgumentHelper.ThrowIfNull(input);
        return ComputeHash(input.AsSpan());
    }

    /// <summary>
    /// Computes the Blake2b hash of the input data.
    /// </summary>
    /// <param name="input">The data to hash.</param>
    /// <returns>The hash output.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public byte[] ComputeHash(ReadOnlySpan<byte> input)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);

        return Blake2bCore.ComputeHash(
            input.ToArray(),
            outputLength,
            key,
            salt,
            personalization);
    }

    /// <summary>
    /// Gets the key that was set or generated.
    /// </summary>
    /// <returns>A copy of the key bytes, or null if no key is set.</returns>
    public byte[]? GetKey()
    {
        return key != null ? [.. key] : null;
    }

    /// <summary>
    /// Gets the salt that was set or generated.
    /// </summary>
    /// <returns>A copy of the salt bytes, or null if no salt is set.</returns>
    public byte[]? GetSalt()
    {
        return salt != null ? [.. salt] : null;
    }

    /// <summary>
    /// Gets the personalization that was set.
    /// </summary>
    /// <returns>A copy of the personalization bytes, or null if no personalization is set.</returns>
    public byte[]? GetPersonalization()
    {
        return personalization != null ? [.. personalization] : null;
    }

    private void ClearKey()
    {
        if (key != null)
        {
            SecureMemoryOperations.SecureClear(key);
            key = null;
        }
    }

    private void ClearSalt()
    {
        if (salt != null)
        {
            SecureMemoryOperations.SecureClear(salt);
            salt = null;
        }
    }

    private void ClearPersonalization()
    {
        if (personalization != null)
        {
            SecureMemoryOperations.SecureClear(personalization);
            personalization = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearKey();
            ClearSalt();
            ClearPersonalization();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
