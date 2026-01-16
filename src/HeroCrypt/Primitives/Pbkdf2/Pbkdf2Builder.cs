using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Pbkdf2;

/// <summary>
/// Fluent builder for PBKDF2 (Password-Based Key Derivation Function 2) operations.
/// Implements RFC 2898 compliant key derivation.
/// </summary>
/// <example>
/// <code>
/// // Derive key from password with default settings
/// using var builder = Pbkdf2Builder.Create()
///     .WithPasswordStoragePreset()
///     .WithPassword("mySecurePassword")
///     .WithSalt(salt);
/// var key = builder.DeriveKey();
///
/// // Derive key with custom parameters
/// using var customBuilder = Pbkdf2Builder.Create()
///     .WithPassword(passwordBytes)
///     .WithSalt(saltBytes)
///     .WithIterations(600000)
///     .WithOutputLength(32)
///     .WithHashAlgorithm(HashAlgorithmName.SHA256);
/// var derivedKey = customBuilder.DeriveKey();
/// </code>
/// </example>
public sealed class Pbkdf2Builder : IDisposable
{
    private const int DefaultIterations = Pbkdf2Core.DEFAULT_ITERATIONS;
    private const int MinSaltLength = Pbkdf2Core.MIN_SALT_LENGTH;
    private const int DefaultSaltLength = Pbkdf2Core.DEFAULT_SALT_LENGTH;
    private const int DefaultOutputLength = 32;

    private byte[]? password;
    private byte[]? salt;
    private int iterations = DefaultIterations;
    private int outputLength = DefaultOutputLength;
    private HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
    private bool allowWeakParameters;
    private bool disposed;

    private Pbkdf2Builder() { }

    /// <summary>
    /// Creates a new PBKDF2 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Pbkdf2Builder Create() => new();

    /// <summary>
    /// Sets the password as bytes.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If password is null.</exception>
    public Pbkdf2Builder WithPassword(byte[] password)
    {
        ArgumentHelper.ThrowIfNull(password);
        ClearPassword();
        this.password = [.. password];
        return this;
    }

    /// <summary>
    /// Sets the password as bytes.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder WithPassword(ReadOnlySpan<byte> password)
    {
        ClearPassword();
        this.password = password.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the password as a UTF-8 encoded string.
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If password is null.</exception>
    public Pbkdf2Builder WithPassword(string password)
    {
        ArgumentHelper.ThrowIfNull(password);
        ClearPassword();
        this.password = Encoding.UTF8.GetBytes(password);
        return this;
    }

    /// <summary>
    /// Sets the salt value.
    /// </summary>
    /// <param name="salt">The salt bytes (should be at least 16 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If salt is null.</exception>
    public Pbkdf2Builder WithSalt(byte[] salt)
    {
        ArgumentHelper.ThrowIfNull(salt);
        ClearSalt();
        this.salt = [.. salt];
        return this;
    }

    /// <summary>
    /// Sets the salt value.
    /// </summary>
    /// <param name="salt">The salt bytes (should be at least 16 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder WithSalt(ReadOnlySpan<byte> salt)
    {
        ClearSalt();
        this.salt = salt.ToArray();
        return this;
    }

    /// <summary>
    /// Generates and sets a random salt.
    /// </summary>
    /// <param name="length">Salt length in bytes (default: 32).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder WithRandomSalt(int length = DefaultSaltLength)
    {
        if (length < MinSaltLength)
        {
            throw new ArgumentException($"Salt length must be at least {MinSaltLength} bytes.", nameof(length));
        }

        ClearSalt();
        salt = Pbkdf2Core.GenerateRandomSalt(length);
        return this;
    }

    /// <summary>
    /// Sets the number of iterations.
    /// </summary>
    /// <param name="iterations">Number of iterations (recommended: at least 100,000).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If iterations is less than 1.</exception>
    public Pbkdf2Builder WithIterations(int iterations)
    {
        if (iterations < 1)
        {
            throw new ArgumentException("Iterations must be at least 1.", nameof(iterations));
        }

        this.iterations = iterations;
        return this;
    }

    /// <summary>
    /// Sets the output length in bytes.
    /// </summary>
    /// <param name="length">Output length in bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If length is less than 1.</exception>
    public Pbkdf2Builder WithOutputLength(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Output length must be positive.", nameof(length));
        }

        outputLength = length;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm to use for PBKDF2.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm (SHA1, SHA256, SHA384, or SHA512).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If hash algorithm is not supported.</exception>
    public Pbkdf2Builder WithHashAlgorithm(HashAlgorithmName hashAlgorithm)
    {
        if (!Pbkdf2Core.IsHashAlgorithmSupported(hashAlgorithm))
        {
            throw new ArgumentException($"Hash algorithm {hashAlgorithm} is not supported.", nameof(hashAlgorithm));
        }

        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /// <summary>
    /// Allows parameters below security recommendations for standards compliance (e.g., RFC test vectors, BIP-39).
    /// Use with caution in production environments.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder AllowWeakParameters()
    {
        allowWeakParameters = true;
        return this;
    }

    /// <summary>
    /// Configures parameters for password storage and verification (600,000 iterations, SHA256, 32-byte output).
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder WithPasswordStoragePreset()
    {
        hashAlgorithm = HashAlgorithmName.SHA256;
        iterations = 600000;
        outputLength = 32;
        return this;
    }

    /// <summary>
    /// Configures parameters for key derivation from passwords (100,000 iterations, SHA256, 32-byte output).
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder WithKeyDerivationPreset()
    {
        hashAlgorithm = HashAlgorithmName.SHA256;
        iterations = 100000;
        outputLength = 32;
        return this;
    }

    /// <summary>
    /// Configures parameters for high-security applications (1,000,000 iterations, SHA512, 64-byte output).
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Pbkdf2Builder WithHighSecurityPreset()
    {
        hashAlgorithm = HashAlgorithmName.SHA512;
        iterations = 1000000;
        outputLength = 64;
        return this;
    }

    /// <summary>
    /// Derives a key using the configured parameters.
    /// </summary>
    /// <returns>The derived key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If password or salt is not set.</exception>
    public byte[] DeriveKey()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return Pbkdf2Core.DeriveKey(
            password!,
            salt!,
            iterations,
            outputLength,
            hashAlgorithm,
            allowWeakParameters
        );
    }

    /// <summary>
    /// Calculates appropriate iteration count for a target derivation time.
    /// </summary>
    /// <param name="targetTimeMs">Target derivation time in milliseconds.</param>
    /// <returns>Recommended iteration count.</returns>
    public int CalculateIterations(int targetTimeMs)
    {
        if (salt == null)
        {
            throw new InvalidOperationException("Salt must be set before calculating iterations. Use WithSalt() or WithRandomSalt() first.");
        }

        return Pbkdf2Core.CalculateIterations(targetTimeMs, hashAlgorithm, outputLength);
    }

    /// <summary>
    /// Gets the salt that was set or generated.
    /// </summary>
    /// <returns>A copy of the salt bytes.</returns>
    /// <exception cref="InvalidOperationException">If salt is not set.</exception>
    public byte[] GetSalt()
    {
        if (salt == null)
        {
            throw new InvalidOperationException("Salt has not been set. Use WithSalt() or WithRandomSalt() first.");
        }

        return [.. salt];
    }

    private void ValidateState()
    {
        if (password == null)
        {
            throw new InvalidOperationException("Password has not been set. Use WithPassword() first.");
        }

        if (salt == null)
        {
            throw new InvalidOperationException("Salt has not been set. Use WithSalt() or WithRandomSalt() first.");
        }
    }

    private void ClearPassword()
    {
        if (password != null)
        {
            SecureMemoryOperations.SecureClear(password);
            password = null;
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

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearPassword();
            ClearSalt();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
