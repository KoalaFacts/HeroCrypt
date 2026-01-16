using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Argon2;

/// <summary>
/// Fluent builder for Argon2 password hashing and key derivation operations.
/// Implements RFC 9106 specification for Argon2d, Argon2i, and Argon2id variants.
/// </summary>
/// <example>
/// <code>
/// // Derive key from password using interactive preset
/// using var builder = Argon2Builder.Create()
///     .WithInteractivePreset()
///     .WithPassword("mySecurePassword")
///     .WithSalt(salt);
/// var key = builder.DeriveKey();
///
/// // Derive key with custom parameters
/// using var customBuilder = Argon2Builder.Create()
///     .WithPassword(passwordBytes)
///     .WithSalt(saltBytes)
///     .WithIterations(3)
///     .WithMemorySize(65536)
///     .WithParallelism(4)
///     .WithOutputLength(32)
///     .WithType(Argon2Type.Argon2id);
/// var derivedKey = customBuilder.DeriveKey();
/// </code>
/// </example>
public sealed class Argon2Builder : IDisposable
{
    private const int MinSaltLength = 8;
    private const int DefaultSaltLength = 16;
    private const int DefaultOutputLength = 32;

    private byte[]? password;
    private byte[]? salt;
    private byte[]? secret;
    private byte[]? associatedData;
    private int iterations = 2;
    private int memorySize = 19456; // 19 MB
    private int parallelism = 1;
    private int outputLength = DefaultOutputLength;
    private Argon2Type type = Argon2Type.Argon2id;
    private bool disposed;

    private Argon2Builder() { }

    /// <summary>
    /// Creates a new Argon2 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Argon2Builder Create() => new();

    /// <summary>
    /// Sets the password as bytes.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If password is null.</exception>
    public Argon2Builder WithPassword(byte[] password)
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
    public Argon2Builder WithPassword(ReadOnlySpan<byte> password)
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
    public Argon2Builder WithPassword(string password)
    {
        ArgumentHelper.ThrowIfNull(password);
        ClearPassword();
        this.password = Encoding.UTF8.GetBytes(password);
        return this;
    }

    /// <summary>
    /// Sets the salt value.
    /// </summary>
    /// <param name="salt">The salt bytes (should be at least 8 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If salt is null.</exception>
    /// <exception cref="ArgumentException">If salt is less than 8 bytes.</exception>
    public Argon2Builder WithSalt(byte[] salt)
    {
        ArgumentHelper.ThrowIfNull(salt);
        if (salt.Length < MinSaltLength)
        {
            throw new ArgumentException($"Salt must be at least {MinSaltLength} bytes, but was {salt.Length} bytes.", nameof(salt));
        }

        ClearSalt();
        this.salt = [.. salt];
        return this;
    }

    /// <summary>
    /// Sets the salt value.
    /// </summary>
    /// <param name="salt">The salt bytes (should be at least 8 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If salt is less than 8 bytes.</exception>
    public Argon2Builder WithSalt(ReadOnlySpan<byte> salt)
    {
        if (salt.Length < MinSaltLength)
        {
            throw new ArgumentException($"Salt must be at least {MinSaltLength} bytes, but was {salt.Length} bytes.", nameof(salt));
        }

        ClearSalt();
        this.salt = salt.ToArray();
        return this;
    }

    /// <summary>
    /// Generates and sets a random salt.
    /// </summary>
    /// <param name="length">Salt length in bytes (default: 16).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithRandomSalt(int length = DefaultSaltLength)
    {
        if (length < MinSaltLength)
        {
            throw new ArgumentException($"Salt length must be at least {MinSaltLength} bytes.", nameof(length));
        }

        ClearSalt();
        salt = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return this;
    }

    /// <summary>
    /// Sets the number of iterations (time cost).
    /// </summary>
    /// <param name="iterations">Number of iterations (must be at least 1).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If iterations is less than 1.</exception>
    public Argon2Builder WithIterations(int iterations)
    {
        if (iterations < 1)
        {
            throw new ArgumentException("Iterations must be at least 1.", nameof(iterations));
        }

        this.iterations = iterations;
        return this;
    }

    /// <summary>
    /// Sets the memory size in kilobytes.
    /// </summary>
    /// <param name="memorySize">Memory usage in KB (must be at least 8 * parallelism).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If memory size is less than 1.</exception>
    public Argon2Builder WithMemorySize(int memorySize)
    {
        if (memorySize < 1)
        {
            throw new ArgumentException("Memory size must be at least 1 KB.", nameof(memorySize));
        }

        this.memorySize = memorySize;
        return this;
    }

    /// <summary>
    /// Sets the parallelism level (number of lanes).
    /// </summary>
    /// <param name="parallelism">Parallelism level (must be at least 1).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If parallelism is less than 1.</exception>
    public Argon2Builder WithParallelism(int parallelism)
    {
        if (parallelism < 1)
        {
            throw new ArgumentException("Parallelism must be at least 1.", nameof(parallelism));
        }

        this.parallelism = parallelism;
        return this;
    }

    /// <summary>
    /// Sets the output length in bytes.
    /// </summary>
    /// <param name="length">Output length in bytes (must be at least 4).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If length is less than 4.</exception>
    public Argon2Builder WithOutputLength(int length)
    {
        if (length < 4)
        {
            throw new ArgumentException("Output length must be at least 4 bytes.", nameof(length));
        }

        outputLength = length;
        return this;
    }

    /// <summary>
    /// Sets the Argon2 variant type.
    /// </summary>
    /// <param name="type">Argon2 variant (Argon2d, Argon2i, or Argon2id).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithType(Argon2Type type)
    {
        this.type = type;
        return this;
    }

    /// <summary>
    /// Sets the optional secret key.
    /// </summary>
    /// <param name="secret">Secret key bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithSecret(byte[]? secret)
    {
        ClearSecret();
        this.secret = secret != null ? [.. secret] : null;
        return this;
    }

    /// <summary>
    /// Sets the optional secret key.
    /// </summary>
    /// <param name="secret">Secret key bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithSecret(ReadOnlySpan<byte> secret)
    {
        ClearSecret();
        this.secret = secret.IsEmpty ? null : secret.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the optional associated data.
    /// </summary>
    /// <param name="associatedData">Associated data bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithAssociatedData(byte[]? associatedData)
    {
        ClearAssociatedData();
        this.associatedData = associatedData != null ? [.. associatedData] : null;
        return this;
    }

    /// <summary>
    /// Sets the optional associated data.
    /// </summary>
    /// <param name="associatedData">Associated data bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithAssociatedData(ReadOnlySpan<byte> associatedData)
    {
        ClearAssociatedData();
        this.associatedData = associatedData.IsEmpty ? null : associatedData.ToArray();
        return this;
    }

    /// <summary>
    /// Configures parameters for interactive applications requiring fast response times.
    /// Uses Argon2id with 2 iterations, 19 MB memory, and parallelism of 1.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithInteractivePreset()
    {
        iterations = 2;
        memorySize = 19456; // 19 MB
        parallelism = 1;
        type = Argon2Type.Argon2id;
        return this;
    }

    /// <summary>
    /// Configures parameters for moderate security with balanced performance.
    /// Uses Argon2id with 3 iterations, 256 MB memory, and parallelism of 1.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithModeratePreset()
    {
        iterations = 3;
        memorySize = 262144; // 256 MB
        parallelism = 1;
        type = Argon2Type.Argon2id;
        return this;
    }

    /// <summary>
    /// Configures parameters for sensitive data requiring high security.
    /// Uses Argon2id with 4 iterations, 1 GB memory, and parallelism of 1.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public Argon2Builder WithSensitivePreset()
    {
        iterations = 4;
        memorySize = 1048576; // 1 GB
        parallelism = 1;
        type = Argon2Type.Argon2id;
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

        return Argon2Core.Hash(
            password!,
            salt!,
            iterations,
            memorySize,
            parallelism,
            outputLength,
            type,
            associatedData,
            secret
        );
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

        if (memorySize < 8 * parallelism)
        {
            throw new InvalidOperationException($"Memory size must be at least {8 * parallelism} KB for parallelism of {parallelism}.");
        }
    }

    private void ClearPassword()
    {
        if (password == null)
            return;

        SecureMemoryOperations.SecureClear(password);
        password = null;
    }

    private void ClearSalt()
    {
        if (salt == null)
            return;

        SecureMemoryOperations.SecureClear(salt);
        salt = null;
    }

    private void ClearSecret()
    {
        if (secret == null)
            return;

        SecureMemoryOperations.SecureClear(secret);
        secret = null;
    }

    private void ClearAssociatedData()
    {
        if (associatedData == null)
            return;

        SecureMemoryOperations.SecureClear(associatedData);
        associatedData = null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (disposed)
            return;

        ClearPassword();
        ClearSalt();
        ClearSecret();
        ClearAssociatedData();
        disposed = true;
        GC.SuppressFinalize(this);
    }
}
