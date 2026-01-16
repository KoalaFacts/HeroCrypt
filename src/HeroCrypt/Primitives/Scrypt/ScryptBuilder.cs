using System.Text;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Scrypt;

/// <summary>
/// Fluent builder for scrypt (Script) key derivation operations.
/// Implements RFC 7914 compliant memory-hard key derivation.
/// </summary>
/// <example>
/// <code>
/// // Derive key with interactive preset
/// using var builder = ScryptBuilder.Create()
///     .WithInteractivePreset()
///     .WithPassword("mySecurePassword")
///     .WithSalt(salt);
/// var key = builder.DeriveKey();
///
/// // Derive key with custom parameters
/// using var customBuilder = ScryptBuilder.Create()
///     .WithPassword(passwordBytes)
///     .WithSalt(saltBytes)
///     .WithN(32768)
///     .WithR(8)
///     .WithP(1)
///     .WithOutputLength(32);
/// var derivedKey = customBuilder.DeriveKey();
/// </code>
/// </example>
public sealed class ScryptBuilder : IDisposable
{
    private const int DefaultN = ScryptCore.DEFAULT_N;
    private const int DefaultR = ScryptCore.DEFAULT_R;
    private const int DefaultP = ScryptCore.DEFAULT_P;
    private const int MinSaltLength = ScryptCore.MIN_SALT_LENGTH;
    private const int DefaultSaltLength = ScryptCore.DEFAULT_SALT_LENGTH;
    private const int DefaultOutputLength = 32;

    private byte[]? password;
    private byte[]? salt;
    private int n = DefaultN;
    private int r = DefaultR;
    private int p = DefaultP;
    private int outputLength = DefaultOutputLength;
    private bool disposed;

    private ScryptBuilder() { }

    /// <summary>
    /// Creates a new scrypt builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static ScryptBuilder Create() => new();

    /// <summary>
    /// Sets the password as bytes.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If password is null.</exception>
    public ScryptBuilder WithPassword(byte[] password)
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
    public ScryptBuilder WithPassword(ReadOnlySpan<byte> password)
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
    public ScryptBuilder WithPassword(string password)
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
    public ScryptBuilder WithSalt(byte[] salt)
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
    public ScryptBuilder WithSalt(ReadOnlySpan<byte> salt)
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
    public ScryptBuilder WithRandomSalt(int length = DefaultSaltLength)
    {
        if (length < MinSaltLength)
        {
            throw new ArgumentException($"Salt length must be at least {MinSaltLength} bytes.", nameof(length));
        }

        ClearSalt();
        salt = ScryptCore.GenerateRandomSalt(length);
        return this;
    }

    /// <summary>
    /// Sets the CPU/memory cost parameter N.
    /// </summary>
    /// <param name="n">CPU/memory cost (must be a power of 2 greater than 0).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If N is not a power of 2.</exception>
    public ScryptBuilder WithN(int n)
    {
        if (n <= 0 || !BitOperations.IsPowerOfTwo(n))
        {
            throw new ArgumentException("N must be a power of 2 greater than 0.", nameof(n));
        }

        this.n = n;
        return this;
    }

    /// <summary>
    /// Sets the block size parameter r.
    /// </summary>
    /// <param name="r">Block size (must be positive).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If r is not positive.</exception>
    public ScryptBuilder WithR(int r)
    {
        if (r <= 0)
        {
            throw new ArgumentException("r must be positive.", nameof(r));
        }

        this.r = r;
        return this;
    }

    /// <summary>
    /// Sets the parallelization parameter p.
    /// </summary>
    /// <param name="p">Parallelization factor (must be positive).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If p is not positive.</exception>
    public ScryptBuilder WithP(int p)
    {
        if (p <= 0)
        {
            throw new ArgumentException("p must be positive.", nameof(p));
        }

        this.p = p;
        return this;
    }

    /// <summary>
    /// Sets the output length in bytes.
    /// </summary>
    /// <param name="length">Output length in bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If length is not positive.</exception>
    public ScryptBuilder WithOutputLength(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Output length must be positive.", nameof(length));
        }

        outputLength = length;
        return this;
    }

    /// <summary>
    /// Configures parameters for interactive login scenarios (N=32768, r=8, p=1).
    /// Fast response time, suitable for interactive applications.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public ScryptBuilder WithInteractivePreset()
    {
        n = 32768;     // 2^15
        r = 8;
        p = 1;
        return this;
    }

    /// <summary>
    /// Configures parameters for sensitive data protection (N=1048576, r=8, p=1).
    /// Slower derivation time, suitable for sensitive data.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public ScryptBuilder WithSensitivePreset()
    {
        n = 1048576;   // 2^20
        r = 8;
        p = 1;
        return this;
    }

    /// <summary>
    /// Configures parameters for file encryption (N=65536, r=8, p=1).
    /// Balanced security and performance for file encryption.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public ScryptBuilder WithFileEncryptionPreset()
    {
        n = 65536;     // 2^16
        r = 8;
        p = 1;
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

        return ScryptCore.DeriveKey(
            password!,
            salt!,
            n,
            r,
            p,
            outputLength
        );
    }

    /// <summary>
    /// Calculates the memory usage in bytes for the current parameters.
    /// </summary>
    /// <returns>Memory usage in bytes.</returns>
    public long CalculateMemoryUsage()
    {
        return ScryptCore.CalculateMemoryUsage(n, r, p);
    }

    /// <summary>
    /// Calculates the memory usage in megabytes for the current parameters.
    /// </summary>
    /// <returns>Memory usage in MB.</returns>
    public double CalculateMemoryUsageMB()
    {
        return CalculateMemoryUsage() / (1024.0 * 1024.0);
    }

    /// <summary>
    /// Suggests parameters for a target memory usage in MB and applies them.
    /// </summary>
    /// <param name="targetMemoryMB">Target memory usage in MB.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If target memory is not positive.</exception>
    public ScryptBuilder WithSuggestedParameters(int targetMemoryMB)
    {
        var (n, r, p) = ScryptCore.SuggestParameters(targetMemoryMB);
        this.n = n;
        this.r = r;
        this.p = p;
        return this;
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

    /// <summary>
    /// Gets the current scrypt parameters.
    /// </summary>
    /// <returns>Tuple containing (N, r, p) parameters.</returns>
    public (int N, int R, int P) GetParameters()
    {
        return (n, r, p);
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
