using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.S2K;

/// <summary>
/// Fluent builder for OpenPGP String-to-Key (S2K) operations.
/// Implements RFC 4880 Section 3.7.
/// </summary>
/// <remarks>
/// S2K is used to derive symmetric keys from passphrases in OpenPGP.
/// For new applications, use Iterated S2K (Type 3) with high iteration count,
/// or use the dedicated Argon2 builder for stronger protection.
/// </remarks>
/// <example>
/// <code>
/// // Iterated S2K (legacy recommended)
/// var key = S2KBuilder.Create()
///     .WithType(S2KType.IteratedAndSalted)
///     .WithRandomSalt()
///     .WithIterationCount(65536)
///     .DeriveKey(password, 32);
///
/// // Argon2 S2K (RFC 9580 - strongest protection)
/// var key = S2KBuilder.Create()
///     .WithArgon2Parameters(timePasses: 3, parallelism: 4, memoryExponent: 16)
///     .WithRandomSalt()
///     .DeriveKey(password, 32);
///
/// // With custom salt
/// var key = S2KBuilder.Create()
///     .WithType(S2KType.Salted)
///     .WithSalt(mySalt)
///     .DeriveKey(password, 32);
/// </code>
/// </example>
public sealed class S2KBuilder : IDisposable
{
    private S2KType s2kType = S2KType.IteratedAndSalted;
    private HashAlgorithmName hashAlgorithm = S2KCore.DEFAULT_HASH;
    private byte[]? salt;
    private long iterationCount = 65536; // Default: 65536 bytes
    private byte argon2TimePasses = 3;
    private byte argon2Parallelism = 4;
    private byte argon2MemoryExponent = 16; // 64 MiB
    private bool disposed;

    private S2KBuilder() { }

    /// <summary>
    /// Creates a new S2K builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static S2KBuilder Create() => new();

    /// <summary>
    /// Sets the S2K type.
    /// </summary>
    /// <param name="type">The S2K type to use.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithType(S2KType type)
    {
        s2kType = type;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for S2K.
    /// </summary>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
    {
        hashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the salt for S2K operations.
    /// </summary>
    /// <param name="saltValue">The salt (8 bytes for types 0-3, 16 bytes for Argon2).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If salt is null.</exception>
    /// <exception cref="ArgumentException">If salt has invalid length for the current S2K type.</exception>
    public S2KBuilder WithSalt(byte[] saltValue)
    {
        ArgumentHelper.ThrowIfNull(saltValue);

        var expectedSize = s2kType == S2KType.Argon2
            ? S2KCore.ARGON2_SALT_SIZE
            : S2KCore.DEFAULT_SALT_SIZE;

        if (saltValue.Length != expectedSize)
        {
            throw new ArgumentException($"Salt must be {expectedSize} bytes for {s2kType}.", nameof(saltValue));
        }

        ClearSalt();
        salt = [.. saltValue];
        return this;
    }

    /// <summary>
    /// Generates and sets a random salt.
    /// Automatically uses 8-byte salt for types 0-3, or 16-byte salt for Argon2.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithRandomSalt()
    {
        ClearSalt();
        salt = s2kType == S2KType.Argon2
            ? S2KCore.GenerateArgon2Salt()
            : S2KCore.GenerateSalt();
        return this;
    }

    /// <summary>
    /// Sets the iteration count for Iterated S2K.
    /// </summary>
    /// <param name="count">The number of bytes to hash.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If count is less than 1.</exception>
    public S2KBuilder WithIterationCount(long count)
    {
        if (count < 1)
        {
            throw new ArgumentException("Iteration count must be at least 1.", nameof(count));
        }
        iterationCount = count;
        return this;
    }

    /// <summary>
    /// Sets the iteration count using the encoded byte value.
    /// </summary>
    /// <param name="encodedCount">The RFC 4880 encoded count byte.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithEncodedIterationCount(byte encodedCount)
    {
        iterationCount = S2KCore.DecodeIterationCount(encodedCount);
        return this;
    }

    /// <summary>
    /// Sets the Argon2 time passes (iterations) parameter.
    /// </summary>
    /// <param name="timePasses">Number of iterations (1-255).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithArgon2TimePasses(byte timePasses)
    {
        if (timePasses < 1)
        {
            throw new ArgumentException("Time passes must be at least 1.", nameof(timePasses));
        }
        argon2TimePasses = timePasses;
        return this;
    }

    /// <summary>
    /// Sets the Argon2 parallelism parameter.
    /// </summary>
    /// <param name="parallelism">Parallelism degree (1-255).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithArgon2Parallelism(byte parallelism)
    {
        if (parallelism < 1)
        {
            throw new ArgumentException("Parallelism must be at least 1.", nameof(parallelism));
        }
        argon2Parallelism = parallelism;
        return this;
    }

    /// <summary>
    /// Sets the Argon2 memory exponent (memory = 2^m KiB).
    /// </summary>
    /// <param name="memoryExponent">Memory exponent (reasonable range: 10-24).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithArgon2MemoryExponent(byte memoryExponent)
    {
        argon2MemoryExponent = memoryExponent;
        return this;
    }

    /// <summary>
    /// Configures Argon2 S2K with all parameters at once.
    /// </summary>
    /// <param name="timePasses">Number of iterations.</param>
    /// <param name="parallelism">Parallelism degree.</param>
    /// <param name="memoryExponent">Memory exponent (memory = 2^m KiB).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithArgon2Parameters(byte timePasses, byte parallelism, byte memoryExponent)
    {
        return WithType(S2KType.Argon2)
            .WithArgon2TimePasses(timePasses)
            .WithArgon2Parallelism(parallelism)
            .WithArgon2MemoryExponent(memoryExponent);
    }

    /// <summary>
    /// Derives a key from the given password.
    /// </summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="keySize">Desired key size in bytes.</param>
    /// <returns>The derived key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="ArgumentNullException">If password is null.</exception>
    /// <exception cref="InvalidOperationException">If salt is required but not set.</exception>
    public byte[] DeriveKey(byte[] password, int keySize)
    {
        ArgumentHelper.ThrowIfNull(password);
        ArgumentHelper.ThrowIfDisposed(disposed, this);

        return s2kType switch
        {
            S2KType.Simple => S2KCore.SimpleS2K(password, keySize, hashAlgorithm),
            S2KType.Salted => DeriveWithSalt(password, keySize, false),
            S2KType.IteratedAndSalted => DeriveWithSalt(password, keySize, true),
            S2KType.Argon2 => DeriveWithArgon2(password, keySize),
            _ => throw new InvalidOperationException($"Unsupported S2K type: {s2kType}")
        };
    }

    /// <summary>
    /// Derives a key from the given password string (UTF-8 encoded).
    /// </summary>
    /// <param name="password">The password string.</param>
    /// <param name="keySize">Desired key size in bytes.</param>
    /// <returns>The derived key.</returns>
    public byte[] DeriveKey(string password, int keySize)
    {
        ArgumentHelper.ThrowIfNull(password);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return DeriveKey(passwordBytes, keySize);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(passwordBytes);
        }
    }

    /// <summary>
    /// Gets the current salt value.
    /// </summary>
    /// <returns>A copy of the salt, or null if not set.</returns>
    public byte[]? GetSalt()
    {
        return salt == null ? null : [.. salt];
    }

    /// <summary>
    /// Gets the encoded iteration count byte.
    /// </summary>
    /// <returns>The RFC 4880 encoded count byte.</returns>
    public byte GetEncodedIterationCount()
    {
        return S2KCore.EncodeIterationCount(iterationCount);
    }

    private byte[] DeriveWithSalt(byte[] password, int keySize, bool iterated)
    {
        if (salt == null)
        {
            throw new InvalidOperationException("Salt is required. Use WithSalt() or WithRandomSalt().");
        }

        if (iterated)
        {
            return S2KCore.IteratedS2K(password, salt, iterationCount, keySize, hashAlgorithm);
        }
        else
        {
            return S2KCore.SaltedS2K(password, salt, keySize, hashAlgorithm);
        }
    }

    private byte[] DeriveWithArgon2(byte[] password, int keySize)
    {
        if (salt == null)
        {
            throw new InvalidOperationException("Salt is required for Argon2 S2K. Use WithSalt() or WithRandomSalt().");
        }

        if (salt.Length != S2KCore.ARGON2_SALT_SIZE)
        {
            throw new InvalidOperationException($"Argon2 requires a {S2KCore.ARGON2_SALT_SIZE}-byte salt. Current salt is {salt.Length} bytes. Use WithRandomSalt() to generate a proper salt.");
        }

        return S2KCore.Argon2S2K(password, salt, argon2TimePasses, argon2Parallelism, argon2MemoryExponent, keySize);
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
            ClearSalt();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
