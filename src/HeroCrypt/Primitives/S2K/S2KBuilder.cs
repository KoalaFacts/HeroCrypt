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
/// // Iterated S2K (recommended)
/// var key = S2KBuilder.Create()
///     .WithType(S2KType.IteratedAndSalted)
///     .WithIterationCount(65536)
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
    /// Sets the salt for Salted and Iterated S2K.
    /// </summary>
    /// <param name="saltValue">The 8-byte salt.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If salt is null.</exception>
    /// <exception cref="ArgumentException">If salt is not 8 bytes.</exception>
    public S2KBuilder WithSalt(byte[] saltValue)
    {
        ArgumentHelper.ThrowIfNull(saltValue);
        if (saltValue.Length != S2KCore.DEFAULT_SALT_SIZE)
        {
            throw new ArgumentException($"Salt must be {S2KCore.DEFAULT_SALT_SIZE} bytes.", nameof(saltValue));
        }

        ClearSalt();
        salt = [.. saltValue];
        return this;
    }

    /// <summary>
    /// Generates and sets a random salt.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public S2KBuilder WithRandomSalt()
    {
        ClearSalt();
        salt = S2KCore.GenerateSalt();
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
