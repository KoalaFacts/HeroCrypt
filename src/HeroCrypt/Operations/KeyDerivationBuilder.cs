using System.Security.Cryptography;
using HeroCrypt.Primitives.Argon2;
using HeroCrypt.Primitives.Common;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Primitives.Pbkdf2;
using HeroCrypt.Primitives.Scrypt;
using HeroCrypt.Security;

namespace HeroCrypt.Operations;

/// <summary>
/// Fluent builder for key derivation operations.
/// </summary>
/// <remarks>
/// <para>
/// This builder implements <see cref="IDisposable"/> to securely clear sensitive password and salt material
/// from memory when the builder is no longer needed. It is recommended to use this builder
/// within a <c>using</c> statement.
/// </para>
/// </remarks>
public sealed class KeyDerivationBuilder : IDisposable
{
    private KeyDerivationAlgorithm algorithm = KeyDerivationAlgorithm.Argon2id;
    private byte[]? password;
    private byte[]? salt;
    private byte[]? info;
    private int outputLength = 32;
    private bool disposed;

    private void ThrowIfDisposed()
    {
#if NETSTANDARD2_0
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(KeyDerivationBuilder));
        }
#else
        ObjectDisposedException.ThrowIf(disposed, this);
#endif
    }

    private void ClearPassword()
    {
        if (password == null) return;
        SecureMemoryOperations.SecureClear(password);
        password = null;
    }

    private void ClearSalt()
    {
        if (salt == null) return;
        SecureMemoryOperations.SecureClear(salt);
        salt = null;
    }

    private void ClearInfo()
    {
        if (info == null) return;
        SecureMemoryOperations.SecureClear(info);
        info = null;
    }

    /// <summary>
    /// Releases all resources used by this builder and securely clears sensitive password and salt material.
    /// </summary>
    public void Dispose()
    {
        if (disposed) return;
        ClearPassword();
        ClearSalt();
        ClearInfo();
        disposed = true;
        GC.SuppressFinalize(this);
    }

    // Default parameters for KDFs
    private const int DefaultArgon2MemoryKiB = 65536;  // 64 MB
    private const int DefaultArgon2Iterations = 3;
    private const int DefaultArgon2Parallelism = 4;
    private const int DefaultPbkdf2Iterations = 100_000;
    private const int DefaultScryptN = 16384;
    private const int DefaultScryptR = 8;
    private const int DefaultScryptP = 1;
#if !NETSTANDARD2_0
    private const int DefaultBalloonSpaceCost = BalloonHashing.DEFAULT_SPACE_COST;
    private const int DefaultBalloonTimeCost = BalloonHashing.DEFAULT_TIME_COST;
#endif

    /// <summary>
    /// Sets the KDF algorithm to use.
    /// </summary>
    public KeyDerivationBuilder WithAlgorithm(KeyDerivationAlgorithm algorithm)
    {
        ThrowIfDisposed();
        this.algorithm = algorithm;
        return this;
    }

    // Password Hashing KDFs (Memory-hard, slow by design)

    /// <summary>
    /// Use Argon2id for key derivation (default, recommended for passwords).
    /// Hybrid of Argon2d (GPU-resistant) and Argon2i (side-channel resistant).
    /// </summary>
    public KeyDerivationBuilder WithArgon2id() => WithAlgorithm(KeyDerivationAlgorithm.Argon2id);

    /// <summary>
    /// Use Argon2d for key derivation (GPU-resistant but vulnerable to side-channel attacks).
    /// Best for backend applications where side-channel attacks are not a concern.
    /// </summary>
    public KeyDerivationBuilder WithArgon2d() => WithAlgorithm(KeyDerivationAlgorithm.Argon2d);

    /// <summary>
    /// Use Argon2i for key derivation (side-channel resistant but less GPU-resistant).
    /// Best for environments where side-channel attacks are a concern.
    /// </summary>
    public KeyDerivationBuilder WithArgon2i() => WithAlgorithm(KeyDerivationAlgorithm.Argon2i);

    /// <summary>
    /// Use Scrypt for key derivation (memory-hard, widely deployed).
    /// </summary>
    public KeyDerivationBuilder WithScrypt() => WithAlgorithm(KeyDerivationAlgorithm.Scrypt);

#if !NETSTANDARD2_0
    /// <summary>
    /// Use Balloon Hashing with SHA-256 for key derivation.
    /// Memory-hard with provable security and cache-timing resistance.
    /// </summary>
    public KeyDerivationBuilder WithBalloonSha256() => WithAlgorithm(KeyDerivationAlgorithm.BalloonSha256);

    /// <summary>
    /// Use Balloon Hashing with SHA-512 for key derivation.
    /// Memory-hard with provable security and cache-timing resistance.
    /// </summary>
    public KeyDerivationBuilder WithBalloonSha512() => WithAlgorithm(KeyDerivationAlgorithm.BalloonSha512);
#endif

    // Password-Based KDFs (Iterative, for legacy/compatibility)

    /// <summary>
    /// Use PBKDF2 with SHA-256 for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithPbkdf2Sha256() => WithAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha256);

    /// <summary>
    /// Use PBKDF2 with SHA-512 for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithPbkdf2Sha512() => WithAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha512);

    /// <summary>
    /// Use PBKDF2 with SHA-384 for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithPbkdf2Sha384() => WithAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha384);

    /// <summary>
    /// Use PBKDF2 with SHA-1 for key derivation (legacy compatibility only).
    /// Note: SHA-1 is not recommended for new applications.
    /// </summary>
    public KeyDerivationBuilder WithPbkdf2Sha1() => WithAlgorithm(KeyDerivationAlgorithm.Pbkdf2Sha1);

    // Key Expansion KDFs (Fast, NOT for password hashing)

    /// <summary>
    /// Use HKDF with SHA-256 for key derivation.
    /// Not suitable for password hashing - use Argon2id or Scrypt instead.
    /// </summary>
    public KeyDerivationBuilder WithHkdfSha256() => WithAlgorithm(KeyDerivationAlgorithm.HkdfSha256);

    /// <summary>
    /// Use HKDF with SHA-512 for key derivation.
    /// Not suitable for password hashing - use Argon2id or Scrypt instead.
    /// </summary>
    public KeyDerivationBuilder WithHkdfSha512() => WithAlgorithm(KeyDerivationAlgorithm.HkdfSha512);

    /// <summary>
    /// Use HKDF with SHA-384 for key derivation.
    /// Not suitable for password hashing - use Argon2id or Scrypt instead.
    /// </summary>
    public KeyDerivationBuilder WithHkdfSha384() => WithAlgorithm(KeyDerivationAlgorithm.HkdfSha384);

    /// <summary>
    /// Use HKDF with SHA-1 for key derivation (legacy compatibility only).
    /// Not suitable for password hashing - use Argon2id or Scrypt instead.
    /// </summary>
    public KeyDerivationBuilder WithHkdfSha1() => WithAlgorithm(KeyDerivationAlgorithm.HkdfSha1);

    /// <summary>
    /// Sets the password bytes for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithPassword(byte[] password)
    {
        ThrowIfDisposed();
        ClearPassword();
        this.password = [.. password];
        return this;
    }

    /// <summary>
    /// Sets the password string for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithPassword(string password)
    {
        ThrowIfDisposed();
        ClearPassword();
        this.password = System.Text.Encoding.UTF8.GetBytes(password);
        return this;
    }

    /// <summary>
    /// Sets the salt for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithSalt(byte[] salt)
    {
        ThrowIfDisposed();
        ClearSalt();
        this.salt = [.. salt];
        return this;
    }

    /// <summary>
    /// Generates and sets a cryptographically secure random salt.
    /// </summary>
    /// <param name="length">Length of the salt in bytes (default: 16).</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// The generated salt can be retrieved using <see cref="GetSalt"/> after calling this method.
    /// For password hashing, a salt length of 16 bytes (128 bits) or more is recommended.
    /// </remarks>
    public KeyDerivationBuilder WithRandomSalt(int length = 16)
    {
        ThrowIfDisposed();
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Salt length must be positive.");
        }

        ClearSalt();
        salt = new byte[length];
        SecureRandomNumberGenerator.Fill(salt);
        return this;
    }

    /// <summary>
    /// Gets a copy of the current salt.
    /// </summary>
    /// <returns>A copy of the salt bytes.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no salt has been set.</exception>
    /// <remarks>
    /// This method is useful for retrieving a randomly generated salt that needs to be stored
    /// alongside the derived key for later verification.
    /// </remarks>
    public byte[] GetSalt()
    {
        ThrowIfDisposed();
        if (salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt() or WithRandomSalt()");
        }

        return [.. salt];
    }

    /// <summary>
    /// Returns the salt as a lowercase hexadecimal string.
    /// </summary>
    /// <returns>The salt as a lowercase hexadecimal string.</returns>
    /// <exception cref="InvalidOperationException">Thrown when salt has not been set.</exception>
    /// <remarks>
    /// <para>
    /// This is a convenience method for obtaining the salt in a format suitable for storage or display.
    /// </para>
    /// <para>
    /// Example usage with random salt:
    /// <code>
    /// using var kdf = HeroCryptBuilder.Argon2();
    /// kdf.WithPassword(password).WithRandomSalt();
    /// var saltHex = kdf.GetSaltAsHex();  // Store this alongside the derived key
    /// var derivedKey = kdf.DeriveKey();
    /// </code>
    /// </para>
    /// </remarks>
    public string GetSaltAsHex()
    {
        var saltBytes = GetSalt();
        return Convert.ToHexString(saltBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Returns the salt as a Base64-encoded string.
    /// </summary>
    /// <returns>The salt as a Base64-encoded string.</returns>
    /// <exception cref="InvalidOperationException">Thrown when salt has not been set.</exception>
    /// <remarks>
    /// This is a convenience method for obtaining the salt in a format suitable for storage
    /// in JSON, databases, or other text-based formats.
    /// </remarks>
    public string GetSaltAsBase64()
    {
        var saltBytes = GetSalt();
        return Convert.ToBase64String(saltBytes);
    }

    /// <summary>
    /// Returns the salt as a URL-safe Base64-encoded string (no padding).
    /// </summary>
    /// <returns>The salt as a URL-safe Base64-encoded string.</returns>
    /// <exception cref="InvalidOperationException">Thrown when salt has not been set.</exception>
    /// <remarks>
    /// <para>
    /// URL-safe Base64 replaces '+' with '-', '/' with '_', and omits padding '=' characters.
    /// </para>
    /// <para>
    /// Use this when embedding the salt in URLs or when standard Base64 characters may cause issues.
    /// </para>
    /// </remarks>
    public string GetSaltAsBase64Url()
    {
        var saltBytes = GetSalt();
        return Convert.ToBase64String(saltBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Sets the desired output length in bytes (default: 32).
    /// </summary>
    public KeyDerivationBuilder WithOutputLength(int length)
    {
        ThrowIfDisposed();
        outputLength = length;
        return this;
    }

    /// <summary>
    /// Sets the context/application-specific info for HKDF key derivation.
    /// </summary>
    /// <param name="info">The info/context bytes used for domain separation in HKDF.</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// <para>
    /// The info parameter is only used by HKDF algorithms (HkdfSha256, HkdfSha384, HkdfSha512, HkdfSha1).
    /// For other KDFs (Argon2, Scrypt, PBKDF2, Balloon), this parameter is ignored.
    /// </para>
    /// <para>
    /// The info parameter enables deriving multiple independent keys from the same input keying material
    /// by using different info values. This is useful for key separation in protocols.
    /// </para>
    /// <para>
    /// Example:
    /// </para>
    /// <code>
    /// // Derive separate keys for encryption and authentication
    /// var encryptionKey = builder.WithInfo("encryption"u8.ToArray()).DeriveKey();
    /// var authKey = builder.WithInfo("authentication"u8.ToArray()).DeriveKey();
    /// </code>
    /// </remarks>
    public KeyDerivationBuilder WithInfo(byte[] info)
    {
        ThrowIfDisposed();
        ClearInfo();
        this.info = [.. info];
        return this;
    }

    /// <summary>
    /// Sets the context/application-specific info for HKDF key derivation using a string.
    /// </summary>
    /// <param name="info">The info/context string used for domain separation in HKDF (UTF-8 encoded).</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// <para>
    /// The info parameter is only used by HKDF algorithms. For other KDFs, this parameter is ignored.
    /// The string is converted to bytes using UTF-8 encoding.
    /// </para>
    /// </remarks>
    public KeyDerivationBuilder WithInfo(string info)
    {
        ThrowIfDisposed();
        ClearInfo();
        this.info = System.Text.Encoding.UTF8.GetBytes(info);
        return this;
    }

    /// <summary>
    /// Derives a key from the configured parameters.
    /// </summary>
    public byte[] DeriveKey()
    {
        ThrowIfDisposed();

        if (password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }

        if (salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        InputValidator.ValidateByteArray(password, nameof(password));
        InputValidator.ValidateByteArray(salt, nameof(salt));

        return algorithm switch
        {
            // Password Hashing KDFs (Memory-hard)
            KeyDerivationAlgorithm.Argon2id => Argon2Core.Hash(
                password, salt, DefaultArgon2Iterations, DefaultArgon2MemoryKiB,
                DefaultArgon2Parallelism, outputLength, Argon2Type.Argon2id),
            KeyDerivationAlgorithm.Argon2d => Argon2Core.Hash(
                password, salt, DefaultArgon2Iterations, DefaultArgon2MemoryKiB,
                DefaultArgon2Parallelism, outputLength, Argon2Type.Argon2d),
            KeyDerivationAlgorithm.Argon2i => Argon2Core.Hash(
                password, salt, DefaultArgon2Iterations, DefaultArgon2MemoryKiB,
                DefaultArgon2Parallelism, outputLength, Argon2Type.Argon2i),
            KeyDerivationAlgorithm.Scrypt => ScryptCore.DeriveKey(
                password, salt, DefaultScryptN, DefaultScryptR, DefaultScryptP, outputLength),
#if !NETSTANDARD2_0
            KeyDerivationAlgorithm.BalloonSha256 => BalloonHashing.Hash(
                password, salt, DefaultBalloonSpaceCost, DefaultBalloonTimeCost, outputLength, HashAlgorithmName.SHA256),
            KeyDerivationAlgorithm.BalloonSha512 => BalloonHashing.Hash(
                password, salt, DefaultBalloonSpaceCost, DefaultBalloonTimeCost, outputLength, HashAlgorithmName.SHA512),
#endif
            KeyDerivationAlgorithm.Bcrypt => throw new NotImplementedException(
                "Bcrypt is not yet implemented. Use Argon2id or Scrypt as recommended alternatives."),

            // Password-Based KDFs (Iterative)
            KeyDerivationAlgorithm.Pbkdf2Sha256 => Pbkdf2Core.DeriveKey(
                password, salt, DefaultPbkdf2Iterations, outputLength, HashAlgorithmName.SHA256),
            KeyDerivationAlgorithm.Pbkdf2Sha512 => Pbkdf2Core.DeriveKey(
                password, salt, DefaultPbkdf2Iterations, outputLength, HashAlgorithmName.SHA512),
            KeyDerivationAlgorithm.Pbkdf2Sha384 => Pbkdf2Core.DeriveKey(
                password, salt, DefaultPbkdf2Iterations, outputLength, HashAlgorithmName.SHA384),
            KeyDerivationAlgorithm.Pbkdf2Sha1 => Pbkdf2Core.DeriveKey(
                password, salt, DefaultPbkdf2Iterations, outputLength, HashAlgorithmName.SHA1),

            // Key Expansion KDFs (Fast)
            KeyDerivationAlgorithm.HkdfSha256 => HkdfCore.DeriveKey(
                password, salt, info ?? [], outputLength, HashAlgorithmName.SHA256),
            KeyDerivationAlgorithm.HkdfSha512 => HkdfCore.DeriveKey(
                password, salt, info ?? [], outputLength, HashAlgorithmName.SHA512),
            KeyDerivationAlgorithm.HkdfSha384 => HkdfCore.DeriveKey(
                password, salt, info ?? [], outputLength, HashAlgorithmName.SHA384),
            KeyDerivationAlgorithm.HkdfSha1 => HkdfCore.DeriveKey(
                password, salt, info ?? [], outputLength, HashAlgorithmName.SHA1),

            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }
}
