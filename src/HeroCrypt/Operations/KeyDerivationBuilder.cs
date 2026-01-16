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
public class KeyDerivationBuilder
{
    private KeyDerivationAlgorithm algorithm = KeyDerivationAlgorithm.Argon2id;
    private byte[]? password;
    private byte[]? salt;
    private int outputLength = 32;

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
        this.password = password;
        return this;
    }

    /// <summary>
    /// Sets the password string for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithPassword(string password)
    {
        this.password = System.Text.Encoding.UTF8.GetBytes(password);
        return this;
    }

    /// <summary>
    /// Sets the salt for key derivation.
    /// </summary>
    public KeyDerivationBuilder WithSalt(byte[] salt)
    {
        this.salt = salt;
        return this;
    }

    /// <summary>
    /// Sets the desired output length in bytes (default: 32).
    /// </summary>
    public KeyDerivationBuilder WithOutputLength(int length)
    {
        outputLength = length;
        return this;
    }

    /// <summary>
    /// Derives a key from the configured parameters.
    /// </summary>
    public byte[] DeriveKey()
    {
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
                password, salt, [], outputLength, HashAlgorithmName.SHA256),
            KeyDerivationAlgorithm.HkdfSha512 => HkdfCore.DeriveKey(
                password, salt, [], outputLength, HashAlgorithmName.SHA512),
            KeyDerivationAlgorithm.HkdfSha384 => HkdfCore.DeriveKey(
                password, salt, [], outputLength, HashAlgorithmName.SHA384),
            KeyDerivationAlgorithm.HkdfSha1 => HkdfCore.DeriveKey(
                password, salt, [], outputLength, HashAlgorithmName.SHA1),

            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }
}
