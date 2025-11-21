using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Kdf;

/// <summary>
/// PBKDF2 convenience utilities for password-based key derivation
/// </summary>
public static class Pbkdf2Utilities
{
    /// <summary>
    /// Derives a key from a password with recommended security parameters
    /// </summary>
    /// <param name="password">Password string</param>
    /// <param name="salt">Salt bytes (generated if null)</param>
    /// <param name="keyLength">Desired key length (default: 32 bytes)</param>
    /// <returns>Tuple of (derived key, salt used)</returns>
    public static (byte[] Key, byte[] Salt) DeriveKeySecure(string password, byte[]? salt = null, int keyLength = 32)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        }

        var actualSalt = salt ?? Pbkdf2Core.GenerateRandomSalt();
        var parameters = Pbkdf2Core.GetRecommendedParameters(Pbkdf2UseCase.KeyDerivation);

        var key = Pbkdf2Core.DeriveKeyFromString(password, actualSalt, parameters.Iterations,
            keyLength, parameters.HashAlgorithm);

        return (key, actualSalt);
    }

    /// <summary>
    /// Creates a password hash for storage and verification
    /// </summary>
    /// <param name="password">Password to hash</param>
    /// <param name="salt">Salt bytes (generated if null)</param>
    /// <returns>Password hash result with metadata</returns>
    public static PasswordHashResult HashPassword(string password, byte[]? salt = null)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        }

        var actualSalt = salt ?? Pbkdf2Core.GenerateRandomSalt();
        var parameters = Pbkdf2Core.GetRecommendedParameters(Pbkdf2UseCase.PasswordStorage);

        var hash = Pbkdf2Core.DeriveKeyFromString(password, actualSalt, parameters.Iterations,
            parameters.OutputLength, parameters.HashAlgorithm);

        return new PasswordHashResult
        {
            Hash = hash,
            Salt = actualSalt,
            Iterations = parameters.Iterations,
            HashAlgorithm = parameters.HashAlgorithm,
            OutputLength = parameters.OutputLength
        };
    }

    /// <summary>
    /// Verifies a password against a stored hash
    /// </summary>
    /// <param name="password">Password to verify</param>
    /// <param name="hashResult">Stored password hash result</param>
    /// <returns>True if password matches</returns>
    public static bool VerifyPassword(string password, PasswordHashResult hashResult)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        }
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(hashResult);
#else
        if (hashResult == null)
        {
            throw new ArgumentNullException(nameof(hashResult));
        }
#endif

        var computedHash = Pbkdf2Core.DeriveKeyFromString(password, hashResult.Salt,
            hashResult.Iterations, hashResult.OutputLength, hashResult.HashAlgorithm);

        try
        {
            return SecureMemoryOperations.ConstantTimeEquals(computedHash, hashResult.Hash);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(computedHash);
        }
    }

    /// <summary>
    /// Derives multiple related keys from a single password
    /// </summary>
    /// <param name="password">Master password</param>
    /// <param name="salt">Salt for key derivation</param>
    /// <param name="keySpecs">Key specifications</param>
    /// <param name="iterations">Number of PBKDF2 iterations</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Array of derived keys</returns>
    public static byte[][] DeriveMultipleKeys(string password, ReadOnlySpan<byte> salt,
        KeySpec[] keySpecs, int iterations = 0, HashAlgorithmName hashAlgorithm = default)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        }
        if (keySpecs == null || keySpecs.Length == 0)
        {
            throw new ArgumentException("Key specifications cannot be null or empty", nameof(keySpecs));
        }

        var actualIterations = iterations > 0 ? iterations : Pbkdf2Core.DEFAULT_ITERATIONS;
        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;

        var keys = new byte[keySpecs.Length][];

        try
        {
            for (var i = 0; i < keySpecs.Length; i++)
            {
                var spec = keySpecs[i];
                var contextSalt = CombineSaltWithContext(salt, spec.Context);
                keys[i] = Pbkdf2Core.DeriveKeyFromString(password, contextSalt, actualIterations,
                    spec.Length, algorithm);
            }

            return keys;
        }
        catch
        {
            // Clean up on error
            foreach (var key in keys)
            {
                if (key != null)
                {
                    SecureMemoryOperations.SecureClear(key);
                }
            }
            throw;
        }
    }

    /// <summary>
    /// Derives an encryption key and IV from a password
    /// </summary>
    /// <param name="password">Password</param>
    /// <param name="salt">Salt for key derivation</param>
    /// <param name="keySize">Size of encryption key</param>
    /// <param name="ivSize">Size of IV</param>
    /// <param name="iterations">Number of iterations</param>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <returns>Tuple of (key, iv)</returns>
    public static (byte[] Key, byte[] Iv) DeriveKeyAndIv(string password, ReadOnlySpan<byte> salt,
        int keySize = 32, int ivSize = 16, int iterations = 0, HashAlgorithmName hashAlgorithm = default)
    {
        var specs = new[]
        {
            new KeySpec("key", keySize),
            new KeySpec("iv", ivSize)
        };

        var keys = DeriveMultipleKeys(password, salt, specs, iterations, hashAlgorithm);
        return (keys[0], keys[1]);
    }

    /// <summary>
    /// Calibrates PBKDF2 iterations for target timing
    /// </summary>
    /// <param name="targetMilliseconds">Target derivation time in milliseconds</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <param name="samplePassword">Sample password for testing</param>
    /// <returns>Calibrated iteration count</returns>
    public static int CalibrateIterations(int targetMilliseconds, HashAlgorithmName hashAlgorithm = default,
        string samplePassword = "test")
    {
        _ = samplePassword; // retained for API compatibility

        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;
        return Pbkdf2Core.CalculateIterations(targetMilliseconds, algorithm);
    }

    /// <summary>
    /// Derives a key with automatic iteration calibration
    /// </summary>
    /// <param name="password">Password</param>
    /// <param name="salt">Salt</param>
    /// <param name="targetTimeMs">Target derivation time in milliseconds</param>
    /// <param name="keyLength">Desired key length</param>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <returns>Tuple of (key, iterations used)</returns>
    public static (byte[] Key, int Iterations) DeriveKeyWithCalibration(string password, ReadOnlySpan<byte> salt,
        int targetTimeMs = 100, int keyLength = 32, HashAlgorithmName hashAlgorithm = default)
    {
        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;
        var iterations = CalibrateIterations(targetTimeMs, algorithm, password);

        var key = Pbkdf2Core.DeriveKeyFromString(password, salt, iterations, keyLength, algorithm);
        return (key, iterations);
    }

    /// <summary>
    /// Creates a password-based encryption context
    /// </summary>
    /// <param name="password">Password</param>
    /// <param name="useCase">PBKDF2 use case</param>
    /// <returns>Encryption context with derived keys</returns>
    public static PasswordBasedEncryptionContext CreateEncryptionContext(string password, Pbkdf2UseCase useCase = Pbkdf2UseCase.KeyDerivation)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        }

        var parameters = Pbkdf2Core.GetRecommendedParameters(useCase);
        var salt = Pbkdf2Core.GenerateRandomSalt(parameters.SaltLength);

        var specs = new[]
        {
            new KeySpec("encryption", 32),  // AES-256 key
            new KeySpec("hmac", 32),        // HMAC key
            new KeySpec("iv", 16)           // AES IV
        };

        var keys = DeriveMultipleKeys(password, salt, specs, parameters.Iterations, parameters.HashAlgorithm);

        return new PasswordBasedEncryptionContext
        {
            EncryptionKey = keys[0],
            HmacKey = keys[1],
            Iv = keys[2],
            Salt = salt,
            Iterations = parameters.Iterations,
            HashAlgorithm = parameters.HashAlgorithm
        };
    }

    /// <summary>
    /// Combines salt with context information
    /// </summary>
    private static byte[] CombineSaltWithContext(ReadOnlySpan<byte> salt, string? context)
    {
        if (string.IsNullOrEmpty(context))
        {
            return salt.ToArray();
        }

        var contextBytes = Encoding.UTF8.GetBytes(context);
        var combined = new byte[salt.Length + contextBytes.Length];

        salt.CopyTo(combined.AsSpan(0, salt.Length));
        contextBytes.CopyTo(combined, salt.Length);

        return combined;
    }
}

/// <summary>
/// Password hash result containing all necessary information for verification
/// </summary>
public class PasswordHashResult
{
    /// <summary>Derived password hash</summary>
    public byte[] Hash { get; set; } = [];

    /// <summary>Salt used for derivation</summary>
    public byte[] Salt { get; set; } = [];

    /// <summary>Number of iterations used</summary>
    public int Iterations { get; set; }

    /// <summary>Hash algorithm used</summary>
    public HashAlgorithmName HashAlgorithm { get; set; }

    /// <summary>Output length of the hash</summary>
    public int OutputLength { get; set; }

    /// <summary>Timestamp when hash was created</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Clears sensitive data</summary>
    public void Clear()
    {
        SecureMemoryOperations.SecureClear(Hash);
        SecureMemoryOperations.SecureClear(Salt);
    }
}

/// <summary>
/// Password-based encryption context with derived keys
/// </summary>
public class PasswordBasedEncryptionContext : IDisposable
{
    /// <summary>Encryption key</summary>
    public byte[] EncryptionKey { get; set; } = [];

    /// <summary>HMAC key for authentication</summary>
    public byte[] HmacKey { get; set; } = [];

    /// <summary>Initialization vector</summary>
    public byte[] Iv { get; set; } = [];

    /// <summary>Salt used for key derivation</summary>
    public byte[] Salt { get; set; } = [];

    /// <summary>Number of PBKDF2 iterations</summary>
    public int Iterations { get; set; }

    /// <summary>Hash algorithm used</summary>
    public HashAlgorithmName HashAlgorithm { get; set; }

    /// <summary>Disposes and clears sensitive data</summary>
    public void Dispose()
    {
        SecureMemoryOperations.SecureClear(EncryptionKey);
        SecureMemoryOperations.SecureClear(HmacKey);
        SecureMemoryOperations.SecureClear(Iv);
        SecureMemoryOperations.SecureClear(Salt);

        GC.SuppressFinalize(this);
    }
}
