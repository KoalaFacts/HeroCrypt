using HeroCrypt.Security;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.KeyDerivation;

/// <summary>
/// PBKDF2 (Password-Based Key Derivation Function 2) implementation
/// RFC 2898 compliant implementation with configurable hash algorithms and iterations
/// </summary>
internal static class Pbkdf2Core
{
    /// <summary>
    /// Minimum recommended iteration count for new applications
    /// </summary>
    public const int MinRecommendedIterations = 100000;

    /// <summary>
    /// Default iteration count for general use
    /// </summary>
    public const int DefaultIterations = 600000;

    /// <summary>
    /// Minimum salt length in bytes
    /// </summary>
    public const int MinSaltLength = 16;

    /// <summary>
    /// Default salt length in bytes
    /// </summary>
    public const int DefaultSaltLength = 32;

    /// <summary>
    /// Derives a key using PBKDF2
    /// </summary>
    /// <param name="password">Password bytes</param>
    /// <param name="salt">Salt bytes</param>
    /// <param name="iterations">Number of iterations</param>
    /// <param name="outputLength">Desired output length in bytes</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <param name="allowWeakParameters">Allow parameters below security recommendations for standards compliance (e.g., BIP-39). Use with caution.</param>
    /// <returns>Derived key</returns>
    public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int iterations, int outputLength, HashAlgorithmName hashAlgorithm, bool allowWeakParameters = false)
    {
        ValidateParameters(password, salt, iterations, outputLength, hashAlgorithm, allowWeakParameters);

#if NET6_0_OR_GREATER
        // Use .NET 6+ optimized implementation
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, outputLength);
#else
        // Custom implementation for older frameworks
        return DeriveKeyLegacy(password, salt, iterations, outputLength, hashAlgorithm);
#endif
    }

    /// <summary>
    /// Derives a key from a password string using PBKDF2
    /// </summary>
    /// <param name="password">Password string</param>
    /// <param name="salt">Salt bytes</param>
    /// <param name="iterations">Number of iterations</param>
    /// <param name="outputLength">Desired output length in bytes</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Derived key</returns>
    public static byte[] DeriveKeyFromString(string password, ReadOnlySpan<byte> salt,
        int iterations, int outputLength, HashAlgorithmName hashAlgorithm)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        try
        {
            return DeriveKey(passwordBytes, salt, iterations, outputLength, hashAlgorithm);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(passwordBytes);
        }
    }

    /// <summary>
    /// Validates PBKDF2 parameters
    /// </summary>
    /// <param name="password">Password bytes</param>
    /// <param name="salt">Salt bytes</param>
    /// <param name="iterations">Number of iterations</param>
    /// <param name="outputLength">Output length</param>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <param name="allowWeakParameters">Allow parameters below security recommendations</param>
    public static void ValidateParameters(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int iterations, int outputLength, HashAlgorithmName hashAlgorithm, bool allowWeakParameters = false)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password cannot be empty", nameof(password));

        if (!allowWeakParameters && salt.Length < MinSaltLength)
            throw new ArgumentException($"Salt must be at least {MinSaltLength} bytes", nameof(salt));

        if (iterations < 1)
            throw new ArgumentException("Iterations must be positive", nameof(iterations));

        if (!allowWeakParameters && iterations < MinRecommendedIterations)
            throw new ArgumentException($"Iterations should be at least {MinRecommendedIterations} for security", nameof(iterations));

        if (outputLength <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLength));

        if (!IsHashAlgorithmSupported(hashAlgorithm))
            throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm));

        var maxOutputLength = GetMaxOutputLength(hashAlgorithm);
        if (outputLength > maxOutputLength)
            throw new ArgumentException($"Output length too large for {hashAlgorithm} (max: {maxOutputLength})", nameof(outputLength));
    }

    /// <summary>
    /// Generates a random salt for PBKDF2
    /// </summary>
    /// <param name="length">Salt length (default: 32 bytes)</param>
    /// <returns>Random salt</returns>
    public static byte[] GenerateRandomSalt(int length = DefaultSaltLength)
    {
        if (length < MinSaltLength)
            throw new ArgumentException($"Salt length must be at least {MinSaltLength} bytes", nameof(length));

        var salt = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Calculates appropriate iteration count based on target time
    /// </summary>
    /// <param name="targetTimeMs">Target derivation time in milliseconds</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <param name="testLength">Test key length (default: 32 bytes)</param>
    /// <returns>Recommended iteration count</returns>
    public static int CalculateIterations(int targetTimeMs, HashAlgorithmName hashAlgorithm, int testLength = 32)
    {
        if (targetTimeMs <= 0)
            throw new ArgumentException("Target time must be positive", nameof(targetTimeMs));

        const int testIterations = 10000;
        var testPassword = new byte[16];
        var testSalt = GenerateRandomSalt();

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(testPassword);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        DeriveKey(testPassword, testSalt, testIterations, testLength, hashAlgorithm);
        stopwatch.Stop();

        var actualTimeMs = stopwatch.Elapsed.TotalMilliseconds;
        var iterationsPerMs = testIterations / actualTimeMs;
        var recommendedIterations = (int)(iterationsPerMs * targetTimeMs);

        // Ensure minimum security requirements
        return Math.Max(recommendedIterations, MinRecommendedIterations);
    }

    /// <summary>
    /// Gets recommended parameters for different use cases
    /// </summary>
    /// <param name="useCase">PBKDF2 use case</param>
    /// <returns>Recommended parameters</returns>
    public static Pbkdf2Parameters GetRecommendedParameters(Pbkdf2UseCase useCase)
    {
        return useCase switch
        {
            Pbkdf2UseCase.PasswordStorage => new Pbkdf2Parameters
            {
                HashAlgorithm = HashAlgorithmName.SHA256,
                Iterations = 600000,
                SaltLength = DefaultSaltLength,
                OutputLength = 32,
                Description = "Password storage and verification"
            },
            Pbkdf2UseCase.KeyDerivation => new Pbkdf2Parameters
            {
                HashAlgorithm = HashAlgorithmName.SHA256,
                Iterations = 100000,
                SaltLength = DefaultSaltLength,
                OutputLength = 32,
                Description = "Key derivation from passwords"
            },
            Pbkdf2UseCase.HighSecurity => new Pbkdf2Parameters
            {
                HashAlgorithm = HashAlgorithmName.SHA512,
                Iterations = 1000000,
                SaltLength = 64,
                OutputLength = 64,
                Description = "High-security applications"
            },
            Pbkdf2UseCase.LegacyCompatibility => new Pbkdf2Parameters
            {
                HashAlgorithm = HashAlgorithmName.SHA1,
                Iterations = 100000,
                SaltLength = MinSaltLength,
                OutputLength = 20,
                Description = "Legacy system compatibility (SHA-1 not recommended)"
            },
            _ => throw new ArgumentException($"Unknown use case: {useCase}", nameof(useCase))
        };
    }

    /// <summary>
    /// Checks if a hash algorithm is supported
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm to check</param>
    /// <returns>True if supported</returns>
    public static bool IsHashAlgorithmSupported(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm == HashAlgorithmName.SHA1 ||
               hashAlgorithm == HashAlgorithmName.SHA256 ||
               hashAlgorithm == HashAlgorithmName.SHA384 ||
               hashAlgorithm == HashAlgorithmName.SHA512;
    }

    /// <summary>
    /// Gets maximum output length for a hash algorithm
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <returns>Maximum output length in bytes</returns>
    public static int GetMaxOutputLength(HashAlgorithmName hashAlgorithm)
    {
        // PBKDF2 can generate up to (2^32 - 1) * hLen bytes theoretically,
        // but we limit to reasonable values
        return hashAlgorithm.Name switch
        {
            "SHA1" => 1048576,      // 1MB
            "SHA256" => 1048576,    // 1MB
            "SHA384" => 1048576,    // 1MB
            "SHA512" => 1048576,    // 1MB
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm))
        };
    }

#if !NET6_0_OR_GREATER
    /// <summary>
    /// Legacy PBKDF2 implementation for older .NET versions
    /// </summary>
    private static byte[] DeriveKeyLegacy(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int iterations, int outputLength, HashAlgorithmName hashAlgorithm)
    {
#if NETSTANDARD2_0
        // .NET Standard 2.0 doesn't support HashAlgorithmName parameter
        using var deriveBytes = new Rfc2898DeriveBytes(password.ToArray(), salt.ToArray(), iterations);
        return deriveBytes.GetBytes(outputLength);
#else
        using var deriveBytes = new Rfc2898DeriveBytes(password.ToArray(), salt.ToArray(), iterations, hashAlgorithm);
        return deriveBytes.GetBytes(outputLength);
#endif
    }
#endif
}

/// <summary>
/// PBKDF2 use cases for parameter recommendations
/// </summary>
public enum Pbkdf2UseCase
{
    /// <summary>Password storage and verification</summary>
    PasswordStorage,
    /// <summary>Key derivation from passwords</summary>
    KeyDerivation,
    /// <summary>High-security applications</summary>
    HighSecurity,
    /// <summary>Legacy system compatibility</summary>
    LegacyCompatibility
}

/// <summary>
/// PBKDF2 parameters for different use cases
/// </summary>
public class Pbkdf2Parameters
{
    /// <summary>Recommended hash algorithm</summary>
    public HashAlgorithmName HashAlgorithm { get; set; }

    /// <summary>Recommended iteration count</summary>
    public int Iterations { get; set; }

    /// <summary>Recommended salt length</summary>
    public int SaltLength { get; set; }

    /// <summary>Recommended output length</summary>
    public int OutputLength { get; set; }

    /// <summary>Description of the parameters</summary>
    public string Description { get; set; } = string.Empty;
}