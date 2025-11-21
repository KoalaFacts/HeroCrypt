using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Kdf;

/// <summary>
/// HKDF convenience utilities for common key derivation scenarios
/// </summary>
public static class HkdfUtilities
{
    /// <summary>
    /// Derives a key from a password using HKDF with SHA-256
    /// </summary>
    /// <param name="password">Password string</param>
    /// <param name="salt">Salt bytes (optional)</param>
    /// <param name="info">Context information string (optional)</param>
    /// <param name="length">Desired key length</param>
    /// <returns>Derived key</returns>
    public static byte[] DeriveKeyFromPassword(string password, ReadOnlySpan<byte> salt = default,
        string? info = null, int length = 32)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be null or empty", nameof(password));
        }

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var infoBytes = info != null ? Encoding.UTF8.GetBytes(info) : ReadOnlySpan<byte>.Empty;

        try
        {
            return HkdfCore.DeriveKey(passwordBytes, salt, infoBytes, length, HashAlgorithmName.SHA256);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(passwordBytes);
        }
    }

    /// <summary>
    /// Derives multiple keys from a single master key
    /// </summary>
    /// <param name="masterKey">Master key material</param>
    /// <param name="salt">Salt for key derivation</param>
    /// <param name="keySpecs">Key specifications (context, length pairs)</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Array of derived keys</returns>
    public static byte[][] DeriveMultipleKeys(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt,
        KeySpec[] keySpecs, HashAlgorithmName hashAlgorithm = default)
    {
        if (keySpecs == null || keySpecs.Length == 0)
        {
            throw new ArgumentException("Key specifications cannot be null or empty", nameof(keySpecs));
        }

        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;
        var keys = new byte[keySpecs.Length][];

        // Extract once, expand multiple times
        var prk = HkdfCore.Extract(masterKey, salt, algorithm);

        try
        {
            for (var i = 0; i < keySpecs.Length; i++)
            {
                var spec = keySpecs[i];
                var info = spec.Context != null ? Encoding.UTF8.GetBytes(spec.Context) : ReadOnlySpan<byte>.Empty;
                keys[i] = HkdfCore.Expand(prk, info, spec.Length, algorithm);
            }

            return keys;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(prk);
        }
    }

    /// <summary>
    /// Derives encryption and MAC keys from a single master key
    /// </summary>
    /// <param name="masterKey">Master key material</param>
    /// <param name="salt">Salt for key derivation</param>
    /// <param name="encryptionKeySize">Size of encryption key (default: 32)</param>
    /// <param name="macKeySize">Size of MAC key (default: 32)</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Tuple of (encryption key, MAC key)</returns>
    public static (byte[] EncryptionKey, byte[] MacKey) DeriveEncryptionAndMacKeys(
        ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt,
        int encryptionKeySize = 32, int macKeySize = 32,
        HashAlgorithmName hashAlgorithm = default)
    {
        var specs = new[]
        {
            new KeySpec("encryption", encryptionKeySize),
            new KeySpec("mac", macKeySize)
        };

        var keys = DeriveMultipleKeys(masterKey, salt, specs, hashAlgorithm);
        return (keys[0], keys[1]);
    }

    /// <summary>
    /// Derives a key hierarchy for nested encryption
    /// </summary>
    /// <param name="rootKey">Root key material</param>
    /// <param name="salt">Salt for root derivation</param>
    /// <param name="levels">Number of hierarchy levels</param>
    /// <param name="keySize">Size of each derived key (default: 32)</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Array of keys from root to leaf</returns>
    public static byte[][] DeriveKeyHierarchy(ReadOnlySpan<byte> rootKey, ReadOnlySpan<byte> salt,
        int levels, int keySize = 32, HashAlgorithmName hashAlgorithm = default)
    {
        if (levels <= 0)
        {
            throw new ArgumentException("Levels must be positive", nameof(levels));
        }

        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;
        var keys = new byte[levels][];

        // Derive root key
        var currentKey = HkdfCore.DeriveKey(rootKey, salt, "root"u8, keySize, algorithm);
        keys[0] = currentKey;

        try
        {
            // Derive subsequent levels
            for (var level = 1; level < levels; level++)
            {
                var info = Encoding.UTF8.GetBytes($"level-{level}");
                var nextKey = HkdfCore.DeriveKey(currentKey, salt, info, keySize, algorithm);
                keys[level] = nextKey;

                // Clear previous key (except root which we return)
                if (level > 1)
                {
                    SecureMemoryOperations.SecureClear(currentKey);
                }

                currentKey = nextKey;
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
    /// Derives a session key with timestamp for key rotation
    /// </summary>
    /// <param name="masterKey">Master key material</param>
    /// <param name="salt">Salt for derivation</param>
    /// <param name="sessionId">Session identifier</param>
    /// <param name="timestamp">Timestamp for key rotation</param>
    /// <param name="keySize">Size of session key (default: 32)</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Session key</returns>
    public static byte[] DeriveSessionKey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt,
        string sessionId, DateTimeOffset timestamp, int keySize = 32,
        HashAlgorithmName hashAlgorithm = default)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            throw new ArgumentException("Session ID cannot be null or empty", nameof(sessionId));
        }

        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;

        // Create context with session ID and timestamp
        var timestampTicks = timestamp.Ticks;
        var contextString = $"session:{sessionId}:ts:{timestampTicks}";
        var context = Encoding.UTF8.GetBytes(contextString);

        return HkdfCore.DeriveKey(masterKey, salt, context, keySize, algorithm);
    }

    /// <summary>
    /// Validates and normalizes HKDF input parameters
    /// </summary>
    /// <param name="ikm">Input key material</param>
    /// <param name="salt">Salt (will be generated if empty)</param>
    /// <param name="info">Context information</param>
    /// <param name="length">Output length</param>
    /// <param name="hashAlgorithm">Hash algorithm</param>
    /// <returns>Normalized parameters</returns>
    public static (byte[] Ikm, byte[] Salt, byte[] Info) NormalizeParameters(
        ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info,
        int length, HashAlgorithmName hashAlgorithm)
    {
        HkdfCore.ValidateParameters(ikm, length, hashAlgorithm);

        var normalizedIkm = ikm.ToArray();

        // Generate random salt if not provided
        var normalizedSalt = salt.IsEmpty ? GenerateRandomSalt(hashAlgorithm) : salt.ToArray();

        var normalizedInfo = info.ToArray();

        return (normalizedIkm, normalizedSalt, normalizedInfo);
    }

    /// <summary>
    /// Generates a random salt for HKDF
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm to determine salt size</param>
    /// <returns>Random salt</returns>
    public static byte[] GenerateRandomSalt(HashAlgorithmName hashAlgorithm = default)
    {
        var algorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;
        var recommended = HkdfCore.GetRecommendedParameters(HkdfUseCase.GeneralPurpose);

        if (algorithm == HashAlgorithmName.SHA512)
        {
            recommended = HkdfCore.GetRecommendedParameters(HkdfUseCase.HighSecurity);
        }

        var salt = new byte[recommended.RecommendedSaltLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        return salt;
    }

    /// <summary>
    /// Creates a key derivation context with domain separation
    /// </summary>
    /// <param name="domain">Application domain</param>
    /// <param name="purpose">Key purpose</param>
    /// <param name="version">Context version</param>
    /// <returns>Context bytes</returns>
    public static byte[] CreateContext(string domain, string purpose, int version = 1)
    {
        if (string.IsNullOrEmpty(domain))
        {
            throw new ArgumentException("Domain cannot be null or empty", nameof(domain));
        }
        if (string.IsNullOrEmpty(purpose))
        {
            throw new ArgumentException("Purpose cannot be null or empty", nameof(purpose));
        }

        var contextString = $"{domain}:{purpose}:v{version}";
        return Encoding.UTF8.GetBytes(contextString);
    }
}

/// <summary>
/// Key specification for multiple key derivation
/// </summary>
/// <remarks>
/// Creates a new key specification
/// </remarks>
/// <param name="context">Context information</param>
/// <param name="length">Key length in bytes</param>
public class KeySpec(string? context, int length)
{
    /// <summary>
    /// Context information for the key
    /// </summary>
    public string? Context { get; set; } = context;

    /// <summary>
    /// Length of the key in bytes
    /// </summary>
    public int Length { get; set; } = length;
}
