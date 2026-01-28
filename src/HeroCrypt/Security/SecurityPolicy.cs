using System.Security.Cryptography;

namespace HeroCrypt.Security;

/// <summary>
/// Defines the security enforcement level for cryptographic operations.
/// </summary>
public enum SecurityLevel
{
    /// <summary>
    /// No restrictions. All algorithms are permitted including deprecated ones.
    /// Use only for legacy compatibility scenarios.
    /// </summary>
    None = 0,

    /// <summary>
    /// Default level. Blocks broken algorithms (MD5, SHA-1, DES, RC4).
    /// Allows non-FIPS algorithms like ChaCha20, Blake2b, Argon2, Ed25519.
    /// </summary>
    Standard = 1,

    /// <summary>
    /// Strict level. Blocks deprecated and weak algorithms.
    /// Same as Standard but with additional warnings for algorithms approaching deprecation.
    /// </summary>
    Strict = 2,

    /// <summary>
    /// Compliance mode. Only algorithms from the configured compliance list are permitted.
    /// Default compliance list is FIPS 140-2/140-3.
    /// Blocks: ChaCha20, Blake2b, Argon2, Ed25519, X25519, Secp256k1.
    /// Allows: AES, SHA-2/3, RSA, ECDSA (NIST curves), PBKDF2, HKDF.
    /// </summary>
    Compliance = 3
}

/// <summary>
/// Provides unified security policy enforcement for cryptographic operations.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SecurityPolicy"/> consolidates security enforcement into a single configurable policy.
/// It provides unified security enforcement with FIPS compliance checking.
/// </para>
/// <para>
/// <b>Security Levels:</b>
/// <list type="bullet">
///   <item><see cref="SecurityLevel.None"/>: No restrictions (legacy compatibility only)</item>
///   <item><see cref="SecurityLevel.Standard"/>: Blocks broken algorithms (default)</item>
///   <item><see cref="SecurityLevel.Strict"/>: Blocks deprecated + additional warnings</item>
///   <item><see cref="SecurityLevel.Compliance"/>: Compliance-approved algorithms only (FIPS by default)</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Set global security policy
/// SecurityPolicy.Current = SecurityLevel.Compliance;
///
/// // This will throw SecurityPolicyException
/// var hash = HeroCryptBuilder.Hash()
///     .WithBlake2b()  // Not FIPS-approved
///     .ComputeHash(data);
///
/// // This will succeed
/// var hash = HeroCryptBuilder.Hash()
///     .WithSha256()   // FIPS-approved
///     .ComputeHash(data);
///
/// // Temporary override for legacy compatibility
/// using (SecurityPolicy.Override(SecurityLevel.None))
/// {
///     // Legacy algorithms permitted within this scope
/// }
/// </code>
/// </example>
public static class SecurityPolicy
{
    private static readonly AsyncLocal<SecurityLevel?> CurrentLevel = new();

    /// <summary>
    /// Gets or sets the current security level.
    /// Default is <see cref="SecurityLevel.Standard"/>.
    /// </summary>
    public static SecurityLevel Current
    {
        get => CurrentLevel.Value ?? SecurityLevel.Standard;
        set => CurrentLevel.Value = value;
    }

    /// <summary>
    /// Gets whether the underlying operating system has FIPS mode enabled.
    /// </summary>
    public static bool IsSystemFipsEnabled => CryptoConfig.AllowOnlyFipsAlgorithms;

    /// <summary>
    /// Gets whether the current policy is compliance mode (FIPS by default).
    /// </summary>
    public static bool IsComplianceMode => Current == SecurityLevel.Compliance;

    /// <summary>
    /// Gets whether the current policy allows legacy/deprecated algorithms.
    /// </summary>
    public static bool AllowsLegacy => Current == SecurityLevel.None;

    /// <summary>
    /// Validates an algorithm against the current security policy.
    /// </summary>
    /// <param name="algorithm">The algorithm name.</param>
    /// <param name="category">The algorithm category.</param>
    /// <exception cref="SecurityPolicyException">If the algorithm violates the current policy.</exception>
    public static void Validate(string algorithm, AlgorithmCategory category)
    {
        var level = Current;
        if (level == SecurityLevel.None)
        {
            return; // No restrictions
        }

        var normalizedAlgorithm = algorithm.ToUpperInvariant();
        var (isAllowed, alternative, reason) = CheckAlgorithm(normalizedAlgorithm, category, level);

        if (!isAllowed)
        {
            throw new SecurityPolicyException(algorithm, alternative, reason, level);
        }

        // Emit audit warnings for deprecated algorithms even when allowed
        CryptoAudit.CheckAlgorithm(normalizedAlgorithm);
    }

    /// <summary>
    /// Validates a symmetric cipher algorithm.
    /// </summary>
    public static void ValidateSymmetric(string algorithm) => Validate(algorithm, AlgorithmCategory.Symmetric);

    /// <summary>
    /// Validates a hash algorithm.
    /// </summary>
    public static void ValidateHash(string algorithm) => Validate(algorithm, AlgorithmCategory.Hash);

    /// <summary>
    /// Validates a key derivation function.
    /// </summary>
    public static void ValidateKdf(string algorithm) => Validate(algorithm, AlgorithmCategory.KeyDerivation);

    /// <summary>
    /// Validates a signature algorithm.
    /// </summary>
    public static void ValidateSignature(string algorithm) => Validate(algorithm, AlgorithmCategory.Signature);

    /// <summary>
    /// Validates a key agreement algorithm.
    /// </summary>
    public static void ValidateKeyAgreement(string algorithm) => Validate(algorithm, AlgorithmCategory.KeyAgreement);

    /// <summary>
    /// Validates an OpenPGP symmetric algorithm by ID.
    /// </summary>
    public static void ValidateOpenPgpSymmetric(byte algorithmId)
    {
        var (name, _) = GetOpenPgpSymmetricInfo(algorithmId);
        ValidateSymmetric(name);
    }

    /// <summary>
    /// Validates an OpenPGP hash algorithm by ID.
    /// </summary>
    public static void ValidateOpenPgpHash(byte algorithmId)
    {
        var name = GetOpenPgpHashName(algorithmId);
        ValidateHash(name);
    }

    /// <summary>
    /// Creates a disposable scope that temporarily overrides the security level.
    /// </summary>
    /// <param name="level">The security level to use within the scope.</param>
    /// <returns>An <see cref="IDisposable"/> that restores the previous level when disposed.</returns>
    public static IDisposable Override(SecurityLevel level)
    {
        return new SecurityPolicyScope(level);
    }

    /// <summary>
    /// Creates a disposable scope that temporarily enables compliance mode.
    /// </summary>
    public static IDisposable ComplianceScope() => Override(SecurityLevel.Compliance);

    /// <summary>
    /// Creates a disposable scope that temporarily disables all restrictions.
    /// Use with caution for legacy compatibility only.
    /// </summary>
    public static IDisposable LegacyScope() => Override(SecurityLevel.None);

    /// <summary>
    /// Executes an action with a temporary security level override.
    /// </summary>
    public static void WithLevel(SecurityLevel level, Action action)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(action);
#else
        if (action == null) throw new ArgumentNullException(nameof(action));
#endif

        using var _ = Override(level);
        action();
    }

    /// <summary>
    /// Executes a function with a temporary security level override.
    /// </summary>
    public static T WithLevel<T>(SecurityLevel level, Func<T> func)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(func);
#else
        if (func == null) throw new ArgumentNullException(nameof(func));
#endif

        using var _ = Override(level);
        return func();
    }

    private static (bool IsAllowed, string Alternative, string Reason) CheckAlgorithm(
        string algorithm, AlgorithmCategory category, SecurityLevel level)
    {
        return category switch
        {
            AlgorithmCategory.Symmetric => CheckSymmetricAlgorithm(algorithm, level),
            AlgorithmCategory.Hash => CheckHashAlgorithm(algorithm, level),
            AlgorithmCategory.KeyDerivation => CheckKdfAlgorithm(algorithm, level),
            AlgorithmCategory.Signature => CheckSignatureAlgorithm(algorithm, level),
            AlgorithmCategory.KeyAgreement => CheckKeyAgreementAlgorithm(algorithm, level),
            _ => (true, string.Empty, string.Empty)
        };
    }

    private static (bool IsAllowed, string Alternative, string Reason) CheckSymmetricAlgorithm(
        string algorithm, SecurityLevel level)
    {
        // Always blocked (broken)
        var brokenAlgorithms = new HashSet<string> { "DES", "RC4" };
        if (brokenAlgorithms.Contains(algorithm))
        {
            return (false, "AES-256", $"{algorithm} is cryptographically broken");
        }

        // Blocked at Standard+ (deprecated 64-bit block ciphers)
        if (level >= SecurityLevel.Standard)
        {
            var deprecatedAlgorithms = new HashSet<string> { "3DES", "TRIPLEDES", "DES-EDE", "BLOWFISH", "CAST5", "IDEA" };
            if (deprecatedAlgorithms.Contains(algorithm))
            {
                return (false, "AES-256", $"{algorithm} has 64-bit block size (vulnerable to birthday attacks)");
            }
        }

        // Blocked at FIPS (non-FIPS approved)
        if (level == SecurityLevel.Compliance)
        {
            var nonFipsAlgorithms = new HashSet<string>
            {
                "CHACHA20", "CHACHA20-POLY1305", "XCHACHA20-POLY1305",
                "AES-OCB", "AES-SIV", "AES-GCM-SIV",
                "TWOFISH", "CAMELLIA", "CAMELLIA-128", "CAMELLIA-192", "CAMELLIA-256"
            };

            if (nonFipsAlgorithms.Contains(algorithm))
            {
                return (false, "AES-GCM", $"{algorithm} is not FIPS-approved");
            }
        }

        return (true, string.Empty, string.Empty);
    }

    private static (bool IsAllowed, string Alternative, string Reason) CheckHashAlgorithm(
        string algorithm, SecurityLevel level)
    {
        // Always blocked (broken)
        if (algorithm == "MD5")
        {
            return (false, "SHA-256", "MD5 has trivial collision attacks");
        }

        // Blocked at Standard+ (deprecated)
        if (level >= SecurityLevel.Standard)
        {
            if (algorithm is "SHA1" or "SHA-1")
            {
                return (false, "SHA-256", "SHA-1 has practical collision attacks (SHAttered)");
            }
        }

        // Blocked at FIPS (non-FIPS approved)
        if (level == SecurityLevel.Compliance)
        {
            var nonFipsAlgorithms = new HashSet<string>
            {
                "BLAKE2B", "BLAKE2S", "BLAKE3",
                "RIPEMD-160", "RIPEMD160"
            };

            if (nonFipsAlgorithms.Contains(algorithm))
            {
                return (false, "SHA-256", $"{algorithm} is not FIPS-approved");
            }
        }

        return (true, string.Empty, string.Empty);
    }

    private static (bool IsAllowed, string Alternative, string Reason) CheckKdfAlgorithm(
        string algorithm, SecurityLevel level)
    {
        // Blocked at Standard+ (uses SHA-1)
        if (level >= SecurityLevel.Standard && algorithm == "PBKDF2-SHA1")
        {
            return (false, "PBKDF2-SHA256", "PBKDF2-SHA1 uses deprecated SHA-1");
        }

        // Blocked at FIPS (non-FIPS approved)
        if (level == SecurityLevel.Compliance)
        {
            var nonFipsAlgorithms = new HashSet<string>
            {
                "ARGON2", "ARGON2ID", "ARGON2I", "ARGON2D",
                "SCRYPT", "BCRYPT",
                "BALLOON", "BALLOON-SHA256", "BALLOON-SHA512"
            };

            if (nonFipsAlgorithms.Contains(algorithm))
            {
                return (false, "PBKDF2-SHA256 (600,000+ iterations)", $"{algorithm} is not FIPS-approved");
            }
        }

        return (true, string.Empty, string.Empty);
    }

    private static (bool IsAllowed, string Alternative, string Reason) CheckSignatureAlgorithm(
        string algorithm, SecurityLevel level)
    {
        // Blocked at FIPS (non-FIPS approved)
        if (level == SecurityLevel.Compliance)
        {
            var nonFipsAlgorithms = new HashSet<string>
            {
                "ED25519", "ED448",
                "SECP256K1"
            };

            if (nonFipsAlgorithms.Contains(algorithm))
            {
                return (false, "ECDSA-P256 or RSA-PSS", $"{algorithm} is not FIPS-approved");
            }
        }

        return (true, string.Empty, string.Empty);
    }

    private static (bool IsAllowed, string Alternative, string Reason) CheckKeyAgreementAlgorithm(
        string algorithm, SecurityLevel level)
    {
        // Blocked at FIPS (non-FIPS approved)
        if (level == SecurityLevel.Compliance)
        {
            var nonFipsAlgorithms = new HashSet<string>
            {
                "X25519", "X448", "CURVE25519"
            };

            if (nonFipsAlgorithms.Contains(algorithm))
            {
                return (false, "ECDH-P256 or ECDH-P384", $"{algorithm} is not FIPS-approved");
            }
        }

        return (true, string.Empty, string.Empty);
    }

    private static (string Name, bool IsFipsApproved) GetOpenPgpSymmetricInfo(byte algorithmId)
    {
        return algorithmId switch
        {
            0 => ("Plaintext", false),
            1 => ("IDEA", false),
            2 => ("3DES", false),
            3 => ("CAST5", false),
            4 => ("Blowfish", false),
            7 => ("AES-128", true),
            8 => ("AES-192", true),
            9 => ("AES-256", true),
            10 => ("Twofish", false),
            11 => ("Camellia-128", false),
            12 => ("Camellia-192", false),
            13 => ("Camellia-256", false),
            _ => ($"Unknown-{algorithmId}", false)
        };
    }

    private static string GetOpenPgpHashName(byte algorithmId)
    {
        return algorithmId switch
        {
            1 => "MD5",
            2 => "SHA-1",
            3 => "RIPEMD-160",
            8 => "SHA-256",
            9 => "SHA-384",
            10 => "SHA-512",
            11 => "SHA-224",
            12 => "SHA3-256",
            14 => "SHA3-512",
            _ => $"Unknown-{algorithmId}"
        };
    }

    private sealed class SecurityPolicyScope : IDisposable
    {
        private readonly SecurityLevel previousLevel;
        private bool disposed;

        /// <summary>
        /// Initializes a new instance of <see cref="SecurityPolicyScope"/>.
        /// </summary>
        /// <param name="level">The security level to set for the scope.</param>
        public SecurityPolicyScope(SecurityLevel level)
        {
            previousLevel = Current;
            Current = level;
        }

        /// <summary>
        /// Restores the previous security level.
        /// </summary>
        public void Dispose()
        {
            if (!disposed)
            {
                Current = previousLevel;
                disposed = true;
            }
        }
    }
}

/// <summary>
/// Categories of cryptographic algorithms for security policy validation.
/// </summary>
public enum AlgorithmCategory
{
    /// <summary>Symmetric encryption algorithms (AES, ChaCha20, etc.)</summary>
    Symmetric,

    /// <summary>Hash functions (SHA-256, Blake2b, etc.)</summary>
    Hash,

    /// <summary>Key derivation functions (Argon2, PBKDF2, HKDF, etc.)</summary>
    KeyDerivation,

    /// <summary>Digital signature algorithms (RSA, ECDSA, Ed25519, etc.)</summary>
    Signature,

    /// <summary>Key agreement algorithms (ECDH, X25519, etc.)</summary>
    KeyAgreement
}

/// <summary>
/// Exception thrown when an algorithm violates the current security policy.
/// </summary>
public class SecurityPolicyException : InvalidOperationException
{
    /// <summary>Gets the blocked algorithm.</summary>
    public string Algorithm { get; }

    /// <summary>Gets the recommended alternative.</summary>
    public string Alternative { get; }

    /// <summary>Gets the reason the algorithm was blocked.</summary>
    public string Reason { get; }

    /// <summary>Gets the security level that blocked the algorithm.</summary>
    public SecurityLevel Level { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="SecurityPolicyException"/>.
    /// </summary>
    public SecurityPolicyException(string algorithm, string alternative, string reason, SecurityLevel level)
        : base($"Security policy ({level}) violation: '{algorithm}' is not permitted. {reason}. Use '{alternative}' instead.")
    {
        Algorithm = algorithm;
        Alternative = alternative;
        Reason = reason;
        Level = level;
    }
}
