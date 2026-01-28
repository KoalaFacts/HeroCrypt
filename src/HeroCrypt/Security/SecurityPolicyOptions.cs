namespace HeroCrypt.Security;

/// <summary>
/// Immutable security policy that can be passed to builders and primitives for validation.
/// </summary>
/// <remarks>
/// <para>
/// Use this record to configure security policy for cryptographic operations.
/// Pass instances to builders via <c>WithSecurityPolicy()</c> or pass to primitives directly.
/// </para>
/// <para>
/// As a record, you can use the <c>with</c> syntax to create variations:
/// </para>
/// <code>
/// // Start from default and override specific options
/// var options = SecurityPolicyOptions.Default with { AllowDeterministicNonSiv = true };
///
/// // Use in builder
/// var result = HeroCryptBuilder.Encrypt()
///     .WithAesGcm()
///     .WithKey(key)
///     .WithSecurityPolicy(opt => opt with { AllowDeterministicNonSiv = true })
///     .WithDeterministicMode()
///     .Encrypt(data);
/// </code>
/// </remarks>
/// <param name="Level">The security enforcement level.</param>
/// <param name="AllowDeterministicNonSiv">
/// Whether to allow deterministic mode with non-SIV algorithms.
/// This is extremely dangerous and should only be used for testing.
/// </param>
public sealed record SecurityPolicyOptions(
    SecurityLevel Level = SecurityLevel.Standard,
    bool AllowDeterministicNonSiv = false)
{
    /// <summary>
    /// Gets the default security policy options (Standard level, no dangerous features).
    /// </summary>
    public static SecurityPolicyOptions Default { get; } = new();

    /// <summary>
    /// Gets security policy options suitable for testing (allows all dangerous features).
    /// </summary>
    /// <remarks>
    /// <b>Warning:</b> Never use this in production code. It disables security checks.
    /// </remarks>
    public static SecurityPolicyOptions Testing { get; } = new(SecurityLevel.None, AllowDeterministicNonSiv: true);

    /// <summary>
    /// Gets strict security policy options.
    /// </summary>
    public static SecurityPolicyOptions Strict { get; } = new(SecurityLevel.Strict);

    /// <summary>
    /// Gets compliance (FIPS) security policy options.
    /// </summary>
    public static SecurityPolicyOptions Compliance { get; } = new(SecurityLevel.Compliance);

    /// <summary>
    /// Gets whether this policy allows legacy/deprecated algorithms.
    /// </summary>
    public bool AllowsLegacy => Level == SecurityLevel.None;

    /// <summary>
    /// Gets whether this policy is in compliance mode.
    /// </summary>
    public bool IsComplianceMode => Level == SecurityLevel.Compliance;

    /// <summary>
    /// Validates an algorithm against this security policy.
    /// </summary>
    /// <param name="algorithm">The algorithm name.</param>
    /// <param name="category">The algorithm category.</param>
    /// <exception cref="SecurityPolicyException">If the algorithm violates this policy.</exception>
    public void Validate(string algorithm, AlgorithmCategory category)
    {
        if (Level == SecurityLevel.None)
        {
            return; // No restrictions
        }

        var normalizedAlgorithm = algorithm.ToUpperInvariant();
        var (isAllowed, alternative, reason) = CheckAlgorithm(normalizedAlgorithm, category);

        if (!isAllowed)
        {
            throw new SecurityPolicyException(algorithm, alternative, reason, Level);
        }

        // Emit audit warnings for deprecated algorithms even when allowed
        CryptoAudit.CheckAlgorithm(normalizedAlgorithm);
    }

    /// <summary>
    /// Validates a symmetric cipher algorithm.
    /// </summary>
    public void ValidateSymmetric(string algorithm) => Validate(algorithm, AlgorithmCategory.Symmetric);

    /// <summary>
    /// Validates a hash algorithm.
    /// </summary>
    public void ValidateHash(string algorithm) => Validate(algorithm, AlgorithmCategory.Hash);

    /// <summary>
    /// Validates a key derivation function.
    /// </summary>
    public void ValidateKdf(string algorithm) => Validate(algorithm, AlgorithmCategory.KeyDerivation);

    /// <summary>
    /// Validates a signature algorithm.
    /// </summary>
    public void ValidateSignature(string algorithm) => Validate(algorithm, AlgorithmCategory.Signature);

    /// <summary>
    /// Validates a key agreement algorithm.
    /// </summary>
    public void ValidateKeyAgreement(string algorithm) => Validate(algorithm, AlgorithmCategory.KeyAgreement);

    /// <summary>
    /// Validates an OpenPGP symmetric algorithm by ID.
    /// </summary>
    public void ValidateOpenPgpSymmetric(byte algorithmId)
    {
        var (name, _) = GetOpenPgpSymmetricInfo(algorithmId);
        ValidateSymmetric(name);
    }

    /// <summary>
    /// Validates an OpenPGP hash algorithm by ID.
    /// </summary>
    public void ValidateOpenPgpHash(byte algorithmId)
    {
        var name = GetOpenPgpHashName(algorithmId);
        ValidateHash(name);
    }

    private (bool IsAllowed, string Alternative, string Reason) CheckAlgorithm(
        string algorithm, AlgorithmCategory category)
    {
        return category switch
        {
            AlgorithmCategory.Symmetric => CheckSymmetricAlgorithm(algorithm),
            AlgorithmCategory.Hash => CheckHashAlgorithm(algorithm),
            AlgorithmCategory.KeyDerivation => CheckKdfAlgorithm(algorithm),
            AlgorithmCategory.Signature => CheckSignatureAlgorithm(algorithm),
            AlgorithmCategory.KeyAgreement => CheckKeyAgreementAlgorithm(algorithm),
            _ => (true, string.Empty, string.Empty)
        };
    }

    private (bool IsAllowed, string Alternative, string Reason) CheckSymmetricAlgorithm(string algorithm)
    {
        // Always blocked (broken)
        var brokenAlgorithms = new HashSet<string> { "DES", "RC4" };
        if (brokenAlgorithms.Contains(algorithm))
        {
            return (false, "AES-256", $"{algorithm} is cryptographically broken");
        }

        // Blocked at Standard+ (deprecated 64-bit block ciphers)
        if (Level >= SecurityLevel.Standard)
        {
            var deprecatedAlgorithms = new HashSet<string> { "3DES", "TRIPLEDES", "DES-EDE", "BLOWFISH", "CAST5", "IDEA" };
            if (deprecatedAlgorithms.Contains(algorithm))
            {
                return (false, "AES-256", $"{algorithm} has 64-bit block size (vulnerable to birthday attacks)");
            }
        }

        // Blocked at FIPS (non-FIPS approved)
        if (Level == SecurityLevel.Compliance)
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

    private (bool IsAllowed, string Alternative, string Reason) CheckHashAlgorithm(string algorithm)
    {
        // Always blocked (broken)
        if (algorithm == "MD5")
        {
            return (false, "SHA-256", "MD5 has trivial collision attacks");
        }

        // Blocked at Standard+ (deprecated)
        if (Level >= SecurityLevel.Standard)
        {
            if (algorithm is "SHA1" or "SHA-1")
            {
                return (false, "SHA-256", "SHA-1 has practical collision attacks (SHAttered)");
            }
        }

        // Blocked at FIPS (non-FIPS approved)
        if (Level == SecurityLevel.Compliance)
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

    private (bool IsAllowed, string Alternative, string Reason) CheckKdfAlgorithm(string algorithm)
    {
        // Blocked at Standard+ (uses SHA-1)
        if (Level >= SecurityLevel.Standard && algorithm == "PBKDF2-SHA1")
        {
            return (false, "PBKDF2-SHA256", "PBKDF2-SHA1 uses deprecated SHA-1");
        }

        // Blocked at FIPS (non-FIPS approved)
        if (Level == SecurityLevel.Compliance)
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

    private (bool IsAllowed, string Alternative, string Reason) CheckSignatureAlgorithm(string algorithm)
    {
        // Blocked at FIPS (non-FIPS approved)
        if (Level == SecurityLevel.Compliance)
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

    private (bool IsAllowed, string Alternative, string Reason) CheckKeyAgreementAlgorithm(string algorithm)
    {
        // Blocked at FIPS (non-FIPS approved)
        if (Level == SecurityLevel.Compliance)
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
}
