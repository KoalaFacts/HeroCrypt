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
