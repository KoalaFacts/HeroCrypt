namespace HeroCrypt.Operations;

/// <summary>
/// Key derivation algorithm selection.
/// </summary>
/// <remarks>
/// <para>Key derivation functions (KDFs) are categorized into:</para>
/// <list type="bullet">
///   <item><b>Password Hashing KDFs</b>: Memory-hard functions designed for secure password storage
///     (Argon2, Scrypt, Balloon). These are intentionally slow to resist brute-force attacks.</item>
///   <item><b>Password-Based KDFs</b>: Iterative functions for deriving keys from passwords
///     (PBKDF2). Suitable when memory-hard functions are not available.</item>
///   <item><b>Key Expansion KDFs</b>: Fast functions for deriving multiple keys from a master key
///     (HKDF). Not suitable for password hashing.</item>
/// </list>
/// </remarks>
public enum KeyDerivationAlgorithm
{
    // ═══════════════════════════════════════════════════════════════════════════
    // PASSWORD HASHING KDFs (Memory-hard, slow by design)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Argon2id - Hybrid variant combining Argon2i and Argon2d.
    /// Recommended for password hashing (RFC 9106). Provides resistance to both
    /// GPU attacks and side-channel attacks.
    /// </summary>
    Argon2id,

    /// <summary>
    /// Argon2d - Data-dependent variant.
    /// Maximizes resistance to GPU cracking attacks but vulnerable to side-channel attacks.
    /// Use only when side-channel attacks are not a concern.
    /// </summary>
    Argon2d,

    /// <summary>
    /// Argon2i - Data-independent variant.
    /// Resistant to side-channel attacks but allows more efficient GPU attacks.
    /// Use when side-channel resistance is critical.
    /// </summary>
    Argon2i,

    /// <summary>
    /// Scrypt - Memory-hard KDF (RFC 7914).
    /// Good choice when Argon2 is not available. Provides strong resistance to
    /// hardware brute-force attacks through memory hardness.
    /// </summary>
    Scrypt,

    /// <summary>
    /// Balloon Hashing with SHA-256.
    /// Memory-hard password hashing with provable security guarantees.
    /// Resistant to cache-timing attacks. Requires .NET 8.0+.
    /// </summary>
    BalloonSha256,

    /// <summary>
    /// Balloon Hashing with SHA-512.
    /// Memory-hard password hashing with provable security guarantees.
    /// Resistant to cache-timing attacks. Requires .NET 8.0+.
    /// </summary>
    BalloonSha512,

    /// <summary>
    /// bcrypt - Blowfish-based password hashing.
    /// Classic password hashing algorithm with built-in salt.
    /// </summary>
    [NotImplemented("Requires third-party library or custom implementation", Priority = 2)]
    Bcrypt,

    // ═══════════════════════════════════════════════════════════════════════════
    // PASSWORD-BASED KDFs (Iterative, for legacy/compatibility)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// PBKDF2 with SHA-256 (RFC 2898).
    /// Widely supported password-based KDF. Use high iteration counts (600,000+).
    /// Prefer Argon2id or Scrypt for new applications.
    /// </summary>
    Pbkdf2Sha256,

    /// <summary>
    /// PBKDF2 with SHA-512 (RFC 2898).
    /// Longer hash provides additional security margin.
    /// </summary>
    Pbkdf2Sha512,

    /// <summary>
    /// PBKDF2 with SHA-384 (RFC 2898).
    /// Intermediate option between SHA-256 and SHA-512.
    /// </summary>
    Pbkdf2Sha384,

    /// <summary>
    /// PBKDF2 with SHA-1 (RFC 2898).
    /// Legacy algorithm for compatibility with older systems (e.g., PKCS#12, WPA).
    /// Not recommended for new applications.
    /// </summary>
    Pbkdf2Sha1,

    // ═══════════════════════════════════════════════════════════════════════════
    // KEY EXPANSION KDFs (Fast, NOT for password hashing)
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// HKDF with SHA-256 (RFC 5869).
    /// For key expansion from existing key material, NOT for password hashing.
    /// Used in TLS 1.3 and many cryptographic protocols.
    /// </summary>
    HkdfSha256,

    /// <summary>
    /// HKDF with SHA-512 (RFC 5869).
    /// For key expansion with larger security margin.
    /// </summary>
    HkdfSha512,

    /// <summary>
    /// HKDF with SHA-384 (RFC 5869).
    /// Intermediate option between SHA-256 and SHA-512.
    /// </summary>
    HkdfSha384,

    /// <summary>
    /// HKDF with SHA-1 (RFC 5869).
    /// Legacy algorithm for compatibility. Not recommended for new applications.
    /// </summary>
    HkdfSha1
}
