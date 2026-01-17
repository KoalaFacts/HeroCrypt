namespace HeroCrypt.Operations;

/// <summary>
/// Cryptographic hash algorithms.
/// </summary>
/// <remarks>
/// <para><b>Platform Support Summary:</b></para>
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Platform Support</description>
///   </listheader>
///   <item>
///     <term>SHA-2 (SHA-256, SHA-384, SHA-512)</term>
///     <description>All platforms.</description>
///   </item>
///   <item>
///     <term>SHA-3 (SHA3-256, SHA3-384, SHA3-512)</term>
///     <description>.NET 8+ only.</description>
///   </item>
///   <item>
///     <term>SHAKE (SHAKE128, SHAKE256)</term>
///     <description>.NET 9+ only.</description>
///   </item>
///   <item>
///     <term>Blake2b</term>
///     <description>All platforms (pure managed implementation).</description>
///   </item>
///   <item>
///     <term>SHA-1, MD5</term>
///     <description>All platforms (legacy - not recommended for security).</description>
///   </item>
/// </list>
/// <para>
/// Algorithms marked with <see cref="NotImplementedAttribute"/> are planned for future implementation.
/// </para>
/// </remarks>
public enum HashingAlgorithm
{
    // ─────────────────────────────────────────────────────────────────────────
    // SHA-2 Family - NIST FIPS 180-4
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// SHA-256 (256-bit output) - Primary recommended hash function.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 180-4</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Block size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// Default choice for most applications. Used in TLS, Bitcoin, Git, and many other protocols.
    /// Provides 128-bit security level against collision attacks.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(8, Rfc = "RFC 4880")]
    Sha256,

    /// <summary>
    /// SHA-384 (384-bit output) - Truncated SHA-512 for higher security.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 180-4</para>
    /// <para><b>Output size:</b> 384 bits (48 bytes)</para>
    /// <para><b>Block size:</b> 1024 bits (128 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// Truncated version of SHA-512 with different initialization values.
    /// Used in TLS 1.2/1.3 cipher suites and NSA Suite B.
    /// Provides 192-bit security level against collision attacks.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(9, Rfc = "RFC 4880")]
    Sha384,

    /// <summary>
    /// SHA-512 (512-bit output) - Maximum security SHA-2 variant.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 180-4</para>
    /// <para><b>Output size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Block size:</b> 1024 bits (128 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// Highest security SHA-2 variant. Often faster than SHA-256 on 64-bit systems
    /// due to 64-bit word operations. Provides 256-bit security level.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(10, Rfc = "RFC 4880")]
    Sha512,

    /// <summary>
    /// SHA-224 (224-bit output) - Truncated SHA-256.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 180-4</para>
    /// <para><b>Output size:</b> 224 bits (28 bytes)</para>
    /// <para><b>Block size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (planned).</para>
    /// <para>
    /// Truncated version of SHA-256 with different initialization values.
    /// Provides 112-bit security level. Used when shorter hashes are needed.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(11, Rfc = "RFC 4880")]
    [NotImplemented("SHA-224 truncated variant", Priority = 4)]
    Sha224,

    /// <summary>
    /// SHA-512/256 (256-bit output from SHA-512) - Fast SHA-256 alternative on 64-bit systems.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 180-4</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Block size:</b> 1024 bits (128 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (planned).</para>
    /// <para>
    /// Uses SHA-512 internally but outputs 256 bits. Faster than SHA-256 on 64-bit platforms.
    /// Resistant to length extension attacks unlike standard SHA-256.
    /// </para>
    /// </remarks>
    [NotImplemented("SHA-512/256 for performance on 64-bit", Priority = 3)]
    Sha512_256,

    // ─────────────────────────────────────────────────────────────────────────
    // SHA-3 Family - NIST FIPS 202 (Keccak)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// SHA3-256 (256-bit output) - Keccak-based hash function.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 202</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Capacity:</b> 512 bits</para>
    /// <para><b>Platform Support:</b> .NET 8+ only.</para>
    /// <para>
    /// NIST standardized alternative to SHA-2 based on sponge construction.
    /// Immune to length extension attacks. Recommended for new applications
    /// when SHA-3 compatibility is required.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(12, Rfc = "RFC 9580")]
    Sha3_256,

    /// <summary>
    /// SHA3-384 (384-bit output) - Higher security Keccak-based hash.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 202</para>
    /// <para><b>Output size:</b> 384 bits (48 bytes)</para>
    /// <para><b>Capacity:</b> 768 bits</para>
    /// <para><b>Platform Support:</b> .NET 8+ only.</para>
    /// <para>
    /// Higher security SHA-3 variant. Provides 192-bit security level.
    /// </para>
    /// </remarks>
    Sha3_384,

    /// <summary>
    /// SHA3-512 (512-bit output) - Maximum security Keccak-based hash.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 202</para>
    /// <para><b>Output size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Capacity:</b> 1024 bits</para>
    /// <para><b>Platform Support:</b> .NET 8+ only.</para>
    /// <para>
    /// Maximum security SHA-3 variant. Provides 256-bit security level.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(14, Rfc = "RFC 9580")]
    Sha3_512,

    // ─────────────────────────────────────────────────────────────────────────
    // SHA-3 XOF (Extendable Output Functions) - NIST FIPS 202
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// SHAKE128 - Extendable output function with 128-bit security.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 202</para>
    /// <para><b>Output size:</b> Variable (specify at runtime)</para>
    /// <para><b>Capacity:</b> 256 bits</para>
    /// <para><b>Platform Support:</b> .NET 9+ only.</para>
    /// <para>
    /// Extendable-output function (XOF) that can produce arbitrary length output.
    /// Useful for key derivation, random number generation, and protocols
    /// requiring variable-length hash output.
    /// </para>
    /// </remarks>
    Shake128,

    /// <summary>
    /// SHAKE256 - Extendable output function with 256-bit security.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 202</para>
    /// <para><b>Output size:</b> Variable (specify at runtime)</para>
    /// <para><b>Capacity:</b> 512 bits</para>
    /// <para><b>Platform Support:</b> .NET 9+ only.</para>
    /// <para>
    /// Higher security XOF variant. Provides 256-bit security level.
    /// Used in ML-DSA (Dilithium) and other post-quantum algorithms.
    /// </para>
    /// </remarks>
    Shake256,

    // ─────────────────────────────────────────────────────────────────────────
    // Blake Family - Modern High-Performance Hashing
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Blake2b with 256-bit output - High-performance hash function.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7693</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Block size:</b> 1024 bits (128 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation).</para>
    /// <para>
    /// Faster than MD5 and SHA-1 while being as secure as SHA-3.
    /// Optimized for 64-bit platforms. Used in Argon2 and many modern protocols.
    /// Supports keyed hashing (MAC) natively.
    /// </para>
    /// </remarks>
    Blake2b256,

    /// <summary>
    /// Blake2b with 512-bit output - Maximum security Blake2b variant.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7693</para>
    /// <para><b>Output size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Block size:</b> 1024 bits (128 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation).</para>
    /// <para>
    /// Full output size Blake2b. Provides 256-bit security level.
    /// Default choice when maximum security is needed with Blake2b.
    /// </para>
    /// </remarks>
    Blake2b512,

    /// <summary>
    /// Blake2s with 256-bit output - Optimized for 8-32 bit platforms.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7693</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Block size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// Smaller variant of Blake2 optimized for 32-bit platforms and constrained devices.
    /// Uses 32-bit word operations. Ideal for embedded systems and IoT.
    /// </para>
    /// </remarks>
    [NotImplemented("Blake2s for 32-bit platforms and constrained devices", Priority = 3)]
    Blake2s256,

    /// <summary>
    /// Blake3 - Next generation Blake hash function.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> Blake3 specification (2020)</para>
    /// <para><b>Output size:</b> Variable (default 256 bits)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// Evolution of Blake2 with parallelism and streaming support.
    /// Significantly faster than Blake2b on modern CPUs with SIMD support.
    /// Designed for high-performance hashing of large data.
    /// </para>
    /// </remarks>
    [NotImplemented("Blake3 for high-performance parallel hashing", Priority = 2)]
    Blake3,

    // ─────────────────────────────────────────────────────────────────────────
    // Specialized Hash Functions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// RIPEMD-160 (160-bit output) - Used in Bitcoin address generation.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> ISO/IEC 10118-3</para>
    /// <para><b>Output size:</b> 160 bits (20 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms (pure managed implementation planned).</para>
    /// <para>
    /// Required for Bitcoin address generation (with SHA-256 as Hash160).
    /// Also used in PGP and some other cryptocurrency protocols.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(3, Rfc = "RFC 4880")]
    [NotImplemented("RIPEMD-160 for Bitcoin/cryptocurrency compatibility", Priority = 3)]
    Ripemd160,

    // ─────────────────────────────────────────────────────────────────────────
    // Legacy Algorithms (Compatibility Only - NOT SECURE)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// SHA-1 (160-bit output) - Legacy hash function.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST FIPS 180-4 (deprecated)</para>
    /// <para><b>Output size:</b> 160 bits (20 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// <b>DEPRECATED - NOT RECOMMENDED FOR SECURITY.</b>
    /// Collision attacks are practical (SHAttered attack, 2017).
    /// Only use for compatibility with legacy systems (Git, some certificates).
    /// Prefer SHA-256 or SHA-3 for new applications.
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(2, Rfc = "RFC 4880")]
    Sha1,

    /// <summary>
    /// MD5 (128-bit output) - Legacy hash function.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 1321 (deprecated)</para>
    /// <para><b>Output size:</b> 128 bits (16 bytes)</para>
    /// <para><b>Platform Support:</b> All platforms.</para>
    /// <para>
    /// <b>BROKEN - DO NOT USE FOR SECURITY.</b>
    /// Collision attacks are trivial. Practical chosen-prefix attacks exist.
    /// Only use for non-security purposes (checksums, cache keys, legacy compatibility).
    /// </para>
    /// </remarks>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    Md5,
}
