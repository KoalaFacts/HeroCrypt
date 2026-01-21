namespace HeroCrypt.Operations;

/// <summary>
/// Symmetric block cipher algorithms (without mode of operation).
/// </summary>
/// <remarks>
/// <para>
/// This enum represents raw symmetric block ciphers, not modes of operation.
/// Use <see cref="EncryptionAlgorithm"/> for combined cipher+mode selections,
/// or <see cref="AeadAlgorithm"/> for AEAD modes.
/// </para>
/// <para>
/// OpenPGP (RFC 4880, RFC 9580) uses these identifiers in packet headers
/// to specify which symmetric cipher to use for encryption.
/// </para>
/// </remarks>
public enum SymmetricCipherAlgorithm : byte
{
    // ─────────────────────────────────────────────────────────────────────────
    // Unencrypted
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Plaintext - no encryption.
    /// </summary>
    [PgpAlgorithmId(0, Rfc = "RFC 4880")]
    Plaintext = 0,

    // ─────────────────────────────────────────────────────────────────────────
    // Legacy Algorithms (Deprecated)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// IDEA - 64-bit block, 128-bit key.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> DEPRECATED - 64-bit block size vulnerable to birthday attacks.</para>
    /// </remarks>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    [NotImplemented("Legacy algorithm - 64-bit block size", Priority = 5)]
    [Obsolete("IDEA is deprecated due to 64-bit block size vulnerability. Use AES-256 for new applications. This algorithm is only provided for legacy compatibility.")]
    Idea = 1,

    /// <summary>
    /// Triple DES (3DES/DES-EDE) - 64-bit block, 168-bit key.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> DEPRECATED - Slow and 64-bit block size is vulnerable.</para>
    /// <para>MUST be implemented per RFC 4880 for backward compatibility.</para>
    /// </remarks>
    [PgpAlgorithmId(2, Rfc = "RFC 4880")]
    [NotImplemented("Legacy - MUST implement per RFC 4880", Priority = 4)]
    [Obsolete("3DES is deprecated due to 64-bit block size vulnerability. Use AES-256 for new applications. This algorithm is only provided for OpenPGP legacy compatibility.")]
    TripleDes = 2,

    /// <summary>
    /// CAST5 (CAST-128) - 64-bit block, 128-bit key.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> DEPRECATED - 64-bit block size.</para>
    /// <para>MUST be implemented per RFC 4880 for backward compatibility.</para>
    /// </remarks>
    [PgpAlgorithmId(3, Rfc = "RFC 4880")]
    [NotImplemented("Legacy - MUST implement per RFC 4880", Priority = 4)]
    [Obsolete("CAST5 is deprecated due to 64-bit block size vulnerability. Use AES-256 for new applications. This algorithm is only provided for OpenPGP legacy compatibility.")]
    Cast5 = 3,

    /// <summary>
    /// Blowfish - 64-bit block, 128-bit key.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> DEPRECATED - 64-bit block size vulnerable.</para>
    /// </remarks>
    [PgpAlgorithmId(4, Rfc = "RFC 4880")]
    [NotImplemented("Legacy algorithm - 64-bit block size", Priority = 5)]
    [Obsolete("Blowfish is deprecated due to 64-bit block size vulnerability. Use AES-256 or ChaCha20 for new applications. This algorithm is only provided for legacy compatibility.")]
    Blowfish = 4,

    // ─────────────────────────────────────────────────────────────────────────
    // AES Family (Recommended)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// AES with 128-bit key - 128-bit block.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 197</para>
    /// <para><b>Security:</b> ~128-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED - Recommended for most applications.</para>
    /// </remarks>
    [PgpAlgorithmId(7, Rfc = "RFC 4880")]
    Aes128 = 7,

    /// <summary>
    /// AES with 192-bit key - 128-bit block.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 197</para>
    /// <para><b>Security:</b> ~192-bit</para>
    /// </remarks>
    [PgpAlgorithmId(8, Rfc = "RFC 4880")]
    Aes192 = 8,

    /// <summary>
    /// AES with 256-bit key - 128-bit block.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> FIPS 197</para>
    /// <para><b>Security:</b> ~256-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED - Recommended for high-security applications.</para>
    /// </remarks>
    [PgpAlgorithmId(9, Rfc = "RFC 4880")]
    Aes256 = 9,

    // ─────────────────────────────────────────────────────────────────────────
    // Twofish
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Twofish with 256-bit key - 128-bit block.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Optional - AES finalist, good fallback.</para>
    /// </remarks>
    [PgpAlgorithmId(10, Rfc = "RFC 4880")]
    [NotImplemented("Optional algorithm - AES finalist", Priority = 4)]
    Twofish = 10,

    // ─────────────────────────────────────────────────────────────────────────
    // Camellia Family (RFC 5581)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Camellia with 128-bit key.
    /// </summary>
    [PgpAlgorithmId(11, Rfc = "RFC 5581")]
    [NotImplemented("Optional - Japanese government standard", Priority = 4)]
    Camellia128 = 11,

    /// <summary>
    /// Camellia with 192-bit key.
    /// </summary>
    [PgpAlgorithmId(12, Rfc = "RFC 5581")]
    [NotImplemented("Optional - Camellia 192-bit variant", Priority = 4)]
    Camellia192 = 12,

    /// <summary>
    /// Camellia with 256-bit key.
    /// </summary>
    [PgpAlgorithmId(13, Rfc = "RFC 5581")]
    [NotImplemented("Optional - Camellia 256-bit variant", Priority = 4)]
    Camellia256 = 13,
}
