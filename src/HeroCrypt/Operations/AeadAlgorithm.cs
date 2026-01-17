namespace HeroCrypt.Operations;

/// <summary>
/// AEAD (Authenticated Encryption with Associated Data) mode algorithms.
/// </summary>
/// <remarks>
/// <para>
/// This enum represents AEAD modes of operation used with symmetric ciphers.
/// OpenPGP (RFC 9580) uses these identifiers in SEIPD v2 packets and
/// AEAD-encrypted secret key material.
/// </para>
/// <para>
/// RFC 9580 requires implementations to support OCB and GCM. EAX is optional.
/// </para>
/// </remarks>
public enum AeadAlgorithm : byte
{
    /// <summary>
    /// No AEAD - use legacy CFB mode.
    /// </summary>
    /// <remarks>
    /// <para>Used with SEIPD v1 packets (legacy).</para>
    /// </remarks>
    None = 0,

    /// <summary>
    /// EAX mode - Encrypt-then-Authenticate-then-Translate.
    /// </summary>
    /// <remarks>
    /// <para><b>Nonce size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Status:</b> Optional in RFC 9580.</para>
    /// <para>Two-pass mode, simpler than GCM but slower.</para>
    /// </remarks>
    [PgpAlgorithmId(1, Rfc = "RFC 9580")]
    [NotImplemented("Optional AEAD mode - two-pass design", Priority = 4)]
    Eax = 1,

    /// <summary>
    /// OCB mode - Offset Codebook Mode.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 7253</para>
    /// <para><b>Nonce size:</b> 15 bytes (120 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Status:</b> IMPLEMENTED - MUST implement per RFC 9580.</para>
    /// <para>Single-pass, fastest AEAD mode. Patent-free since 2021.</para>
    /// </remarks>
    [PgpAlgorithmId(2, Rfc = "RFC 9580")]
    Ocb = 2,

    /// <summary>
    /// GCM mode - Galois/Counter Mode.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> NIST SP 800-38D</para>
    /// <para><b>Nonce size:</b> 12 bytes (96 bits)</para>
    /// <para><b>Tag size:</b> 16 bytes (128 bits)</para>
    /// <para><b>Status:</b> IMPLEMENTED - MUST implement per RFC 9580.</para>
    /// <para>Most widely deployed AEAD mode. Hardware acceleration available.</para>
    /// </remarks>
    [PgpAlgorithmId(3, Rfc = "RFC 9580")]
    Gcm = 3,
}
