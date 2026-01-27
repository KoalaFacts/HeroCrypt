namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// S2K usage convention values for secret key packets.
/// </summary>
/// <remarks>
/// <para>
/// The S2K usage byte determines how the secret key material is protected:
/// <list type="bullet">
///   <item>0: Unencrypted (plaintext key material with 2-byte checksum)</item>
///   <item>254: Encrypted with S2K, SHA-1 hash of plaintext for integrity</item>
///   <item>255: Encrypted with S2K, 2-byte checksum (legacy)</item>
///   <item>253: AEAD encryption (RFC 9580)</item>
///   <item>1-252: Direct cipher algorithm ID (legacy, deprecated)</item>
/// </list>
/// </para>
/// </remarks>
public enum PgpS2KUsage : byte
{
    /// <summary>
    /// No encryption - plaintext secret key with 2-byte checksum.
    /// </summary>
    None = 0,

    /// <summary>
    /// Encrypted with S2K, 2-byte checksum of plaintext (legacy).
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Legacy format, prefer Sha1Hash for better security.</para>
    /// </remarks>
    Checksum = 255,

    /// <summary>
    /// Encrypted with S2K, SHA-1 hash of plaintext for integrity.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Recommended for v4 keys.</para>
    /// </remarks>
    Sha1Hash = 254,

    /// <summary>
    /// AEAD encryption (RFC 9580).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Modern AEAD protection for v6 keys.</para>
    /// </remarks>
    Aead = 253,
}
