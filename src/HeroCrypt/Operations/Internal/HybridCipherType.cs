namespace HeroCrypt.Operations.Internal;

/// <summary>
/// Specifies the symmetric AEAD cipher used in hybrid encryption schemes (e.g., X25519 + AEAD).
/// </summary>
/// <remarks>
/// <para>
/// Hybrid encryption combines asymmetric key exchange (like X25519 or ML-KEM) with
/// symmetric AEAD encryption. The asymmetric operation establishes a shared secret,
/// which is then used as the key for the symmetric cipher.
/// </para>
/// <para>
/// <b>Recommended cipher selection:</b>
/// </para>
/// <list type="bullet">
///   <item>
///     <term>ChaCha20-Poly1305</term>
///     <description>Default choice - excellent software performance, widely deployed (TLS 1.3, WireGuard)</description>
///   </item>
///   <item>
///     <term>XChaCha20-Poly1305</term>
///     <description>When random nonces are preferred - 192-bit nonce allows safe random generation</description>
///   </item>
///   <item>
///     <term>AES-GCM</term>
///     <description>When hardware acceleration (AES-NI) is available and performance is critical</description>
///   </item>
/// </list>
/// </remarks>
internal enum HybridCipherType
{
    /// <summary>
    /// ChaCha20-Poly1305 (RFC 8439) - 256-bit key, 96-bit nonce.
    /// </summary>
    /// <remarks>
    /// Recommended default. Excellent software performance without hardware acceleration.
    /// Nonce must be unique per key; counter-based nonces recommended.
    /// </remarks>
    ChaCha20Poly1305,

    /// <summary>
    /// XChaCha20-Poly1305 - 256-bit key, 192-bit nonce (extended nonce variant).
    /// </summary>
    /// <remarks>
    /// Extended nonce variant allowing safe random nonce generation.
    /// The 192-bit nonce space makes collision probability negligible even with random nonces.
    /// </remarks>
    XChaCha20Poly1305,

    /// <summary>
    /// AES-256-GCM - 256-bit key, 96-bit nonce.
    /// </summary>
    /// <remarks>
    /// Hardware-accelerated on CPUs with AES-NI. NIST approved.
    /// Nonce must be unique per key; counter-based nonces recommended.
    /// </remarks>
    AesGcm
}
