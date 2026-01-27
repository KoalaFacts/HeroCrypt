namespace HeroCrypt.Operations.Internal;

/// <summary>
/// Specifies the symmetric AEAD cipher used in hybrid encryption schemes (e.g., X25519 + AEAD).
/// </summary>
internal enum HybridCipherType
{
    /// <summary>
    /// ChaCha20-Poly1305 (RFC 8439) - 256-bit key, 96-bit nonce.
    /// </summary>
    ChaCha20Poly1305,

    /// <summary>
    /// XChaCha20-Poly1305 - 256-bit key, 192-bit nonce (extended nonce variant).
    /// </summary>
    XChaCha20Poly1305,

    /// <summary>
    /// AES-256-GCM - 256-bit key, 96-bit nonce.
    /// </summary>
    AesGcm
}
