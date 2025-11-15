namespace HeroCrypt.Cryptography.Encryption;

/// <summary>
/// Symmetric and asymmetric encryption algorithms
/// </summary>
public enum EncryptionAlgorithm
{
    /// <summary>
    /// AES-GCM (Galois/Counter Mode) - AEAD cipher
    /// </summary>
    AesGcm,

    /// <summary>
    /// AES-CCM (Counter with CBC-MAC) - AEAD cipher
    /// </summary>
    AesCcm,

    /// <summary>
    /// ChaCha20-Poly1305 - AEAD cipher (RFC 8439)
    /// </summary>
    ChaCha20Poly1305,

    /// <summary>
    /// XChaCha20-Poly1305 - Extended nonce AEAD cipher
    /// </summary>
    XChaCha20Poly1305,

    /// <summary>
    /// RSA-OAEP with SHA-256 - Asymmetric encryption
    /// </summary>
    RsaOaepSha256,

    /// <summary>
    /// ML-KEM-768 + AES-GCM hybrid encryption (.NET 10+)
    /// Post-quantum hybrid: ML-KEM for key encapsulation, AES-GCM for data
    /// </summary>
    MLKem768AesGcm,

    /// <summary>
    /// ML-KEM-1024 + AES-GCM hybrid encryption (.NET 10+)
    /// Post-quantum hybrid: ML-KEM for key encapsulation, AES-GCM for data
    /// </summary>
    MLKem1024AesGcm
}
