namespace HeroCrypt.Security;

/// <summary>
/// Categories of cryptographic algorithms for security policy validation.
/// </summary>
public enum AlgorithmCategory
{
    /// <summary>Symmetric encryption algorithms (AES, ChaCha20, etc.)</summary>
    Symmetric,

    /// <summary>Hash functions (SHA-256, Blake2b, etc.)</summary>
    Hash,

    /// <summary>Key derivation functions (Argon2, PBKDF2, HKDF, etc.)</summary>
    KeyDerivation,

    /// <summary>Digital signature algorithms (RSA, ECDSA, Ed25519, etc.)</summary>
    Signature,

    /// <summary>Key agreement algorithms (ECDH, X25519, etc.)</summary>
    KeyAgreement
}
