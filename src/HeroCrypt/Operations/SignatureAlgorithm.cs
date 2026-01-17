namespace HeroCrypt.Operations;

/// <summary>
/// Digital signature and MAC (Message Authentication Code) algorithms.
/// </summary>
public enum SignatureAlgorithm
{
    // HMAC (Symmetric MAC)
    /// <summary>HMAC using SHA-256 (recommended for most use cases).</summary>
    HmacSha256,
    /// <summary>HMAC using SHA-384.</summary>
    HmacSha384,
    /// <summary>HMAC using SHA-512.</summary>
    HmacSha512,
    /// <summary>HMAC using SHA-1 (legacy, not recommended for new applications).</summary>
    [NotImplemented("Legacy algorithm")]
    HmacSha1,

    // AES-CMAC (Symmetric MAC)
    /// <summary>AES-CMAC with 128-bit key (NIST SP 800-38B).</summary>
    AesCmac128,
    /// <summary>AES-CMAC with 192-bit key (NIST SP 800-38B).</summary>
    AesCmac192,
    /// <summary>AES-CMAC with 256-bit key (NIST SP 800-38B).</summary>
    AesCmac256,

    // Poly1305 (One-time MAC)
    /// <summary>Poly1305 one-time authenticator (RFC 8439).</summary>
    Poly1305,

    // RSA-PKCS#1 v1.5 Signatures (Legacy)
    /// <summary>RSASSA-PKCS1-v1_5 using SHA-256.</summary>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    RsaSha256,
    /// <summary>RSASSA-PKCS1-v1_5 using SHA-384.</summary>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    RsaSha384,
    /// <summary>RSASSA-PKCS1-v1_5 using SHA-512.</summary>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    RsaSha512,

    // RSA-PSS Signatures (Recommended)
    /// <summary>RSASSA-PSS using SHA-256 (recommended over PKCS#1 v1.5).</summary>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    RsaPssSha256,
    /// <summary>RSASSA-PSS using SHA-384.</summary>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    RsaPssSha384,
    /// <summary>RSASSA-PSS using SHA-512.</summary>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    RsaPssSha512,

    // ECDSA NIST Curves
    /// <summary>ECDSA using P-256 curve and SHA-256 (128-bit security).</summary>
    [PgpAlgorithmId(19, Rfc = "RFC 6637")]
    EcdsaP256Sha256,
    /// <summary>ECDSA using P-384 curve and SHA-384 (192-bit security).</summary>
    [PgpAlgorithmId(19, Rfc = "RFC 6637")]
    EcdsaP384Sha384,
    /// <summary>ECDSA using P-521 curve and SHA-512 (256-bit security).</summary>
    [PgpAlgorithmId(19, Rfc = "RFC 6637")]
    EcdsaP521Sha512,

    // ECDSA Blockchain Curves
    /// <summary>ECDSA using secp256k1 curve (Bitcoin, Ethereum).</summary>
    Secp256k1,

    // EdDSA (Edwards-curve Digital Signature Algorithm)
    /// <summary>EdDSA signature using Ed25519 (128-bit security, recommended).</summary>
    [PgpAlgorithmId(27, Rfc = "RFC 9580")]
    Ed25519,
    /// <summary>EdDSA signature using Ed448 (224-bit security).</summary>
    [PgpAlgorithmId(28, Rfc = "RFC 9580")]
    [NotImplemented("Higher security EdDSA curve")]
    Ed448,

#if NET10_0_OR_GREATER
    // ML-DSA Post-Quantum Signatures (.NET 10+)
    /// <summary>ML-DSA-44 post-quantum signature (128-bit security, .NET 10+).</summary>
    MLDsa44,
    /// <summary>ML-DSA-65 post-quantum signature (192-bit security, .NET 10+).</summary>
    MLDsa65,
    /// <summary>ML-DSA-87 post-quantum signature (256-bit security, .NET 10+).</summary>
    MLDsa87,

    // SLH-DSA Post-Quantum Signatures (.NET 10+)
    /// <summary>SLH-DSA-SHA2-128f post-quantum signature (fast, 128-bit security, .NET 10+).</summary>
    [NotImplemented("Post-quantum stateless hash-based signature")]
    SlhDsaSha2_128f,
    /// <summary>SLH-DSA-SHA2-128s post-quantum signature (small, 128-bit security, .NET 10+).</summary>
    [NotImplemented("Post-quantum stateless hash-based signature")]
    SlhDsaSha2_128s,
    /// <summary>SLH-DSA-SHA2-192f post-quantum signature (fast, 192-bit security, .NET 10+).</summary>
    [NotImplemented("Post-quantum stateless hash-based signature")]
    SlhDsaSha2_192f,
    /// <summary>SLH-DSA-SHA2-192s post-quantum signature (small, 192-bit security, .NET 10+).</summary>
    [NotImplemented("Post-quantum stateless hash-based signature")]
    SlhDsaSha2_192s,
    /// <summary>SLH-DSA-SHA2-256f post-quantum signature (fast, 256-bit security, .NET 10+).</summary>
    [NotImplemented("Post-quantum stateless hash-based signature")]
    SlhDsaSha2_256f,
    /// <summary>SLH-DSA-SHA2-256s post-quantum signature (small, 256-bit security, .NET 10+).</summary>
    [NotImplemented("Post-quantum stateless hash-based signature")]
    SlhDsaSha2_256s,
#endif
}
