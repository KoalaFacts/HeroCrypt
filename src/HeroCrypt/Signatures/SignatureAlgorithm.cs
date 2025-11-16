namespace HeroCrypt.Signatures;

/// <summary>
/// Digital signature and MAC (Message Authentication Code) algorithms
/// </summary>
public enum SignatureAlgorithm
{
    /// <summary>
    /// HMAC using SHA-256
    /// </summary>
    HmacSha256,

    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    HmacSha384,

    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    HmacSha512,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    RsaSha256,

    /// <summary>
    /// RSASSA-PSS using SHA-256
    /// </summary>
    RsaPssSha256,

    /// <summary>
    /// ECDSA using P-256 curve and SHA-256
    /// </summary>
    EcdsaP256Sha256,

    /// <summary>
    /// ECDSA using P-384 curve and SHA-384
    /// </summary>
    EcdsaP384Sha384,

    /// <summary>
    /// ECDSA using P-521 curve and SHA-512
    /// </summary>
    EcdsaP521Sha512,

    /// <summary>
    /// EdDSA signature using Ed25519 (.NET 7+)
    /// </summary>
    Ed25519,

    /// <summary>
    /// ML-DSA-65 post-quantum signature (192-bit security, .NET 10+)
    /// </summary>
    MLDsa65,

    /// <summary>
    /// ML-DSA-87 post-quantum signature (256-bit security, .NET 10+)
    /// </summary>
    MLDsa87
}
