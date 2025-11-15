namespace HeroCrypt.Cryptography.JWT;

/// <summary>
/// JSON Web Signature (JWS) algorithms as defined in RFC 7518
/// </summary>
public enum JwsAlgorithm
{
    /// <summary>
    /// HMAC using SHA-256 (HS256)
    /// </summary>
    HS256,

    /// <summary>
    /// HMAC using SHA-384 (HS384)
    /// </summary>
    HS384,

    /// <summary>
    /// HMAC using SHA-512 (HS512)
    /// </summary>
    HS512,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256 (RS256)
    /// </summary>
    RS256,

    /// <summary>
    /// RSASSA-PSS using SHA-256 (PS256)
    /// </summary>
    PS256,

    /// <summary>
    /// ECDSA using P-256 and SHA-256 (ES256)
    /// </summary>
    ES256,

    /// <summary>
    /// ECDSA using P-384 and SHA-384 (ES384)
    /// </summary>
    ES384,

    /// <summary>
    /// ECDSA using P-521 and SHA-512 (ES512)
    /// </summary>
    ES512,

    /// <summary>
    /// EdDSA signature using Ed25519 (EdDSA)
    /// </summary>
    EdDSA,

    /// <summary>
    /// ML-DSA-65 post-quantum signature (192-bit security, .NET 10+)
    /// </summary>
    MLDSA65,

    /// <summary>
    /// ML-DSA-87 post-quantum signature (256-bit security, .NET 10+)
    /// </summary>
    MLDSA87
}
