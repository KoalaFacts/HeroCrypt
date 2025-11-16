namespace HeroCrypt.Hashing;

/// <summary>
/// Cryptographic hash algorithms
/// </summary>
public enum HashAlgorithm
{
    /// <summary>
    /// SHA-256 (256-bit output)
    /// </summary>
    Sha256,

    /// <summary>
    /// SHA-384 (384-bit output)
    /// </summary>
    Sha384,

    /// <summary>
    /// SHA-512 (512-bit output)
    /// </summary>
    Sha512,

    /// <summary>
    /// Blake2b with 256-bit output
    /// </summary>
    Blake2b256,

    /// <summary>
    /// Blake2b with 512-bit output
    /// </summary>
    Blake2b512
}
