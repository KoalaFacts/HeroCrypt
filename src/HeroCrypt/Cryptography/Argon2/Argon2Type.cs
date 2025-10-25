namespace HeroCrypt.Cryptography.Argon2;

/// <summary>
/// Argon2 algorithm variants as defined in RFC 9106
/// </summary>
public enum Argon2Type
{
    /// <summary>
    /// Argon2d - Data-dependent version, maximizes resistance to GPU cracking attacks
    /// but vulnerable to side-channel attacks
    /// </summary>
    Argon2d = 0,

    /// <summary>
    /// Argon2i - Data-independent version, resistant to side-channel attacks
    /// but allows more efficient GPU attacks
    /// </summary>
    Argon2i = 1,

    /// <summary>
    /// Argon2id - Hybrid version combining Argon2i and Argon2d, recommended for most use cases
    /// Provides resistance to both GPU attacks and side-channel attacks
    /// </summary>
    Argon2id = 2
}