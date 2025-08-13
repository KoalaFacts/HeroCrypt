namespace HeroCrypt.Cryptography.RSA;

/// <summary>
/// Specifies the padding mode to use with RSA encryption/decryption operations
/// </summary>
public enum RsaPaddingMode
{
    /// <summary>
    /// PKCS#1 v1.5 padding
    /// </summary>
    Pkcs1,
    
    /// <summary>
    /// Optimal Asymmetric Encryption Padding (OAEP)
    /// </summary>
    Oaep
}