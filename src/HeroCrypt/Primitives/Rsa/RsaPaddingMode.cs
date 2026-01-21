namespace HeroCrypt.Primitives.Rsa;

/// <summary>
/// Specifies the padding mode to use with RSA encryption/decryption operations.
/// </summary>
/// <remarks>
/// OAEP is the recommended default. PKCS#1 v1.5 is provided only for legacy compatibility.
/// </remarks>
public enum RsaPaddingMode
{
    /// <summary>
    /// PKCS#1 v1.5 padding (legacy, not recommended for new applications).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Security Warning:</b> PKCS#1 v1.5 is vulnerable to Bleichenbacher's adaptive
    /// chosen-ciphertext attack. Use OAEP for new implementations.
    /// </para>
    /// <para>
    /// This mode is provided only for interoperability with legacy systems that
    /// require PKCS#1 v1.5 padding.
    /// </para>
    /// </remarks>
    // Note: Not marked [Obsolete] to avoid breaking internal compatibility code.
    // Security warning is documented in XML comments instead.
    Pkcs1,

    /// <summary>
    /// Optimal Asymmetric Encryption Padding (OAEP) - recommended.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OAEP provides provable security against adaptive chosen-ciphertext attacks
    /// when used with a secure hash function (SHA-256 or higher recommended).
    /// </para>
    /// <para>
    /// This is the default and recommended padding mode for RSA encryption.
    /// </para>
    /// </remarks>
    Oaep
}
