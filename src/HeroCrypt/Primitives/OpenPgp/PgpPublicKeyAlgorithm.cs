namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP public-key algorithm identifiers as defined in RFC 4880 Section 9.1 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// These identifiers specify the public-key algorithm used in key packets and signatures.
/// The algorithm determines the format of key material in the packet.
/// </para>
/// </remarks>
public enum PgpPublicKeyAlgorithm : byte
{
    // ─────────────────────────────────────────────────────────────────────────
    // RSA Algorithms (RFC 4880)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// RSA (Encrypt or Sign) - Algorithm ID 1.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 13.5</para>
    /// <para>General-purpose RSA for both encryption and signing.</para>
    /// <para><b>Key material:</b> n (modulus), e (exponent)</para>
    /// </remarks>
    RsaEncryptOrSign = 1,

    /// <summary>
    /// RSA Encrypt-Only - Algorithm ID 2.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> DEPRECATED in RFC 4880.</para>
    /// <para>Use RsaEncryptOrSign instead.</para>
    /// </remarks>
    [Obsolete("Deprecated - use RsaEncryptOrSign")]
    RsaEncryptOnly = 2,

    /// <summary>
    /// RSA Sign-Only - Algorithm ID 3.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> DEPRECATED in RFC 4880.</para>
    /// <para>Use RsaEncryptOrSign instead.</para>
    /// </remarks>
    [Obsolete("Deprecated - use RsaEncryptOrSign")]
    RsaSignOnly = 3,

    // ─────────────────────────────────────────────────────────────────────────
    // ElGamal (RFC 4880)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Elgamal (Encrypt-Only) - Algorithm ID 16.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para>Discrete logarithm encryption algorithm.</para>
    /// <para><b>Key material:</b> p, g, y</para>
    /// </remarks>
    ElgamalEncryptOnly = 16,

    // ─────────────────────────────────────────────────────────────────────────
    // DSA (RFC 4880)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// DSA (Digital Signature Algorithm) - Algorithm ID 17.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para>FIPS 186 Digital Signature Algorithm.</para>
    /// <para><b>Key material:</b> p, q, g, y</para>
    /// </remarks>
    Dsa = 17,

    // ─────────────────────────────────────────────────────────────────────────
    // Elliptic Curve (RFC 6637)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// ECDH (Elliptic Curve Diffie-Hellman) - Algorithm ID 18.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 6637</para>
    /// <para>Elliptic curve key agreement for encryption.</para>
    /// <para><b>Key material:</b> OID + Q (point) + KDF parameters</para>
    /// </remarks>
    Ecdh = 18,

    /// <summary>
    /// ECDSA (Elliptic Curve DSA) - Algorithm ID 19.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 6637</para>
    /// <para>Elliptic curve digital signature algorithm.</para>
    /// <para><b>Key material:</b> OID + Q (point)</para>
    /// </remarks>
    Ecdsa = 19,

    // ─────────────────────────────────────────────────────────────────────────
    // Reserved
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reserved (formerly Elgamal Encrypt or Sign) - Algorithm ID 20.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Reserved, do not use.</para>
    /// </remarks>
    Reserved20 = 20,

    /// <summary>
    /// Reserved (Diffie-Hellman X9.42) - Algorithm ID 21.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Reserved, do not use.</para>
    /// </remarks>
    Reserved21 = 21,

    // ─────────────────────────────────────────────────────────────────────────
    // EdDSA (Draft, deprecated by RFC 9580)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// EdDSA (Edwards-curve DSA) - Algorithm ID 22.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Deprecated draft algorithm ID.</para>
    /// <para>Use Ed25519 (27) or Ed448 (28) instead per RFC 9580.</para>
    /// <para><b>Key material:</b> OID + Q (point)</para>
    /// </remarks>
    [Obsolete("Deprecated - use Ed25519 (27) or Ed448 (28) per RFC 9580")]
    EdDsaLegacy = 22,

    // ─────────────────────────────────────────────────────────────────────────
    // RFC 9580 Algorithms
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// X25519 (Curve25519 ECDH) - Algorithm ID 25.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Modern elliptic curve key agreement.</para>
    /// <para><b>Key material:</b> 32-byte public key (no OID)</para>
    /// </remarks>
    X25519 = 25,

    /// <summary>
    /// X448 (Curve448 ECDH) - Algorithm ID 26.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Higher-security elliptic curve key agreement.</para>
    /// <para><b>Key material:</b> 56-byte public key (no OID)</para>
    /// </remarks>
    X448 = 26,

    /// <summary>
    /// Ed25519 (Edwards25519 Signature) - Algorithm ID 27.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Modern elliptic curve signature algorithm.</para>
    /// <para><b>Key material:</b> 32-byte public key (no OID)</para>
    /// </remarks>
    Ed25519 = 27,

    /// <summary>
    /// Ed448 (Edwards448 Signature) - Algorithm ID 28.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Higher-security elliptic curve signature algorithm.</para>
    /// <para><b>Key material:</b> 57-byte public key (no OID)</para>
    /// </remarks>
    Ed448 = 28,

    // ─────────────────────────────────────────────────────────────────────────
    // Private/Experimental (100-110)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Private/Experimental use - Algorithm ID 100.
    /// </summary>
    Private100 = 100,

    /// <summary>
    /// Private/Experimental use - Algorithm ID 101.
    /// </summary>
    Private101 = 101,

    /// <summary>
    /// Private/Experimental use - Algorithm ID 110.
    /// </summary>
    Private110 = 110,
}

/// <summary>
/// Extension methods for <see cref="PgpPublicKeyAlgorithm"/>.
/// </summary>
public static class PgpPublicKeyAlgorithmExtensions
{
    /// <summary>
    /// Gets whether this algorithm can be used for encryption/key agreement.
    /// </summary>
    public static bool CanEncrypt(this PgpPublicKeyAlgorithm algorithm) => algorithm switch
    {
        PgpPublicKeyAlgorithm.RsaEncryptOrSign => true,
#pragma warning disable CS0618 // Obsolete member
        PgpPublicKeyAlgorithm.RsaEncryptOnly => true,
#pragma warning restore CS0618
        PgpPublicKeyAlgorithm.ElgamalEncryptOnly => true,
        PgpPublicKeyAlgorithm.Ecdh => true,
        PgpPublicKeyAlgorithm.X25519 => true,
        PgpPublicKeyAlgorithm.X448 => true,
        _ => false
    };

    /// <summary>
    /// Gets whether this algorithm can be used for signing.
    /// </summary>
    public static bool CanSign(this PgpPublicKeyAlgorithm algorithm) => algorithm switch
    {
        PgpPublicKeyAlgorithm.RsaEncryptOrSign => true,
#pragma warning disable CS0618 // Obsolete member
        PgpPublicKeyAlgorithm.RsaSignOnly => true,
        PgpPublicKeyAlgorithm.EdDsaLegacy => true,
#pragma warning restore CS0618
        PgpPublicKeyAlgorithm.Dsa => true,
        PgpPublicKeyAlgorithm.Ecdsa => true,
        PgpPublicKeyAlgorithm.Ed25519 => true,
        PgpPublicKeyAlgorithm.Ed448 => true,
        _ => false
    };

    /// <summary>
    /// Gets whether this algorithm uses elliptic curves with OID encoding (RFC 6637 style).
    /// </summary>
    public static bool UsesOidEncoding(this PgpPublicKeyAlgorithm algorithm) => algorithm switch
    {
        PgpPublicKeyAlgorithm.Ecdh => true,
        PgpPublicKeyAlgorithm.Ecdsa => true,
#pragma warning disable CS0618 // Obsolete member
        PgpPublicKeyAlgorithm.EdDsaLegacy => true,
#pragma warning restore CS0618
        _ => false
    };

    /// <summary>
    /// Gets whether this algorithm uses RFC 9580 native format (no OID, fixed-size keys).
    /// </summary>
    public static bool UsesNativeFormat(this PgpPublicKeyAlgorithm algorithm) => algorithm switch
    {
        PgpPublicKeyAlgorithm.X25519 => true,
        PgpPublicKeyAlgorithm.X448 => true,
        PgpPublicKeyAlgorithm.Ed25519 => true,
        PgpPublicKeyAlgorithm.Ed448 => true,
        _ => false
    };

    /// <summary>
    /// Gets the public key size in bytes for native format algorithms.
    /// </summary>
    /// <returns>The public key size, or 0 if not a native format algorithm.</returns>
    public static int GetNativePublicKeySize(this PgpPublicKeyAlgorithm algorithm) => algorithm switch
    {
        PgpPublicKeyAlgorithm.X25519 => 32,
        PgpPublicKeyAlgorithm.X448 => 56,
        PgpPublicKeyAlgorithm.Ed25519 => 32,
        PgpPublicKeyAlgorithm.Ed448 => 57,
        _ => 0
    };

    /// <summary>
    /// Gets the secret key size in bytes for native format algorithms.
    /// </summary>
    /// <returns>The secret key size, or 0 if not a native format algorithm.</returns>
    public static int GetNativeSecretKeySize(this PgpPublicKeyAlgorithm algorithm) => algorithm switch
    {
        PgpPublicKeyAlgorithm.X25519 => 32,
        PgpPublicKeyAlgorithm.X448 => 56,
        PgpPublicKeyAlgorithm.Ed25519 => 32,
        PgpPublicKeyAlgorithm.Ed448 => 57,
        _ => 0
    };
}
