using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP elliptic curve OIDs as defined in RFC 6637 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// In OpenPGP, elliptic curves are identified by their OID (Object Identifier).
/// The OID is encoded in the public key packet for EC keys.
/// </para>
/// <para>
/// This enum provides symbolic names; the actual OID bytes are provided
/// by the <see cref="PgpCurveOidExtensions"/> class.
/// </para>
/// </remarks>
public enum PgpCurveOid
{
    // ─────────────────────────────────────────────────────────────────────────
    // NIST Curves (RFC 6637)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// NIST P-256 (secp256r1) - 256-bit prime curve.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.2.840.10045.3.1.7</para>
    /// <para><b>Key size:</b> 256 bits</para>
    /// <para><b>Security:</b> ~128-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED - Widely supported.</para>
    /// </remarks>
    NistP256,

    /// <summary>
    /// NIST P-384 (secp384r1) - 384-bit prime curve.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.132.0.34</para>
    /// <para><b>Key size:</b> 384 bits</para>
    /// <para><b>Security:</b> ~192-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED</para>
    /// </remarks>
    NistP384,

    /// <summary>
    /// NIST P-521 (secp521r1) - 521-bit prime curve.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.132.0.35</para>
    /// <para><b>Key size:</b> 521 bits</para>
    /// <para><b>Security:</b> ~256-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED</para>
    /// </remarks>
    NistP521,

    // ─────────────────────────────────────────────────────────────────────────
    // Curve25519/Ed25519 (RFC 9580)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Ed25519 - Edwards curve for signatures.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.6.1.4.1.11591.15.1</para>
    /// <para><b>Key size:</b> 256 bits</para>
    /// <para><b>Security:</b> ~128-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED - Modern recommended signature curve.</para>
    /// </remarks>
    Ed25519,

    /// <summary>
    /// Curve25519 (X25519) - Montgomery curve for ECDH.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.6.1.4.1.3029.1.5.1</para>
    /// <para><b>Key size:</b> 256 bits</para>
    /// <para><b>Security:</b> ~128-bit</para>
    /// <para><b>Status:</b> IMPLEMENTED - Modern recommended encryption curve.</para>
    /// </remarks>
    Curve25519,

    // ─────────────────────────────────────────────────────────────────────────
    // Curve448/Ed448 (RFC 9580)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Ed448 - Edwards curve for signatures (higher security).
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.101.113</para>
    /// <para><b>Key size:</b> 448 bits</para>
    /// <para><b>Security:</b> ~224-bit</para>
    /// <para><b>Status:</b> Higher security variant of Ed25519.</para>
    /// </remarks>
    [NotImplemented("Ed448 - higher security Edwards curve", Priority = 3)]
    Ed448,

    /// <summary>
    /// X448 - Montgomery curve for ECDH (higher security).
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.101.111</para>
    /// <para><b>Key size:</b> 448 bits</para>
    /// <para><b>Security:</b> ~224-bit</para>
    /// <para><b>Status:</b> Higher security variant of X25519.</para>
    /// </remarks>
    [NotImplemented("X448 - higher security Montgomery curve", Priority = 3)]
    X448,

    // ─────────────────────────────────────────────────────────────────────────
    // Brainpool Curves (RFC 9580)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Brainpool P-256r1 - German BSI curve.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.36.3.3.2.8.1.1.7</para>
    /// <para><b>Key size:</b> 256 bits</para>
    /// <para><b>Status:</b> Alternative to NIST curves for European compliance.</para>
    /// </remarks>
    [NotImplemented("Brainpool P-256 - European compliance", Priority = 4)]
    BrainpoolP256r1,

    /// <summary>
    /// Brainpool P-384r1 - German BSI curve.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.36.3.3.2.8.1.1.11</para>
    /// <para><b>Key size:</b> 384 bits</para>
    /// </remarks>
    [NotImplemented("Brainpool P-384 - European compliance", Priority = 4)]
    BrainpoolP384r1,

    /// <summary>
    /// Brainpool P-512r1 - German BSI curve.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.36.3.3.2.8.1.1.13</para>
    /// <para><b>Key size:</b> 512 bits</para>
    /// </remarks>
    [NotImplemented("Brainpool P-512 - European compliance", Priority = 4)]
    BrainpoolP512r1,

    // ─────────────────────────────────────────────────────────────────────────
    // secp256k1 (Bitcoin/Ethereum)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// secp256k1 - Koblitz curve used in Bitcoin/Ethereum.
    /// </summary>
    /// <remarks>
    /// <para><b>OID:</b> 1.3.132.0.10</para>
    /// <para><b>Key size:</b> 256 bits</para>
    /// <para><b>Status:</b> IMPLEMENTED - Used in cryptocurrency applications.</para>
    /// <para>Note: Not commonly used in standard OpenPGP but supported for interop.</para>
    /// </remarks>
    Secp256k1,
}

/// <summary>
/// Extension methods for <see cref="PgpCurveOid"/> providing OID byte arrays.
/// </summary>
public static class PgpCurveOidExtensions
{
    /// <summary>
    /// Gets the DER-encoded OID bytes for the curve.
    /// </summary>
    /// <param name="curve">The curve identifier.</param>
    /// <returns>The OID as a byte array.</returns>
    public static byte[] GetOidBytes(this PgpCurveOid curve) => curve switch
    {
        // NIST curves
        PgpCurveOid.NistP256 => [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], // 1.2.840.10045.3.1.7
        PgpCurveOid.NistP384 => [0x2B, 0x81, 0x04, 0x00, 0x22], // 1.3.132.0.34
        PgpCurveOid.NistP521 => [0x2B, 0x81, 0x04, 0x00, 0x23], // 1.3.132.0.35

        // Curve25519/Ed25519
        PgpCurveOid.Ed25519 => [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01], // 1.3.6.1.4.1.11591.15.1
        PgpCurveOid.Curve25519 => [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01], // 1.3.6.1.4.1.3029.1.5.1

        // Curve448/Ed448
        PgpCurveOid.Ed448 => [0x2B, 0x65, 0x71], // 1.3.101.113
        PgpCurveOid.X448 => [0x2B, 0x65, 0x6F], // 1.3.101.111

        // Brainpool
        PgpCurveOid.BrainpoolP256r1 => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], // 1.3.36.3.3.2.8.1.1.7
        PgpCurveOid.BrainpoolP384r1 => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B], // 1.3.36.3.3.2.8.1.1.11
        PgpCurveOid.BrainpoolP512r1 => [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D], // 1.3.36.3.3.2.8.1.1.13

        // secp256k1
        PgpCurveOid.Secp256k1 => [0x2B, 0x81, 0x04, 0x00, 0x0A], // 1.3.132.0.10

        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown curve OID")
    };

    /// <summary>
    /// Gets the key size in bits for the curve.
    /// </summary>
    /// <param name="curve">The curve identifier.</param>
    /// <returns>The key size in bits.</returns>
    public static int GetKeySizeBits(this PgpCurveOid curve) => curve switch
    {
        PgpCurveOid.NistP256 => 256,
        PgpCurveOid.NistP384 => 384,
        PgpCurveOid.NistP521 => 521,
        PgpCurveOid.Ed25519 => 256,
        PgpCurveOid.Curve25519 => 256,
        PgpCurveOid.Ed448 => 448,
        PgpCurveOid.X448 => 448,
        PgpCurveOid.BrainpoolP256r1 => 256,
        PgpCurveOid.BrainpoolP384r1 => 384,
        PgpCurveOid.BrainpoolP512r1 => 512,
        PgpCurveOid.Secp256k1 => 256,
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Unknown curve")
    };

    /// <summary>
    /// Gets whether the curve is suitable for ECDH key agreement.
    /// </summary>
    /// <param name="curve">The curve identifier.</param>
    /// <returns>True if the curve can be used for ECDH.</returns>
    public static bool IsEcdhCurve(this PgpCurveOid curve) => curve switch
    {
        PgpCurveOid.NistP256 => true,
        PgpCurveOid.NistP384 => true,
        PgpCurveOid.NistP521 => true,
        PgpCurveOid.Curve25519 => true,
        PgpCurveOid.X448 => true,
        PgpCurveOid.BrainpoolP256r1 => true,
        PgpCurveOid.BrainpoolP384r1 => true,
        PgpCurveOid.BrainpoolP512r1 => true,
        PgpCurveOid.Secp256k1 => true,
        _ => false
    };

    /// <summary>
    /// Gets whether the curve is suitable for ECDSA/EdDSA signatures.
    /// </summary>
    /// <param name="curve">The curve identifier.</param>
    /// <returns>True if the curve can be used for signatures.</returns>
    public static bool IsSignatureCurve(this PgpCurveOid curve) => curve switch
    {
        PgpCurveOid.NistP256 => true,
        PgpCurveOid.NistP384 => true,
        PgpCurveOid.NistP521 => true,
        PgpCurveOid.Ed25519 => true,
        PgpCurveOid.Ed448 => true,
        PgpCurveOid.BrainpoolP256r1 => true,
        PgpCurveOid.BrainpoolP384r1 => true,
        PgpCurveOid.BrainpoolP512r1 => true,
        PgpCurveOid.Secp256k1 => true,
        _ => false
    };
}
