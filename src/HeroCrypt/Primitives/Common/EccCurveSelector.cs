using System.Security.Cryptography;

namespace HeroCrypt.Primitives.Common;

/// <summary>
/// Utility class for selecting appropriate elliptic curves based on key size.
/// </summary>
/// <remarks>
/// <para>
/// This class provides NIST P-curve selection for ECDSA and ECDH operations.
/// The supported curves are:
/// </para>
/// <list type="bullet">
///   <item>
///     <term>P-256 (secp256r1)</term>
///     <description>128-bit security level, most widely deployed</description>
///   </item>
///   <item>
///     <term>P-384 (secp384r1)</term>
///     <description>192-bit security level, required by NSA Suite B</description>
///   </item>
///   <item>
///     <term>P-521 (secp521r1)</term>
///     <description>256-bit security level, highest security NIST curve</description>
///   </item>
/// </list>
/// <para>
/// <b>Note:</b> For new applications, consider using Ed25519/X25519 (Curve25519) which
/// offers better performance and simpler implementation. Use NIST curves when
/// interoperability with existing systems or compliance requirements dictate.
/// </para>
/// </remarks>
public static class EccCurveSelector
{
    /// <summary>
    /// Gets the appropriate NIST EC curve for the specified key size.
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits (256, 384, or 521).</param>
    /// <returns>The corresponding <see cref="ECCurve"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when an unsupported curve size is specified.</exception>
    public static ECCurve GetECCurve(int curveSizeBits)
    {
        return curveSizeBits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported curve size: {curveSizeBits}. Supported sizes are 256, 384, and 521 bits.", nameof(curveSizeBits))
        };
    }

    /// <summary>
    /// Determines if the specified curve size is supported.
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <returns>True if the curve size is supported, false otherwise.</returns>
    public static bool IsSupportedCurveSize(int curveSizeBits)
    {
        return curveSizeBits is 256 or 384 or 521;
    }
}
