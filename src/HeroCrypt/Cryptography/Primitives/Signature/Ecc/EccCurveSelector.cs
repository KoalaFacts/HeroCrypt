using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Primitives.Signature.Ecc;

/// <summary>
/// Utility class for selecting appropriate elliptic curves based on key size.
/// </summary>
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
