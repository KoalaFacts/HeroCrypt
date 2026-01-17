using System.Security.Cryptography;
using HeroCrypt.Primitives.Common;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Ecdsa;

/// <summary>
/// ECDSA (Elliptic Curve Digital Signature Algorithm) implementation using NIST curves.
/// Supports P-256, P-384, and P-521 curves as used in OpenPGP (RFC 6637).
/// </summary>
/// <remarks>
/// ECDSA provides digital signatures with security levels:
/// - P-256: ~128-bit security (recommended for most applications)
/// - P-384: ~192-bit security (high security)
/// - P-521: ~256-bit security (highest security)
/// </remarks>
internal static class EcdsaCore
{
    /// <summary>
    /// Supported curve sizes in bits.
    /// </summary>
    public static readonly int[] SupportedCurveSizes = [256, 384, 521];

    /// <summary>
    /// Generates a new ECDSA key pair for the specified curve.
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits (256, 384, or 521).</param>
    /// <returns>The EC parameters containing the key pair.</returns>
    /// <exception cref="ArgumentException">If the curve size is not supported.</exception>
    public static ECParameters GenerateKeyPair(int curveSizeBits)
    {
        ValidateCurveSize(curveSizeBits);

        var curve = EccCurveSelector.GetECCurve(curveSizeBits);
        using var ecdsa = ECDsa.Create(curve);

        return ecdsa.ExportParameters(true);
    }

    /// <summary>
    /// Signs a message hash using the ECDSA private key.
    /// </summary>
    /// <param name="hash">The hash of the message to sign.</param>
    /// <param name="parameters">The EC parameters containing the private key.</param>
    /// <returns>The signature as raw (r || s) concatenated bytes (IEEE P1363 format).</returns>
    public static byte[] SignHash(ReadOnlySpan<byte> hash, ECParameters parameters)
    {
        using var ecdsa = ECDsa.Create(parameters);
#if NETSTANDARD2_0
        return ecdsa.SignHash(hash.ToArray());
#else
        return ecdsa.SignHash(hash.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
#endif
    }

    /// <summary>
    /// Signs data using the ECDSA private key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="parameters">The EC parameters containing the private key.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>The signature as raw (r || s) concatenated bytes (IEEE P1363 format).</returns>
    public static byte[] SignData(ReadOnlySpan<byte> data, ECParameters parameters, HashAlgorithmName hashAlgorithm)
    {
        using var ecdsa = ECDsa.Create(parameters);
#if NETSTANDARD2_0
        return ecdsa.SignData(data.ToArray(), hashAlgorithm);
#else
        return ecdsa.SignData(data.ToArray(), hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
#endif
    }

    /// <summary>
    /// Verifies a signature against a message hash.
    /// </summary>
    /// <param name="hash">The hash of the message.</param>
    /// <param name="signature">The signature as raw (r || s) bytes.</param>
    /// <param name="parameters">The EC parameters containing the public key.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    public static bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ECParameters parameters)
    {
        try
        {
            using var ecdsa = ECDsa.Create(parameters);
#if NETSTANDARD2_0
            return ecdsa.VerifyHash(hash.ToArray(), signature.ToArray());
#else
            return ecdsa.VerifyHash(hash.ToArray(), signature.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
#endif
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies a signature against data.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature as raw (r || s) bytes.</param>
    /// <param name="parameters">The EC parameters containing the public key.</param>
    /// <param name="hashAlgorithm">The hash algorithm used for signing.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    public static bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ECParameters parameters, HashAlgorithmName hashAlgorithm)
    {
        try
        {
            using var ecdsa = ECDsa.Create(parameters);
#if NETSTANDARD2_0
            return ecdsa.VerifyData(data.ToArray(), signature.ToArray(), hashAlgorithm);
#else
            return ecdsa.VerifyData(data.ToArray(), signature.ToArray(), hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
#endif
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Extracts the public key parameters from full key parameters.
    /// </summary>
    /// <param name="parameters">The full EC parameters (may include private key).</param>
    /// <returns>EC parameters containing only the public key.</returns>
    public static ECParameters ExtractPublicKey(ECParameters parameters)
    {
        return new ECParameters
        {
            Curve = parameters.Curve,
            Q = parameters.Q
        };
    }

    /// <summary>
    /// Creates key parameters from raw components (OpenPGP format).
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <param name="d">The private key scalar (optional, null for public key only).</param>
    /// <param name="x">The public key X coordinate.</param>
    /// <param name="y">The public key Y coordinate.</param>
    /// <returns>The EC parameters.</returns>
    public static ECParameters CreateParameters(int curveSizeBits, byte[]? d, byte[] x, byte[] y)
    {
        ValidateCurveSize(curveSizeBits);

        var curve = EccCurveSelector.GetECCurve(curveSizeBits);
        return new ECParameters
        {
            Curve = curve,
            D = d,
            Q = new ECPoint { X = x, Y = y }
        };
    }

    /// <summary>
    /// Creates public key parameters from raw coordinates (OpenPGP format).
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <param name="x">The public key X coordinate.</param>
    /// <param name="y">The public key Y coordinate.</param>
    /// <returns>The EC parameters with public key only.</returns>
    public static ECParameters CreatePublicKeyParameters(int curveSizeBits, byte[] x, byte[] y)
    {
        return CreateParameters(curveSizeBits, null, x, y);
    }

    /// <summary>
    /// Signs a hash and returns the raw signature components (r, s).
    /// </summary>
    /// <param name="hash">The hash to sign.</param>
    /// <param name="parameters">The EC parameters containing the private key.</param>
    /// <returns>The signature as (r, s) components.</returns>
    public static (byte[] r, byte[] s) SignHashRaw(ReadOnlySpan<byte> hash, ECParameters parameters)
    {
        var signature = SignHash(hash, parameters);
        var halfLen = signature.Length / 2;

        var r = new byte[halfLen];
        var s = new byte[halfLen];
        Array.Copy(signature, 0, r, 0, halfLen);
        Array.Copy(signature, halfLen, s, 0, halfLen);

        SecureMemoryOperations.SecureClear(signature);

        return (r, s);
    }

    /// <summary>
    /// Verifies a signature using raw (r, s) format.
    /// </summary>
    /// <param name="hash">The hash that was signed.</param>
    /// <param name="r">The r component of the signature.</param>
    /// <param name="s">The s component of the signature.</param>
    /// <param name="parameters">The EC parameters containing the public key.</param>
    /// <returns>True if valid, false otherwise.</returns>
    public static bool VerifyHashRaw(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, ECParameters parameters)
    {
        // Combine r and s into IEEE P1363 format
        var signature = new byte[r.Length + s.Length];
        r.CopyTo(signature);
        s.CopyTo(signature.AsSpan(r.Length));

        return VerifyHash(hash, signature, parameters);
    }

    /// <summary>
    /// Gets the recommended hash algorithm for a given curve size.
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <returns>The recommended hash algorithm name.</returns>
    public static HashAlgorithmName GetRecommendedHashAlgorithm(int curveSizeBits)
    {
        return curveSizeBits switch
        {
            256 => HashAlgorithmName.SHA256,
            384 => HashAlgorithmName.SHA384,
            521 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };
    }

    /// <summary>
    /// Gets the expected coordinate size for a given curve.
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <returns>The size of each coordinate in bytes.</returns>
    public static int GetCoordinateSize(int curveSizeBits)
    {
        return (curveSizeBits + 7) / 8;
    }

    /// <summary>
    /// Gets the signature component size (r or s) for a given curve.
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <returns>The size of each signature component in bytes.</returns>
    public static int GetSignatureComponentSize(int curveSizeBits)
    {
        return GetCoordinateSize(curveSizeBits);
    }

    /// <summary>
    /// Gets the total signature size for a given curve (r + s).
    /// </summary>
    /// <param name="curveSizeBits">The curve size in bits.</param>
    /// <returns>The total signature size in bytes.</returns>
    public static int GetSignatureSize(int curveSizeBits)
    {
        return GetCoordinateSize(curveSizeBits) * 2;
    }

    /// <summary>
    /// Validates that the parameters represent a valid key.
    /// </summary>
    /// <param name="parameters">The EC parameters to validate.</param>
    /// <exception cref="CryptographicException">If the parameters are invalid.</exception>
    public static void ValidateParameters(ECParameters parameters)
    {
        // Try to create an ECDsa instance to validate
        using var ecdsa = ECDsa.Create(parameters);
        // If we get here, parameters are valid
    }

    private static void ValidateCurveSize(int curveSizeBits)
    {
        if (!EccCurveSelector.IsSupportedCurveSize(curveSizeBits))
        {
            throw new ArgumentException(
                $"Unsupported curve size: {curveSizeBits}. Supported sizes are 256, 384, and 521 bits.",
                nameof(curveSizeBits));
        }
    }
}

/// <summary>
/// ECDSA curve identifiers.
/// </summary>
public enum EcdsaCurve
{
    /// <summary>NIST P-256 curve (~128-bit security).</summary>
    P256 = 256,

    /// <summary>NIST P-384 curve (~192-bit security).</summary>
    P384 = 384,

    /// <summary>NIST P-521 curve (~256-bit security).</summary>
    P521 = 521
}
