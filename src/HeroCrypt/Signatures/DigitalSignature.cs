using System.Security.Cryptography;
using System.Text;
using Primitives = HeroCrypt.Cryptography.Primitives;

namespace HeroCrypt.Signatures;

internal static class EccCurveSelector
{
    public static ECCurve GetECCurve(int curveSizeBits)
    {
        return curveSizeBits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported curve size: {curveSizeBits}", nameof(curveSizeBits))
        };
    }
}

/// <summary>
/// Provides digital signature and MAC operations for various algorithms
/// </summary>
internal static class DigitalSignature
{
    /// <summary>
    /// Signs data using the specified algorithm
    /// </summary>
    /// <param name="data">The data to sign</param>
    /// <param name="key">The signing key (format depends on algorithm)</param>
    /// <param name="algorithm">The signature algorithm to use</param>
    /// <returns>The signature bytes</returns>
    /// <exception cref="ArgumentNullException">Thrown when data or key is null</exception>
    /// <exception cref="NotSupportedException">Thrown when algorithm is not supported on this platform</exception>
    public static byte[] Sign(byte[] data, byte[] key, SignatureAlgorithm algorithm)
    {
#if NETSTANDARD2_0
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }
#else
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);
#endif

        return algorithm switch
        {
            SignatureAlgorithm.HmacSha256 => SignHmac(data, key, HashAlgorithmName.SHA256),
            SignatureAlgorithm.HmacSha384 => SignHmac(data, key, HashAlgorithmName.SHA384),
            SignatureAlgorithm.HmacSha512 => SignHmac(data, key, HashAlgorithmName.SHA512),
            SignatureAlgorithm.RsaSha256 => SignRsa(data, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            SignatureAlgorithm.RsaPssSha256 => SignRsa(data, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SignatureAlgorithm.EcdsaP256Sha256 => SignEcdsa(data, key, HashAlgorithmName.SHA256, 256),
            SignatureAlgorithm.EcdsaP384Sha384 => SignEcdsa(data, key, HashAlgorithmName.SHA384, 384),
            SignatureAlgorithm.EcdsaP521Sha512 => SignEcdsa(data, key, HashAlgorithmName.SHA512, 521),
            SignatureAlgorithm.Ed25519 => SignEdDsa(data, key),
#if NET10_0_OR_GREATER
            SignatureAlgorithm.MLDsa65 => SignMLDsa(data, key, 65),
            SignatureAlgorithm.MLDsa87 => SignMLDsa(data, key, 87),
#else
            SignatureAlgorithm.MLDsa65 or SignatureAlgorithm.MLDsa87 =>
                throw new NotSupportedException("ML-DSA algorithms require .NET 10 or greater"),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Verifies a signature using the specified algorithm
    /// </summary>
    /// <param name="data">The data that was signed</param>
    /// <param name="signature">The signature to verify</param>
    /// <param name="key">The verification key (format depends on algorithm)</param>
    /// <param name="algorithm">The signature algorithm used</param>
    /// <returns>True if the signature is valid; otherwise, false</returns>
    /// <exception cref="ArgumentNullException">Thrown when data, signature, or key is null</exception>
    /// <exception cref="NotSupportedException">Thrown when algorithm is not supported on this platform</exception>
    public static bool Verify(byte[] data, byte[] signature, byte[] key, SignatureAlgorithm algorithm)
    {
#if NETSTANDARD2_0
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (signature == null)
        {
            throw new ArgumentNullException(nameof(signature));
        }
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }
#else
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(key);
#endif

        return algorithm switch
        {
            SignatureAlgorithm.HmacSha256 => VerifyHmac(data, signature, key, HashAlgorithmName.SHA256),
            SignatureAlgorithm.HmacSha384 => VerifyHmac(data, signature, key, HashAlgorithmName.SHA384),
            SignatureAlgorithm.HmacSha512 => VerifyHmac(data, signature, key, HashAlgorithmName.SHA512),
            SignatureAlgorithm.RsaSha256 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            SignatureAlgorithm.RsaPssSha256 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SignatureAlgorithm.EcdsaP256Sha256 => VerifyEcdsa(data, signature, key, HashAlgorithmName.SHA256, 256),
            SignatureAlgorithm.EcdsaP384Sha384 => VerifyEcdsa(data, signature, key, HashAlgorithmName.SHA384, 384),
            SignatureAlgorithm.EcdsaP521Sha512 => VerifyEcdsa(data, signature, key, HashAlgorithmName.SHA512, 521),
            SignatureAlgorithm.Ed25519 => VerifyEdDsa(data, signature, key),
#if NET10_0_OR_GREATER
            SignatureAlgorithm.MLDsa65 => VerifyMLDsa(data, signature, key, 65),
            SignatureAlgorithm.MLDsa87 => VerifyMLDsa(data, signature, key, 87),
#else
            SignatureAlgorithm.MLDsa65 or SignatureAlgorithm.MLDsa87 =>
                throw new NotSupportedException("ML-DSA algorithms require .NET 10 or greater"),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    #region HMAC Algorithms

    private static byte[] SignHmac(byte[] data, byte[] key, HashAlgorithmName hashAlgorithm)
    {
        using HMAC hmac = hashAlgorithm.Name switch
        {
            "SHA256" => new HMACSHA256(key),
            "SHA384" => new HMACSHA384(key),
            "SHA512" => new HMACSHA512(key),
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported for HMAC")
        };

        return hmac.ComputeHash(data);
    }

    private static bool VerifyHmac(byte[] data, byte[] signature, byte[] key, HashAlgorithmName hashAlgorithm)
    {
        var computed = SignHmac(data, key, hashAlgorithm);
        return CryptographicOperations.FixedTimeEquals(computed, signature);
    }

    #endregion

    #region RSA Algorithms

#if !NETSTANDARD2_0
    private static byte[] SignRsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKey, out _);
        return rsa.SignData(data, hashAlgorithm, padding);
    }

    private static bool VerifyRsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            return rsa.VerifyData(data, signature, hashAlgorithm, padding);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
#else
    private static byte[] SignRsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        throw new NotSupportedException("RSA signing is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }

    private static bool VerifyRsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        throw new NotSupportedException("RSA signature verification is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }
#endif

    #endregion

    #region ECDSA Algorithms

#if !NETSTANDARD2_0
    private static byte[] SignEcdsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, int curveSizeBits)
    {
        using var ecdsa = ECDsa.Create(EccCurveSelector.GetECCurve(curveSizeBits));
        ecdsa.ImportECPrivateKey(privateKey, out _);
        return ecdsa.SignData(data, hashAlgorithm);
    }

    private static bool VerifyEcdsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, int curveSizeBits)
    {
        try
        {
            using var ecdsa = ECDsa.Create(EccCurveSelector.GetECCurve(curveSizeBits));
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            return ecdsa.VerifyData(data, signature, hashAlgorithm);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
#else
    private static byte[] SignEcdsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, int curveSizeBits)
    {
        throw new NotSupportedException("ECDSA signing is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }

    private static bool VerifyEcdsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, int curveSizeBits)
    {
        throw new NotSupportedException("ECDSA signature verification is not supported on .NET Standard 2.0. Requires .NET 8.0 or greater.");
    }

#endif

    #endregion

    #region EdDSA Algorithm

    private static byte[] SignEdDsa(byte[] data, byte[] privateKey)
    {
        // Using HeroCrypt's custom Ed25519Core implementation
        return Primitives.Signature.Ecc.Ed25519Core.Sign(data, privateKey);
    }

    private static bool VerifyEdDsa(byte[] data, byte[] signature, byte[] publicKey)
    {
        // Using HeroCrypt's custom Ed25519Core implementation
        return Primitives.Signature.Ecc.Ed25519Core.Verify(data, signature, publicKey);
    }

    #endregion

    #region ML-DSA Algorithms (Post-Quantum)

#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006 // Experimental feature warnings
    private static byte[] SignMLDsa(byte[] data, byte[] privateKeyPem, int parameterSet)
    {
        var pem = Encoding.UTF8.GetString(privateKeyPem);

        return parameterSet switch
        {
            65 => Primitives.PostQuantum.Signature.MLDsaWrapper.Sign(pem, data, securityBits: 192),
            87 => Primitives.PostQuantum.Signature.MLDsaWrapper.Sign(pem, data, securityBits: 256),
            _ => throw new ArgumentException($"Unsupported ML-DSA parameter set: {parameterSet}")
        };
    }

    private static bool VerifyMLDsa(byte[] data, byte[] signature, byte[] publicKeyPem, int parameterSet)
    {
        try
        {
            var pem = Encoding.UTF8.GetString(publicKeyPem);

            return parameterSet switch
            {
                65 => Primitives.PostQuantum.Signature.MLDsaWrapper.Verify(pem, data, signature),
                87 => Primitives.PostQuantum.Signature.MLDsaWrapper.Verify(pem, data, signature),
                _ => throw new ArgumentException($"Unsupported ML-DSA parameter set: {parameterSet}")
            };
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
#pragma warning restore SYSLIB5006
#endif

    #endregion
}
