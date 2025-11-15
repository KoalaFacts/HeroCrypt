using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Cryptography.DigitalSignatures;

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
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (key == null)
            throw new ArgumentNullException(nameof(key));

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
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));
        if (key == null)
            throw new ArgumentNullException(nameof(key));

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
        using var hmac = hashAlgorithm.Name switch
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

    #endregion

    #region ECDSA Algorithms

    private static byte[] SignEcdsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, int curveSizeBits)
    {
        using var ecdsa = ECDsa.Create(GetECCurve(curveSizeBits));
        ecdsa.ImportECPrivateKey(privateKey, out _);
        return ecdsa.SignData(data, hashAlgorithm);
    }

    private static bool VerifyEcdsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, int curveSizeBits)
    {
        try
        {
            using var ecdsa = ECDsa.Create(GetECCurve(curveSizeBits));
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            return ecdsa.VerifyData(data, signature, hashAlgorithm);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static ECCurve GetECCurve(int curveSizeBits)
    {
        return curveSizeBits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported curve size: {curveSizeBits}")
        };
    }

    #endregion

    #region EdDSA Algorithm

    private static byte[] SignEdDsa(byte[] data, byte[] privateKey)
    {
#if NET7_0_OR_GREATER
        if (privateKey.Length != 32)
            throw new ArgumentException("Ed25519 private key must be 32 bytes", nameof(privateKey));

        using var ed25519 = System.Security.Cryptography.Ed25519.Create();
        var keyData = new byte[32];
        Array.Copy(privateKey, keyData, 32);
        ed25519.ImportPkcs8PrivateKey(CreateEd25519Pkcs8(keyData), out _);
        return ed25519.SignData(data);
#else
        throw new NotSupportedException("EdDSA (Ed25519) requires .NET 7 or greater. For older frameworks, use the Ed25519Core implementation.");
#endif
    }

    private static bool VerifyEdDsa(byte[] data, byte[] signature, byte[] publicKey)
    {
#if NET7_0_OR_GREATER
        try
        {
            if (publicKey.Length != 32)
                throw new ArgumentException("Ed25519 public key must be 32 bytes", nameof(publicKey));

            using var ed25519 = System.Security.Cryptography.Ed25519.Create();
            ed25519.ImportSubjectPublicKeyInfo(CreateEd25519Spki(publicKey), out _);
            return ed25519.VerifyData(data, signature);
        }
        catch (CryptographicException)
        {
            return false;
        }
#else
        throw new NotSupportedException("EdDSA (Ed25519) requires .NET 7 or greater. For older frameworks, use the Ed25519Core implementation.");
#endif
    }

#if NET7_0_OR_GREATER
    private static byte[] CreateEd25519Pkcs8(byte[] privateKey)
    {
        // PKCS#8 format for Ed25519: Fixed header + 32-byte private key
        var pkcs8 = new byte[48];
        // ASN.1 header for Ed25519 PKCS#8
        byte[] header = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
        Array.Copy(header, 0, pkcs8, 0, header.Length);
        Array.Copy(privateKey, 0, pkcs8, header.Length, 32);
        return pkcs8;
    }

    private static byte[] CreateEd25519Spki(byte[] publicKey)
    {
        // SubjectPublicKeyInfo format for Ed25519: Fixed header + 32-byte public key
        var spki = new byte[44];
        // ASN.1 header for Ed25519 SPKI
        byte[] header = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
        Array.Copy(header, 0, spki, 0, header.Length);
        Array.Copy(publicKey, 0, spki, header.Length, 32);
        return spki;
    }
#endif

    #endregion

    #region ML-DSA Algorithms (Post-Quantum)

#if NET10_0_OR_GREATER
    private static byte[] SignMLDsa(byte[] data, byte[] privateKeyPem, int parameterSet)
    {
        var pem = Encoding.UTF8.GetString(privateKeyPem);

        return parameterSet switch
        {
            65 => PostQuantum.Dilithium.MLDsaWrapper.Sign(pem, data, securityBits: 192),
            87 => PostQuantum.Dilithium.MLDsaWrapper.Sign(pem, data, securityBits: 256),
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
                65 => PostQuantum.Dilithium.MLDsaWrapper.Verify(pem, data, signature),
                87 => PostQuantum.Dilithium.MLDsaWrapper.Verify(pem, data, signature),
                _ => throw new ArgumentException($"Unsupported ML-DSA parameter set: {parameterSet}")
            };
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
#endif

    #endregion
}
