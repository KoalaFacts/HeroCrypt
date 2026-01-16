using System.Security.Cryptography;
using HeroCrypt.Primitives.AesCmac;
using HeroCrypt.Primitives.Common;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Poly1305;
using HeroCrypt.Primitives.Secp256k1;
using HeroCrypt.Security;
#if NET10_0_OR_GREATER
using HeroCrypt.Primitives.MLDsa;
#endif

namespace HeroCrypt.Operations;

/// <summary>
/// Fluent builder for digital signature operations.
/// </summary>
public class SignatureBuilder
{
    private SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;
    private byte[]? privateKey;

    /// <summary>
    /// Sets the signature algorithm to use.
    /// </summary>
    public SignatureBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    // HMAC (Symmetric MAC)
    /// <summary>Use HMAC-SHA256 for signing.</summary>
    public SignatureBuilder WithHmacSha256() => WithAlgorithm(SignatureAlgorithm.HmacSha256);
    /// <summary>Use HMAC-SHA384 for signing.</summary>
    public SignatureBuilder WithHmacSha384() => WithAlgorithm(SignatureAlgorithm.HmacSha384);
    /// <summary>Use HMAC-SHA512 for signing.</summary>
    public SignatureBuilder WithHmacSha512() => WithAlgorithm(SignatureAlgorithm.HmacSha512);

    // AES-CMAC (Symmetric MAC)
    /// <summary>Use AES-CMAC with 128-bit key.</summary>
    public SignatureBuilder WithAesCmac128() => WithAlgorithm(SignatureAlgorithm.AesCmac128);
    /// <summary>Use AES-CMAC with 192-bit key.</summary>
    public SignatureBuilder WithAesCmac192() => WithAlgorithm(SignatureAlgorithm.AesCmac192);
    /// <summary>Use AES-CMAC with 256-bit key.</summary>
    public SignatureBuilder WithAesCmac256() => WithAlgorithm(SignatureAlgorithm.AesCmac256);

    // Poly1305 (One-time MAC)
    /// <summary>Use Poly1305 one-time authenticator.</summary>
    public SignatureBuilder WithPoly1305() => WithAlgorithm(SignatureAlgorithm.Poly1305);

    // RSA-PKCS#1 v1.5 Signatures
    /// <summary>Use RSA-PKCS#1 v1.5 with SHA-256 for signing.</summary>
    public SignatureBuilder WithRsaSha256() => WithAlgorithm(SignatureAlgorithm.RsaSha256);
    /// <summary>Use RSA-PKCS#1 v1.5 with SHA-384 for signing.</summary>
    public SignatureBuilder WithRsaSha384() => WithAlgorithm(SignatureAlgorithm.RsaSha384);
    /// <summary>Use RSA-PKCS#1 v1.5 with SHA-512 for signing.</summary>
    public SignatureBuilder WithRsaSha512() => WithAlgorithm(SignatureAlgorithm.RsaSha512);

    // RSA-PSS Signatures (Recommended)
    /// <summary>Use RSA-PSS with SHA-256 for signing (recommended over PKCS#1 v1.5).</summary>
    public SignatureBuilder WithRsaPssSha256() => WithAlgorithm(SignatureAlgorithm.RsaPssSha256);
    /// <summary>Use RSA-PSS with SHA-384 for signing.</summary>
    public SignatureBuilder WithRsaPssSha384() => WithAlgorithm(SignatureAlgorithm.RsaPssSha384);
    /// <summary>Use RSA-PSS with SHA-512 for signing.</summary>
    public SignatureBuilder WithRsaPssSha512() => WithAlgorithm(SignatureAlgorithm.RsaPssSha512);

    // ECDSA NIST Curves
    /// <summary>Use ECDSA P-256 with SHA-256 for signing.</summary>
    public SignatureBuilder WithEcdsaP256() => WithAlgorithm(SignatureAlgorithm.EcdsaP256Sha256);
    /// <summary>Use ECDSA P-384 with SHA-384 for signing.</summary>
    public SignatureBuilder WithEcdsaP384() => WithAlgorithm(SignatureAlgorithm.EcdsaP384Sha384);
    /// <summary>Use ECDSA P-521 with SHA-512 for signing.</summary>
    public SignatureBuilder WithEcdsaP521() => WithAlgorithm(SignatureAlgorithm.EcdsaP521Sha512);

    // ECDSA Blockchain Curves
    /// <summary>Use secp256k1 ECDSA for signing (Bitcoin, Ethereum).</summary>
    public SignatureBuilder WithSecp256k1() => WithAlgorithm(SignatureAlgorithm.Secp256k1);

    // EdDSA
    /// <summary>Use Ed25519 for signing (default, recommended).</summary>
    public SignatureBuilder WithEd25519() => WithAlgorithm(SignatureAlgorithm.Ed25519);

#if NET10_0_OR_GREATER
    // ML-DSA Post-Quantum Signatures
    /// <summary>Use ML-DSA-44 post-quantum signature (128-bit security).</summary>
    public SignatureBuilder WithMLDsa44() => WithAlgorithm(SignatureAlgorithm.MLDsa44);
    /// <summary>Use ML-DSA-65 post-quantum signature (192-bit security).</summary>
    public SignatureBuilder WithMLDsa65() => WithAlgorithm(SignatureAlgorithm.MLDsa65);
    /// <summary>Use ML-DSA-87 post-quantum signature (256-bit security).</summary>
    public SignatureBuilder WithMLDsa87() => WithAlgorithm(SignatureAlgorithm.MLDsa87);
#endif

    /// <summary>
    /// Sets the private key for signing.
    /// </summary>
    public SignatureBuilder WithPrivateKey(byte[] privateKey)
    {
        this.privateKey = privateKey;
        return this;
    }

    /// <summary>
    /// Signs the data and returns the signature.
    /// </summary>
    public byte[] Sign(byte[] data)
    {
        if (privateKey == null)
            throw new InvalidOperationException("Private key must be set using WithPrivateKey()");

        InputValidator.ValidateByteArray(data, nameof(data));
        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        return SignInternal(data, privateKey, algorithm);
    }

    internal static byte[] SignInternal(byte[] data, byte[] key, SignatureAlgorithm algorithm)
    {
        return algorithm switch
        {
            // HMAC
            SignatureAlgorithm.HmacSha256 => SignHmac(data, key, HashAlgorithmName.SHA256),
            SignatureAlgorithm.HmacSha384 => SignHmac(data, key, HashAlgorithmName.SHA384),
            SignatureAlgorithm.HmacSha512 => SignHmac(data, key, HashAlgorithmName.SHA512),
            // AES-CMAC
            SignatureAlgorithm.AesCmac128 => SignAesCmac(data, key, 16),
            SignatureAlgorithm.AesCmac192 => SignAesCmac(data, key, 24),
            SignatureAlgorithm.AesCmac256 => SignAesCmac(data, key, 32),
            // Poly1305
            SignatureAlgorithm.Poly1305 => SignPoly1305(data, key),
            // RSA-PKCS#1 v1.5
            SignatureAlgorithm.RsaSha256 => SignRsa(data, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            SignatureAlgorithm.RsaSha384 => SignRsa(data, key, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            SignatureAlgorithm.RsaSha512 => SignRsa(data, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            // RSA-PSS
            SignatureAlgorithm.RsaPssSha256 => SignRsa(data, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SignatureAlgorithm.RsaPssSha384 => SignRsa(data, key, HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            SignatureAlgorithm.RsaPssSha512 => SignRsa(data, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            // ECDSA NIST
            SignatureAlgorithm.EcdsaP256Sha256 => SignEcdsa(data, key, HashAlgorithmName.SHA256, 256),
            SignatureAlgorithm.EcdsaP384Sha384 => SignEcdsa(data, key, HashAlgorithmName.SHA384, 384),
            SignatureAlgorithm.EcdsaP521Sha512 => SignEcdsa(data, key, HashAlgorithmName.SHA512, 521),
            // ECDSA Blockchain
            SignatureAlgorithm.Secp256k1 => SignSecp256k1(data, key),
            // EdDSA
            SignatureAlgorithm.Ed25519 => Ed25519Core.Sign(data, key),
#if NET10_0_OR_GREATER
            // ML-DSA
            SignatureAlgorithm.MLDsa44 => SignMLDsa(data, key, 44),
            SignatureAlgorithm.MLDsa65 => SignMLDsa(data, key, 65),
            SignatureAlgorithm.MLDsa87 => SignMLDsa(data, key, 87),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    internal static bool VerifyInternal(byte[] data, byte[] signature, byte[] key, SignatureAlgorithm algorithm)
    {
        return algorithm switch
        {
            // HMAC
            SignatureAlgorithm.HmacSha256 => VerifyHmac(data, signature, key, HashAlgorithmName.SHA256),
            SignatureAlgorithm.HmacSha384 => VerifyHmac(data, signature, key, HashAlgorithmName.SHA384),
            SignatureAlgorithm.HmacSha512 => VerifyHmac(data, signature, key, HashAlgorithmName.SHA512),
            // AES-CMAC
            SignatureAlgorithm.AesCmac128 => VerifyAesCmac(data, signature, key, 16),
            SignatureAlgorithm.AesCmac192 => VerifyAesCmac(data, signature, key, 24),
            SignatureAlgorithm.AesCmac256 => VerifyAesCmac(data, signature, key, 32),
            // Poly1305
            SignatureAlgorithm.Poly1305 => VerifyPoly1305(data, signature, key),
            // RSA-PKCS#1 v1.5
            SignatureAlgorithm.RsaSha256 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            SignatureAlgorithm.RsaSha384 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            SignatureAlgorithm.RsaSha512 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            // RSA-PSS
            SignatureAlgorithm.RsaPssSha256 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SignatureAlgorithm.RsaPssSha384 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            SignatureAlgorithm.RsaPssSha512 => VerifyRsa(data, signature, key, HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            // ECDSA NIST
            SignatureAlgorithm.EcdsaP256Sha256 => VerifyEcdsa(data, signature, key, HashAlgorithmName.SHA256, 256),
            SignatureAlgorithm.EcdsaP384Sha384 => VerifyEcdsa(data, signature, key, HashAlgorithmName.SHA384, 384),
            SignatureAlgorithm.EcdsaP521Sha512 => VerifyEcdsa(data, signature, key, HashAlgorithmName.SHA512, 521),
            // ECDSA Blockchain
            SignatureAlgorithm.Secp256k1 => VerifySecp256k1(data, signature, key),
            // EdDSA
            SignatureAlgorithm.Ed25519 => Ed25519Core.Verify(data, signature, key),
#if NET10_0_OR_GREATER
            // ML-DSA
            SignatureAlgorithm.MLDsa44 => VerifyMLDsa(data, signature, key, 44),
            SignatureAlgorithm.MLDsa65 => VerifyMLDsa(data, signature, key, 65),
            SignatureAlgorithm.MLDsa87 => VerifyMLDsa(data, signature, key, 87),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    // HMAC
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

    // AES-CMAC
    private static byte[] SignAesCmac(byte[] data, byte[] key, int expectedKeySize)
    {
        if (key.Length != expectedKeySize)
            throw new ArgumentException($"Key must be {expectedKeySize} bytes for AES-CMAC-{expectedKeySize * 8}", nameof(key));
        var tag = new byte[16];
        AesCmacCore.ComputeTag(tag, data, key);
        return tag;
    }

    private static bool VerifyAesCmac(byte[] data, byte[] signature, byte[] key, int expectedKeySize)
    {
        if (key.Length != expectedKeySize)
            throw new ArgumentException($"Key must be {expectedKeySize} bytes for AES-CMAC-{expectedKeySize * 8}", nameof(key));
        return AesCmacCore.VerifyTag(signature, data, key);
    }

    // Poly1305
    private static byte[] SignPoly1305(byte[] data, byte[] key)
    {
        var tag = new byte[16];
        Poly1305Core.ComputeMac(tag, data, key);
        return tag;
    }

    private static bool VerifyPoly1305(byte[] data, byte[] signature, byte[] key)
    {
        return Poly1305Core.VerifyMac(signature, data, key);
    }

    // RSA
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
        catch (CryptographicException) { return false; }
    }
#else
    private static byte[] SignRsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        throw new NotSupportedException("RSA signing requires .NET 8.0 or greater.");

    private static bool VerifyRsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        throw new NotSupportedException("RSA verification requires .NET 8.0 or greater.");
#endif

    // ECDSA NIST
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
        catch (CryptographicException) { return false; }
    }
#else
    private static byte[] SignEcdsa(byte[] data, byte[] privateKey, HashAlgorithmName hashAlgorithm, int curveSizeBits) =>
        throw new NotSupportedException("ECDSA signing requires .NET 8.0 or greater.");

    private static bool VerifyEcdsa(byte[] data, byte[] signature, byte[] publicKey, HashAlgorithmName hashAlgorithm, int curveSizeBits) =>
        throw new NotSupportedException("ECDSA verification requires .NET 8.0 or greater.");
#endif

    // Secp256k1
    private static byte[] SignSecp256k1(byte[] data, byte[] privateKey)
    {
        // Secp256k1 expects a message hash (32 bytes)
#if NETSTANDARD2_0
        using var sha256 = SHA256.Create();
        var messageHash = sha256.ComputeHash(data);
#else
        var messageHash = SHA256.HashData(data);
#endif
        return Secp256k1Core.Sign(messageHash, privateKey);
    }

    private static bool VerifySecp256k1(byte[] data, byte[] signature, byte[] publicKey)
    {
        try
        {
#if NETSTANDARD2_0
            using var sha256 = SHA256.Create();
            var messageHash = sha256.ComputeHash(data);
#else
            var messageHash = SHA256.HashData(data);
#endif
            return Secp256k1Core.Verify(messageHash, signature, publicKey);
        }
        catch (CryptographicException) { return false; }
    }

    // ML-DSA
#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006
    private static byte[] SignMLDsa(byte[] data, byte[] privateKeyPem, int parameterSet)
    {
        var pem = System.Text.Encoding.UTF8.GetString(privateKeyPem);
        return parameterSet switch
        {
            44 => MLDsaCore.Sign(pem, data, securityBits: 128),
            65 => MLDsaCore.Sign(pem, data, securityBits: 192),
            87 => MLDsaCore.Sign(pem, data, securityBits: 256),
            _ => throw new ArgumentException($"Unsupported ML-DSA parameter set: {parameterSet}")
        };
    }

    private static bool VerifyMLDsa(byte[] data, byte[] signature, byte[] publicKeyPem, int parameterSet)
    {
        try
        {
            var pem = System.Text.Encoding.UTF8.GetString(publicKeyPem);
            return parameterSet switch
            {
                44 => MLDsaCore.Verify(pem, data, signature),
                65 => MLDsaCore.Verify(pem, data, signature),
                87 => MLDsaCore.Verify(pem, data, signature),
                _ => throw new ArgumentException($"Unsupported ML-DSA parameter set: {parameterSet}")
            };
        }
        catch (CryptographicException) { return false; }
    }
#pragma warning restore SYSLIB5006
#endif
}
