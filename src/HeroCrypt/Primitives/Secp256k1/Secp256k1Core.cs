using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>
/// secp256k1 key and ECDSA operations backed by Bouncy Castle's curve implementation.
/// </summary>
internal sealed class Secp256k1Core
{
    /// <summary>The size of a secp256k1 private key in bytes.</summary>
    public const int PRIVATE_KEY_SIZE = 32;
    /// <summary>The size of an uncompressed secp256k1 public key in bytes.</summary>
    public const int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
    /// <summary>The size of a compressed secp256k1 public key in bytes.</summary>
    public const int COMPRESSED_PUBLIC_KEY_SIZE = 33;
    /// <summary>The size of a compact ECDSA signature in bytes.</summary>
    public const int SIGNATURE_SIZE = 64;

    private static readonly ECDomainParameters Domain = CreateDomain();
    private readonly SecurityPolicyOptions policy;

    /// <summary>Creates secp256k1 operations under the specified security policy.</summary>
    /// <param name="policy">The policy to enforce, or the current policy when omitted.</param>
    public Secp256k1Core(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
    }

    /// <summary>Generates a private key and its uncompressed public key.</summary>
    /// <returns>A secp256k1 key pair.</returns>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        policy.ValidateSignature("SECP256K1");
        using var rng = RandomNumberGenerator.Create();
        var privateKey = new byte[PRIVATE_KEY_SIZE];
        do
        {
            rng.GetBytes(privateKey);
        } while (!IsValidPrivateKey(privateKey));

        return (privateKey, DerivePublicKey(privateKey));
    }

    /// <summary>Derives a public key from a valid private key.</summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <param name="compressed">Whether to return the compressed encoding.</param>
    /// <returns>The encoded public key.</returns>
    public byte[] DerivePublicKey(byte[] privateKey, bool compressed = false)
    {
        policy.ValidateSignature("SECP256K1");
        ValidatePrivateKey(privateKey);

        var scalar = new BcBigInteger(1, privateKey);
        return Domain.G.Multiply(scalar).Normalize().GetEncoded(compressed);
    }

    /// <summary>Signs a 32-byte message hash with deterministic ECDSA and low-S normalization.</summary>
    /// <param name="messageHash">The hash to sign.</param>
    /// <param name="privateKey">The signing private key.</param>
    /// <returns>The 64-byte r-and-s signature.</returns>
    public byte[] Sign(byte[] messageHash, byte[] privateKey)
    {
        policy.ValidateSignature("SECP256K1");
        ValidateMessageHash(messageHash);
        ValidatePrivateKey(privateKey);

        var scalar = new BcBigInteger(1, privateKey);
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, new ECPrivateKeyParameters(scalar, Domain));
        var components = signer.GenerateSignature(messageHash);
        var r = components[0];
        var s = components[1];

        // Bitcoin-style low-S normalization also avoids a second encoding for the same signature.
        if (s.CompareTo(Domain.N.ShiftRight(1)) > 0)
        {
            s = Domain.N.Subtract(s);
        }

        var signature = new byte[SIGNATURE_SIZE];
        WriteScalar(r, signature, 0);
        WriteScalar(s, signature, 32);
        return signature;
    }

    /// <summary>Verifies a compact ECDSA signature against a public key.</summary>
    /// <param name="messageHash">The 32-byte signed hash.</param>
    /// <param name="signature">The 64-byte r-and-s signature.</param>
    /// <param name="publicKey">The compressed or uncompressed public key.</param>
    /// <returns>True when the signature is valid.</returns>
    public bool Verify(byte[] messageHash, byte[] signature, byte[] publicKey)
    {
        policy.ValidateSignature("SECP256K1");
        ValidateMessageHash(messageHash);
        ArgumentHelper.ThrowIfNull(signature);
        if (signature.Length != SIGNATURE_SIZE)
        {
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));
        }
        ValidatePublicKeyLength(publicKey);

        var point = Domain.Curve.DecodePoint(publicKey);
        var verifier = new ECDsaSigner();
        verifier.Init(false, new ECPublicKeyParameters(point, Domain));
        var r = new BcBigInteger(1, signature.AsSpan(0, 32).ToArray());
        var s = new BcBigInteger(1, signature.AsSpan(32, 32).ToArray());
        return verifier.VerifySignature(messageHash, r, s);
    }

    /// <summary>Converts an uncompressed public key to compressed form.</summary>
    /// <param name="uncompressedKey">The uncompressed public key.</param>
    /// <returns>The compressed public key.</returns>
    public byte[] CompressPublicKey(byte[] uncompressedKey)
    {
        ArgumentHelper.ThrowIfNull(uncompressedKey);
        if (uncompressedKey.Length != UNCOMPRESSED_PUBLIC_KEY_SIZE || uncompressedKey[0] != 0x04)
        {
            throw new ArgumentException("Invalid uncompressed public key", nameof(uncompressedKey));
        }

        return Domain.Curve.DecodePoint(uncompressedKey).GetEncoded(true);
    }

    /// <summary>Converts a compressed public key to uncompressed form.</summary>
    /// <param name="compressedKey">The compressed public key.</param>
    /// <returns>The uncompressed public key.</returns>
    public byte[] DecompressPublicKey(byte[] compressedKey)
    {
        ArgumentHelper.ThrowIfNull(compressedKey);
        if (compressedKey.Length != COMPRESSED_PUBLIC_KEY_SIZE || compressedKey[0] is not 0x02 and not 0x03)
        {
            throw new ArgumentException("Invalid compressed public key", nameof(compressedKey));
        }

        return Domain.Curve.DecodePoint(compressedKey).GetEncoded(false);
    }

    private static ECDomainParameters CreateDomain()
    {
        var parameters = SecNamedCurves.GetByName("secp256k1")
            ?? throw new InvalidOperationException("The secp256k1 curve is unavailable.");
        return new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H);
    }

    private static bool IsValidPrivateKey(byte[] privateKey)
    {
        var scalar = new BcBigInteger(1, privateKey);
        return scalar.SignValue > 0 && scalar.CompareTo(Domain.N) < 0;
    }

    private static void ValidatePrivateKey(byte[] privateKey)
    {
        ArgumentHelper.ThrowIfNull(privateKey);
        if (privateKey.Length != PRIVATE_KEY_SIZE)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        }
        if (!IsValidPrivateKey(privateKey))
        {
            throw new ArgumentException("Invalid private key", nameof(privateKey));
        }
    }

    private static void ValidateMessageHash(byte[] messageHash)
    {
        ArgumentHelper.ThrowIfNull(messageHash);
        if (messageHash.Length != 32)
        {
            throw new ArgumentException("Message hash must be 32 bytes", nameof(messageHash));
        }
    }

    private static void ValidatePublicKeyLength(byte[] publicKey)
    {
        ArgumentHelper.ThrowIfNull(publicKey);
        if (publicKey.Length is not COMPRESSED_PUBLIC_KEY_SIZE and not UNCOMPRESSED_PUBLIC_KEY_SIZE)
        {
            throw new ArgumentException("Public key must be 33 or 65 bytes", nameof(publicKey));
        }
    }

    private static void WriteScalar(BcBigInteger value, byte[] destination, int offset)
    {
        var bytes = value.ToByteArrayUnsigned();
        if (bytes.Length > 32)
        {
            throw new CryptographicException("ECDSA produced an invalid scalar.");
        }

        Array.Copy(bytes, 0, destination, offset + 32 - bytes.Length, bytes.Length);
    }
}
