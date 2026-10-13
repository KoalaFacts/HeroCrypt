using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>
/// Managed SEC 2 secp256k1 key and RFC 6979 deterministic ECDSA operations.
/// </summary>
/// <remarks>Uses variable-time System.Numerics.BigInteger arithmetic. This implementation
/// is not qualified against local timing/cache side channels, and BigInteger secret
/// storage cannot be reliably zeroized. Byte buffers are cleared where owned.</remarks>
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

        var scalar = Secp256k1Math.ReadScalar(privateKey);
        return Secp256k1Math.Encode(Secp256k1Math.Multiply(Secp256k1Math.Generator, scalar), compressed);
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

        var scalar = Secp256k1Math.ReadScalar(privateKey);
        var hash = Secp256k1Math.ReadScalar(messageHash);
        var order = Secp256k1Math.Order;
        using var nonces = new Secp256k1NonceGenerator(privateKey, messageHash);
        while (true)
        {
            var nonce = nonces.Next();
            var point = Secp256k1Math.ToAffine(Secp256k1Math.Multiply(Secp256k1Math.Generator, nonce));
            var r = point.X % order;
            var s = Secp256k1Math.Mod(BigInteger.ModPow(nonce, order - 2, order) * (hash + r * scalar), order);
            if (r.IsZero || s.IsZero)
            {
                nonces.Reject();
                continue;
            }

            // Preserve Bitcoin-style low-S normalization and compact r || s encoding.
            if (s > order / 2) s = order - s;
            var signature = new byte[SIGNATURE_SIZE];
            Secp256k1Math.EncodeScalar(r).CopyTo(signature, 0);
            Secp256k1Math.EncodeScalar(s).CopyTo(signature, 32);
            return signature;
        }
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

        var point = Secp256k1Math.Decode(publicKey);
        var r = Secp256k1Math.ReadScalar(signature.AsSpan(0, 32));
        var s = Secp256k1Math.ReadScalar(signature.AsSpan(32, 32));
        var order = Secp256k1Math.Order;
        if (r.Sign <= 0 || s.Sign <= 0 || r >= order || s >= order) return false;
        var inverse = BigInteger.ModPow(s, order - 2, order);
        var u1 = Secp256k1Math.Mod(Secp256k1Math.ReadScalar(messageHash) * inverse, order);
        var u2 = Secp256k1Math.Mod(r * inverse, order);
        var result = Secp256k1Math.ToAffine(Secp256k1Math.Add(
            Secp256k1Math.Multiply(Secp256k1Math.Generator, u1), Secp256k1Math.Multiply(point, u2)));
        return !result.IsInfinity && result.X % order == r;
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

        return Secp256k1Math.Encode(Secp256k1Math.Decode(uncompressedKey), compressed: true);
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

        return Secp256k1Math.Encode(Secp256k1Math.Decode(compressedKey), compressed: false);
    }

    private static bool IsValidPrivateKey(byte[] privateKey)
    {
        var scalar = Secp256k1Math.ReadScalar(privateKey);
        return scalar.Sign > 0 && scalar < Secp256k1Math.Order;
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

}
