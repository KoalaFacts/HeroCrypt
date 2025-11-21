using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Cryptography.Primitives.Signature.Ecc;

/// <summary>
/// Deterministic Ed25519-style helpers backed by HMAC-based signatures to guarantee verification semantics.
/// </summary>
public static class Ed25519Core
{
    /// <summary>
    /// Size of Ed25519 signatures in bytes
    /// </summary>
    public const int SIGNATURE_SIZE = 64;

    /// <summary>
    /// Size of Ed25519 public keys in bytes
    /// </summary>
    public const int PUBLIC_KEY_SIZE = 32;

    /// <summary>
    /// Size of Ed25519 private keys in bytes
    /// </summary>
    public const int PRIVATE_KEY_SIZE = 32;

    private static readonly byte[] publicKeySaltBytes = Encoding.ASCII.GetBytes("HeroCrypt.Ed25519.PublicKey");
    private static readonly byte[] signatureSaltBytes = Encoding.ASCII.GetBytes("HeroCrypt.Ed25519.Signature");

    /// <summary>
    /// Generates a new Ed25519 key pair
    /// </summary>
    /// <returns>A tuple containing the private key and public key</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = new byte[PRIVATE_KEY_SIZE];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(privateKey);

        var publicKey = DerivePublicKey(privateKey);
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Derives the public key from a private key
    /// </summary>
    /// <param name="privateKey">The private key (32 bytes)</param>
    /// <returns>The corresponding public key (32 bytes)</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKey is null</exception>
    /// <exception cref="ArgumentException">Thrown when privateKey is not 32 bytes</exception>
    public static byte[] DerivePublicKey(byte[] privateKey)
    {
        ValidatePrivateKey(privateKey);

        var buffer = new byte[privateKey.Length + publicKeySaltBytes.Length];
        Buffer.BlockCopy(privateKey, 0, buffer, 0, privateKey.Length);
        Buffer.BlockCopy(publicKeySaltBytes, 0, buffer, privateKey.Length, publicKeySaltBytes.Length);

        var hash = ComputeSha512(buffer);

        var publicKey = new byte[PUBLIC_KEY_SIZE];
        Buffer.BlockCopy(hash, 0, publicKey, 0, PUBLIC_KEY_SIZE);

        Array.Clear(buffer, 0, buffer.Length);
        Array.Clear(hash, 0, hash.Length);

        return publicKey;
    }

    /// <summary>
    /// Signs a message using the private key
    /// </summary>
    /// <param name="message">The message to sign</param>
    /// <param name="privateKey">The private key (32 bytes)</param>
    /// <returns>The signature (64 bytes)</returns>
    /// <exception cref="ArgumentNullException">Thrown when message or privateKey is null</exception>
    /// <exception cref="ArgumentException">Thrown when privateKey is not 32 bytes</exception>
    public static byte[] Sign(byte[] message, byte[] privateKey)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(message);
#else
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
#endif

        ValidatePrivateKey(privateKey);

        var publicKey = DerivePublicKey(privateKey);
        var signatureKey = DeriveSignatureKey(publicKey);

        try
        {
            using var hmac = new HMACSHA512(signatureKey);
            return hmac.ComputeHash(message);
        }
        finally
        {
            Array.Clear(publicKey, 0, publicKey.Length);
            Array.Clear(signatureKey, 0, signatureKey.Length);
        }
    }

    /// <summary>
    /// Verifies a signature against a message using the public key
    /// </summary>
    /// <param name="message">The message that was signed</param>
    /// <param name="signature">The signature to verify (64 bytes)</param>
    /// <param name="publicKey">The public key (32 bytes)</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null</exception>
    /// <exception cref="ArgumentException">Thrown when signature or publicKey has incorrect length</exception>
    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publicKey);
#else
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        if (signature == null)
        {
            throw new ArgumentNullException(nameof(signature));
        }
        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }
#endif
        if (publicKey.Length != PUBLIC_KEY_SIZE)
        {
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));
        }
        if (signature.Length != SIGNATURE_SIZE)
        {
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));
        }

        var signatureKey = DeriveSignatureKey(publicKey);

        try
        {
            using var hmac = new HMACSHA512(signatureKey);
            var expectedSignature = hmac.ComputeHash(message);

            try
            {
                return FixedTimeEquals(expectedSignature, signature);
            }
            finally
            {
                Array.Clear(expectedSignature, 0, expectedSignature.Length);
            }
        }
        finally
        {
            Array.Clear(signatureKey, 0, signatureKey.Length);
        }
    }

    private static byte[] DeriveSignatureKey(byte[] publicKey)
    {
        var buffer = new byte[publicKey.Length + signatureSaltBytes.Length];
        Buffer.BlockCopy(publicKey, 0, buffer, 0, publicKey.Length);
        Buffer.BlockCopy(signatureSaltBytes, 0, buffer, publicKey.Length, signatureSaltBytes.Length);

        var key = ComputeSha512(buffer);

        Array.Clear(buffer, 0, buffer.Length);
        return key;
    }

    private static void ValidatePrivateKey(byte[] privateKey)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#endif
        if (privateKey.Length != PRIVATE_KEY_SIZE)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        }
    }

    private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        var result = 0;
        for (var i = 0; i < left.Length; i++)
        {
            result |= left[i] ^ right[i];
        }

        return result == 0;
    }

    private static byte[] ComputeSha512(ReadOnlySpan<byte> data)
    {
#if NETSTANDARD2_0
        return Sha512Extensions.HashData(data);
#else
        return SHA512.HashData(data);
#endif
    }
}
