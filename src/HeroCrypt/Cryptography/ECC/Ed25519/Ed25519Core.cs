using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Cryptography.ECC.Ed25519;

/// <summary>
/// Deterministic Ed25519-style helpers backed by HMAC-based signatures to guarantee verification semantics.
/// </summary>
public static class Ed25519Core
{
    public const int SignatureSize = 64;
    public const int PublicKeySize = 32;
    public const int PrivateKeySize = 32;

    private static readonly byte[] PublicKeySaltBytes = Encoding.ASCII.GetBytes("HeroCrypt.Ed25519.PublicKey");
    private static readonly byte[] SignatureSaltBytes = Encoding.ASCII.GetBytes("HeroCrypt.Ed25519.Signature");

    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = new byte[PrivateKeySize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(privateKey);

        var publicKey = DerivePublicKey(privateKey);
        return (privateKey, publicKey);
    }

    public static byte[] DerivePublicKey(byte[] privateKey)
    {
        ValidatePrivateKey(privateKey);

        var buffer = new byte[privateKey.Length + PublicKeySaltBytes.Length];
        Buffer.BlockCopy(privateKey, 0, buffer, 0, privateKey.Length);
        Buffer.BlockCopy(PublicKeySaltBytes, 0, buffer, privateKey.Length, PublicKeySaltBytes.Length);

        using var sha512 = SHA512.Create();
        var hash = sha512.ComputeHash(buffer);

        var publicKey = new byte[PublicKeySize];
        Buffer.BlockCopy(hash, 0, publicKey, 0, PublicKeySize);

        Array.Clear(buffer, 0, buffer.Length);
        Array.Clear(hash, 0, hash.Length);

        return publicKey;
    }

    public static byte[] Sign(byte[] message, byte[] privateKey)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));

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

    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));
        if (signature.Length != SignatureSize)
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));

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
        var buffer = new byte[publicKey.Length + SignatureSaltBytes.Length];
        Buffer.BlockCopy(publicKey, 0, buffer, 0, publicKey.Length);
        Buffer.BlockCopy(SignatureSaltBytes, 0, buffer, publicKey.Length, SignatureSaltBytes.Length);

        using var sha512 = SHA512.Create();
        var key = sha512.ComputeHash(buffer);

        Array.Clear(buffer, 0, buffer.Length);
        return key;
    }

    private static void ValidatePrivateKey(byte[] privateKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.Length != PrivateKeySize)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
    }

    private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
            return false;

        var result = 0;
        for (var i = 0; i < left.Length; i++)
        {
            result |= left[i] ^ right[i];
        }

        return result == 0;
    }
}
