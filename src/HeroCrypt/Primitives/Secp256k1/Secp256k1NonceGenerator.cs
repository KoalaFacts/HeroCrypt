using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>RFC 6979 section 3.2 deterministic HMAC-SHA256 ECDSA nonce generation.</summary>
internal sealed class Secp256k1NonceGenerator : IDisposable
{
    private byte[] key = new byte[32];
    private byte[] value = CreateInitialValue();

    internal Secp256k1NonceGenerator(byte[] privateKey, byte[] messageHash)
    {
        var reducedHash = Secp256k1Math.EncodeScalar(Secp256k1Math.ReadScalar(messageHash) % Secp256k1Math.Order);
        var seed = new byte[97];
        try
        {
            value.CopyTo(seed, 0);
            privateKey.CopyTo(seed, 33);
            reducedHash.CopyTo(seed, 65);
            Replace(ref key, Hmac(key, seed));
            Replace(ref value, Hmac(key, value));
            value.CopyTo(seed, 0);
            seed[32] = 1;
            Replace(ref key, Hmac(key, seed));
            Replace(ref value, Hmac(key, value));
        }
        finally
        {
            SecureMemoryOperations.SecureClear(reducedHash);
            SecureMemoryOperations.SecureClear(seed);
        }
    }

    internal BigInteger Next()
    {
        while (true)
        {
            Replace(ref value, Hmac(key, value));
            var candidate = Secp256k1Math.ReadScalar(value);
            if (candidate.Sign > 0 && candidate < Secp256k1Math.Order) return candidate;
            Reject();
        }
    }

    internal void Reject()
    {
        var input = new byte[33];
        try
        {
            value.CopyTo(input, 0);
            Replace(ref key, Hmac(key, input));
            Replace(ref value, Hmac(key, value));
        }
        finally
        {
            SecureMemoryOperations.SecureClear(input);
        }
    }

    public void Dispose()
    {
        SecureMemoryOperations.SecureClear(key);
        SecureMemoryOperations.SecureClear(value);
    }

    private static byte[] Hmac(byte[] hmacKey, byte[] input)
    {
        using var hmac = new HMACSHA256(hmacKey);
        return hmac.ComputeHash(input);
    }

    private static void Replace(ref byte[] destination, byte[] replacement)
    {
        SecureMemoryOperations.SecureClear(destination);
        destination = replacement;
    }

    private static byte[] CreateInitialValue()
    {
        var initial = new byte[32];
        for (var i = 0; i < initial.Length; i++) initial[i] = 1;
        return initial;
    }
}
