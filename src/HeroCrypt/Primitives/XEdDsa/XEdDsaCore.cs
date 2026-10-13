using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.XEdDsa;

internal sealed class XEdDsaCore(SecurityPolicyOptions? policy = null)
{
    private readonly SecurityPolicyOptions policy = policy ?? SecurityPolicy.CurrentPolicy;
    internal (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair()
    {
        ValidatePolicy();
        var curve = new Curve25519Core(policy);
        var key = curve.GeneratePrivateKey();
        try { return (key, curve.DerivePublicKey(key)); }
        catch { SecureMemoryOperations.SecureClear(key.AsSpan()); throw; }
    }

    internal byte[] DerivePublicKey(byte[] privateKey)
    {
        ValidatePolicy();
        ArgumentHelper.ThrowIfNull(privateKey);
        return new Curve25519Core(policy).DerivePublicKey(privateKey);
    }

    internal byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        ValidatePolicy();
        if (privateKey.Length != 32) throw new ArgumentException("XEdDSA private key must be 32 bytes.", nameof(privateKey));
        byte[] key = [];
        byte[] randomness = [];
        try
        {
            key = privateKey.ToArray(); randomness = new byte[64];
            key[0] &= 248; key[31] = (byte)((key[31] & 127) | 64);
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomness);
            return new Ed25519Impl().SignXEdDsa(message, key, randomness);
        }
        finally { SecureMemoryOperations.SecureClear(key.AsSpan()); SecureMemoryOperations.SecureClear(randomness.AsSpan()); }
    }

    internal bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        ValidatePolicy();
        if (signature.Length != 64 || publicKey.Length != 32)
            throw new ArgumentException("XEdDSA requires a 64-byte signature and 32-byte public key.");
        return new Ed25519Impl().VerifyXEdDsa(message, signature, publicKey);
    }

    private void ValidatePolicy()
    {
        policy.ValidateSignature("XEDDSA"); policy.ValidateKeyAgreement("X25519"); policy.ValidateHash("SHA512");
    }
}
