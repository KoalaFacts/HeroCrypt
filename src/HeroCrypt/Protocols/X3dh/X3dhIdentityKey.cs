using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>An owned X25519 identity for X3DH and XEdDSA; no private-key export.</summary>
public sealed class X3dhIdentityKey : IDisposable
{
#if NET9_0_OR_GREATER
    private readonly Lock sync = new();
#else
    private readonly object sync = new();
#endif
    private readonly byte[] privateKey;
    private readonly byte[] publicKey;
    private readonly SecurityPolicyOptions policy;
    private bool disposed;
    private X3dhIdentityKey(byte[] privateKey, byte[] publicKey, SecurityPolicyOptions policy)
    { this.privateKey = privateKey; this.publicKey = publicKey; this.policy = policy; }
    /// <summary>Generates a fresh identity under the captured policy.</summary>
    public static X3dhIdentityKey Generate(SecurityPolicyOptions? policy = null)
    {
        var effective = policy ?? SecurityPolicy.CurrentPolicy; X3dhValidation.ValidatePolicy(effective);
        var key = new Curve25519Core(effective).GeneratePrivateKey();
        try { return FromPrivateKey(key, effective); }
        finally { SecureMemoryOperations.SecureClear(key.AsSpan()); }
    }
    /// <summary>Copies and clamps a 32-byte X25519 private scalar, not an Ed25519 seed.</summary>
    public static X3dhIdentityKey FromPrivateKey(byte[] privateKey, SecurityPolicyOptions? policy = null)
    {
        ArgumentHelper.ThrowIfNull(privateKey);
        if (privateKey.Length != 32) throw new ArgumentException("Identity private key must be 32 bytes.", nameof(privateKey));
        var effective = policy ?? SecurityPolicy.CurrentPolicy; X3dhValidation.ValidatePolicy(effective);
        var key = privateKey.AsSpan().ToArray(); byte[] pub = [];
        try
        {
            key[0] &= 248; key[31] = (byte)((key[31] & 127) | 64);
            pub = new Curve25519Core(effective).DerivePublicKey(key);
            return new X3dhIdentityKey(key, pub, effective);
        }
        catch { SecureMemoryOperations.SecureClear(key.AsSpan()); SecureMemoryOperations.SecureClear(pub.AsSpan()); throw; }
    }
    /// <summary>Returns a copy of the identity public key.</summary>
    public byte[] PublicKey { get { lock (sync) { ThrowIfDisposed(); return publicKey.AsSpan().ToArray(); } } }
    internal byte[] CopyPrivateKey()
    {
        lock (sync) { ThrowIfDisposed(); X3dhValidation.ValidatePolicy(policy); return privateKey.AsSpan().ToArray(); }
    }
    /// <summary>Clears identity buffers; does not invalidate independent store copies.</summary>
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return; disposed = true;
            SecureMemoryOperations.SecureClear(privateKey.AsSpan()); SecureMemoryOperations.SecureClear(publicKey.AsSpan());
        }
    }
    private void ThrowIfDisposed() => ArgumentHelper.ThrowIfDisposed(disposed, this);
}
