using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>Owned in-memory prekeys and fixed-capacity replay storage.</summary>
/// <remarks>After restart create fresh prekeys. Do not restore old private prekeys with an empty replay cache.</remarks>
public sealed partial class X3dhPreKeyStore : IDisposable
{
#if NET9_0_OR_GREATER
    private readonly Lock sync = new();
#else
    private readonly object sync = new();
#endif
    private readonly byte[] identityPrivateKey;
    private readonly byte[] identityPublicKey;
    private readonly byte[] acceptedTranscriptDigests;
    private readonly Dictionary<uint, X3dhPreKeyMaterial> signedPreKeys = [];
    private readonly Dictionary<uint, X3dhPreKeyMaterial> oneTimePreKeys = [];
    private readonly SecurityPolicyOptions policy;
    private readonly int maxOneTimeKeys;
    private readonly int maxRetainedSignedPreKeys;
    private uint currentSignedPreKeyId;
    private uint lastSignedPreKeyId;
    private uint lastOneTimePreKeyId;
    private bool disposed;
    private X3dhPreKeyStore(byte[] identity, byte[] publicKey, byte[] replay, int maxOneTimeKeys, int maxRetainedSignedPreKeys, SecurityPolicyOptions policy)
    {
        identityPrivateKey = identity; identityPublicKey = publicKey; acceptedTranscriptDigests = replay;
        this.maxOneTimeKeys = maxOneTimeKeys; this.maxRetainedSignedPreKeys = maxRetainedSignedPreKeys; this.policy = policy;
    }
    /// <summary>Creates a store with a copied identity, fresh signed prekey and bounded capacities.</summary>
    public static X3dhPreKeyStore Create(X3dhIdentityKey identity, int maxOneTimeKeys = 1000, int maxReplayEntries = 10000,
        int maxRetainedSignedPreKeys = 4, SecurityPolicyOptions? policy = null)
    {
        ArgumentHelper.ThrowIfNull(identity);
        if (maxOneTimeKeys is < 0 or > 10000) throw new ArgumentOutOfRangeException(nameof(maxOneTimeKeys));
        if (maxReplayEntries is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(maxReplayEntries));
        if (maxRetainedSignedPreKeys is < 1 or > 32) throw new ArgumentOutOfRangeException(nameof(maxRetainedSignedPreKeys));
        var effective = policy ?? SecurityPolicy.CurrentPolicy; X3dhValidation.ValidatePolicy(effective);
        var replay = new byte[32 * maxReplayEntries]; byte[] key = []; byte[] pub = []; X3dhPreKeyStore? store = null;
        try
        {
            key = identity.CopyPrivateKey(); pub = new Curve25519Core(effective).DerivePublicKey(key);
            store = new X3dhPreKeyStore(key, pub, replay, maxOneTimeKeys, maxRetainedSignedPreKeys, effective);
            store.RotateSignedPreKey(); return store;
        }
        catch
        {
            if (store != null) store.Dispose();
            else { SecureMemoryOperations.SecureClear(key.AsSpan()); SecureMemoryOperations.SecureClear(pub.AsSpan()); SecureMemoryOperations.SecureClear(replay.AsSpan()); }
            throw;
        }
    }
    /// <summary>Generates a one-time key without publishing or consuming it.</summary>
    public uint GenerateOneTimePreKey()
    {
        lock (sync)
        {
            ThrowIfDisposed();
            if (oneTimePreKeys.Count >= maxOneTimeKeys || lastOneTimePreKeyId == uint.MaxValue) throw new InvalidOperationException("One-time prekey capacity or identifier exhausted.");
            var id = lastOneTimePreKeyId + 1; var material = GenerateMaterial(false);
            try { oneTimePreKeys.Add(id, material); }
            catch { material.Dispose(); throw; }
            lastOneTimePreKeyId = id; return id;
        }
    }
    /// <summary>Generates a fresh signed key, retaining previous keys up to the configured cap.</summary>
    public uint RotateSignedPreKey()
    {
        lock (sync)
        {
            ThrowIfDisposed();
            if (signedPreKeys.Count >= maxRetainedSignedPreKeys || lastSignedPreKeyId == uint.MaxValue) throw new InvalidOperationException("Signed prekey capacity or identifier exhausted.");
            var id = lastSignedPreKeyId + 1; var material = GenerateMaterial(true);
            try { signedPreKeys.Add(id, material); }
            catch { material.Dispose(); throw; }
            lastSignedPreKeyId = currentSignedPreKeyId = id; return id;
        }
    }
    /// <summary>Erases a retained noncurrent signed key; pending initiations for it will reject.</summary>
    public void RetireSignedPreKey(uint id)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            if (id == currentSignedPreKeyId) throw new InvalidOperationException("Cannot retire the current signed prekey.");
            if (!signedPreKeys.TryGetValue(id, out var material)) throw new CryptographicException("Signed prekey unavailable.");
            signedPreKeys.Remove(id); material.Dispose();
        }
    }
    /// <summary>Publishes a copied current bundle. A selected one-time key remains unused until acceptance.</summary>
    public X3dhPreKeyBundle GetBundle(uint? oneTimePreKeyId = null)
    {
        lock (sync)
        {
            ThrowIfDisposed(); X3dhPreKeyMaterial? oneTime = null;
            if (oneTimePreKeyId.HasValue && !oneTimePreKeys.TryGetValue(oneTimePreKeyId.Value, out oneTime)) throw new CryptographicException("One-time prekey unavailable.");
            var signed = signedPreKeys[currentSignedPreKeyId];
            return X3dhPreKeyBundle.Create(identityPublicKey, currentSignedPreKeyId, signed.PublicKey, signed.Signature, oneTimePreKeyId, oneTime?.PublicKey);
        }
    }
    private X3dhPreKeyMaterial GenerateMaterial(bool signed)
    {
        var curve = new Curve25519Core(policy); byte[] key = []; byte[] pub = []; byte[] signature = [];
        try
        {
            key = curve.GeneratePrivateKey(); pub = curve.DerivePublicKey(key);
            if (signed) signature = new XEdDsaCore(policy).Sign(X3dhEncoding.EncodePublicKey(pub), identityPrivateKey);
            return new X3dhPreKeyMaterial(key, pub, signature);
        }
        catch { SecureMemoryOperations.SecureClear(key.AsSpan()); SecureMemoryOperations.SecureClear(pub.AsSpan()); SecureMemoryOperations.SecureClear(signature.AsSpan()); throw; }
    }
    /// <summary>Clears store keys and replay buffers without closing independently owned sessions.</summary>
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return; disposed = true;
            foreach (var pair in signedPreKeys) pair.Value.Dispose();
            foreach (var pair in oneTimePreKeys) pair.Value.Dispose();
            signedPreKeys.Clear(); oneTimePreKeys.Clear();
            SecureMemoryOperations.SecureClear(identityPrivateKey.AsSpan()); SecureMemoryOperations.SecureClear(identityPublicKey.AsSpan());
            SecureMemoryOperations.SecureClear(acceptedTranscriptDigests.AsSpan());
        }
    }
    private void ThrowIfDisposed() => ArgumentHelper.ThrowIfDisposed(disposed, this);
}
