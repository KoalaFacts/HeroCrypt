using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.XEdDsa;

/// <summary>Normalized-sign-bit XEdDSA signatures using X25519 private scalars.</summary>
public sealed class XEdDsaBuilder : IDisposable
{
    private readonly XEdDsaCore core;
    private byte[]? privateKey;
    private byte[]? publicKey;
    private byte[]? message;
    private byte[]? signature;
    private bool disposed;

    private XEdDsaBuilder(SecurityPolicyOptions? policy = null)
    {
        core = new XEdDsaCore(policy);
    }

    /// <summary>Creates a builder.</summary>
    public static XEdDsaBuilder Create() => new();
    /// <summary>Creates a builder with an explicit policy.</summary>
    public static XEdDsaBuilder Create(SecurityPolicyOptions policy)
    {
        ArgumentHelper.ThrowIfNull(policy); return new(policy);
    }
    /// <summary>Copies a private scalar.</summary>
    public XEdDsaBuilder WithPrivateKey(byte[] key) { ArgumentHelper.ThrowIfNull(key); return WithPrivateKey(key.AsSpan()); }
    /// <summary>Copies a private scalar.</summary>
    public XEdDsaBuilder WithPrivateKey(ReadOnlySpan<byte> key) { Set(ref privateKey, key, 32); return this; }
    /// <summary>Copies a public key.</summary>
    public XEdDsaBuilder WithPublicKey(byte[] key) { ArgumentHelper.ThrowIfNull(key); return WithPublicKey(key.AsSpan()); }
    /// <summary>Copies a 32-byte X25519 public key.</summary>
    public XEdDsaBuilder WithPublicKey(ReadOnlySpan<byte> key) { Set(ref publicKey, key, 32); return this; }
    /// <summary>Copies a message, including an empty message.</summary>
    public XEdDsaBuilder WithMessage(byte[] message) { ArgumentHelper.ThrowIfNull(message); return WithMessage(message.AsSpan()); }
    /// <summary>Copies a message, including an empty message.</summary>
    public XEdDsaBuilder WithMessage(ReadOnlySpan<byte> message) { Set(ref this.message, message, 0); return this; }
    /// <summary>Copies a signature.</summary>
    public XEdDsaBuilder WithSignature(byte[] signature) { ArgumentHelper.ThrowIfNull(signature); return WithSignature(signature.AsSpan()); }
    /// <summary>Copies a 64-byte signature.</summary>
    public XEdDsaBuilder WithSignature(ReadOnlySpan<byte> signature) { Set(ref this.signature, signature, 64); return this; }
    /// <summary>Generates a key pair owned by the caller.</summary>
    public (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair() { ThrowIfDisposed(); return core.GenerateKeyPair(); }
    /// <summary>Derives the public key.</summary>
    public byte[] DerivePublicKey() { ThrowIfDisposed(); return core.DerivePublicKey(Required(privateKey)); }
    /// <summary>Signs the configured message.</summary>
    public byte[] Sign() { ThrowIfDisposed(); return core.Sign(Required(message), Required(privateKey)); }
    /// <summary>Verifies the configured signature.</summary>
    public bool Verify() { ThrowIfDisposed(); return core.Verify(Required(message), Required(signature), Required(publicKey)); }
    /// <summary>Clears owned buffers.</summary>
    public void Dispose()
    {
        if (disposed) return; disposed = true;
        Clear(privateKey); Clear(publicKey); Clear(message); Clear(signature);
        privateKey = publicKey = message = signature = null;
    }

    private void Set(ref byte[]? target, ReadOnlySpan<byte> value, int size)
    {
        ThrowIfDisposed();
        if (size != 0 && value.Length != size) throw new ArgumentException($"Input must be {size} bytes.", nameof(value));
        var copy = value.ToArray(); Clear(target); target = copy;
    }

    private static byte[] Required(byte[]? value) => value ?? throw new InvalidOperationException("Required input has not been set.");
    private static void Clear(byte[]? value) { if (value != null) SecureMemoryOperations.SecureClear(value.AsSpan()); }
    private void ThrowIfDisposed() => ArgumentHelper.ThrowIfDisposed(disposed, this);
}
