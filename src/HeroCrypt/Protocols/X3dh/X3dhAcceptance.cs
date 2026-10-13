using HeroCrypt.Polyfills;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>Owns an accepted session and its first authenticated plaintext.</summary>
public sealed class X3dhAcceptance : IDisposable
{
#if NET9_0_OR_GREATER
    private readonly Lock sync = new();
#else
    private readonly object sync = new();
#endif
    private readonly byte[] plaintext;
    private bool disposed;
    internal X3dhAcceptance(DoubleRatchetSession session, byte[] plaintext) { Session = session; this.plaintext = plaintext; }
    /// <summary>Returns the independently owned session. Disposing this result closes it.</summary>
    public DoubleRatchetSession Session { get; }
    /// <summary>Returns a plaintext copy which the caller must clear.</summary>
    public byte[] Plaintext { get { lock (sync) { ArgumentHelper.ThrowIfDisposed(disposed, this); return plaintext.AsSpan().ToArray(); } } }
    /// <summary>Closes the session and clears owned plaintext; idempotent.</summary>
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return; disposed = true;
            try { Session.Dispose(); }
            finally { SecureMemoryOperations.SecureClear(plaintext.AsSpan()); }
        }
    }
}
