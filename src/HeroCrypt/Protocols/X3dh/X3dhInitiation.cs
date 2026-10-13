using HeroCrypt.Protocols.DoubleRatchet;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>Owns an initiator session and its immutable first envelope.</summary>
/// <remarks>The responder is not key-confirmed until a reply authenticates.</remarks>
public sealed class X3dhInitiation : IDisposable
{
    internal X3dhInitiation(DoubleRatchetSession session, X3dhInitialMessage initialMessage)
    { Session = session; InitialMessage = initialMessage; }
    /// <summary>Returns the owned session. Disposing this result closes it.</summary>
    public DoubleRatchetSession Session { get; }
    /// <summary>Returns the immutable initial envelope for delivery.</summary>
    public X3dhInitialMessage InitialMessage { get; }
    /// <summary>Closes the owned session; idempotent.</summary>
    public void Dispose() => Session.Dispose();
}
