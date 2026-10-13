using System.Buffers.Binary;
using HeroCrypt.Polyfills;
using HeroCrypt.Protocols.DoubleRatchet;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>An immutable X3DH envelope containing ratchet message zero.</summary>
public sealed class X3dhInitialMessage
{
    private readonly byte[] encoded;

    private X3dhInitialMessage(byte[] encoded, DoubleRatchetMessage message) { this.encoded = encoded; RatchetMessage = message; }
    /// <summary>Returns a copy of the initiator identity key.</summary>
    public byte[] InitiatorIdentityPublicKey => encoded.AsSpan(5, 32).ToArray();
    /// <summary>Returns a copy of the initiator ephemeral key.</summary>
    public byte[] EphemeralPublicKey => encoded.AsSpan(37, 32).ToArray();
    /// <summary>Returns the selected signed-key identifier.</summary>
    public uint SignedPreKeyId => BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(69, 4));
    /// <summary>Returns the selected optional one-time identifier.</summary>
    public uint? OneTimePreKeyId => encoded[73] == 1 ? BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(74, 4)) : null;
    /// <summary>Returns the immutable nested ratchet message zero.</summary>
    public DoubleRatchetMessage RatchetMessage { get; }
    /// <summary>Parses/copies an envelope with zero initial counters and bounded exact lengths.</summary>
    public static X3dhInitialMessage FromBytes(byte[] encoded)
    {
        ArgumentHelper.ThrowIfNull(encoded);
        if (encoded.Length < 147 || encoded.Length > 82 + 69 + 16 * 1024 * 1024)
            throw new ArgumentException("Invalid X3DH initial message size.", nameof(encoded));
        var owned = encoded.AsSpan().ToArray();
        X3dhEncoding.Header(owned, "HCXI"u8); var opk = X3dhEncoding.Flag(owned[73]);
        var offset = opk ? 82 : 78;
        var length = BinaryPrimitives.ReadUInt32BigEndian(owned.AsSpan(offset - 4, 4));
        if (length != (uint)(owned.Length - offset)) throw new ArgumentException("Invalid nested message length.", nameof(encoded));
        DoubleRatchetMessage.ValidatePublicKey(owned.AsSpan(5, 32)); DoubleRatchetMessage.ValidatePublicKey(owned.AsSpan(37, 32));
        X3dhEncoding.Id(owned.AsSpan(69, 4)); if (opk) X3dhEncoding.Id(owned.AsSpan(74, 4));
        var nested = DoubleRatchetMessage.FromBytes(owned.AsSpan(offset).ToArray());
        if (nested.MessageNumber != 0 || nested.PreviousChainLength != 0) throw new ArgumentException("An X3DH initial must contain ratchet message zero.", nameof(encoded));
        return new X3dhInitialMessage(owned, nested);
    }
    /// <summary>Returns an owned serialized copy.</summary>
    public byte[] ToBytes() => encoded.AsSpan().ToArray();
    internal static X3dhInitialMessage Create(byte[] identityPublicKey, byte[] ephemeralPublicKey, uint signedPreKeyId,
        uint? oneTimePreKeyId, DoubleRatchetMessage ratchetMessage)
    {
        ArgumentHelper.ThrowIfNull(identityPublicKey); ArgumentHelper.ThrowIfNull(ephemeralPublicKey); ArgumentHelper.ThrowIfNull(ratchetMessage);
        DoubleRatchetMessage.ValidatePublicKey(identityPublicKey); DoubleRatchetMessage.ValidatePublicKey(ephemeralPublicKey);
        var nested = ratchetMessage.ToBytes(); var offset = oneTimePreKeyId.HasValue ? 82 : 78;
        var wire = new byte[offset + nested.Length]; "HCXI"u8.CopyTo(wire); wire[4] = 1;
        identityPublicKey.CopyTo(wire, 5); ephemeralPublicKey.CopyTo(wire, 37);
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(69, 4), signedPreKeyId);
        if (oneTimePreKeyId.HasValue) { wire[73] = 1; BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(74, 4), oneTimePreKeyId.Value); }
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(offset - 4, 4), (uint)nested.Length); nested.CopyTo(wire, offset);
        return FromBytes(wire);
    }
}
