using System.Buffers.Binary;
using HeroCrypt.Polyfills;
using HeroCrypt.Protocols.DoubleRatchet;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>An immutable published X3DH bundle. OPK availability is not signed.</summary>
public sealed class X3dhPreKeyBundle
{
    private readonly byte[] encoded;
    private X3dhPreKeyBundle(byte[] encoded) => this.encoded = encoded;
    /// <summary>Returns a copy of the identity public key.</summary>
    public byte[] IdentityPublicKey => encoded.AsSpan(5, 32).ToArray();
    /// <summary>Returns the signed prekey identifier.</summary>
    public uint SignedPreKeyId => BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(37, 4));
    /// <summary>Returns a copy of the signed prekey public key.</summary>
    public byte[] SignedPreKeyPublicKey => encoded.AsSpan(41, 32).ToArray();
    /// <summary>Returns a copy of the signature over the encoded signed prekey.</summary>
    public byte[] SignedPreKeySignature => encoded.AsSpan(73, 64).ToArray();
    /// <summary>Returns the optional one-time identifier.</summary>
    public uint? OneTimePreKeyId => encoded[137] == 1 ? BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(138, 4)) : null;
    /// <summary>Returns a copy of the optional one-time public key.</summary>
    public byte[]? OneTimePreKeyPublicKey => encoded[137] == 1 ? encoded.AsSpan(142, 32).ToArray() : null;
    /// <summary>Parses and copies a canonical bundle; signature authentication is separate.</summary>
    public static X3dhPreKeyBundle FromBytes(byte[] encoded)
    {
        ArgumentHelper.ThrowIfNull(encoded);
        if (encoded.Length is not (138 or 174)) throw new ArgumentException("Invalid X3DH bundle length.", nameof(encoded));
        var owned = encoded.AsSpan().ToArray();
        X3dhEncoding.Header(owned, "HCXB"u8);
        var opk = X3dhEncoding.Flag(owned[137]);
        if (owned.Length != (opk ? 174 : 138)) throw new ArgumentException("Inconsistent X3DH bundle fields.", nameof(encoded));
        DoubleRatchetMessage.ValidatePublicKey(owned.AsSpan(5, 32)); DoubleRatchetMessage.ValidatePublicKey(owned.AsSpan(41, 32));
        X3dhEncoding.Id(owned.AsSpan(37, 4));
        if (opk) { X3dhEncoding.Id(owned.AsSpan(138, 4)); DoubleRatchetMessage.ValidatePublicKey(owned.AsSpan(142, 32)); }
        return new X3dhPreKeyBundle(owned);
    }
    /// <summary>Returns an owned serialized copy.</summary>
    public byte[] ToBytes() => encoded.AsSpan().ToArray();
    internal static X3dhPreKeyBundle Create(byte[] identityPublicKey, uint signedPreKeyId, byte[] signedPreKeyPublicKey,
        byte[] signature, uint? oneTimePreKeyId, byte[]? oneTimePreKeyPublicKey)
    {
        ArgumentHelper.ThrowIfNull(identityPublicKey); ArgumentHelper.ThrowIfNull(signedPreKeyPublicKey); ArgumentHelper.ThrowIfNull(signature);
        DoubleRatchetMessage.ValidatePublicKey(identityPublicKey); DoubleRatchetMessage.ValidatePublicKey(signedPreKeyPublicKey);
        if (signature.Length != 64 || oneTimePreKeyId.HasValue != (oneTimePreKeyPublicKey != null))
            throw new ArgumentException("Invalid signature or optional-key fields.");
        var wire = new byte[oneTimePreKeyId.HasValue ? 174 : 138];
        "HCXB"u8.CopyTo(wire); wire[4] = 1; identityPublicKey.CopyTo(wire, 5);
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(37, 4), signedPreKeyId);
        signedPreKeyPublicKey.CopyTo(wire, 41); signature.CopyTo(wire, 73);
        if (oneTimePreKeyId.HasValue)
        {
            DoubleRatchetMessage.ValidatePublicKey(oneTimePreKeyPublicKey!);
            wire[137] = 1; BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(138, 4), oneTimePreKeyId.Value);
            oneTimePreKeyPublicKey!.CopyTo(wire, 142);
        }
        return FromBytes(wire);
    }
}
