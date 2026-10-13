using System.Buffers.Binary;
using HeroCrypt.Protocols.DoubleRatchet;

namespace HeroCrypt.Protocols.X3dh;

internal static class X3dhEncoding
{
    internal static byte[] EncodePublicKey(ReadOnlySpan<byte> key)
    {
        DoubleRatchetMessage.ValidatePublicKey(key);
        var output = new byte[33]; output[0] = 5; key.CopyTo(output.AsSpan(1)); return output;
    }
    internal static void Header(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> magic)
    {
        if (!encoded[..4].SequenceEqual(magic) || encoded[4] != 1) throw new ArgumentException("Invalid X3DH format/version.");
    }
    internal static uint Id(ReadOnlySpan<byte> encoded)
    {
        var id = BinaryPrimitives.ReadUInt32BigEndian(encoded);
        if (id == 0) throw new ArgumentException("X3DH identifiers must be nonzero.");
        return id;
    }
    internal static bool Flag(byte value) => value switch
    {
        0 => false,
        1 => true,
        _ => throw new ArgumentException("Invalid X3DH optional-key flag.")
    };
}
