using System.Buffers.Binary;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Protocols.X3dh;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhEncodingTests
{
    internal static byte[] Key(byte coordinate = 9) => [coordinate, .. new byte[31]];
    internal static DoubleRatchetMessage Ratchet()
    {
        var wire = new byte[69]; wire[0] = 1; wire[1] = 9;
        return DoubleRatchetMessage.FromBytes(wire);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Packets_UseExactLayoutAndOwnAllBuffers(bool opk)
    {
        var bundle = X3dhPreKeyBundle.Create(Key(), 0x01020304, Key(10), new byte[64], opk ? 2u : null, opk ? Key(11) : null);
        var wire = bundle.ToBytes();
        Assert.Equal(opk ? 174 : 138, wire.Length);
        Assert.Equal("HCXB"u8.ToArray(), wire[..4]); Assert.Equal(1, wire[4]);
        Assert.Equal(0x01020304u, BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(37, 4)));
        Assert.Equal(opk ? 1 : 0, wire[137]);
        var original = wire.ToArray(); var parsed = X3dhPreKeyBundle.FromBytes(wire); Array.Clear(wire);
        Array.Clear(parsed.IdentityPublicKey); Array.Clear(parsed.SignedPreKeyPublicKey); Array.Clear(parsed.SignedPreKeySignature);
        if (opk) Array.Clear(parsed.OneTimePreKeyPublicKey!);
        Assert.Equal(original, parsed.ToBytes());
        var initial = X3dhInitialMessage.Create(Key(), Key(10), 0x01020304, opk ? 2u : null, Ratchet());
        var input = initial.ToBytes();
        Assert.Equal((opk ? 82 : 78) + 69, input.Length); Assert.Equal("HCXI"u8.ToArray(), input[..4]);
        Assert.Equal(69u, BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(opk ? 78 : 74, 4)));
        var saved = input.ToArray(); var copy = X3dhInitialMessage.FromBytes(input); Array.Clear(input);
        Array.Clear(copy.InitiatorIdentityPublicKey); Array.Clear(copy.EphemeralPublicKey);
        Assert.Equal(saved, copy.ToBytes());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Parse_RejectsEveryTruncationAndTrailingBytes(bool opk)
    {
        var bundle = X3dhPreKeyBundle.Create(Key(), 1, Key(10), new byte[64], opk ? 2u : null, opk ? Key(11) : null).ToBytes();
        var initial = X3dhInitialMessage.Create(Key(), Key(10), 1, opk ? 2u : null, Ratchet()).ToBytes();
        for (var i = 0; i < bundle.Length; i++) Assert.Throws<ArgumentException>(() => X3dhPreKeyBundle.FromBytes(bundle[..i]));
        for (var i = 0; i < initial.Length; i++) Assert.Throws<ArgumentException>(() => X3dhInitialMessage.FromBytes(initial[..i]));
        Assert.Throws<ArgumentException>(() => X3dhPreKeyBundle.FromBytes([.. bundle, 0]));
        Assert.Throws<ArgumentException>(() => X3dhInitialMessage.FromBytes([.. initial, 0]));
    }

    [Fact]
    public void Parse_RejectsMagicVersionFlagsIdsCoordinatesAndCounterOrLengthOverflow()
    {
        var bundle = X3dhPreKeyBundle.Create(Key(), 1, Key(10), new byte[64], null, null).ToBytes();
        foreach (var (offset, value) in new[] { (0, 0), (4, 2), (40, 0), (137, 2), (36, 128) })
        {
            var bad = bundle.ToArray(); bad[offset] = (byte)value;
            Assert.Throws<ArgumentException>(() => X3dhPreKeyBundle.FromBytes(bad));
        }
        var initial = X3dhInitialMessage.Create(Key(), Key(10), 1, null, Ratchet()).ToBytes();
        foreach (var offset in new[] { 78 + 36, 78 + 40 })
        {
            var bad = initial.ToArray(); bad[offset] = 1;
            Assert.Throws<ArgumentException>(() => X3dhInitialMessage.FromBytes(bad));
        }
        BinaryPrimitives.WriteUInt32BigEndian(initial.AsSpan(74, 4), uint.MaxValue);
        Assert.Throws<ArgumentException>(() => X3dhInitialMessage.FromBytes(initial));
        Assert.Throws<ArgumentNullException>(() => X3dhPreKeyBundle.FromBytes(null!));
    }
}
