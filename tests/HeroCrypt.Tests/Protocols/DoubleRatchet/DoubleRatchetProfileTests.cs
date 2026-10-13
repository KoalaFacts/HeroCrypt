using System.Buffers.Binary;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Protocols.DoubleRatchet;

[Trait("Category", TestCategories.COMPLIANCE)]
public class DoubleRatchetProfileTests
{
    [Fact]
    public void RootKdf_MatchesIndependentHkdfSha256Vector()
    {
        var root = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var dh = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
        var result = DoubleRatchetKdf.Root(root, dh, SecurityPolicyOptions.Default);
        Assert.Equal(Convert.FromHexString("e8ce1895c00643ccf2c12c9658287e06d11fbdd03bc106d5f9dde6d256404309"), result.Root);
        Assert.Equal(Convert.FromHexString("b796643289d74c313f993bf27c03d43561a35badbac8ed7c4fb97fe2f8235d54"), result.Chain);
    }

    [Fact]
    public void ChainKdf_MatchesIndependentHmacSha256Vector()
    {
        var input = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var result = DoubleRatchetKdf.Chain(input);
        Assert.Equal(Convert.FromHexString("9b4c8120a4823a95f47cde17a244f4507244ee6e3957d1fab9fa29b44d3829b7"), result.Message);
        Assert.Equal(Convert.FromHexString("4304c22c84a53755ab08ead8d97a8d429be5efa480682d7ad1da27f73e1fbe1d"), result.Next);
        Assert.Equal(Enumerable.Range(0, 32).Select(i => (byte)i), input);
    }

    [Fact]
    public void WireFormat_UsesCanonicalHeaderAndOwnsInputAndOutput()
    {
        var input = Encoded();
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(33, 4), 0x01020304);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(37, 4), 0x05060708);
        var original = input.ToArray();
        var message = DoubleRatchetMessage.FromBytes(input);
        input[0] = 0;
        Assert.Equal(original, message.ToBytes());
        Assert.Equal(0x01020304u, message.PreviousChainLength);
        Assert.Equal(0x05060708u, message.MessageNumber);
        Assert.Equal(original.AsSpan(1, 32).ToArray(), message.RatchetPublicKey);
        Assert.Equal(original.AsSpan(41, 12).ToArray(), message.Nonce);
        Assert.Equal(original.AsSpan(53).ToArray(), message.Ciphertext);
        var copy = message.ToBytes();
        copy[0] = 0;
        var publicKey = message.RatchetPublicKey;
        publicKey[0] = 0;
        Assert.Equal(original, message.ToBytes());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(52)]
    [InlineData(53)]
    [InlineData(68)]
    public void Parse_RejectsShortHeaderOrMissingTag(int size)
    {
        Assert.Throws<ArgumentException>(() => DoubleRatchetMessage.FromBytes(new byte[size]));
    }

    [Fact]
    public void Parse_RejectsUnknownVersionAndNoncanonicalKeys()
    {
        Assert.Throws<ArgumentNullException>(() => DoubleRatchetMessage.FromBytes(null!));
        var input = Encoded();
        input[0] = 2;
        Assert.Throws<ArgumentException>(() => DoubleRatchetMessage.FromBytes(input));
        input = Encoded();
        input[32] = 0x80;
        Assert.Throws<ArgumentException>(() => DoubleRatchetMessage.FromBytes(input));
        input = Encoded();
        Convert.FromHexString("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F").CopyTo(input, 1);
        Assert.Throws<ArgumentException>(() => DoubleRatchetMessage.FromBytes(input));
    }

    [Fact]
    public void Parse_RejectsOversizedPayload()
    {
        var input = new byte[53 + 16 + 16 * 1024 * 1024 + 1];
        input[0] = 1;
        input[1] = 9;
        Assert.Throws<ArgumentException>(() => DoubleRatchetMessage.FromBytes(input));
    }

    internal static byte[] Encoded()
    {
        var input = new byte[69];
        input[0] = 1;
        input[1] = 9;
        for (var i = 41; i < input.Length; i++) input[i] = (byte)i;
        return input;
    }
}
