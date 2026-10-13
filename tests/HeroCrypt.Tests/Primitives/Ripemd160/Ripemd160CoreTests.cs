using System.Text;
using HeroCrypt.Primitives.Ripemd160;
using Org.BouncyCastle.Crypto.Digests;

namespace HeroCrypt.Tests.Primitives.Ripemd160;

[Trait("Category", TestCategories.COMPLIANCE)]
public class Ripemd160CoreTests
{
    [Theory]
    [InlineData("", "9c1185a5c5e9fc54612808977ee8f548b2258d31")]
    [InlineData("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")]
    [InlineData("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")]
    [InlineData("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")]
    [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b")]
    public void PublishedVectors_Match(string message, string expected)
    {
        Assert.Equal(Convert.FromHexString(expected), Ripemd160Core.Hash(Encoding.ASCII.GetBytes(message)));
    }

    [Fact]
    public void MillionAs_MatchesPublishedVector()
    {
        Assert.Equal(Convert.FromHexString("52783243c1697bdbe16d37f97f68f08325dc1528"),
            Ripemd160Core.Hash(Enumerable.Repeat((byte)'a', 1_000_000).ToArray()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(57)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(1024)]
    public void PaddingBoundaries_MatchIndependentImplementation(int length)
    {
        var message = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
        var original = message.ToArray();
        var reference = new RipeMD160Digest();
        reference.BlockUpdate(message, 0, message.Length);
        var expected = new byte[20];
        reference.DoFinal(expected, 0);
        Assert.Equal(expected, Ripemd160Core.Hash(message));
        Assert.Equal(original, message);
    }
}
