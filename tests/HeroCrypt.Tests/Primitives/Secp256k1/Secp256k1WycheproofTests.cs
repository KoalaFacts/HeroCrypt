using System.Security.Cryptography;
using System.Text.Json;
using HeroCrypt.Primitives.Secp256k1;

namespace HeroCrypt.Tests.Primitives.Secp256k1;

[Trait("Category", TestCategories.COMPLIANCE)]
public class Secp256k1WycheproofTests
{
    private const string FixtureHash = "7A339EFC7134FB2495CD32AFDBD692E0F86427D3C24E9073F6A7D858BB8788D2";

    public static IEnumerable<object[]> Vectors()
    {
        using var stream = typeof(Secp256k1WycheproofTests).Assembly.GetManifestResourceStream(
            "HeroCrypt.Tests.Fixtures.Wycheproof.ecdsa_secp256k1_sha256_p1363_test.json")!;
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        var bytes = buffer.ToArray();
        Assert.Equal(FixtureHash, Convert.ToHexString(SHA256.HashData(bytes)));
        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;
        Assert.Equal(252, root.GetProperty("numberOfTests").GetInt32());
        var valid = 0;
        var invalid = 0;
        var cases = new List<object[]>();
        foreach (var group in root.GetProperty("testGroups").EnumerateArray())
        {
            Assert.Equal("SHA-256", group.GetProperty("sha").GetString());
            var key = group.GetProperty("publicKey").GetProperty("uncompressed").GetString()!;
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                var result = test.GetProperty("result").GetString();
                Assert.True(result is "valid" or "invalid", "Unexpected upstream result classification.");
                if (result == "valid") valid++; else invalid++;
                cases.Add([test.GetProperty("tcId").GetInt32(), key,
                    test.GetProperty("msg").GetString()!, test.GetProperty("sig").GetString()!, result == "valid"]);
            }
        }
        Assert.Equal(167, valid);
        Assert.Equal(85, invalid);
        return cases;
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Verify_MatchesPinnedWycheproofCorpus(int caseId, string keyHex, string messageHex,
        string signatureHex, bool expected)
    {
        var core = new Secp256k1Core();
        var hash = SHA256.HashData(Convert.FromHexString(messageHex));
        var signature = Convert.FromHexString(signatureHex);
        var publicKey = Convert.FromHexString(keyHex);
        foreach (var key in new[] { publicKey, core.CompressPublicKey(publicKey) })
        {
            if (signature.Length != 64)
            {
                Assert.False(expected, $"Valid vector {caseId} has a malformed signature length.");
                Assert.Throws<ArgumentException>(() => core.Verify(hash, signature, key));
            }
            else
            {
                Assert.True(core.Verify(hash, signature, key) == expected, $"Wycheproof case {caseId} failed.");
            }
        }
    }
}
