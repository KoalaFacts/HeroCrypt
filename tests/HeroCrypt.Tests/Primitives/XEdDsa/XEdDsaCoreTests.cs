using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace HeroCrypt.Tests.Primitives.XEdDsa;

[Trait("Category", TestCategories.COMPLIANCE)]
public class XEdDsaCoreTests
{
    [Fact]
    public void Verify_RejectsEquivalentNoncanonicalScalarAndPublicCoordinate()
    {
        var order = new BigInteger(Convert.FromHexString("EDD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010"));
        var key = new byte[32]; (5 * order - 1).ToByteArray().CopyTo(key, 0);
        var core = new XEdDsaCore(); var publicKey = core.DerivePublicKey(key);
        Assert.Equal(new byte[] { 9 }.Concat(new byte[31]), publicKey);
        var signature = core.Sign("malleability"u8, key);
        var s = new BigInteger(signature.AsSpan(32).ToArray()); var alternate = signature.ToArray();
        (s + order).ToByteArray().CopyTo(alternate, 32);
        Assert.False(core.Verify("malleability"u8, alternate, publicKey));
        var p = (BigInteger.One << 255) - 19; var noncanonical = new byte[32];
        (p + 9).ToByteArray().CopyTo(noncanonical, 0);
        Assert.False(core.Verify("malleability"u8, signature, noncanonical));
    }
    public static IEnumerable<object[]> Vectors()
    {
        using var stream = typeof(XEdDsaCoreTests).Assembly.GetManifestResourceStream("HeroCrypt.Tests.Fixtures.XEdDsa.vectors.json")!;
        using var buffer = new MemoryStream(); stream.CopyTo(buffer);
        var bytes = buffer.ToArray();
        Assert.Equal("B723C30D08E6BAFE9A1F5BF4051130ED5006F7C4B221396B4D4B002582F9FAFC", Convert.ToHexString(SHA256.HashData(bytes)));
        using var doc = JsonDocument.Parse(bytes);
        Assert.Equal(16, doc.RootElement.GetArrayLength());
        return doc.RootElement.EnumerateArray().Select(v => new object[]
        {
            v.GetProperty("private").GetString()!, v.GetProperty("clamped").GetString()!,
            v.GetProperty("message").GetString()!, v.GetProperty("randomness").GetString()!,
            v.GetProperty("public").GetString()!, v.GetProperty("signature").GetString()!
        }).ToArray();
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Sign_MatchesIndependentNormalizedVectors(string raw, string clamped, string message, string randomness,
        string publicKey, string expected)
    {
        var msg = Convert.FromHexString(message);
        var signature = new Ed25519Impl().SignXEdDsa(msg, Convert.FromHexString(clamped), Convert.FromHexString(randomness));
        Assert.Equal(Convert.FromHexString(expected), signature);
        var core = new XEdDsaCore();
        Assert.Equal(Convert.FromHexString(publicKey), core.DerivePublicKey(Convert.FromHexString(raw)));
        Assert.True(core.Verify(msg, signature, Convert.FromHexString(publicKey)));
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(ConvertPublic(Convert.FromHexString(publicKey)), 0));
        verifier.BlockUpdate(msg, 0, msg.Length);
        Assert.True(verifier.VerifySignature(signature));
        Assert.True(core.Verify(msg, core.Sign(msg, Convert.FromHexString(raw)), Convert.FromHexString(publicKey)));
    }

    [Fact]
    public void Verify_RejectsModifiedAndNoncanonicalInputs()
    {
        var core = new XEdDsaCore();
        var pair = core.GenerateKeyPair();
        var message = "prekey"u8.ToArray();
        var signature = core.Sign(message, pair.PrivateKey);
        for (var i = 0; i < signature.Length; i++)
        {
            var bad = signature.ToArray(); bad[i] ^= 1;
            Assert.False(core.Verify(message, bad, pair.PublicKey));
        }
        Assert.False(core.Verify("wrong"u8, signature, pair.PublicKey));
        var highS = signature.ToArray();
        Convert.FromHexString("EDD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010").CopyTo(highS, 32);
        Assert.False(core.Verify(message, highS, pair.PublicKey));
        var noncanonicalR = signature.ToArray();
        Convert.FromHexString("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F").CopyTo(noncanonicalR, 0);
        Assert.False(core.Verify(message, noncanonicalR, pair.PublicKey));
        foreach (var hex in new[] {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "E0EB7A7C3B41B8AE1656E3FAF19FC46ADA098DEB9C32B1FD866205165F49B800",
            "5F9C95BCA3508C24B1D0B1559C83EF5B04445CC4581C8E86D8224EDDD09F1157",
            "ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
            "EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F" })
            Assert.False(core.Verify(message, signature, Convert.FromHexString(hex)));
    }

    [Fact]
    public void PrivateScalar_IsClampedRatherThanHashedAsEd25519Seed()
    {
        var key = SHA256.HashData("identity"u8);
        Assert.NotEqual(new Ed25519Core().DerivePublicKey(key), new XEdDsaCore().DerivePublicKey(key));
        Assert.Throws<ArgumentException>(() => new XEdDsaCore().Sign([], new byte[31]));
        Assert.Throws<ArgumentException>(() => new XEdDsaCore().Verify([], new byte[63], new byte[32]));
        Assert.Throws<SecurityPolicyException>(() => new XEdDsaCore(SecurityPolicyOptions.Compliance).GenerateKeyPair());
    }

    private static byte[] ConvertPublic(byte[] key)
    {
        var p = (BigInteger.One << 255) - 19;
        var u = new BigInteger([.. key, 0]);
        var y = (u - 1) * BigInteger.ModPow(u + 1, p - 2, p) % p;
        if (y < 0) y += p;
        var output = new byte[32];
        y.ToByteArray().AsSpan(0, Math.Min(32, y.ToByteArray().Length)).CopyTo(output);
        return output;
    }
}
