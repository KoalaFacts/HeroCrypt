using System.Security.Cryptography;
using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Protocols.X3dh;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhAdversarialTests
{
    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("E0EB7A7C3B41B8AE1656E3FAF19FC46ADA098DEB9C32B1FD866205165F49B800")]
    [InlineData("5F9C95BCA3508C24B1D0B1559C83EF5B04445CC4581C8E86D8224EDDD09F1157")]
    [InlineData("ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F")]
    public void LowOrderPrekeysEphemeralAndRatchetContributions_RejectWithoutOpkConsumption(string hex)
    {
        using var pair = new X3dhHandshakeTests.Pair(); var opk = pair.Store.GenerateOneTimePreKey();
        var bundle = pair.Store.GetBundle(opk); var low = Convert.FromHexString(hex);
        var identity = pair.Bob.CopyPrivateKey();
        try
        {
            var malicious = X3dhPreKeyBundle.Create(bundle.IdentityPublicKey, bundle.SignedPreKeyId, low,
                new XEdDsaCore().Sign([5, .. low], identity), opk, bundle.OneTimePreKeyPublicKey);
            Assert.Throws<CryptographicException>(() => pair.StartBundle(malicious));
        }
        finally { CryptographicOperations.ZeroMemory(identity); }
        var badOpk = X3dhPreKeyBundle.Create(bundle.IdentityPublicKey, bundle.SignedPreKeyId, bundle.SignedPreKeyPublicKey,
            bundle.SignedPreKeySignature, opk, low);
        Assert.Throws<CryptographicException>(() => pair.StartBundle(badOpk));
        using var init = pair.StartBundle(bundle);
        foreach (var offset in new[] { 37, 82 + 1 })
        {
            var wire = init.InitialMessage.ToBytes(); low.CopyTo(wire, offset);
            Assert.Throws<CryptographicException>(() => pair.Accept(X3dhInitialMessage.FromBytes(wire)));
        }
        using var accepted = pair.Accept(init.InitialMessage); Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
    }

    [Fact]
    public void ExpectedResponderMismatchRejectsAndCapturedPolicySurvivesAmbientChange()
    {
        using var pair = new X3dhHandshakeTests.Pair(); var opk = pair.Store.GenerateOneTimePreKey();
        var bundle = pair.Store.GetBundle(opk);
        Assert.Throws<CryptographicException>(() => X3dhHandshake.Initiate(pair.Alice, bundle, pair.Alice.PublicKey, pair.Context, []));
        using var init = pair.StartBundle(bundle);
        using (SecurityPolicy.ComplianceScope())
        {
            using var accepted = pair.Accept(init.InitialMessage); Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
        }
    }

    [Fact]
    public void EveryInitialByteMutation_IsRejectedAndOriginalStillConsumesSameOpk()
    {
        using var pair = new X3dhHandshakeTests.Pair();
        var length = 0;
        for (var position = 0; position == 0 || position < length; position++)
        {
            using var init = pair.Start(true); var original = init.InitialMessage.ToBytes(); length = original.Length;
            var bad = original.ToArray(); bad[position] ^= 1;
            var error = Record.Exception(() =>
            {
                using var result = pair.Accept(X3dhInitialMessage.FromBytes(bad));
            });
            Assert.True(error is ArgumentException or CryptographicException, $"Accepted mutation at {position}.");
            using var valid = pair.Accept(init.InitialMessage); Assert.Equal("hello"u8.ToArray(), valid.Plaintext);
        }
    }

    [Fact]
    public void WrongIdentityContextMetadataAndDowngrade_DoNotConsumeKeysOrReplaySlots()
    {
        using var pair = new X3dhHandshakeTests.Pair(1); using var init = pair.Start(true);
        var first = init.InitialMessage; var opk = first.OneTimePreKeyId;
        Assert.Throws<CryptographicException>(() => pair.Store.Accept(first, pair.Bob.PublicKey, pair.Context, "metadata"u8));
        Assert.Throws<CryptographicException>(() => pair.Store.Accept(first, pair.Alice.PublicKey, "wrong"u8.ToArray(), "metadata"u8));
        Assert.Throws<CryptographicException>(() => pair.Store.Accept(first, pair.Alice.PublicKey, pair.Context, "wrong"u8));
        var wire = first.ToBytes(); var dropped = new byte[wire.Length - 4];
        wire.AsSpan(0, 74).CopyTo(dropped); dropped[73] = 0; wire.AsSpan(78).CopyTo(dropped.AsSpan(74));
        Assert.Throws<CryptographicException>(() => pair.Accept(X3dhInitialMessage.FromBytes(dropped)));
        var low = first.ToBytes(); Array.Clear(low, 37, 32);
        Assert.Throws<CryptographicException>(() => pair.Accept(X3dhInitialMessage.FromBytes(low)));
        Assert.Equal(opk, pair.Store.GetBundle(opk).OneTimePreKeyId);
        using var accepted = pair.Accept(first); Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
        Assert.Throws<CryptographicException>(() => pair.Store.GetBundle(opk));
    }

    [Fact]
    public void ReplayWithChangedCiphertext_RejectsWithoutEvictingOrGrowingCache()
    {
        using var pair = new X3dhHandshakeTests.Pair(1); using var init = pair.Start(false);
        var buffer = (byte[])X3dhPreKeyStoreTests.Field(pair.Store, "acceptedTranscriptDigests");
        using var accepted = pair.Accept(init.InitialMessage);
        var bad = init.InitialMessage.ToBytes(); bad[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => pair.Accept(X3dhInitialMessage.FromBytes(bad)));
        using var next = pair.Start(true);
        Assert.Throws<InvalidOperationException>(() => pair.Accept(next.InitialMessage));
        Assert.Equal(next.InitialMessage.OneTimePreKeyId, pair.Store.GetBundle(next.InitialMessage.OneTimePreKeyId).OneTimePreKeyId);
        Assert.Same(buffer, X3dhPreKeyStoreTests.Field(pair.Store, "acceptedTranscriptDigests"));
        Assert.Equal(1, (int)X3dhPreKeyStoreTests.Field(pair.Store, "acceptedHandshakeCount"));
    }
}
