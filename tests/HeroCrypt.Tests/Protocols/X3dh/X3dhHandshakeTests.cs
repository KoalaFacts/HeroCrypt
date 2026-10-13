using System.Security.Cryptography;
using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Protocols.X3dh;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhHandshakeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ThreeAndFourDh_AuthenticateThenExchangeMultiEpochTraffic(bool opk)
    {
        using var pair = new Pair();
        using var first = pair.Start(opk, []);
        var signed = (Dictionary<uint, X3dhPreKeyMaterial>)X3dhPreKeyStoreTests.Field(pair.Store, "signedPreKeys");
        var oneTime = (Dictionary<uint, X3dhPreKeyMaterial>)X3dhPreKeyStoreTests.Field(pair.Store, "oneTimePreKeys");
        var privateKey = pair.Bob.CopyPrivateKey();
        try
        {
            Assert.Empty(X3dhReference.DecryptInitial(first.InitialMessage.ToBytes(), privateKey,
                signed[first.InitialMessage.SignedPreKeyId].PrivateKey,
                opk ? oneTime[first.InitialMessage.OneTimePreKeyId!.Value].PrivateKey : null, pair.Context, "metadata"u8.ToArray()));
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        using var accepted = pair.Accept(first.InitialMessage);
        Assert.Empty(accepted.Plaintext);
        for (var turn = 0; turn < 12; turn++)
        {
            var message = first.Session.Encrypt([(byte)turn]);
            Assert.Equal(new byte[] { (byte)turn }, accepted.Session.Decrypt(message));
            Assert.Equal(new byte[] { (byte)turn }, first.Session.Decrypt(accepted.Session.Encrypt([(byte)turn])));
        }
        Assert.Throws<CryptographicException>(() => pair.Accept(first.InitialMessage));
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(4096, X3dhValidation.MaxMetadata)]
    public void MaximumPayloadAndContextEndpoints_RoundTrip(int contextLength, int metadataLength)
    {
        using var alice = X3dhIdentityKey.Generate();
        using var bob = X3dhIdentityKey.Generate();
        using var store = X3dhPreKeyStore.Create(bob);
        var context = new byte[contextLength];
        var metadata = new byte[metadataLength];
        var plaintext = new byte[X3dhValidation.MaxPayload];
        context[^1] = 1;
        plaintext[0] = 23; plaintext[^1] = 42;
        if (metadataLength != 0) metadata[^1] = 7;
        using var first = X3dhHandshake.Initiate(alice, store.GetBundle(store.GenerateOneTimePreKey()),
            bob.PublicKey, context, plaintext, metadata);
        var parsed = X3dhInitialMessage.FromBytes(first.InitialMessage.ToBytes());
        using var accepted = store.Accept(parsed, alice.PublicKey, context, metadata);
        Assert.Equal(plaintext, accepted.Plaintext);
        Assert.Equal(new byte[] { 9 }, first.Session.Decrypt(accepted.Session.Encrypt([9])));
    }

    [Fact]
    public void InvalidBundleSignatureAndDirectoryOpkWithholding_AreDistinguished()
    {
        using var pair = new Pair(); var opk = pair.Store.GenerateOneTimePreKey();
        var bundle = pair.Store.GetBundle(opk); var bad = bundle.ToBytes(); bad[73] ^= 1;
        Assert.Throws<CryptographicException>(() => pair.StartBundle(X3dhPreKeyBundle.FromBytes(bad)));
        var stripped = bundle.ToBytes()[..138]; stripped[137] = 0;
        var threeDh = X3dhPreKeyBundle.FromBytes(stripped);
        Assert.True(new XEdDsaCore().Verify([5, .. threeDh.SignedPreKeyPublicKey], threeDh.SignedPreKeySignature, threeDh.IdentityPublicKey));
        using var first = pair.StartBundle(threeDh); using var accepted = pair.Accept(first.InitialMessage);
        Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
        Assert.Equal(opk, pair.Store.GetBundle(opk).OneTimePreKeyId);
    }

    [Fact]
    public void DelayedHandshake_UsesRetainedSignedKeyAndRetirementPreservesOpk()
    {
        using var pair = new Pair(); using var pending = pair.Start(true);
        pair.Store.RotateSignedPreKey(); using var accepted = pair.Accept(pending.InitialMessage);
        Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
        using var retired = pair.Start(true); var oldId = retired.InitialMessage.SignedPreKeyId;
        pair.Store.RotateSignedPreKey(); pair.Store.RetireSignedPreKey(oldId);
        Assert.Throws<CryptographicException>(() => pair.Accept(retired.InitialMessage));
        Assert.Equal(retired.InitialMessage.OneTimePreKeyId, pair.Store.GetBundle(retired.InitialMessage.OneTimePreKeyId).OneTimePreKeyId);
    }

    internal sealed class Pair : IDisposable
    {
        internal readonly X3dhIdentityKey Alice = X3dhIdentityKey.Generate();
        internal readonly X3dhIdentityKey Bob = X3dhIdentityKey.Generate();
        internal readonly X3dhPreKeyStore Store;
        internal readonly byte[] Context = "expected account pair / application"u8.ToArray();
        internal Pair(int replayCap = 10000) { Store = X3dhPreKeyStore.Create(Bob, 1, replayCap); }
        internal X3dhInitiation Start(bool opk, byte[]? plaintext = null) =>
            StartBundle(Store.GetBundle(opk ? Store.GenerateOneTimePreKey() : null), plaintext);
        internal X3dhInitiation StartBundle(X3dhPreKeyBundle bundle, byte[]? plaintext = null) =>
            X3dhHandshake.Initiate(Alice, bundle, Bob.PublicKey, Context, plaintext ?? "hello"u8.ToArray(), "metadata"u8);
        internal X3dhAcceptance Accept(X3dhInitialMessage initial) => Store.Accept(initial, Alice.PublicKey, Context, "metadata"u8);
        public void Dispose() { Store.Dispose(); Alice.Dispose(); Bob.Dispose(); }
    }
}
