using System.Reflection;
using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Protocols.X3dh;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhPreKeyStoreTests
{
    [Fact]
    public void Publication_RotationLimitsAndRetirementPreserveSelectedKeys()
    {
        using var identity = X3dhIdentityKey.Generate();
        using var store = X3dhPreKeyStore.Create(identity, 1, 1, 2);
        var opk = store.GenerateOneTimePreKey(); Assert.Equal(1u, opk);
        var first = store.GetBundle(opk); var repeat = store.GetBundle(opk);
        Assert.Equal(first.ToBytes(), repeat.ToBytes()); Assert.Equal(1u, first.SignedPreKeyId);
        Assert.True(new XEdDsaCore().Verify([5, .. first.SignedPreKeyPublicKey], first.SignedPreKeySignature, first.IdentityPublicKey));
        Assert.Throws<InvalidOperationException>(() => store.GenerateOneTimePreKey());
        Assert.Equal(2u, store.RotateSignedPreKey());
        Assert.Throws<InvalidOperationException>(() => store.RotateSignedPreKey());
        Assert.Throws<InvalidOperationException>(() => store.RetireSignedPreKey(2));
        store.RetireSignedPreKey(1); Assert.Equal(3u, store.RotateSignedPreKey());
        Assert.Equal(first.OneTimePreKeyPublicKey, store.GetBundle(opk).OneTimePreKeyPublicKey);
    }

    [Fact]
    public void StoreOwnsIdentityAndClearsAllPrivatePrekeysAndFixedReplayBuffer()
    {
        var key = X3dhReference.Key("owned identity");
        var identity = X3dhIdentityKey.FromPrivateKey(key);
        var expected = identity.PublicKey; Array.Clear(key);
        var store = X3dhPreKeyStore.Create(identity, maxReplayEntries: 3);
        identity.Dispose(); var opk = store.GenerateOneTimePreKey();
        Assert.Equal(expected, store.GetBundle(opk).IdentityPublicKey);
        var identityBuffer = (byte[])Field(store, "identityPrivateKey");
        var replay = (byte[])Field(store, "acceptedTranscriptDigests"); Assert.Equal(96, replay.Length);
        var signed = (Dictionary<uint, X3dhPreKeyMaterial>)Field(store, "signedPreKeys");
        var oneTime = (Dictionary<uint, X3dhPreKeyMaterial>)Field(store, "oneTimePreKeys");
        var buffers = signed.Values.Concat(oneTime.Values).Select(p => p.PrivateKey).Append(identityBuffer).ToArray();
        Assert.All(buffers, b => Assert.Contains(b, value => value != 0));
        var published = store.GetBundle(opk).ToBytes();
        store.Dispose(); store.Dispose();
        Assert.All(buffers, b => Assert.All(b, value => Assert.Equal(0, value)));
        Assert.All(replay, value => Assert.Equal(0, value));
        Assert.Equal(published, X3dhPreKeyBundle.FromBytes(published).ToBytes());
        Assert.Throws<ObjectDisposedException>(() => store.GetBundle());
        Assert.Throws<ObjectDisposedException>(() => identity.PublicKey);
    }

    [Fact]
    public void CapsAndExhaustedIdentifiers_RejectWithoutMutation()
    {
        using var identity = X3dhIdentityKey.Generate();
        using var one = X3dhPreKeyStore.Create(identity, 0, 1, 1);
        Assert.Throws<InvalidOperationException>(() => one.GenerateOneTimePreKey());
        Assert.Throws<InvalidOperationException>(() => one.RotateSignedPreKey());
        foreach (var cap in new[] { 0, 33 }) Assert.Throws<ArgumentOutOfRangeException>(() => X3dhPreKeyStore.Create(identity, maxRetainedSignedPreKeys: cap));
        foreach (var cap in new[] { 0, 10001 }) Assert.Throws<ArgumentOutOfRangeException>(() => X3dhPreKeyStore.Create(identity, maxReplayEntries: cap));
        foreach (var cap in new[] { -1, 10001 }) Assert.Throws<ArgumentOutOfRangeException>(() => X3dhPreKeyStore.Create(identity, maxOneTimeKeys: cap));
        using var store = X3dhPreKeyStore.Create(identity);
        foreach (var name in new[] { "lastSignedPreKeyId", "lastOneTimePreKeyId" })
            typeof(X3dhPreKeyStore).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(store, uint.MaxValue);
        Assert.Throws<InvalidOperationException>(() => store.GenerateOneTimePreKey());
        Assert.Throws<InvalidOperationException>(() => store.RotateSignedPreKey());
        Assert.Equal(1u, store.GetBundle().SignedPreKeyId);
        Assert.Throws<SecurityPolicyException>(() => X3dhPreKeyStore.Create(identity, policy: SecurityPolicyOptions.Compliance));
    }

    [Fact]
    public async Task IdentitySnapshots_AreAtomicUnderDisposalAsync()
    {
        var original = X3dhReference.Key("identity race"); original[0] &= 248; original[31] = (byte)((original[31] & 127) | 64);
        using var identity = X3dhIdentityKey.FromPrivateKey(original);
        var tasks = Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            try { return identity.CopyPrivateKey(); }
            catch (ObjectDisposedException) { return null; }
        }, TestContext.Current.CancellationToken)).ToArray();
        identity.Dispose();
        foreach (var snapshot in await Task.WhenAll(tasks))
            if (snapshot != null) { Assert.Equal(original, snapshot); Array.Clear(snapshot); }
    }

    internal static object Field(X3dhPreKeyStore store, string name) =>
        typeof(X3dhPreKeyStore).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(store)!;
}
