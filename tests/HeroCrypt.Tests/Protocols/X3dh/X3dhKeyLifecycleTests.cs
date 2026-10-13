using System.Security.Cryptography;
using HeroCrypt.Protocols.X3dh;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhKeyLifecycleTests
{
    [Fact]
    public void SuccessfulCommit_ClearsConsumedKeyAndTransfersIndependentSession()
    {
        using var pair = new X3dhHandshakeTests.Pair(); using var init = pair.Start(true);
        var keys = (Dictionary<uint, X3dhPreKeyMaterial>)X3dhPreKeyStoreTests.Field(pair.Store, "oneTimePreKeys");
        var original = keys[init.InitialMessage.OneTimePreKeyId!.Value].PrivateKey;
        var before = original.ToArray(); var forged = init.InitialMessage.ToBytes(); forged[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => pair.Accept(X3dhInitialMessage.FromBytes(forged)));
        Assert.Equal(before, original);
        using var accepted = pair.Accept(init.InitialMessage);
        Assert.All(original, value => Assert.Equal(0, value));
        var copy = accepted.Plaintext; Array.Clear(copy); Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
        pair.Store.Dispose(); pair.Bob.Dispose(); pair.Alice.Dispose();
        Assert.Equal("survives"u8.ToArray(), accepted.Session.Decrypt(init.Session.Encrypt("survives"u8)));
        var plaintextBuffer = (byte[])typeof(X3dhAcceptance).GetField("plaintext", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(accepted)!;
        accepted.Dispose(); accepted.Dispose();
        Assert.All(plaintextBuffer, value => Assert.Equal(0, value));
        Assert.Throws<ObjectDisposedException>(() => accepted.Plaintext);
        Assert.Throws<ObjectDisposedException>(() => accepted.Session.Encrypt([]));
    }

    [Fact]
    public void FreshStoreRecovery_RejectsOldEnvelopeAcceptsFreshAndPreservesOldSession()
    {
        using var pair = new X3dhHandshakeTests.Pair(1); using var old = pair.Start(true);
        using var oldAccepted = pair.Accept(old.InitialMessage);
        using var fresh = X3dhPreKeyStore.Create(pair.Bob); var opk = fresh.GenerateOneTimePreKey();
        Assert.Throws<CryptographicException>(() => fresh.Accept(old.InitialMessage, pair.Alice.PublicKey, pair.Context, "metadata"u8));
        using var init = X3dhHandshake.Initiate(pair.Alice, fresh.GetBundle(opk), pair.Bob.PublicKey, pair.Context, "fresh"u8, "metadata"u8);
        using var accepted = fresh.Accept(init.InitialMessage, pair.Alice.PublicKey, pair.Context, "metadata"u8);
        Assert.Equal("fresh"u8.ToArray(), accepted.Plaintext);
        pair.Store.Dispose();
        Assert.Equal("old session"u8.ToArray(), oldAccepted.Session.Decrypt(old.Session.Encrypt("old session"u8)));
    }
}
