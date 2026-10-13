using System.Reflection;
using System.Security.Cryptography;
using HeroCrypt.Protocols.DoubleRatchet;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace HeroCrypt.Tests.Protocols.DoubleRatchet;

[Trait("Category", TestCategories.SECURITY)]
public class DoubleRatchetKeyLifecycleTests
{
    private static readonly byte[] Shared = SHA256.HashData("lifecycle shared fixture"u8);
    private static readonly byte[] BobPrivate = SHA256.HashData("lifecycle responder fixture"u8);
    private static readonly byte[] Context = "lifecycle fixture"u8.ToArray();

    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("E0EB7A7C3B41B8AE1656E3FAF19FC46ADA098DEB9C32B1FD866205165F49B800")]
    [InlineData("5F9C95BCA3508C24B1D0B1559C83EF5B04445CC4581C8E86D8224EDDD09F1157")]
    [InlineData("ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F")]
    public void AllCanonicalLowOrderKeys_RejectInitiationAndRollBackInitialAndLaterReceives(string keyHex)
    {
        // The five canonical low-order u-coordinates (also listed by libsodium's
        // X25519 blacklist). Noncanonical representatives are rejected by parsing.
        var key = Convert.FromHexString(keyHex);
        Assert.False(BcX25519.CalculateAgreement(BobPrivate, 0, key, 0, new byte[32], 0));
        Assert.Throws<CryptographicException>(() => DoubleRatchetSession.CreateInitiator(Shared, key, Context));
        using var alice = Alice();
        using var bob = Bob();
        RejectForgedKeyAndRetry(bob, alice.Encrypt("initial"u8), key, "initial"u8.ToArray());
        alice.Decrypt(bob.Encrypt("reply"u8));
        RejectForgedKeyAndRetry(bob, alice.Encrypt("later"u8), key, "later"u8.ToArray());
    }

    [Fact]
    public void SuccessfulSend_ClearsSupersededOwnedKeyBuffers()
    {
        using var alice = Alice();
        using var bob = Bob();
        var old = State(alice);
        var buffers = Buffers(old);
        var message = alice.Encrypt("send"u8);
        Assert.NotSame(old, State(alice));
        AssertCleared(buffers);
        Assert.Equal("send"u8.ToArray(), bob.Decrypt(message));
    }

    [Fact]
    public void SuccessfulReceives_ClearSupersededKeysAcrossChainsAndSkippedConsumption()
    {
        using var alice = Alice();
        using var bob = Bob();
        var old = alice.Encrypt("late"u8);
        var current = alice.Encrypt("current"u8);
        ReceiveAndCheckCleanup(bob, current, "current"u8.ToArray());
        Assert.Single(State(bob).Skipped);
        ReceiveAndCheckCleanup(bob, old, "late"u8.ToArray());
        Assert.Empty(State(bob).Skipped);
        ReceiveAndCheckCleanup(bob, alice.Encrypt("same chain"u8), "same chain"u8.ToArray());
        alice.Decrypt(bob.Encrypt("turn"u8));
        ReceiveAndCheckCleanup(bob, alice.Encrypt("new chain"u8), "new chain"u8.ToArray());
    }

    [Fact]
    public void AuthenticationFailure_PreservesOriginalKeysCountersAndSkippedKeys()
    {
        using var alice = Alice();
        using var bob = Bob();
        var late = alice.Encrypt("late"u8);
        bob.Decrypt(alice.Encrypt("current"u8));
        alice.Decrypt(bob.Encrypt("turn"u8));
        var next = alice.Encrypt("new chain"u8);
        var before = State(bob);
        var buffers = Buffers(before);
        var copies = buffers.Select(b => b.ToArray()).ToArray();
        var counts = (before.SendCount, before.ReceiveCount, before.PreviousSendCount, before.Skipped.Count);
        var forged = next.ToBytes();
        forged[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => bob.Decrypt(DoubleRatchetMessage.FromBytes(forged)));
        Assert.Same(before, State(bob));
        for (var i = 0; i < buffers.Length; i++) Assert.Equal(copies[i], buffers[i]);
        Assert.Equal(counts, (before.SendCount, before.ReceiveCount, before.PreviousSendCount, before.Skipped.Count));
        Assert.Equal("late"u8.ToArray(), bob.Decrypt(late));
        Assert.Equal("new chain"u8.ToArray(), bob.Decrypt(next));
    }

    private static void RejectForgedKeyAndRetry(DoubleRatchetSession session, DoubleRatchetMessage original,
        byte[] key, byte[] expected)
    {
        var state = State(session);
        var modified = original.ToBytes();
        key.CopyTo(modified, 1);
        Assert.Throws<CryptographicException>(() => session.Decrypt(DoubleRatchetMessage.FromBytes(modified)));
        Assert.Same(state, State(session));
        Assert.Equal(expected, session.Decrypt(original));
    }

    private static void ReceiveAndCheckCleanup(DoubleRatchetSession session, DoubleRatchetMessage message, byte[] expected)
    {
        var old = State(session);
        var buffers = Buffers(old);
        Assert.Equal(expected, session.Decrypt(message));
        Assert.NotSame(old, State(session));
        AssertCleared(buffers);
    }

    private static void AssertCleared(byte[][] buffers)
    {
        Assert.All(buffers, b => Assert.All(b, value => Assert.Equal(0, value)));
    }

    private static byte[][] Buffers(DoubleRatchetState state)
    {
        var buffers = new[] { state.Root, state.PrivateKey, state.PublicKey, state.RemoteKey, state.SendingChain, state.ReceivingChain }
            .Where(b => b != null).Select(b => b!).Concat(state.Skipped.Values).ToArray();
        Assert.Contains(buffers, b => b.Any(value => value != 0));
        return buffers;
    }

    private static DoubleRatchetState State(DoubleRatchetSession session) =>
        (DoubleRatchetState)typeof(DoubleRatchetSession).GetField("state", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(session)!;

    private static DoubleRatchetSession Alice() =>
        DoubleRatchetSession.CreateInitiator(Shared, DoubleRatchetReferencePeer.PublicKey(BobPrivate), Context);

    private static DoubleRatchetSession Bob() => DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context);
}
