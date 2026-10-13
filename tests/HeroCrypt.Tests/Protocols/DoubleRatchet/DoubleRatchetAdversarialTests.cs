using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Protocols.DoubleRatchet;

namespace HeroCrypt.Tests.Protocols.DoubleRatchet;

[Trait("Category", TestCategories.COMPLIANCE)]
public class DoubleRatchetAdversarialTests
{
    private static readonly byte[] Shared = SHA256.HashData("adversarial shared fixture"u8);
    private static readonly byte[] BobPrivate = SHA256.HashData("adversarial responder fixture"u8);
    private static readonly byte[] Context = "independent transcript v1"u8.ToArray();

    [Theory]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    [InlineData(true, 2)]
    [InlineData(true, 3)]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(false, 2)]
    [InlineData(false, 3)]
    public void MultiEpochTranscript_InteroperatesWithIndependentPeerUnderHostileDelivery(bool initiator, int seed)
    {
        using var actual = initiator
            ? DoubleRatchetSession.CreateInitiator(Shared, DoubleRatchetReferencePeer.PublicKey(BobPrivate), Context, 64)
            : DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context, 64);
        var reference = new DoubleRatchetReferencePeer(Shared, BobPrivate, Context, seed, !initiator);
        if (!initiator)
        {
            var initial = reference.Encrypt("bootstrap"u8.ToArray(), []);
            Assert.Equal("bootstrap"u8.ToArray(), actual.Decrypt(DoubleRatchetMessage.FromBytes(initial)));
        }

        Packet? delayed = null;
        for (var epoch = 0; epoch < 24; epoch++)
        {
            var outbound = Enumerable.Range(0, 5).Select(i =>
            {
                var payload = Encoding.UTF8.GetBytes($"actual {seed} {epoch} {i}");
                var metadata = Encoding.UTF8.GetBytes($"metadata actual {epoch} {i}");
                return new Packet(actual.Encrypt(payload, metadata).ToBytes(), payload, metadata);
            }).ToArray();
            foreach (var packet in outbound.AsEnumerable().Reverse())
                Assert.Equal(packet.Payload, reference.Decrypt(packet.Wire, packet.Metadata));

            var inbound = Enumerable.Range(0, 5).Select(i =>
            {
                var payload = Encoding.UTF8.GetBytes($"reference {seed} {epoch} {i}");
                var metadata = Encoding.UTF8.GetBytes($"metadata reference {epoch} {i}");
                return new Packet(reference.Encrypt(payload, metadata), payload, metadata);
            }).ToArray();

            // Reject attacks before the new DH chain has been authenticated.
            var latest = inbound[^1];
            var forged = latest.Wire.ToArray();
            forged[^1] ^= 1;
            Assert.Throws<CryptographicException>(() => actual.Decrypt(DoubleRatchetMessage.FromBytes(forged), latest.Metadata));
            Assert.Throws<CryptographicException>(() => actual.Decrypt(DoubleRatchetMessage.FromBytes(latest.Wire), "wrong metadata"u8));
            for (var i = inbound.Length - 1; i >= 1; i--) Deliver(actual, inbound[i]);

            // A key cached before the DH turn must survive repeated forged uses.
            if (delayed != null)
            {
                var bad = delayed.Wire.ToArray();
                bad[^1] ^= 0x80;
                for (var attempt = 0; attempt < 3; attempt++)
                    Assert.Throws<CryptographicException>(() => actual.Decrypt(DoubleRatchetMessage.FromBytes(bad), delayed.Metadata));
                Deliver(actual, delayed);
            }
            delayed = inbound[0];
        }
        Deliver(actual, delayed!);
    }

    [Fact]
    public void EveryWireBitMutation_IsRejectedAndAllowsAuthenticRetry()
    {
        var reference = new DoubleRatchetReferencePeer(Shared, BobPrivate, Context, 17, true);
        var payload = "authenticated payload"u8.ToArray();
        var metadata = "bound metadata"u8.ToArray();
        var original = reference.Encrypt(payload, metadata);
        for (var position = 0; position < original.Length; position++)
        {
            for (var bit = 0; bit < 8; bit++)
            {
                using var responder = DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context);
                var mutated = original.ToArray();
                mutated[position] ^= (byte)(1 << bit);
                AssertRejected(responder, mutated, metadata);
                Assert.Equal(payload, responder.Decrypt(DoubleRatchetMessage.FromBytes(original), metadata));
            }
        }
    }

    [Fact]
    public void EveryTruncation_IsRejectedAndAllowsAuthenticRetry()
    {
        var reference = new DoubleRatchetReferencePeer(Shared, BobPrivate, Context, 23, true);
        var payload = "truncation payload"u8.ToArray();
        var original = reference.Encrypt(payload, []);
        for (var length = 0; length < original.Length; length++)
        {
            using var responder = DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context);
            AssertRejected(responder, original[..length], []);
            Assert.Equal(payload, responder.Decrypt(DoubleRatchetMessage.FromBytes(original)));
        }
    }

    private static void AssertRejected(DoubleRatchetSession session, byte[] wire, byte[] metadata)
    {
        var error = Record.Exception(() => session.Decrypt(DoubleRatchetMessage.FromBytes(wire), metadata));
        Assert.True(error is ArgumentException or CryptographicException,
            $"Expected parsing/authentication rejection, got {error?.GetType().Name ?? "successful decryption"}.");
    }

    private static void Deliver(DoubleRatchetSession session, Packet packet)
    {
        var message = DoubleRatchetMessage.FromBytes(packet.Wire);
        Assert.Equal(packet.Payload, session.Decrypt(message, packet.Metadata));
        Assert.Throws<CryptographicException>(() => session.Decrypt(message, packet.Metadata));
    }

    private sealed record Packet(byte[] Wire, byte[] Payload, byte[] Metadata);
}
