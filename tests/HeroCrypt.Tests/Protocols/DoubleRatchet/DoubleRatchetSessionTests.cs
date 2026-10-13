using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using BcCipher = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace HeroCrypt.Tests.Protocols.DoubleRatchet;

[Trait("Category", TestCategories.SECURITY)]
public class DoubleRatchetSessionTests
{
    private static readonly byte[] Shared = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("Alice|Bob|test-profile");
    private static readonly byte[] BobPrivate = Convert.FromHexString("77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A");

    [Fact]
    public void Session_AlternatingMessagesAdvanceBothDhRatchets()
    {
        using var pair = new Pair();
        byte[]? previousAliceKey = null;
        for (var turn = 0; turn < 12; turn++)
        {
            var request = pair.Alice.Encrypt(Encoding.UTF8.GetBytes($"request {turn}"));
            Assert.Equal($"request {turn}", Encoding.UTF8.GetString(pair.Bob.Decrypt(request)));
            Assert.Equal(0u, request.MessageNumber);
            if (previousAliceKey != null) Assert.NotEqual(previousAliceKey, request.RatchetPublicKey);
            previousAliceKey = request.RatchetPublicKey;
            var response = pair.Bob.Encrypt(Encoding.UTF8.GetBytes($"response {turn}"));
            Assert.Equal($"response {turn}", Encoding.UTF8.GetString(pair.Alice.Decrypt(response)));
        }
    }

    [Fact]
    public void Responder_CannotSendBeforeFirstAuthenticatedMessage()
    {
        using var pair = new Pair();
        Assert.Throws<InvalidOperationException>(() => pair.Bob.Encrypt("too early"u8));
        Assert.Equal("ready"u8.ToArray(), pair.Bob.Decrypt(pair.Alice.Encrypt("ready"u8)));
        Assert.Equal("reply"u8.ToArray(), pair.Alice.Decrypt(pair.Bob.Encrypt("reply"u8)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(257)]
    public void PayloadsAndAssociatedData_RoundTrip(int size)
    {
        using var pair = new Pair();
        var payload = Enumerable.Range(0, size).Select(i => (byte)i).ToArray();
        var message = pair.Alice.Encrypt(payload, "metadata"u8);
        Assert.Equal(payload, pair.Bob.Decrypt(DoubleRatchetMessage.FromBytes(message.ToBytes()), "metadata"u8));
    }

    [Fact]
    public void ReorderedMessagesAcrossDhTurns_RetainOldKeysAndRejectReplay()
    {
        using var pair = new Pair();
        var old = Enumerable.Range(0, 3).Select(i => pair.Alice.Encrypt([(byte)i])).ToArray();
        Assert.Equal(new byte[] { 2 }, pair.Bob.Decrypt(old[2]));
        pair.Alice.Decrypt(pair.Bob.Encrypt("turn"u8));
        var first = pair.Alice.Encrypt("new zero"u8);
        var second = pair.Alice.Encrypt("new one"u8);
        Assert.Equal(3u, second.PreviousChainLength);
        Assert.Equal("new one"u8.ToArray(), pair.Bob.Decrypt(second));
        Assert.Equal(new byte[] { 0 }, pair.Bob.Decrypt(old[0]));
        Assert.Equal("new zero"u8.ToArray(), pair.Bob.Decrypt(first));
        Assert.Equal(new byte[] { 1 }, pair.Bob.Decrypt(old[1]));
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(old[0]));
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(first));
    }

    [Fact]
    public void PreviousChainLength_SavesMissingOldMessagesOnDhChange()
    {
        using var pair = new Pair();
        var oldFirst = pair.Alice.Encrypt("old first"u8);
        var oldLate = pair.Alice.Encrypt("old late"u8);
        pair.Bob.Decrypt(oldFirst);
        pair.Alice.Decrypt(pair.Bob.Encrypt("turn"u8));
        Assert.Equal("new chain"u8.ToArray(), pair.Bob.Decrypt(pair.Alice.Encrypt("new chain"u8)));
        Assert.Equal("old late"u8.ToArray(), pair.Bob.Decrypt(oldLate));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(36)]
    [InlineData(40)]
    [InlineData(41)]
    [InlineData(53)]
    [InlineData(69)]
    public void Tampering_IsRejectedWithoutChangingSession(int position)
    {
        using var pair = new Pair();
        var original = pair.Alice.Encrypt("authenticated payload"u8);
        var modified = original.ToBytes();
        modified[position] ^= 1;
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(DoubleRatchetMessage.FromBytes(modified)));
        Assert.Equal("authenticated payload"u8.ToArray(), pair.Bob.Decrypt(original));
    }

    [Fact]
    public void BadSkippedMessage_DoesNotConsumeItsKey()
    {
        using var pair = new Pair();
        var first = pair.Alice.Encrypt("delayed"u8, "metadata"u8);
        pair.Bob.Decrypt(pair.Alice.Encrypt("latest"u8));
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(first, "wrong"u8));
        Assert.Equal("delayed"u8.ToArray(), pair.Bob.Decrypt(first, "metadata"u8));
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(first, "metadata"u8));
    }

    [Fact]
    public void WrongContextOrSharedSecret_CannotAuthenticate()
    {
        using var pair = new Pair();
        var message = pair.Alice.Encrypt("secret"u8);
        using var wrongContext = DoubleRatchetSession.CreateResponder(Shared, BobPrivate, "different"u8.ToArray());
        using var wrongSecret = DoubleRatchetSession.CreateResponder(new byte[32], BobPrivate, Context);
        Assert.Throws<CryptographicException>(() => wrongContext.Decrypt(message));
        Assert.Throws<CryptographicException>(() => wrongSecret.Decrypt(message));
        Assert.Equal("secret"u8.ToArray(), pair.Bob.Decrypt(message));
    }

    [Fact]
    public void SkippedKeyBudget_IsGlobalAcrossChainsAndFailureIsTransactional()
    {
        using var pair = new Pair(2);
        var old = Enumerable.Range(0, 3).Select(i => pair.Alice.Encrypt([(byte)i])).ToArray();
        pair.Bob.Decrypt(old[2]);
        pair.Alice.Decrypt(pair.Bob.Encrypt("turn"u8));
        var nextFirst = pair.Alice.Encrypt("new zero"u8);
        var nextSecond = pair.Alice.Encrypt("new one"u8);
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(nextSecond));
        Assert.Equal(new byte[] { 0 }, pair.Bob.Decrypt(old[0]));
        Assert.Equal("new one"u8.ToArray(), pair.Bob.Decrypt(nextSecond));
        Assert.Equal(new byte[] { 1 }, pair.Bob.Decrypt(old[1]));
        Assert.Equal("new zero"u8.ToArray(), pair.Bob.Decrypt(nextFirst));
    }

    [Fact]
    public void ZeroSkipBudget_OnlyAcceptsOrderedMessages()
    {
        using var pair = new Pair(0);
        var first = pair.Alice.Encrypt("first"u8);
        var second = pair.Alice.Encrypt("second"u8);
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(second));
        Assert.Equal("first"u8.ToArray(), pair.Bob.Decrypt(first));
        Assert.Equal("second"u8.ToArray(), pair.Bob.Decrypt(second));
    }

    [Theory]
    [InlineData(33)]
    [InlineData(37)]
    public void ForgedHugeCounters_AreRejectedBeforeChangingState(int counterOffset)
    {
        using var pair = new Pair();
        var original = pair.Alice.Encrypt("original"u8);
        var modified = original.ToBytes();
        BinaryPrimitives.WriteUInt32BigEndian(modified.AsSpan(counterOffset, 4), uint.MaxValue);
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(DoubleRatchetMessage.FromBytes(modified)));
        Assert.Equal("original"u8.ToArray(), pair.Bob.Decrypt(original));
    }

    [Fact]
    public void LaterDhForgery_RollsBackBothOldAndNewChainSkipping()
    {
        using var pair = new Pair();
        var old = Enumerable.Range(0, 4).Select(i => pair.Alice.Encrypt([(byte)i])).ToArray();
        pair.Bob.Decrypt(old[1]); // Nr=2, with old message 0 already cached.
        pair.Alice.Decrypt(pair.Bob.Encrypt("turn"u8));
        var newFirst = pair.Alice.Encrypt("new zero"u8);
        var newSecond = pair.Alice.Encrypt("new one"u8);
        foreach (var offset in new[] { 33, 37 })
        {
            var farAhead = newSecond.ToBytes();
            BinaryPrimitives.WriteUInt32BigEndian(farAhead.AsSpan(offset, 4), uint.MaxValue);
            Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(DoubleRatchetMessage.FromBytes(farAhead)));
        }
        var badTag = newSecond.ToBytes();
        badTag[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(DoubleRatchetMessage.FromBytes(badTag)));
        Assert.Equal(new byte[] { 0 }, pair.Bob.Decrypt(old[0]));
        Assert.Equal("new one"u8.ToArray(), pair.Bob.Decrypt(newSecond));
        Assert.Equal(new byte[] { 2 }, pair.Bob.Decrypt(old[2]));
        Assert.Equal(new byte[] { 3 }, pair.Bob.Decrypt(old[3]));
        Assert.Equal("new zero"u8.ToArray(), pair.Bob.Decrypt(newFirst));
    }

    [Fact]
    public void FinalCounterValue_ReceivesSafelyAndResetsOnNextDhTurn()
    {
        using var pair = new Pair();
        pair.Bob.Decrypt(pair.Alice.Encrypt("first"u8));
        var field = typeof(DoubleRatchetSession).GetField("state", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var aliceState = (DoubleRatchetState)field.GetValue(pair.Alice)!;
        var bobState = (DoubleRatchetState)field.GetValue(pair.Bob)!;
        // Inject near-exhaustion counters into already aligned chains, without billions of test iterations.
        aliceState.SendCount = uint.MaxValue - 1;
        bobState.ReceiveCount = uint.MaxValue - 1;
        var last = pair.Alice.Encrypt("last"u8);
        Assert.Equal(uint.MaxValue - 1, last.MessageNumber);
        Assert.Equal("last"u8.ToArray(), pair.Bob.Decrypt(last));
        Assert.Throws<InvalidOperationException>(() => pair.Alice.Encrypt("exhausted"u8));
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(last));
        pair.Alice.Decrypt(pair.Bob.Encrypt("new DH"u8));
        var next = pair.Alice.Encrypt("new chain"u8);
        Assert.Equal(uint.MaxValue, next.PreviousChainLength);
        Assert.Equal(0u, next.MessageNumber);
        Assert.Equal("new chain"u8.ToArray(), pair.Bob.Decrypt(next));
    }

    [Fact]
    public void ExhaustedSendCounter_DoesNotWrapOrChangeState()
    {
        using var pair = new Pair();
        var field = typeof(DoubleRatchetSession).GetField("state", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var state = (DoubleRatchetState)field.GetValue(pair.Alice)!;
        state.SendCount = uint.MaxValue;
        Assert.Throws<InvalidOperationException>(() => pair.Alice.Encrypt("exhausted"u8));
        Assert.Equal(uint.MaxValue, ((DoubleRatchetState)field.GetValue(pair.Alice)!).SendCount);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void LowOrderPeerKeys_AreRejected(int coordinate)
    {
        var key = new byte[32];
        key[0] = (byte)coordinate;
        Assert.Throws<CryptographicException>(() => DoubleRatchetSession.CreateInitiator(Shared, key, Context));
        using var pair = new Pair();
        var original = pair.Alice.Encrypt("original"u8);
        var modified = original.ToBytes();
        key.CopyTo(modified, 1);
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(DoubleRatchetMessage.FromBytes(modified)));
        Assert.Equal("original"u8.ToArray(), pair.Bob.Decrypt(original));
    }

    [Fact]
    public void Factories_RejectInvalidConfiguration()
    {
        var publicKey = new Curve25519Core().DerivePublicKey(BobPrivate);
        Assert.Throws<ArgumentNullException>(() => DoubleRatchetSession.CreateInitiator(null!, publicKey, Context));
        Assert.Throws<ArgumentNullException>(() => DoubleRatchetSession.CreateResponder(Shared, null!, Context));
        Assert.Throws<ArgumentNullException>(() => DoubleRatchetSession.CreateResponder(Shared, BobPrivate, null!));
        foreach (var size in new[] { 0, 31, 33 })
        {
            Assert.Throws<ArgumentException>(() => DoubleRatchetSession.CreateInitiator(new byte[size], publicKey, Context));
            Assert.Throws<ArgumentException>(() => DoubleRatchetSession.CreateResponder(Shared, new byte[size], Context));
        }
        foreach (var size in new[] { 0, 4097 })
            Assert.Throws<ArgumentException>(() => DoubleRatchetSession.CreateResponder(Shared, BobPrivate, new byte[size]));
        foreach (var budget in new[] { -1, 10001 })
            Assert.Throws<ArgumentOutOfRangeException>(() => DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context, budget));
        var noncanonical = publicKey.ToArray();
        noncanonical[31] |= 128;
        Assert.Throws<ArgumentException>(() => DoubleRatchetSession.CreateInitiator(Shared, noncanonical, Context));
    }

    [Fact]
    public void Creation_CopiesKeysAndContextAndDisposalIsIdempotent()
    {
        var shared = Shared.ToArray();
        var privateKey = BobPrivate.ToArray();
        var context = Context.ToArray();
        using var bob = DoubleRatchetSession.CreateResponder(shared, privateKey, context);
        using var alice = DoubleRatchetSession.CreateInitiator(Shared, new Curve25519Core().DerivePublicKey(BobPrivate), Context);
        Array.Clear(shared); Array.Clear(privateKey); Array.Clear(context);
        Assert.Equal("owned buffers"u8.ToArray(), bob.Decrypt(alice.Encrypt("owned buffers"u8)));
        bob.Dispose(); bob.Dispose();
        Assert.Throws<ObjectDisposedException>(() => bob.Encrypt("closed"u8));
        Assert.Throws<ObjectDisposedException>(() => bob.Decrypt(alice.Encrypt("closed"u8)));
        Assert.Equal(Shared, Enumerable.Range(1, 32).Select(i => (byte)i));
    }

    [Fact]
    public void ExplicitPolicy_IsCapturedAndComplianceRejectsProfile()
    {
        Assert.Throws<SecurityPolicyException>(() => DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context,
            policy: SecurityPolicyOptions.Compliance));
        using var pair = new Pair();
        using (SecurityPolicy.ComplianceScope())
            Assert.Equal("captured"u8.ToArray(), pair.Bob.Decrypt(pair.Alice.Encrypt("captured"u8)));
    }

    [Fact]
    public void OversizedPayloadAndMetadata_AreRejectedWithoutAdvancingSendChain()
    {
        using var pair = new Pair();
        var oversized = new byte[16 * 1024 * 1024 + 1];
        Assert.Throws<ArgumentException>(() => pair.Alice.Encrypt(oversized));
        Assert.Throws<ArgumentException>(() => pair.Alice.Encrypt("small"u8, oversized));
        var first = pair.Alice.Encrypt("first"u8);
        Assert.Equal(0u, first.MessageNumber);
        Assert.Equal("first"u8.ToArray(), pair.Bob.Decrypt(first));
    }

    [Fact]
    public async Task ConcurrentSendAndReceive_UseDistinctSingleUseKeysAsync()
    {
        using var pair = new Pair();
        var messages = await Task.WhenAll(Enumerable.Range(0, 32).Select(i => Task.Run(() => pair.Alice.Encrypt([(byte)i]))));
        Assert.Equal(32, messages.Select(m => m.MessageNumber).Distinct().Count());
        var decrypted = await Task.WhenAll(messages.AsEnumerable().Reverse().Select(m => Task.Run(() => pair.Bob.Decrypt(m))));
        Assert.Equal(Enumerable.Range(0, 32).Select(i => (byte)i), decrypted.Select(d => d[0]).Order());
        Assert.Throws<CryptographicException>(() => pair.Bob.Decrypt(messages[0]));
    }

    [Fact]
    public async Task ConcurrentDisposal_LeavesCompletedMessagesValidAsync()
    {
        using var pair = new Pair();
        var first = pair.Alice.Encrypt("first"u8);
        var start = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var sends = Enumerable.Range(0, 32).Select(i => Task.Run(async () =>
        {
            await start.Task;
            try { return pair.Alice.Encrypt([(byte)i]); }
            catch (ObjectDisposedException) { return null; }
        }, TestContext.Current.CancellationToken)).ToArray();
        var dispose = Task.Run(async () => { await start.Task; pair.Alice.Dispose(); }, TestContext.Current.CancellationToken);
        start.SetResult(true);
        var completed = await Task.WhenAll(sends);
        await dispose;
        var messages = completed.OfType<DoubleRatchetMessage>().Prepend(first).OrderBy(m => m.MessageNumber).ToArray();
        Assert.Equal(messages.Length, messages.Select(m => m.MessageNumber).Distinct().Count());
        foreach (var message in messages) Assert.NotEmpty(pair.Bob.Decrypt(message));
        Assert.Throws<ObjectDisposedException>(() => pair.Alice.Encrypt("closed"u8));
    }

    [Fact]
    public void InitialMessage_InteroperatesWithIndependentPrimitiveComposition()
    {
        using var pair = new Pair();
        var ownMessage = pair.Alice.Encrypt("independent sender"u8, "metadata"u8);
        Assert.Equal("independent sender"u8.ToArray(), ReferenceDecrypt(ownMessage, "metadata"u8.ToArray()));
        using var responder = DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context);
        var reference = ReferenceEncrypt("independent receiver"u8.ToArray());
        Assert.Equal("independent receiver"u8.ToArray(), responder.Decrypt(reference));
    }

    [Fact]
    public void DhTransitions_InteroperateWithIndependentReferencePeer()
    {
        using var bob = DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context);
        var first = ReferenceEncrypt("first"u8.ToArray());
        bob.Decrypt(first);
        var reply = bob.Encrypt("independent reply"u8);
        var root1 = ReferenceRoot(Shared, BobPrivate, first.RatchetPublicKey);
        var aliceInitial = Convert.FromHexString("5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB");
        var root2 = ReferenceRoot(root1.AsSpan(0, 32).ToArray(), aliceInitial, reply.RatchetPublicKey);
        using var replyHmac = new HMACSHA256(root2.AsSpan(32, 32).ToArray());
        var replyCipher = new BcCipher();
        replyCipher.Init(false, new AeadParameters(new KeyParameter(replyHmac.ComputeHash([1])), 128,
            reply.Nonce, ReferenceAd(reply.ToBytes().AsSpan(0, 53).ToArray(), [])));
        var decrypted = new byte[replyCipher.GetOutputSize(reply.Ciphertext.Length)];
        var length = replyCipher.ProcessBytes(reply.Ciphertext, 0, reply.Ciphertext.Length, decrypted, 0);
        replyCipher.DoFinal(decrypted, length);
        Assert.Equal("independent reply"u8.ToArray(), decrypted);

        var aliceNext = SHA256.HashData("independent next Alice DH key"u8);
        var publicKey = new byte[32];
        BcX25519.GeneratePublicKey(aliceNext, 0, publicKey, 0);
        var root3 = ReferenceRoot(root2.AsSpan(0, 32).ToArray(), aliceNext, reply.RatchetPublicKey);
        using var requestHmac = new HMACSHA256(root3.AsSpan(32, 32).ToArray());
        var payload = "independent new DH turn"u8.ToArray();
        var encoded = new byte[53 + payload.Length + 16];
        encoded[0] = 1;
        publicKey.CopyTo(encoded, 1);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(33, 4), 1);
        var requestCipher = new BcCipher();
        requestCipher.Init(true, new AeadParameters(new KeyParameter(requestHmac.ComputeHash([1])), 128,
            new byte[12], ReferenceAd(encoded.AsSpan(0, 53).ToArray(), [])));
        length = requestCipher.ProcessBytes(payload, 0, payload.Length, encoded, 53);
        requestCipher.DoFinal(encoded, 53 + length);
        Assert.Equal(payload, bob.Decrypt(DoubleRatchetMessage.FromBytes(encoded)));
    }

    [Fact]
    public void Disposal_ClearsOwnedStateIncludingSkippedKeys()
    {
        using var pair = new Pair();
        pair.Alice.Encrypt("old"u8);
        pair.Bob.Decrypt(pair.Alice.Encrypt("latest"u8));
        var field = typeof(DoubleRatchetSession).GetField("state", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var state = (DoubleRatchetState)field.GetValue(pair.Bob)!;
        var owned = new List<byte[]> { state.Root, state.PrivateKey, state.SendingChain!, state.ReceivingChain! };
        owned.AddRange(state.Skipped.Values);
        Assert.NotEmpty(state.Skipped);
        pair.Bob.Dispose();
        foreach (var buffer in owned) Assert.All(buffer, value => Assert.Equal(0, value));
        Assert.Empty(state.Skipped);
    }

    private static byte[] ReferenceKey(byte[] publicKey)
    {
        var material = ReferenceRoot(Shared, BobPrivate, publicKey);
        using var hmac = new HMACSHA256(material.AsSpan(32).ToArray());
        return hmac.ComputeHash([1]);
    }

    private static byte[] ReferenceRoot(byte[] root, byte[] privateKey, byte[] publicKey)
    {
        var dh = new byte[32];
        Assert.True(BcX25519.CalculateAgreement(privateKey, 0, publicKey, 0, dh, 0));
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(dh, root, Encoding.ASCII.GetBytes("HeroCrypt.DoubleRatchet.Root.v1")));
        var material = new byte[64];
        hkdf.GenerateBytes(material, 0, material.Length);
        return material;
    }

    private static byte[] ReferenceAd(byte[] header, byte[] data)
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("HeroCrypt.DoubleRatchet.v1"));
        var length = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)Context.Length);
        stream.Write(length); stream.Write(Context);
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)data.Length);
        stream.Write(length); stream.Write(data); stream.Write(header);
        return stream.ToArray();
    }

    private static byte[] ReferenceDecrypt(DoubleRatchetMessage message, byte[] data)
    {
        var cipher = new BcCipher();
        cipher.Init(false, new AeadParameters(new KeyParameter(ReferenceKey(message.RatchetPublicKey)), 128,
            message.Nonce, ReferenceAd(message.ToBytes().AsSpan(0, 53).ToArray(), data)));
        var ciphertext = message.Ciphertext;
        var output = new byte[cipher.GetOutputSize(ciphertext.Length)];
        var length = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
        length += cipher.DoFinal(output, length);
        Assert.Equal(output.Length, length);
        return output;
    }

    private static DoubleRatchetMessage ReferenceEncrypt(byte[] plaintext)
    {
        var privateKey = Convert.FromHexString("5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB");
        var publicKey = new byte[32];
        BcX25519.GeneratePublicKey(privateKey, 0, publicKey, 0);
        var encoded = new byte[53 + plaintext.Length + 16];
        encoded[0] = 1;
        publicKey.CopyTo(encoded, 1);
        var cipher = new BcCipher();
        cipher.Init(true, new AeadParameters(new KeyParameter(ReferenceKey(publicKey)), 128,
            new byte[12], ReferenceAd(encoded.AsSpan(0, 53).ToArray(), [])));
        var length = cipher.ProcessBytes(plaintext, 0, plaintext.Length, encoded, 53);
        length += cipher.DoFinal(encoded, 53 + length);
        Assert.Equal(plaintext.Length + 16, length);
        return DoubleRatchetMessage.FromBytes(encoded);
    }

    private sealed class Pair : IDisposable
    {
        internal DoubleRatchetSession Alice { get; }
        internal DoubleRatchetSession Bob { get; }

        internal Pair(int budget = 1000)
        {
            Alice = DoubleRatchetSession.CreateInitiator(Shared, new Curve25519Core().DerivePublicKey(BobPrivate), Context, budget);
            Bob = DoubleRatchetSession.CreateResponder(Shared, BobPrivate, Context, budget);
        }

        public void Dispose()
        {
            Alice.Dispose(); Bob.Dispose();
        }
    }
}
