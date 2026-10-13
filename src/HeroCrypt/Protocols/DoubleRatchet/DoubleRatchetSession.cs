using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.DoubleRatchet;

/// <summary>A two-party in-memory Double Ratchet session.</summary>
/// <remarks>
/// Implements the classical DH and symmetric ratchets with X25519, HKDF/HMAC-SHA256
/// and ChaCha20-Poly1305. The shared secret, peer key and session context must be
/// authenticated separately. This HeroCrypt wire profile is not Signal-compatible
/// and implements no persistence or header encryption. The separate
/// <see cref="X3dh.X3dhHandshake"/> API can establish its bootstrap inputs.
/// Establish a fresh
/// authenticated session after restart; do not restore or reuse old state.
/// This implementation has not received an independent security audit.
/// Owned byte buffers are cleared, without a complete managed-runtime zeroization guarantee.
/// </remarks>
public sealed class DoubleRatchetSession : IDisposable
{
#if NET9_0_OR_GREATER
    private readonly Lock sync = new();
#else
    private readonly object sync = new();
#endif
    private readonly byte[] context;
    private readonly int maxSkippedKeys;
    private readonly SecurityPolicyOptions policy;
    private readonly Curve25519Core curve;
    private readonly ChaCha20Poly1305Core cipher;
    private DoubleRatchetState state;
    private bool disposed;

    private DoubleRatchetSession(DoubleRatchetState state, byte[] context, int maxSkippedKeys, SecurityPolicyOptions policy)
    {
        this.state = state;
        this.context = context.AsSpan().ToArray();
        this.maxSkippedKeys = maxSkippedKeys;
        this.policy = policy;
        curve = new Curve25519Core(policy);
        cipher = new ChaCha20Poly1305Core(policy);
    }

    /// <summary>Creates the initiator with an authenticated shared secret and peer key.</summary>
    /// <param name="sharedSecret">Previously authenticated, high-entropy 32-byte shared secret.</param>
    /// <param name="responderPublicKey">Authenticated canonical 32-byte responder X25519 public key.</param>
    /// <param name="sessionContext">Identical peer/application context at both endpoints, 1–4096 bytes.</param>
    /// <param name="maxSkippedKeys">Total skipped-key budget, 0–10000 inclusive.</param>
    /// <param name="policy">Explicit policy, or the current policy captured at creation.</param>
    /// <returns>A session ready to send its first message.</returns>
    public static DoubleRatchetSession CreateInitiator(byte[] sharedSecret, byte[] responderPublicKey,
        byte[] sessionContext, int maxSkippedKeys = 1000, SecurityPolicyOptions? policy = null)
    {
        var effective = ValidateConfiguration(sharedSecret, responderPublicKey, sessionContext, maxSkippedKeys, policy);
        var initial = new DoubleRatchetState();
        try
        {
            initial.Root = sharedSecret.AsSpan().ToArray();
            initial.RemoteKey = responderPublicKey.AsSpan().ToArray();
            DoubleRatchetMessage.ValidatePublicKey(initial.RemoteKey);
            var curve = new Curve25519Core(effective);
            initial.PrivateKey = curve.GeneratePrivateKey();
            initial.PublicKey = curve.DerivePublicKey(initial.PrivateKey);
            AdvanceRoot(initial, curve.ComputeSharedSecret(initial.PrivateKey, initial.RemoteKey), effective, receiving: false);
            return new DoubleRatchetSession(initial, sessionContext, maxSkippedKeys, effective);
        }
        catch
        {
            initial.Dispose();
            throw;
        }
    }

    /// <summary>Creates the responder with an authenticated shared secret and local private key.</summary>
    /// <param name="sharedSecret">Previously authenticated, high-entropy 32-byte shared secret.</param>
    /// <param name="responderPrivateKey">32-byte responder X25519 private key corresponding to the authenticated public key.</param>
    /// <param name="sessionContext">Identical peer/application context at both endpoints, 1–4096 bytes.</param>
    /// <param name="maxSkippedKeys">Total skipped-key budget, 0–10000 inclusive.</param>
    /// <param name="policy">Explicit policy, or the current policy captured at creation.</param>
    /// <returns>A session that must authenticate an initiator message before sending.</returns>
    public static DoubleRatchetSession CreateResponder(byte[] sharedSecret, byte[] responderPrivateKey,
        byte[] sessionContext, int maxSkippedKeys = 1000, SecurityPolicyOptions? policy = null)
    {
        var effective = ValidateConfiguration(sharedSecret, responderPrivateKey, sessionContext, maxSkippedKeys, policy);
        var initial = new DoubleRatchetState();
        try
        {
            initial.Root = sharedSecret.AsSpan().ToArray();
            initial.PrivateKey = responderPrivateKey.AsSpan().ToArray();
            initial.PublicKey = new Curve25519Core(effective).DerivePublicKey(initial.PrivateKey);
            return new DoubleRatchetSession(initial, sessionContext, maxSkippedKeys, effective);
        }
        catch
        {
            initial.Dispose();
            throw;
        }
    }

    /// <summary>Encrypts the next outgoing message.</summary>
    /// <param name="plaintext">Message bytes, at most 16 MiB.</param>
    /// <param name="associatedData">Application metadata, at most 16 MiB; it must match at decryption.</param>
    /// <returns>An immutable authenticated message suitable for serialization.</returns>
    /// <exception cref="InvalidOperationException">No sending chain exists or its counter is exhausted.</exception>
    public DoubleRatchetMessage Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            ValidateSize(plaintext, nameof(plaintext));
            ValidateSize(associatedData, nameof(associatedData));
            if (state.SendingChain == null) throw new InvalidOperationException("The responder must first authenticate an initiator message.");
            if (state.SendCount == uint.MaxValue) throw new InvalidOperationException("The sending chain counter is exhausted.");
            var candidate = state.Clone();
            byte[]? messageKey = null;
            byte[]? authenticatedData = null;
            var committed = false;
            try
            {
                messageKey = AdvanceChain(ref candidate.SendingChain);
                var nonce = new byte[12];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(nonce);
                var header = DoubleRatchetMessage.CreateHeader(candidate.PublicKey, candidate.PreviousSendCount, candidate.SendCount, nonce);
                authenticatedData = DoubleRatchetKdf.AssociatedData(context, associatedData, header);
                var result = cipher.Encrypt(plaintext, messageKey, nonce, authenticatedData);
                var message = DoubleRatchetMessage.Create(header, result.Ciphertext);
                candidate.SendCount++;
                Commit(candidate);
                committed = true;
                return message;
            }
            finally
            {
                DoubleRatchetState.Clear(messageKey);
                DoubleRatchetState.Clear(authenticatedData);
                if (!committed) candidate.Dispose();
            }
        }
    }

    /// <summary>Authenticates and decrypts an incoming message.</summary>
    /// <param name="message">An immutable received message.</param>
    /// <param name="associatedData">The expected application metadata supplied at encryption.</param>
    /// <returns>Owned plaintext bytes; the caller is responsible for clearing them.</returns>
    /// <exception cref="CryptographicException">Authentication, replay, key or skip-budget validation fails.</exception>
    /// <remarks>Authentication failure never advances or consumes session keys.</remarks>
    public byte[] Decrypt(DoubleRatchetMessage message, ReadOnlySpan<byte> associatedData = default)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            ArgumentHelper.ThrowIfNull(message);
            ValidateSize(associatedData, nameof(associatedData));
            if (message.MessageNumber == uint.MaxValue) throw InvalidMessage();
            var candidate = state.Clone();
            byte[]? messageKey = null;
            byte[]? authenticatedData = null;
            var committed = false;
            try
            {
                var remoteKey = message.RatchetPublicKey;
                var keyId = (BitConverter.ToString(remoteKey), message.MessageNumber);
                var isSkipped = candidate.Skipped.TryGetValue(keyId, out var skippedKey);
                if (isSkipped)
                {
                    messageKey = skippedKey!;
                }
                else
                {
                    if (candidate.RemoteKey == null || !candidate.RemoteKey.AsSpan().SequenceEqual(remoteKey))
                    {
                        SkipKeys(candidate, message.PreviousChainLength);
                        Ratchet(candidate, remoteKey);
                    }
                    if (message.MessageNumber < candidate.ReceiveCount) throw InvalidMessage();
                    SkipKeys(candidate, message.MessageNumber);
                    messageKey = AdvanceChain(ref candidate.ReceivingChain);
                }
                authenticatedData = DoubleRatchetKdf.AssociatedData(context, associatedData, message.Header);
                var plaintext = cipher.Decrypt(message.CiphertextSpan, messageKey, message.NonceSpan, authenticatedData);
                if (isSkipped) candidate.Skipped.Remove(keyId);
                else candidate.ReceiveCount++;
                Commit(candidate);
                committed = true;
                return plaintext;
            }
            catch (CryptographicException)
            {
                throw InvalidMessage();
            }
            finally
            {
                DoubleRatchetState.Clear(messageKey);
                DoubleRatchetState.Clear(authenticatedData);
                if (!committed) candidate.Dispose();
            }
        }
    }

    /// <summary>Clears owned state and closes the session.</summary>
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            state.Dispose();
            DoubleRatchetState.Clear(context);
        }
    }

    private void Ratchet(DoubleRatchetState candidate, byte[] remoteKey)
    {
        candidate.PreviousSendCount = candidate.SendCount;
        candidate.SendCount = 0;
        candidate.ReceiveCount = 0;
        DoubleRatchetState.Clear(candidate.RemoteKey);
        candidate.RemoteKey = remoteKey.AsSpan().ToArray();
        AdvanceRoot(candidate, curve.ComputeSharedSecret(candidate.PrivateKey, remoteKey), policy, receiving: true);
        DoubleRatchetState.Clear(candidate.PrivateKey);
        candidate.PrivateKey = curve.GeneratePrivateKey();
        DoubleRatchetState.Clear(candidate.PublicKey);
        candidate.PublicKey = curve.DerivePublicKey(candidate.PrivateKey);
        AdvanceRoot(candidate, curve.ComputeSharedSecret(candidate.PrivateKey, remoteKey), policy, receiving: false);
    }

    private void SkipKeys(DoubleRatchetState candidate, uint until)
    {
        if (until < candidate.ReceiveCount) throw InvalidMessage();
        var gap = (ulong)until - candidate.ReceiveCount;
        if (gap > (ulong)maxSkippedKeys || gap + (ulong)candidate.Skipped.Count > (ulong)maxSkippedKeys)
            throw InvalidMessage();
        if (gap == 0) return;
        if (candidate.ReceivingChain == null || candidate.RemoteKey == null) throw InvalidMessage();
        var publicKeyId = BitConverter.ToString(candidate.RemoteKey);
        while (candidate.ReceiveCount < until)
        {
            var key = AdvanceChain(ref candidate.ReceivingChain);
            candidate.Skipped.Add((publicKeyId, candidate.ReceiveCount), key);
            candidate.ReceiveCount++;
        }
    }

    private static byte[] AdvanceChain(ref byte[]? chain)
    {
        if (chain == null) throw InvalidMessage();
        var derived = DoubleRatchetKdf.Chain(chain);
        DoubleRatchetState.Clear(chain);
        chain = derived.Next;
        return derived.Message;
    }

    private static void AdvanceRoot(DoubleRatchetState candidate, byte[] dh, SecurityPolicyOptions policy, bool receiving)
    {
        try
        {
            var derived = DoubleRatchetKdf.Root(candidate.Root, dh, policy);
            DoubleRatchetState.Clear(candidate.Root);
            candidate.Root = derived.Root;
            if (receiving)
            {
                DoubleRatchetState.Clear(candidate.ReceivingChain);
                candidate.ReceivingChain = derived.Chain;
            }
            else
            {
                DoubleRatchetState.Clear(candidate.SendingChain);
                candidate.SendingChain = derived.Chain;
            }
        }
        finally
        {
            DoubleRatchetState.Clear(dh);
        }
    }

    private void Commit(DoubleRatchetState candidate)
    {
        var old = state;
        state = candidate;
        old.Dispose();
    }

    private static SecurityPolicyOptions ValidateConfiguration(byte[] sharedSecret, byte[] key, byte[] sessionContext,
        int maxSkippedKeys, SecurityPolicyOptions? policy)
    {
        ArgumentHelper.ThrowIfNull(sharedSecret);
        ArgumentHelper.ThrowIfNull(key);
        ArgumentHelper.ThrowIfNull(sessionContext);
        if (sharedSecret.Length != 32 || key.Length != 32) throw new ArgumentException("Secret and X25519 keys must be 32 bytes.");
        if (sessionContext.Length is < 1 or > 4096) throw new ArgumentException("Session context must contain 1–4096 bytes.", nameof(sessionContext));
        if (maxSkippedKeys is < 0 or > 10000) throw new ArgumentOutOfRangeException(nameof(maxSkippedKeys));
        var effective = SecurityPolicy.GetEffective(policy);
        effective.ValidateKeyAgreement("X25519");
        effective.ValidateSymmetric("CHACHA20-POLY1305");
        effective.ValidateHash("SHA256");
        return effective;
    }

    private static void ValidateSize(ReadOnlySpan<byte> data, string name)
    {
        if (data.Length > DoubleRatchetMessage.MaxPayloadSize) throw new ArgumentException("Data exceeds the 16 MiB limit.", name);
    }

    private void ThrowIfDisposed()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
    }

    private static CryptographicException InvalidMessage() => new("Invalid or unauthenticated Double Ratchet message.");
}
