using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

public sealed partial class X3dhPreKeyStore
{
    private int acceptedHandshakeCount;
    /// <summary>Authenticates initial message zero, records its transcript and consumes its selected OPK atomically.</summary>
    /// <remarks>Failures before commitment leave prekeys and replay records intact. Replay/capacity never evicts earlier records.</remarks>
    public X3dhAcceptance Accept(X3dhInitialMessage initialMessage, byte[] expectedInitiatorIdentity, byte[] applicationContext,
        ReadOnlySpan<byte> associatedData = default, int maxSkippedKeys = 1000)
    {
        lock (sync)
        {
            ThrowIfDisposed(); ArgumentHelper.ThrowIfNull(initialMessage); ArgumentHelper.ThrowIfNull(expectedInitiatorIdentity);
            X3dhValidation.ValidateContext(applicationContext); X3dhValidation.ValidatePayloadAndMetadata([], associatedData);
            X3dhValidation.ValidateSkippedKeyBudget(maxSkippedKeys); X3dhValidation.ValidatePolicy(policy);
            if (initialMessage.RatchetMessage.MessageNumber != 0 || initialMessage.RatchetMessage.PreviousChainLength != 0)
                throw new CryptographicException("Initial ratchet counters must be zero.");
            byte[] expected = []; byte[] application = []; byte[] sk = []; byte[] context = []; byte[] ad = []; byte[] plaintext = [];
            DoubleRatchetSession? session = null; X3dhAcceptance? result = null; var committed = false;
            try
            {
                expected = expectedInitiatorIdentity.AsSpan().ToArray(); application = applicationContext.AsSpan().ToArray();
                var initiator = initialMessage.InitiatorIdentityPublicKey; X3dhValidation.RequireIdentity(expected, initiator);
                if (!signedPreKeys.TryGetValue(initialMessage.SignedPreKeyId, out var signed)) throw new CryptographicException("Signed prekey unavailable.");
                X3dhPreKeyMaterial? oneTime = null;
                if (initialMessage.OneTimePreKeyId.HasValue && !oneTimePreKeys.TryGetValue(initialMessage.OneTimePreKeyId.Value, out oneTime))
                    throw new CryptographicException("Selected one-time prekey unavailable.");
                var binding = X3dhPreKeyBundle.Create(identityPublicKey, initialMessage.SignedPreKeyId, signed.PublicKey, signed.Signature,
                    initialMessage.OneTimePreKeyId, oneTime?.PublicKey);
                context = X3dhKdf.SessionContext(initiator, identityPublicKey, initialMessage.EphemeralPublicKey, binding, application);
                for (var i = 0; i < acceptedHandshakeCount; i++)
                    if (SecureMemoryOperations.ConstantTimeEquals(context, acceptedTranscriptDigests.AsSpan(i * 32, 32))) throw new CryptographicException("X3DH handshake replay.");
                if (acceptedHandshakeCount >= acceptedTranscriptDigests.Length / 32) throw new InvalidOperationException("X3DH replay capacity exhausted; create fresh prekeys.");
                sk = X3dhKdf.DeriveResponder(identityPrivateKey, signed.PrivateKey, oneTime?.PrivateKey, initialMessage, policy);
                ad = X3dhKdf.FirstAssociatedData(initiator, identityPublicKey, associatedData);
                session = DoubleRatchetSession.CreateResponder(sk, signed.PrivateKey, context, maxSkippedKeys, policy);
                plaintext = session.Decrypt(initialMessage.RatchetMessage, ad);
                result = new X3dhAcceptance(session, plaintext);
                // All allocating/fallible work is complete. Fixed-slot commit and
                // owned span cleanup cannot grow a container or invoke RNG/GC.
                context.CopyTo(acceptedTranscriptDigests.AsSpan(acceptedHandshakeCount * 32, 32));
                acceptedHandshakeCount++;
                if (initialMessage.OneTimePreKeyId.HasValue)
                { oneTimePreKeys.Remove(initialMessage.OneTimePreKeyId.Value); oneTime!.Dispose(); }
                committed = true; return result;
            }
            finally
            {
                SecureMemoryOperations.SecureClear(expected.AsSpan()); SecureMemoryOperations.SecureClear(application.AsSpan());
                SecureMemoryOperations.SecureClear(sk.AsSpan()); SecureMemoryOperations.SecureClear(context.AsSpan()); SecureMemoryOperations.SecureClear(ad.AsSpan());
                if (!committed)
                {
                    if (result != null) result.Dispose();
                    else { try { session?.Dispose(); } finally { SecureMemoryOperations.SecureClear(plaintext.AsSpan()); } }
                }
            }
        }
    }
}
