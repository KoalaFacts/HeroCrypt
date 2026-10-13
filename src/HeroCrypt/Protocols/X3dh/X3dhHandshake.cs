using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

/// <summary>Classical X3DH establishment for identity-bound HeroCrypt ratchet sessions.</summary>
/// <remarks>Authenticate expected identity keys externally. Optional-key availability is not signed; require bundle OPK presence when four-DH is mandatory.</remarks>
public static class X3dhHandshake
{
    /// <summary>Verifies the expected responder and signed prekey, then encrypts the first payload.</summary>
    public static X3dhInitiation Initiate(X3dhIdentityKey identity, X3dhPreKeyBundle bundle, byte[] expectedResponderIdentity,
        byte[] applicationContext, ReadOnlySpan<byte> firstPlaintext, ReadOnlySpan<byte> associatedData = default,
        int maxSkippedKeys = 1000, SecurityPolicyOptions? policy = null)
    {
        ArgumentHelper.ThrowIfNull(identity); ArgumentHelper.ThrowIfNull(bundle); ArgumentHelper.ThrowIfNull(expectedResponderIdentity);
        X3dhValidation.ValidateContext(applicationContext); X3dhValidation.ValidatePayloadAndMetadata(firstPlaintext, associatedData);
        X3dhValidation.ValidateSkippedKeyBudget(maxSkippedKeys);
        var effective = policy ?? SecurityPolicy.CurrentPolicy; X3dhValidation.ValidatePolicy(effective);
        byte[] expected = []; byte[] application = []; byte[] key = []; byte[] ephemeral = []; byte[] sk = []; byte[] context = []; byte[] ad = [];
        DoubleRatchetSession? session = null; var transferred = false;
        try
        {
            expected = expectedResponderIdentity.AsSpan().ToArray(); application = applicationContext.AsSpan().ToArray();
            var responder = bundle.IdentityPublicKey; X3dhValidation.RequireIdentity(expected, responder);
            if (!new XEdDsaCore(effective).Verify(X3dhEncoding.EncodePublicKey(bundle.SignedPreKeyPublicKey), bundle.SignedPreKeySignature, responder))
                throw new CryptographicException("Invalid X3DH signed-prekey signature.");
            key = identity.CopyPrivateKey(); var curve = new Curve25519Core(effective);
            var initiator = curve.DerivePublicKey(key); ephemeral = curve.GeneratePrivateKey(); var ephemeralPublic = curve.DerivePublicKey(ephemeral);
            sk = X3dhKdf.DeriveInitiator(key, ephemeral, bundle, effective);
            context = X3dhKdf.SessionContext(initiator, responder, ephemeralPublic, bundle, application);
            ad = X3dhKdf.FirstAssociatedData(initiator, responder, associatedData);
            session = DoubleRatchetSession.CreateInitiator(sk, bundle.SignedPreKeyPublicKey, context, maxSkippedKeys, effective);
            var message = session.Encrypt(firstPlaintext, ad);
            var initial = X3dhInitialMessage.Create(initiator, ephemeralPublic, bundle.SignedPreKeyId, bundle.OneTimePreKeyId, message);
            var result = new X3dhInitiation(session, initial); transferred = true; return result;
        }
        finally
        {
            Clear(expected); Clear(application); Clear(key); Clear(ephemeral); Clear(sk); Clear(context); Clear(ad);
            if (!transferred) session?.Dispose();
        }
    }
    private static void Clear(byte[] value) => SecureMemoryOperations.SecureClear(value.AsSpan());
}
