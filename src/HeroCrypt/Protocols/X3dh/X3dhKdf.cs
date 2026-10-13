using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

internal static class X3dhKdf
{
    internal static byte[] DeriveInitiator(byte[] identityPrivateKey, byte[] ephemeralPrivateKey, X3dhPreKeyBundle bundle, SecurityPolicyOptions policy)
    {
        X3dhValidation.ValidatePolicy(policy);
        var pairs = new List<(byte[] Private, byte[] Public)>
        {
            (identityPrivateKey, bundle.SignedPreKeyPublicKey), (ephemeralPrivateKey, bundle.IdentityPublicKey),
            (ephemeralPrivateKey, bundle.SignedPreKeyPublicKey)
        };
        if (bundle.OneTimePreKeyId.HasValue) pairs.Add((ephemeralPrivateKey, bundle.OneTimePreKeyPublicKey!));
        return Extract(pairs, policy);
    }
    internal static byte[] DeriveResponder(byte[] identityPrivateKey, byte[] signedPreKeyPrivateKey, byte[]? oneTimePreKeyPrivateKey,
        X3dhInitialMessage initial, SecurityPolicyOptions policy)
    {
        X3dhValidation.ValidatePolicy(policy);
        if (initial.OneTimePreKeyId.HasValue && oneTimePreKeyPrivateKey == null) throw new CryptographicException("Selected one-time prekey is unavailable.");
        if (!initial.OneTimePreKeyId.HasValue && oneTimePreKeyPrivateKey != null) throw new ArgumentException("Unexpected one-time private key.", nameof(oneTimePreKeyPrivateKey));
        var pairs = new List<(byte[] Private, byte[] Public)>
        {
            (signedPreKeyPrivateKey, initial.InitiatorIdentityPublicKey), (identityPrivateKey, initial.EphemeralPublicKey),
            (signedPreKeyPrivateKey, initial.EphemeralPublicKey)
        };
        if (initial.OneTimePreKeyId.HasValue) pairs.Add((oneTimePreKeyPrivateKey!, initial.EphemeralPublicKey));
        return Extract(pairs, policy);
    }
    private static byte[] Extract(List<(byte[] Private, byte[] Public)> pairs, SecurityPolicyOptions policy)
    {
        var input = new byte[32 + 32 * pairs.Count]; byte[] dh = [];
        try
        {
            input.AsSpan(0, 32).Fill(255); var curve = new Curve25519Core(policy);
            for (var i = 0; i < pairs.Count; i++)
            {
                dh = curve.ComputeSharedSecret(pairs[i].Private, pairs[i].Public);
                dh.CopyTo(input, 32 + 32 * i); SecureMemoryOperations.SecureClear(dh.AsSpan()); dh = [];
            }
            return new HkdfCore(policy).DeriveKey(input, new byte[32], "HeroCrypt.X3DH.v1"u8.ToArray(), 32, HashAlgorithmName.SHA256);
        }
        finally { SecureMemoryOperations.SecureClear(dh.AsSpan()); SecureMemoryOperations.SecureClear(input.AsSpan()); }
    }
    internal static byte[] SessionContext(byte[] initiatorIdentity, byte[] responderIdentity, byte[] ephemeralPublicKey,
        X3dhPreKeyBundle bundle, byte[] applicationContext)
    {
        X3dhValidation.ValidateContext(applicationContext);
        var domain = "HeroCrypt.X3DH.DoubleRatchet.v1"u8;
        var output = new byte[domain.Length + 4 + applicationContext.Length + 132 + 5 + (bundle.OneTimePreKeyId.HasValue ? 37 : 0)];
        try
        {
            var offset = 0; Append(output, ref offset, domain);
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), (uint)applicationContext.Length); offset += 4;
            Append(output, ref offset, applicationContext);
            foreach (var key in new[] { initiatorIdentity, responderIdentity, ephemeralPublicKey, bundle.SignedPreKeyPublicKey })
                Append(output, ref offset, X3dhEncoding.EncodePublicKey(key));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), bundle.SignedPreKeyId); offset += 4;
            output[offset++] = bundle.OneTimePreKeyId.HasValue ? (byte)1 : (byte)0;
            if (bundle.OneTimePreKeyId.HasValue)
            {
                BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), bundle.OneTimePreKeyId.Value); offset += 4;
                Append(output, ref offset, X3dhEncoding.EncodePublicKey(bundle.OneTimePreKeyPublicKey!));
            }
#if NETSTANDARD2_0
            using var hash = SHA256.Create(); return hash.ComputeHash(output);
#else
            return SHA256.HashData(output);
#endif
        }
        finally { SecureMemoryOperations.SecureClear(output.AsSpan()); }
    }
    internal static byte[] FirstAssociatedData(byte[] initiatorIdentity, byte[] responderIdentity, ReadOnlySpan<byte> metadata)
    {
        X3dhValidation.ValidatePayloadAndMetadata([], metadata);
        var output = new byte[70 + metadata.Length]; var offset = 0;
        Append(output, ref offset, X3dhEncoding.EncodePublicKey(initiatorIdentity));
        Append(output, ref offset, X3dhEncoding.EncodePublicKey(responderIdentity));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(66, 4), (uint)metadata.Length); metadata.CopyTo(output.AsSpan(70));
        return output;
    }
    private static void Append(Span<byte> output, ref int offset, ReadOnlySpan<byte> value)
    {
        value.CopyTo(output[offset..]); offset += value.Length;
    }
}
