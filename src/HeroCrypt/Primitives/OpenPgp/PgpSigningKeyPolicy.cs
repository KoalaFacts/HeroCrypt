using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>Current signing eligibility for the supported authenticated key-ring subset.</summary>
internal static class PgpSigningKeyPolicy
{
    internal static bool Contains(PgpPublicKeyRing ring, PgpPublicKeyPacket key) =>
        SameKey(ring.MasterKey, key) || ring.Subkeys.Any(subkey => SameKey(subkey, key));

    private static bool SameKey(PgpPublicKeyPacket left, PgpPublicKeyPacket right) =>
        left.ToArray().AsSpan().SequenceEqual(right.ToArray());

    internal static bool TryAuthorize(PgpPublicKeyRing ring, PgpPublicKeyPacket key, DateTimeOffset atTime, out string? error)
    {
        try
        {
            if (ring.MasterKey.IsSubkey || !ring.MasterKey.Algorithm.CanSign())
                throw new InvalidOperationException("Invalid primary signing key.");
            CheckExpiration(ring.MasterKey, PgpSelfSignatureResolver.Resolve(ring, atTime), atTime);
            if (ring.GetAuthenticatedRevocationReason(out var invalidEvidence).HasValue || invalidEvidence != 0)
                throw new InvalidOperationException("Primary key is revoked or its revocation evidence is unsupported.");

            if (SameKey(ring.MasterKey, key))
            {
                RequireSign(PgpSelfSignatureResolver.PrimaryFlags(ring, atTime));
            }
            else
            {
                var subkey = ring.Subkeys.First(candidate => SameKey(candidate, key));
                var binding = ValidateBinding(ring, subkey, atTime);
                RequireSign(PgpSelfSignatureResolver.Flags(binding));
                CheckExpiration(subkey, binding, atTime);
                using var verifier = PgpSignatureVerifier.Create();
                foreach (var revocation in ring.GetSubkeyRevocationSignatures())
                {
                    if (verifier.VerifySubkeyRevocation(revocation, ring.MasterKey, subkey).IsValid)
                        throw new InvalidOperationException("Signing subkey is revoked.");
                    if (!ring.Subkeys.Any(candidate => verifier.VerifySubkeyRevocation(revocation, ring.MasterKey, candidate).IsValid))
                        throw new InvalidOperationException("Unsupported subkey revocation evidence.");
                }
            }
            error = null;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException)
        {
            error = ex.Message;
            return false;
        }
    }

    internal static PgpSignaturePacket ValidateBinding(PgpPublicKeyRing ring, PgpPublicKeyPacket subkey, DateTimeOffset atTime)
    {
        if (!subkey.IsSubkey || ring.MasterKey.IsSubkey)
            throw new InvalidOperationException("Invalid primary/subkey packet roles.");
        var binding = PgpSelfSignatureResolver.Binding(ring, subkey, atTime);
        var flags = PgpSelfSignatureResolver.Flags(binding);
        if (!subkey.Algorithm.CanSign())
        {
            if (flags.HasValue && (flags.Value & PgpKeyCapabilities.Sign) != 0)
                throw new InvalidOperationException("Subkey algorithm cannot sign.");
            return binding;
        }
        // Explicit authenticated non-signing usage does not require a back signature.
        // Absent usage cannot establish that a signing-capable subkey is encryption-only.
        if (!subkey.Algorithm.CanEncrypt() || !flags.HasValue || (flags.Value & PgpKeyCapabilities.Sign) != 0)
            ValidateConsent(ring.MasterKey, subkey, binding, atTime);
        return binding;
    }

    private static void ValidateConsent(PgpPublicKeyPacket primary, PgpPublicKeyPacket subkey,
        PgpSignaturePacket binding, DateTimeOffset atTime)
    {
        var embedded = binding.HashedSubpackets.Concat(binding.UnhashedSubpackets)
            .Where(packet => packet.Type == PgpSignatureSubpacketType.EmbeddedSignature).ToArray();
        if (embedded.Length != 1 || !PgpSignaturePacket.TryRead(embedded[0].Data.Span, out var back, out _))
            throw new InvalidOperationException("Signing subkey requires one parseable embedded primary-key binding.");
        using var verifier = PgpSignatureVerifier.Create();
        var result = verifier.VerifyPrimaryKeyBinding(back, primary, subkey);
        if (!result.IsValid) throw new InvalidOperationException("Invalid signing-subkey cross-certification: " + result.ErrorMessage);
        var created = back.GetCreationTime();
        var floor = primary.CreationTime > subkey.CreationTime ? primary.CreationTime : subkey.CreationTime;
        if (!created.HasValue || created.Value.ToUnixTimeSeconds() < floor.ToUnixTimeSeconds() ||
            created.Value.ToUnixTimeSeconds() > atTime.ToUnixTimeSeconds())
            throw new InvalidOperationException("Signing-subkey cross-certification has no current creation time.");
        var expiration = back.HashedSubpackets.FirstOrDefault(packet => packet.Type == PgpSignatureSubpacketType.SignatureExpirationTime);
        if (expiration.Type == PgpSignatureSubpacketType.SignatureExpirationTime)
        {
            uint seconds = BinaryPrimitives.ReadUInt32BigEndian(expiration.Data.Span);
            if (seconds != 0 && atTime.ToUnixTimeSeconds() >= created.Value.ToUnixTimeSeconds() + seconds)
                throw new InvalidOperationException("Signing-subkey cross-certification has expired.");
        }
    }

    private static void RequireSign(PgpKeyCapabilities? flags)
    {
        if (!flags.HasValue || (flags.Value & PgpKeyCapabilities.Sign) == 0)
            throw new InvalidOperationException("No current authenticated Sign permission.");
    }

    private static void CheckExpiration(PgpPublicKeyPacket key, PgpSignaturePacket policy, DateTimeOffset atTime)
    {
        var lifetime = PgpSelfSignatureResolver.Lifetime(policy);
        if (key.CreationTime.ToUnixTimeSeconds() > atTime.ToUnixTimeSeconds() ||
            (lifetime.HasValue && atTime.ToUnixTimeSeconds() >= key.CreationTime.ToUnixTimeSeconds() + (long)lifetime.Value.TotalSeconds))
            throw new InvalidOperationException("Signing key is not current or has expired.");
    }
}
