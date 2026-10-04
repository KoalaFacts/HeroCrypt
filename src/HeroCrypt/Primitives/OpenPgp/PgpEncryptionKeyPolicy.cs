namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>Current encryption eligibility for the supported authenticated key-ring subset.</summary>
internal static class PgpEncryptionKeyPolicy
{
    internal static PgpPublicKeyPacket Select(PgpPublicKeyRing ring, DateTimeOffset atTime)
    {
        foreach (var subkey in ring.Subkeys)
        {
            if (TryAuthorize(ring, subkey, atTime, out _)) return subkey;
        }

        if (TryAuthorize(ring, ring.MasterKey, atTime, out var error)) return ring.MasterKey;
        throw new InvalidOperationException("No current authenticated encryption key is available: " + error);
    }

    internal static bool TryAuthorize(PgpPublicKeyRing ring, PgpPublicKeyPacket key,
        DateTimeOffset atTime, out string? error)
    {
        try
        {
            if (!IsSupported(key.Algorithm))
                throw new InvalidOperationException("Key algorithm is not supported for message encryption.");
            if (ring.MasterKey.IsSubkey || !ring.MasterKey.Algorithm.CanSign())
                throw new InvalidOperationException("Invalid primary certification key.");
            CheckExpiration(ring.MasterKey, PgpSelfSignatureResolver.Resolve(ring, atTime), atTime);
            if (ring.GetAuthenticatedRevocationReason(out var invalidEvidence).HasValue || invalidEvidence != 0)
                throw new InvalidOperationException("Primary key is revoked or its revocation evidence is unsupported.");

            if (ring.MasterKey.ToArray().AsSpan().SequenceEqual(key.ToArray()))
            {
                RequireEncryption(PgpSelfSignatureResolver.PrimaryFlags(ring, atTime));
            }
            else
            {
                var subkey = ring.Subkeys.First(candidate => candidate.ToArray().AsSpan().SequenceEqual(key.ToArray()));
                if (!subkey.IsSubkey) throw new InvalidOperationException("Invalid subkey packet role.");
                var binding = PgpSelfSignatureResolver.Binding(ring, subkey, atTime);
                RequireEncryption(PgpSelfSignatureResolver.Flags(binding));
                CheckExpiration(subkey, binding, atTime);
                using var verifier = PgpSignatureVerifier.Create();
                foreach (var revocation in ring.GetSubkeyRevocationSignatures())
                {
                    if (verifier.VerifySubkeyRevocation(revocation, ring.MasterKey, subkey).IsValid)
                        throw new InvalidOperationException("Encryption subkey is revoked.");
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

    private static bool IsSupported(PgpPublicKeyAlgorithm algorithm) =>
        algorithm is PgpPublicKeyAlgorithm.RsaEncryptOrSign or PgpPublicKeyAlgorithm.X25519 ||
#pragma warning disable CS0618 // Existing RSA encrypt-only packets remain supported.
        algorithm == PgpPublicKeyAlgorithm.RsaEncryptOnly;
#pragma warning restore CS0618

    private static void RequireEncryption(PgpKeyCapabilities? flags)
    {
        if (!flags.HasValue || (flags.Value & (PgpKeyCapabilities.EncryptCommunications | PgpKeyCapabilities.EncryptStorage)) == 0)
            throw new InvalidOperationException("No current authenticated encryption permission.");
    }

    private static void CheckExpiration(PgpPublicKeyPacket key, PgpSignaturePacket policy, DateTimeOffset atTime)
    {
        var lifetime = PgpSelfSignatureResolver.Lifetime(policy);
        if (key.CreationTime.ToUnixTimeSeconds() > atTime.ToUnixTimeSeconds() ||
            (lifetime.HasValue && atTime.ToUnixTimeSeconds() >= key.CreationTime.ToUnixTimeSeconds() + (long)lifetime.Value.TotalSeconds))
            throw new InvalidOperationException("Encryption key is not current or has expired.");
    }
}
