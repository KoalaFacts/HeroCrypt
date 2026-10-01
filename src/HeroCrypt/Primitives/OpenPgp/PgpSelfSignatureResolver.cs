using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Resolves authenticated current primary-key policy for the supported V4/V6 subset.
/// </summary>
internal static class PgpSelfSignatureResolver
{
    internal static PgpSignaturePacket Resolve(PgpPublicKeyRing ring, DateTimeOffset atTime)
    {
        if (ring.Version != 4 && ring.Version != 6)
            throw new InvalidOperationException("Unsupported key version for expiration policy.");
        if (ring.Signatures.Any(s => s.SignatureType == PgpSignatureType.CertificationRevocation))
            throw new InvalidOperationException("Certification revocation policy is unsupported.");

        using var verifier = PgpSignatureVerifier.Create();
        var direct = Latest(ring.Signatures.Where(s => s.SignatureType == PgpSignatureType.DirectKey),
            s => verifier.VerifyDirectKeySignature(s, ring.MasterKey, ring.MasterKey).IsValid, ring.CreationTime, atTime);
        if (direct.HasValue) return direct.Value;
        if (ring.Version == 6)
            throw new InvalidOperationException("V6 expiration policy requires a current authenticated Direct Key self-signature.");

        PgpSignaturePacket? selected = null;
        foreach (var user in ring.UserIds)
        {
            var current = Latest(ring.Signatures.Where(s => s.SignatureType is
                PgpSignatureType.GenericCertification or PgpSignatureType.PersonaCertification or
                PgpSignatureType.CasualCertification or PgpSignatureType.PositiveCertification),
                s => verifier.VerifySelfCertification(s, ring.MasterKey, user).IsValid, ring.CreationTime, atTime);
            if (!current.HasValue) continue;
            if (selected.HasValue && Lifetime(selected.Value) != Lifetime(current.Value))
                throw new InvalidOperationException("User ID self-signatures contain conflicting key expiration policies.");
            selected ??= current;
        }

        return selected ?? throw new InvalidOperationException("No current authenticated self-signature establishes key expiration policy.");
    }

    internal static TimeSpan? Lifetime(PgpSignaturePacket signature)
    {
        var packet = signature.HashedSubpackets.FirstOrDefault(s => s.Type == PgpSignatureSubpacketType.KeyExpirationTime);
        if (packet.Type != PgpSignatureSubpacketType.KeyExpirationTime) return null;
        var seconds = BinaryPrimitives.ReadUInt32BigEndian(packet.Data.Span);
        return seconds == 0 ? null : TimeSpan.FromSeconds(seconds);
    }

    private static PgpSignaturePacket? Latest(IEnumerable<PgpSignaturePacket> signatures,
        Func<PgpSignaturePacket, bool> authenticate, DateTimeOffset keyCreation, DateTimeOffset atTime)
    {
        PgpSignaturePacket? latest = null;
        long latestTime = long.MinValue;
        bool conflicting = false;
        foreach (var signature in signatures)
        {
            // The general verifier rejects critical policy fields it does not evaluate.
            // Do not silently fall back to older policy when such evidence is present.
            if (signature.HashedSubpackets.Any(s => s.IsCritical &&
                s.Type != PgpSignatureSubpacketType.SignatureCreationTime &&
                s.Type != PgpSignatureSubpacketType.IssuerFingerprint &&
                s.Type != PgpSignatureSubpacketType.IssuerKeyId))
                throw new InvalidOperationException("Unsupported critical self-signature policy.");
            if (!authenticate(signature)) continue;
            var created = signature.GetCreationTime();
            if (!created.HasValue || created.Value.ToUnixTimeSeconds() < keyCreation.ToUnixTimeSeconds() ||
                created.Value.ToUnixTimeSeconds() > atTime.ToUnixTimeSeconds()) continue;
            long time = created.Value.ToUnixTimeSeconds();
            if (time > latestTime)
            {
                latest = signature;
                latestTime = time;
                conflicting = false;
            }
            else if (time == latestTime && latest.HasValue &&
                !PgpSignatureSubpacket.WriteAll(latest.Value.HashedSubpackets)
                    .AsSpan().SequenceEqual(PgpSignatureSubpacket.WriteAll(signature.HashedSubpackets)))
            {
                conflicting = true;
            }
        }

        if (conflicting) throw new InvalidOperationException("Conflicting self-signatures have the same creation time.");
        if (latest.HasValue)
        {
            var expires = latest.Value.HashedSubpackets.FirstOrDefault(s => s.Type == PgpSignatureSubpacketType.SignatureExpirationTime);
            if (expires.Type == PgpSignatureSubpacketType.SignatureExpirationTime)
            {
                var seconds = BinaryPrimitives.ReadUInt32BigEndian(expires.Data.Span);
                if (seconds != 0 && atTime.ToUnixTimeSeconds() >= latestTime + seconds)
                    throw new InvalidOperationException("The newest self-signature has expired; older policy is not a valid fallback.");
            }
        }
        return latest;
    }
}
