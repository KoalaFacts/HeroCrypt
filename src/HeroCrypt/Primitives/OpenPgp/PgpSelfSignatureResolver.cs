using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Resolves authenticated current primary-key policy for the supported V4/V6 subset.
/// </summary>
internal static class PgpSelfSignatureResolver
{
    internal static byte[]? Preferences(PgpPublicKeyRing ring, PgpSignatureSubpacketType type, DateTimeOffset atTime)
    {
        ValidatePolicyRing(ring);
        using var verifier = PgpSignatureVerifier.Create();
        var direct = Latest(ring.Signatures.Where(s => s.SignatureType == PgpSignatureType.DirectKey),
            s => verifier.VerifyDirectKeySignature(s, ring.MasterKey, ring.MasterKey).IsValid, ring.CreationTime, atTime);
        if (direct.HasValue) return ReadPreferences(direct.Value, type);
        if (ring.Version == 6)
            throw new InvalidOperationException("V6 preferences require a current authenticated Direct Key self-signature.");

        var users = CurrentUsers(ring, atTime);
        if (users.Count == 0)
            throw new InvalidOperationException("No current authenticated self-signature establishes algorithm preferences.");
        var primary = MarkedPrimary(users);
        if (primary.HasValue) return ReadPreferences(users[primary.Value].Signature, type);

        var selected = ReadPreferences(users[0].Signature, type);
        foreach (var user in users.Skip(1))
        {
            var value = ReadPreferences(user.Signature, type);
            if ((selected == null) != (value == null) ||
                (selected != null && value != null && !selected.AsSpan().SequenceEqual(value)))
                throw new InvalidOperationException("User ID algorithm preferences conflict without an authenticated primary User ID.");
        }
        return selected;
    }

    internal static PgpUserIdPacket? PrimaryUser(PgpPublicKeyRing ring, DateTimeOffset atTime)
    {
        if (ring.UserIds.Count == 0) return null;
        var users = CurrentUsers(ring, atTime);
        if (users.Count == 0)
            throw new InvalidOperationException("No current authenticated User ID self-certification is available.");
        return users[MarkedPrimary(users) ?? 0].UserId;
    }

    private static List<(PgpUserIdPacket UserId, PgpSignaturePacket Signature)> CurrentUsers(PgpPublicKeyRing ring, DateTimeOffset atTime)
    {
        ValidatePolicyRing(ring);
        using var verifier = PgpSignatureVerifier.Create();
        var users = new List<(PgpUserIdPacket, PgpSignaturePacket)>();
        foreach (var user in ring.UserIds)
        {
            var current = Latest(ring.Signatures.Where(s => PgpKeyRingPacketLayout.IsCertification(s.SignatureType)),
                s => verifier.VerifySelfCertification(s, ring.MasterKey, user).IsValid, ring.CreationTime, atTime);
            if (current.HasValue) users.Add((user, current.Value));
        }
        return users;
    }

    private static int? MarkedPrimary(IReadOnlyList<(PgpUserIdPacket UserId, PgpSignaturePacket Signature)> users)
    {
        int? selected = null;
        long selectedTime = long.MinValue;
        for (int i = 0; i < users.Count; i++)
        {
            var markers = users[i].Signature.HashedSubpackets.Where(s => s.Type == PgpSignatureSubpacketType.PrimaryUserId).ToArray();
            if (markers.Length > 1 || (markers.Length == 1 && markers[0].Data.Length != 1))
                throw new InvalidOperationException("Malformed or duplicate primary User ID marker.");
            if (markers.Length == 0 || markers[0].Data.Span[0] == 0) continue;
            long time = users[i].Signature.GetCreationTime()!.Value.ToUnixTimeSeconds();
            if (time > selectedTime)
            {
                selected = i;
                selectedTime = time;
            }
            else if (time == selectedTime && selected.HasValue &&
                !users[selected.Value].UserId.ToArray().AsSpan().SequenceEqual(users[i].UserId.ToArray()))
                throw new InvalidOperationException("Conflicting primary User IDs have equal-time current self-signatures.");
        }
        return selected;
    }

    private static byte[]? ReadPreferences(PgpSignaturePacket signature, PgpSignatureSubpacketType type)
    {
        if (type == PgpSignatureSubpacketType.PreferredAeadAlgorithms && signature.HashedSubpackets.Any(s => (byte)s.Type == 34))
            throw new InvalidOperationException("Reserved legacy AEAD preference type 34 requires trusted re-signing with RFC type 39.");
        var fields = signature.HashedSubpackets.Where(s => s.Type == type).ToArray();
        if (fields.Length > 1)
            throw new InvalidOperationException("Duplicate algorithm preference fields are ambiguous.");
        if (fields.Length == 0) return null;
        if (type == PgpSignatureSubpacketType.PreferredAeadAlgorithms && fields[0].Data.Length % 2 != 0)
            throw new InvalidOperationException("AEAD preferences must contain complete cipher/AEAD pairs.");
        return fields[0].Data.ToArray();
    }

    private static void ValidatePolicyRing(PgpPublicKeyRing ring)
    {
        if (ring.Version != 4 && ring.Version != 6)
            throw new InvalidOperationException("Unsupported key version for primary-key policy.");
        if (ring.Signatures.Any(s => s.SignatureType == PgpSignatureType.CertificationRevocation))
            throw new InvalidOperationException("Certification revocation policy is unsupported.");
    }

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
