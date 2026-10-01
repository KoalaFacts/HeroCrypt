namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>Untrusted imported packet targets, retained for lossless signature placement.</summary>
internal sealed record PgpSignatureAssociation(byte[] SignatureBody, PgpPacketTag TargetTag, byte[] TargetBody);

/// <summary>Groups each signature occurrence once for public and secret key-ring export.</summary>
internal static class PgpKeyRingPacketLayout
{
    internal static bool IsCertification(PgpSignatureType type) => type is PgpSignatureType.GenericCertification or
        PgpSignatureType.PersonaCertification or PgpSignatureType.CasualCertification or PgpSignatureType.PositiveCertification;

    internal static List<PgpSignaturePacket>[] Group(PgpPublicKeyRing ring)
    {
        var groups = Enumerable.Range(0, 1 + ring.UserIds.Count + ring.UserAttributes.Count + ring.Subkeys.Count)
            .Select(_ => new List<PgpSignaturePacket>()).ToArray();
        var associations = ring.SignatureAssociations;
        var consumed = new bool[associations.Count];
        using var verifier = PgpSignatureVerifier.Create();
        foreach (var signature in ring.Signatures)
        {
            // Recorded placement is not proof of the signed object. Prefer exact cryptographic association.
            var recorded = ConsumeAssociation(signature, associations, consumed);
            int group = AuthenticatedTarget(signature, ring, verifier);
            if (group < 0 && recorded != null) group = DeclaredTarget(recorded, ring);
            // Unassociated component-constructor packets remain raw diagnostics before the first object.
            groups[group < 0 ? 0 : group].Add(signature);
        }
        return groups;
    }

    private static PgpSignatureAssociation? ConsumeAssociation(PgpSignaturePacket signature,
        IReadOnlyList<PgpSignatureAssociation> associations, bool[] consumed)
    {
        if (associations.Count == 0) return null;
        var bytes = signature.ToArray();
        for (int i = 0; i < associations.Count; i++)
        {
            if (consumed[i] || !bytes.AsSpan().SequenceEqual(associations[i].SignatureBody)) continue;
            consumed[i] = true;
            return associations[i];
        }
        return null;
    }

    private static int AuthenticatedTarget(PgpSignaturePacket signature, PgpPublicKeyRing ring, PgpSignatureVerifier verifier)
    {
        if (signature.SignatureType is PgpSignatureType.DirectKey or PgpSignatureType.KeyRevocation) return 0;
        if (IsCertification(signature.SignatureType) || signature.SignatureType == PgpSignatureType.CertificationRevocation)
        {
            for (int i = 0; i < ring.UserIds.Count; i++)
            {
                var result = IsCertification(signature.SignatureType)
                    ? verifier.VerifySelfCertification(signature, ring.MasterKey, ring.UserIds[i])
                    : verifier.VerifySelfCertificationRevocation(signature, ring.MasterKey, ring.UserIds[i]);
                if (result.IsValid) return 1 + i;
            }
        }
        if (signature.SignatureType is PgpSignatureType.SubkeyBinding or PgpSignatureType.SubkeyRevocation)
        {
            for (int i = 0; i < ring.Subkeys.Count; i++)
            {
                var result = signature.SignatureType == PgpSignatureType.SubkeyBinding
                    ? verifier.VerifySubkeyBinding(signature, ring.MasterKey, ring.Subkeys[i])
                    : verifier.VerifySubkeyRevocation(signature, ring.MasterKey, ring.Subkeys[i]);
                if (result.IsValid) return 1 + ring.UserIds.Count + ring.UserAttributes.Count + i;
            }
        }
        return -1;
    }

    private static int DeclaredTarget(PgpSignatureAssociation association, PgpPublicKeyRing ring)
    {
        if (association.TargetTag == PgpPacketTag.UserId)
            for (int i = 0; i < ring.UserIds.Count; i++)
                if (association.TargetBody.AsSpan().SequenceEqual(ring.UserIds[i].ToArray())) return 1 + i;
        if (association.TargetTag == PgpPacketTag.UserAttribute)
            for (int i = 0; i < ring.UserAttributes.Count; i++)
                if (association.TargetBody.AsSpan().SequenceEqual(ring.UserAttributes[i].ToArray())) return 1 + ring.UserIds.Count + i;
        if (association.TargetTag == PgpPacketTag.PublicSubkey)
            for (int i = 0; i < ring.Subkeys.Count; i++)
                if (association.TargetBody.AsSpan().SequenceEqual(ring.Subkeys[i].ToArray())) return 1 + ring.UserIds.Count + ring.UserAttributes.Count + i;
        return -1;
    }
}
