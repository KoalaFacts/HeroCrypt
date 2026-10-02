using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpSigningKeyPolicySecurityTests
{
    private static readonly DateTimeOffset Created = DateTimeOffset.FromUnixTimeSeconds(1700000000);
    private static readonly byte[] Document = [1, 2, 3, 4];

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void RingVerification_UnboundInjectedKeyCannotVerify(int version, bool inline)
    {
        var owner = Generate(version);
        var child = Generate(version);
        var subkey = AsSubkey(child);
        var ring = owner.PublicKeyRing.AddSubkey(subkey, FakeBinding(version));
        var signature = DocumentSignature(child);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKeyRing(ring);
        var result = inline ? verifier.Verify(new PgpSignedMessage(Document, signature))
            : verifier.Verify(Document, signature);
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void SigningBinding_RequiresSubkeyConsent(int version, bool full)
    {
        var fixture = Fixture(version, back: false);
        Assert.False(VerifyRing(fixture.Ring, fixture.Child).IsValid);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(fixture.Ring);
        if (full) validator.FullValidation(); else validator.VerifySubkeyBindings();
        Assert.False(validator.Validate().IsValid);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void GenuineCrossCertification_IsAcceptedAndAttributesActualSubkey(int version, bool unhashed)
    {
        var fixture = Fixture(version, unhashed: unhashed);
        var ring = PgpPublicKeyRing.Read(fixture.Ring.ToArray());
        var result = VerifyRing(ring, fixture.Child);
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal(fixture.Subkey.ComputeFingerprint(), result.SignerFingerprint);
        Assert.NotEqual(ring.MasterFingerprint, result.SignerFingerprint);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).FullValidation();
        Assert.True(validator.Validate().IsValid);
    }

    [Theory]
    [InlineData(4, 0)]
    [InlineData(4, 1)]
    [InlineData(4, 2)]
    [InlineData(4, 3)]
    [InlineData(4, 4)]
    [InlineData(4, 5)]
    [InlineData(6, 0)]
    [InlineData(6, 1)]
    [InlineData(6, 2)]
    [InlineData(6, 3)]
    [InlineData(6, 4)]
    [InlineData(6, 5)]
    public void CrossCertification_RejectsWrongSignerObjectTypeOrEncoding(int version, int kind)
    {
        var owner = Generate(version);
        var child = Generate(version);
        var other = Generate(version);
        var subkey = AsSubkey(child);
        var back = kind switch
        {
            0 => Sign(owner, PgpSignatureType.PrimaryKeyBinding, owner.MasterPublicKey, subkey),
            1 => Sign(child, PgpSignatureType.PrimaryKeyBinding, other.MasterPublicKey, subkey),
            2 => Sign(child, PgpSignatureType.PrimaryKeyBinding, owner.MasterPublicKey, AsSubkey(other)),
            3 => Sign(child, PgpSignatureType.SubkeyBinding, owner.MasterPublicKey, subkey),
            _ => Sign(child, PgpSignatureType.PrimaryKeyBinding, owner.MasterPublicKey, subkey)
        };
        byte[] body = back.ToArray();
        if (kind == 4) body[^1] ^= 1;
        if (kind == 5) body = [6, 0];
        var binding = Sign(owner, PgpSignatureType.SubkeyBinding, owner.MasterPublicKey, subkey,
            fields: [Flags(PgpKeyCapabilities.Sign), new(PgpSignatureSubpacketType.EmbeddedSignature, false, body)]);
        var ring = owner.PublicKeyRing.AddSubkey(subkey, binding);
        Assert.False(VerifyRing(ring, child).IsValid);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).VerifySubkeyBindings();
        Assert.False(validator.Validate().IsValid);
    }

    [Theory]
    [InlineData(4, 0)]
    [InlineData(4, 1)]
    [InlineData(4, 2)]
    [InlineData(6, 0)]
    [InlineData(6, 1)]
    [InlineData(6, 2)]
    public void BackSignature_RejectsDuplicateFutureOrExpiredEvidence(int version, int kind)
    {
        var owner = Generate(version);
        var child = Generate(version);
        var subkey = AsSubkey(child);
        var back = Sign(child, PgpSignatureType.PrimaryKeyBinding, owner.MasterPublicKey, subkey,
            fields: kind == 2 ? [PgpSignatureSubpacket.CreateSignatureExpirationTime(1)] : [],
            time: kind == 1 ? DateTimeOffset.UtcNow.AddDays(1) : Created);
        var embedded = new PgpSignatureSubpacket(PgpSignatureSubpacketType.EmbeddedSignature, false, back.ToArray());
        var fields = new[] { Flags(PgpKeyCapabilities.Sign), embedded };
        var binding = Sign(owner, PgpSignatureType.SubkeyBinding, owner.MasterPublicKey, subkey,
            fields: kind == 0 ? fields.Append(embedded).ToArray() : fields);
        Assert.False(VerifyRing(owner.PublicKeyRing.AddSubkey(subkey, binding), child).IsValid);
    }

    [Theory]
    [InlineData(4, 0)]
    [InlineData(4, 1)]
    [InlineData(4, 2)]
    [InlineData(4, 3)]
    [InlineData(4, 4)]
    [InlineData(6, 0)]
    [InlineData(6, 1)]
    [InlineData(6, 2)]
    [InlineData(6, 3)]
    [InlineData(6, 4)]
    public void CurrentBinding_DoesNotRollBackToOlderSigningPermission(int version, int kind)
    {
        var fixture = Fixture(version);
        var fields = kind switch
        {
            0 => new[] { Flags(PgpKeyCapabilities.EncryptCommunications) },
            1 => [],
            2 => [Flags(PgpKeyCapabilities.Sign)],
            3 => [Flags(PgpKeyCapabilities.EncryptCommunications), PgpSignatureSubpacket.CreateSignatureExpirationTime(1)],
            _ => [Flags(PgpKeyCapabilities.EncryptCommunications)]
        };
        var binding = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey,
            fields: fields, time: kind == 4 ? DateTimeOffset.UtcNow.AddDays(1) : Created.AddHours(1));
        var result = VerifyRing(fixture.Ring.AddSignature(binding), fixture.Child);
        Assert.Equal(kind == 4, result.IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void PrimaryKey_RequiresCurrentAuthenticatedSigningPermission(int version)
    {
        var owner = Generate(version, PgpKeyCapabilities.Certify);
        Assert.False(VerifyRing(owner.PublicKeyRing, owner).IsValid);
        var current = Sign(owner, PgpSignatureType.DirectKey, owner.MasterPublicKey,
            fields: [Flags(PgpKeyCapabilities.Sign)], time: Created.AddHours(1));
        Assert.True(VerifyRing(owner.PublicKeyRing.AddSignature(current), owner).IsValid);
        var removed = Sign(owner, PgpSignatureType.DirectKey, owner.MasterPublicKey, time: Created.AddHours(2));
        Assert.False(VerifyRing(owner.PublicKeyRing.AddSignature(current).AddSignature(removed), owner).IsValid);
    }

    [Theory]
    [InlineData(4, 0)]
    [InlineData(4, 1)]
    [InlineData(4, 2)]
    [InlineData(4, 3)]
    [InlineData(6, 0)]
    [InlineData(6, 1)]
    [InlineData(6, 2)]
    [InlineData(6, 3)]
    public void KeyFlags_UnsignedDuplicateOrUnknownBitsCannotAuthorizeSigning(int version, int kind)
    {
        var fixture = Fixture(version);
        var back = Sign(fixture.Child, PgpSignatureType.PrimaryKeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey);
        var embedded = new PgpSignatureSubpacket(PgpSignatureSubpacketType.EmbeddedSignature, false, back.ToArray());
        PgpSignatureSubpacket[] flags = kind switch
        {
            0 => [],
            1 => [Flags(PgpKeyCapabilities.Sign), Flags(PgpKeyCapabilities.EncryptCommunications)],
            2 => [new(PgpSignatureSubpacketType.KeyFlags, false, new byte[] { 0x42 })],
            _ => [new(PgpSignatureSubpacketType.KeyFlags, false, new byte[] { 2, 1 })]
        };
        var current = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey,
            fields: flags.Append(embedded).ToArray(), unhashed: kind == 0 ? [Flags(PgpKeyCapabilities.Sign)] : [], time: Created.AddHours(1));
        Assert.False(VerifyRing(fixture.Ring.AddSignature(current), fixture.Child).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void KeyFlags_ZeroExtensionOctetsAreSupported(int version)
    {
        var owner = Generate(version);
        var policy = Sign(owner, PgpSignatureType.DirectKey, owner.MasterPublicKey,
            fields: [new(PgpSignatureSubpacketType.KeyFlags, false, new byte[] { 2, 0, 0 })], time: Created.AddHours(1));
        Assert.True(VerifyRing(owner.PublicKeyRing.AddSignature(policy), owner).IsValid);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void MixingRawAndRingKeys_DoesNotBypassConfiguredRingPolicy(int version, bool rawFirst)
    {
        var fixture = Fixture(version, back: false);
        using var verifier = PgpSignatureVerifier.Create();
        if (rawFirst) verifier.WithPublicKey(fixture.Child.MasterPublicKey);
        verifier.WithPublicKeyRing(fixture.Ring);
        if (!rawFirst) verifier.WithPublicKey(fixture.Child.MasterPublicKey);
        Assert.False(verifier.Verify(Document, DocumentSignature(fixture.Child)).IsValid);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void RingVerification_RejectsAuthenticatedPrimaryOrSubkeyRevocation(int version, bool subkey)
    {
        var fixture = Fixture(version);
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(fixture.Owner.MasterSecretKey);
        var revocation = subkey ? revoker.WithSubkey(fixture.Subkey).RevokeSubkey() : revoker.RevokeKey();
        Assert.False(VerifyRing(fixture.Ring.AddSignature(revocation), fixture.Child).IsValid);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void RingVerification_RejectsExpiredPrimaryOrSubkey(int version, bool subkey)
    {
        var fixture = Fixture(version);
        PgpSignaturePacket current;
        if (subkey)
        {
            var back = Sign(fixture.Child, PgpSignatureType.PrimaryKeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey);
            current = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey,
                fields: [Flags(PgpKeyCapabilities.Sign), PgpSignatureSubpacket.CreateKeyExpirationTime(TimeSpan.FromSeconds(1)),
                    new(PgpSignatureSubpacketType.EmbeddedSignature, false, back.ToArray())], time: Created.AddHours(1));
        }
        else current = Sign(fixture.Owner, PgpSignatureType.DirectKey, fixture.Owner.MasterPublicKey,
            fields: [Flags(PgpKeyCapabilities.Sign), PgpSignatureSubpacket.CreateKeyExpirationTime(TimeSpan.FromSeconds(1))], time: Created.AddHours(1));
        Assert.False(VerifyRing(fixture.Ring.AddSignature(current), fixture.Child).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void GeneratedEncryptionSubkey_DoesNotRequireSigningConsent(int version)
    {
        var pair = PgpKeyGenerator.Create().WithCreationTime(Created).WithVersion((byte)version).WithKeySize(2048)
            .WithUserId("owner@example.invalid").WithEncryptionSubkey().GenerateRsa();
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(pair.PublicKeyRing).FullValidation();
        Assert.True(validator.Validate().IsValid);
        Assert.True(VerifyRing(pair.PublicKeyRing, pair).IsValid);
    }

    [Fact]
    public void Ed25519CrossCertification_UsesIndependentRfcHashes()
    {
        var fixture = Fixture(6, ed: true);
        Assert.True(VerifyRing(PgpPublicKeyRing.Read(fixture.Ring.ToArray()), fixture.Child).IsValid);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(fixture.Ring).FullValidation();
        Assert.True(validator.Validate().IsValid);
    }

    [Theory]
    [InlineData(4, false, 0)]
    [InlineData(4, false, 1)]
    [InlineData(4, false, 2)]
    [InlineData(4, true, 0)]
    [InlineData(4, true, 1)]
    [InlineData(4, true, 2)]
    [InlineData(6, false, 0)]
    [InlineData(6, false, 1)]
    [InlineData(6, false, 2)]
    [InlineData(6, true, 0)]
    [InlineData(6, true, 1)]
    [InlineData(6, true, 2)]
    public void UnhashedMetadata_CannotRestoreOlderSigningPermission(int version, bool subkey, int kind)
    {
        var fixture = Fixture(version);
        var unsigned = kind switch
        {
            0 => PgpSignatureSubpacket.CreateIssuerKeyId(new byte[8]),
            1 => new PgpSignatureSubpacket(PgpSignatureSubpacketType.NotationData, true, new byte[] { 0 }),
            _ => new PgpSignatureSubpacket(PgpSignatureSubpacketType.SignatureCreationTime, false, new byte[] { 0 })
        };
        var removed = Sign(fixture.Owner, subkey ? PgpSignatureType.SubkeyBinding : PgpSignatureType.DirectKey,
            fixture.Owner.MasterPublicKey, subkey ? fixture.Subkey : null,
            fields: [Flags(PgpKeyCapabilities.EncryptCommunications)], unhashed: [unsigned], time: Created.AddHours(1));
        Assert.False(VerifyRing(fixture.Ring.AddSignature(removed), subkey ? fixture.Child : fixture.Owner).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void PrimaryBindingPrimitive_VerifiesExactPairAndActualSubkey(int version)
    {
        var fixture = Fixture(version);
        using var verifier = PgpSignatureVerifier.Create();
        var back = Sign(fixture.Child, PgpSignatureType.PrimaryKeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey);
        var result = verifier.VerifyPrimaryKeyBinding(back, fixture.Owner.MasterPublicKey, fixture.Subkey);
        Assert.True(result.IsValid, result.ErrorMessage);
        Assert.Equal(fixture.Subkey.ComputeFingerprint(), result.SignerFingerprint);
        Assert.False(verifier.VerifyPrimaryKeyBinding(back, Generate(version).MasterPublicKey, fixture.Subkey).IsValid);
        Assert.False(verifier.VerifyPrimaryKeyBinding(back, fixture.Owner.MasterPublicKey, AsSubkey(Generate(version))).IsValid);
        Assert.False(verifier.VerifyPrimaryKeyBinding(DocumentSignature(fixture.Child), fixture.Owner.MasterPublicKey, fixture.Subkey).IsValid);
    }

    [Fact]
    public void SigningOnlySubkey_RequiresConsentEvenWithNonSigningFlags()
    {
        var fixture = Fixture(6, back: false, ed: true);
        var binding = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey,
            fields: [Flags(PgpKeyCapabilities.EncryptCommunications)], time: Created.AddHours(1));
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(fixture.Ring.AddSignature(binding)).VerifySubkeyBindings();
        Assert.False(validator.Validate().IsValid);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void EqualTimeBindingPolicies_AreRejectedInEitherOrder(int version, bool reverse)
    {
        var fixture = Fixture(version);
        var binding = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey,
            fields: [Flags(PgpKeyCapabilities.EncryptCommunications)]);
        var signatures = fixture.Ring.Signatures.Append(binding).ToArray();
        if (reverse) Array.Reverse(signatures);
        var ring = new PgpPublicKeyRing(fixture.Ring.MasterKey, subkeys: fixture.Ring.Subkeys, userIds: fixture.Ring.UserIds, signatures: signatures);
        Assert.False(VerifyRing(ring, fixture.Child).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void CertifyOnlyPrimary_CanAuthorizeSigningSubkey(int version)
    {
        var fixture = Fixture(version);
        var policy = Sign(fixture.Owner, PgpSignatureType.DirectKey, fixture.Owner.MasterPublicKey,
            fields: [Flags(PgpKeyCapabilities.Certify)], time: Created.AddHours(1));
        var ring = fixture.Ring.AddSignature(policy);
        Assert.True(VerifyRing(ring, fixture.Child).IsValid);
        Assert.False(VerifyRing(ring, fixture.Owner).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void RevokedSibling_DoesNotRevokeActualSigner(int version)
    {
        var fixture = Fixture(version);
        var sibling = AsSubkey(Generate(version));
        var binding = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, sibling,
            fields: [Flags(PgpKeyCapabilities.EncryptCommunications)]);
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(fixture.Owner.MasterSecretKey).WithSubkey(sibling);
        var ring = fixture.Ring.AddSubkey(sibling, binding).AddSignature(revoker.RevokeSubkey());
        Assert.True(VerifyRing(ring, fixture.Child).IsValid);
        Assert.True(VerifyRing(ring, fixture.Owner).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void InvalidRevocationEvidence_CannotEstablishRingAcceptance(int version)
    {
        var fixture = Fixture(version);
        var invalid = new PgpSignaturePacket((byte)version, PgpSignatureType.KeyRevocation, 1, 8, [], [], 0,
            new byte[] { 0 }, version == 6 ? new byte[16] : []);
        Assert.False(VerifyRing(fixture.Ring.AddSignature(invalid), fixture.Child).IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void BindingValidation_AtTimeSelectsCurrentConsent(int version)
    {
        var fixture = Fixture(version);
        var missing = Sign(fixture.Owner, PgpSignatureType.SubkeyBinding, fixture.Owner.MasterPublicKey, fixture.Subkey,
            fields: [Flags(PgpKeyCapabilities.Sign)], time: Created.AddHours(1));
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(fixture.Ring.AddSignature(missing)).VerifySubkeyBindings();
        Assert.True(validator.AtTime(Created.AddSeconds(1)).Validate().IsValid);
        Assert.False(validator.AtTime(Created.AddHours(2)).Validate().IsValid);
    }

    private static PgpSignatureSubpacket Flags(PgpKeyCapabilities flags) => PgpSignatureSubpacket.CreateKeyFlags(flags);
    private static PgpPublicKeyPacket AsSubkey(PgpKeyGeneratorResult pair) => PgpPublicKeyPacket.Read(pair.MasterPublicKey.ToArray(), true);
    private static PgpKeyGeneratorResult Generate(int version, PgpKeyCapabilities flags = PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign, bool ed = false)
    {
        var generator = PgpKeyGenerator.Create().WithCreationTime(Created).WithVersion((byte)version).WithUserId("owner@example.invalid").WithKeySize(2048).WithKeyFlags(flags);
        return ed ? generator.GenerateEd25519() : generator.GenerateRsa();
    }
    private static (PgpKeyGeneratorResult Owner, PgpKeyGeneratorResult Child, PgpPublicKeyPacket Subkey, PgpPublicKeyRing Ring) Fixture(int version, bool back = true, bool unhashed = false, bool ed = false)
    {
        var owner = Generate(version, ed: ed);
        var child = Generate(version, ed: ed);
        var subkey = AsSubkey(child);
        var fields = new List<PgpSignatureSubpacket> { Flags(PgpKeyCapabilities.Sign) };
        PgpSignatureSubpacket[] unsigned = [];
        if (back)
        {
            var consent = Sign(child, PgpSignatureType.PrimaryKeyBinding, owner.MasterPublicKey, subkey);
            var embedded = new PgpSignatureSubpacket(PgpSignatureSubpacketType.EmbeddedSignature, false, consent.ToArray());
            if (unhashed) unsigned = [embedded]; else fields.Add(embedded);
        }
        var binding = Sign(owner, PgpSignatureType.SubkeyBinding, owner.MasterPublicKey, subkey, fields: fields.ToArray(), unhashed: unsigned);
        return (owner, child, subkey, owner.PublicKeyRing.AddSubkey(subkey, binding));
    }
    private static PgpSignatureResult VerifyRing(PgpPublicKeyRing ring, PgpKeyGeneratorResult signer)
    {
        using var verifier = PgpSignatureVerifier.Create().WithPublicKeyRing(ring);
        return verifier.Verify(Document, DocumentSignature(signer));
    }
    private static PgpSignaturePacket DocumentSignature(PgpKeyGeneratorResult pair)
    {
        var signature = Sign(pair, PgpSignatureType.BinaryDocument, pair.MasterPublicKey);
        using var raw = PgpSignatureVerifier.Create().WithPublicKey(pair.MasterPublicKey);
        Assert.True(raw.Verify(Document, signature).IsValid);
        return signature;
    }
    private static PgpSignaturePacket FakeBinding(int version) => version == 4
        ? PgpSignaturePacket.CreateV4(PgpSignatureType.SubkeyBinding, 1, 8, [], [], 0, new byte[] { 0 })
        : PgpSignaturePacket.CreateV6(PgpSignatureType.SubkeyBinding, 1, 8, [], [], 0, new byte[16], new byte[] { 0 });

    // Independent RFC 9580 framing; platform RSA and Bouncy Castle Ed25519 verify every fixture.
    private static PgpSignaturePacket Sign(PgpKeyGeneratorResult signer, PgpSignatureType type, PgpPublicKeyPacket primary,
        PgpPublicKeyPacket? subkey = null, PgpSignatureSubpacket[]? fields = null, PgpSignatureSubpacket[]? unhashed = null, DateTimeOffset? time = null)
    {
        byte version = signer.MasterPublicKey.Version;
        byte algorithm = (byte)signer.MasterPublicKey.Algorithm;
        var packets = new[] { PgpSignatureSubpacket.CreateSignatureCreationTime(time ?? Created),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, signer.MasterPublicKey.ComputeFingerprint()) }.Concat(fields ?? []).ToArray();
        var hashed = PgpSignatureSubpacket.WriteAll(packets);
        var material = type == PgpSignatureType.BinaryDocument ? Document : KeyBytes(primary, version);
        if (subkey.HasValue) material = material.Concat(KeyBytes(subkey.Value, version)).ToArray();
        var header = new byte[version == 4 ? 6 : 8];
        header[0] = version; header[1] = (byte)type; header[2] = algorithm; header[3] = 8;
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)hashed.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashed.Length);
        var trailer = new byte[] { version, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)(header.Length + hashed.Length));
        byte[] salt = version == 6 ? new byte[16] : [];
        var digest = SHA256.HashData(salt.Concat(material).Concat(header).Concat(hashed).Concat(trailer).ToArray());
        byte[] encoded;
        if (algorithm == (byte)PgpPublicKeyAlgorithm.Ed25519)
        {
            encoded = new byte[64];
            Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Sign(signer.MasterSecretKey.SecretKeyMaterial.ToArray(), 0, digest, 0, digest.Length, encoded, 0);
            Assert.True(Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Verify(encoded, 0, signer.MasterPublicKey.ReadNativePublicKey(), 0, digest, 0, digest.Length));
        }
        else
        {
            var (d, p, q, _) = signer.MasterSecretKey.ReadRsaSecretKey();
            var (n, e) = signer.MasterPublicKey.ReadRsaKey();
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RsaCore().ToRsaParameters(new RsaPrivateKey(n, d, p, q, e)));
            var raw = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(rsa.VerifyHash(digest, raw, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            encoded = new byte[Mpi.GetEncodedLength(raw)]; Mpi.Write(raw, encoded);
        }
        var hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(digest);
        return version == 4 ? PgpSignaturePacket.CreateV4(type, algorithm, 8, packets, unhashed ?? [], hashPrefix, encoded)
            : PgpSignaturePacket.CreateV6(type, algorithm, 8, packets, unhashed ?? [], hashPrefix, salt, encoded);
    }
    private static byte[] KeyBytes(PgpPublicKeyPacket key, byte version)
    {
        var body = key.ToArray();
        var prefix = new byte[version == 4 ? 3 : 5]; prefix[0] = version == 4 ? (byte)0x99 : (byte)0x9B;
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(1), checked((ushort)body.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)body.Length);
        return prefix.Concat(body).ToArray();
    }
}
