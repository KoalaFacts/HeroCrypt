using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpKeyMetadataSecurityTests
{
    private static readonly DateTimeOffset Created = DateTimeOffset.FromUnixTimeSeconds(1700000000);
    private static readonly PgpSignatureSubpacketType[] Types = [PgpSignatureSubpacketType.PreferredSymmetricAlgorithms,
        PgpSignatureSubpacketType.PreferredHashAlgorithms, PgpSignatureSubpacketType.PreferredCompressionAlgorithms,
        PgpSignatureSubpacketType.PreferredAeadAlgorithms];
    private static readonly byte[][] Preferences = [[9, 8], [10, 8], [2, 0], [9, 3]];

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void Preferences_FuturePolicyIsNotEffectiveAndExpiredNewestDoesNotRollBack(int version, bool expired)
    {
        var owner = Generate(version, true);
        var fields = Types.Select((_, i) => Field(i, [1, 1])).ToList();
        if (expired) fields.Add(new(PgpSignatureSubpacketType.SignatureExpirationTime, false, new byte[] { 0, 0, 0, 1 }));
        var current = Sign(owner, version == 6 ? PgpSignatureType.DirectKey : PgpSignatureType.PositiveCertification,
            fields.ToArray(), version == 6 ? null : owner.PublicKeyRing.UserIds[0],
            time: expired ? Created.AddHours(1) : DateTimeOffset.UtcNow.AddDays(2));
        var ring = Ring(owner, signatures: new[] { current }.Concat(owner.PublicKeyRing.Signatures).ToArray());
        for (int kind = 0; kind < 4; kind++)
        {
            if (expired) Assert.Throws<InvalidOperationException>(() => ReadPreference(ring, kind));
            else Assert.Equal(Preferences[kind], ReadPreference(ring, kind));
        }
    }

    [Fact]
    public void Preferences_EqualTimePolicyConflictFailsClosed()
    {
        var owner = Generate(4, true);
        var a = Sign(owner, PgpSignatureType.PositiveCertification, [Field(0, [9])], owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        var b = Sign(owner, PgpSignatureType.PositiveCertification, [Field(0, [7])], owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        Assert.Throws<InvalidOperationException>(() => owner.PublicKeyRing.AddSignature(a).AddSignature(b).GetPreferredSymmetricAlgorithms());
    }

    [Fact]
    public void Preferences_V6RequiresDirectKeyPolicy()
    {
        var owner = Generate(6, true);
        var ring = Ring(owner, signatures: owner.PublicKeyRing.Signatures.Where(x => x.SignatureType != PgpSignatureType.DirectKey).ToArray());
        Assert.Throws<InvalidOperationException>(ring.GetPreferredSymmetricAlgorithms);
    }

    [Fact]
    public void Preferences_ThirdPartyCertificationCannotBecomeOwnerPolicy()
    {
        var owner = Generate(4, true);
        var other = Generate(4);
        var foreign = Sign(other, PgpSignatureType.PositiveCertification, [Field(0, [7])], owner.PublicKeyRing.UserIds[0], target: owner.MasterPublicKey);
        var ring = Ring(owner, signatures: new[] { foreign }.Concat(owner.PublicKeyRing.Signatures).ToArray());
        Assert.Equal(Preferences[0], ring.GetPreferredSymmetricAlgorithms());
    }

    [Fact]
    public void AeadPreference_UsesRfc9580Type39()
    {
        Assert.Equal(39, (byte)PgpSignatureSubpacket.CreatePreferredAeadAlgorithms([9, 3]).Type);
        var owner = Generate(4);
        var cert = Sign(owner, PgpSignatureType.PositiveCertification,
            [new((PgpSignatureSubpacketType)39, false, new byte[] { 9, 3 })], owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        Assert.Equal(new byte[] { 9, 3 }, owner.PublicKeyRing.AddSignature(cert).GetPreferredAeadAlgorithms());
    }

    [Fact]
    public void AeadPreference_ReservedLegacyType34CannotEstablishPolicy()
    {
        var owner = Generate(4);
        var cert = Sign(owner, PgpSignatureType.PositiveCertification,
            [new((PgpSignatureSubpacketType)34, false, new byte[] { 9, 3 })], owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        Assert.Throws<InvalidOperationException>(() => owner.PublicKeyRing.AddSignature(cert).GetPreferredAeadAlgorithms());
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(1, true)]
    [InlineData(2, false)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(3, true)]
    public void Preferences_UnsignedPacketCannotOverridePolicy(int kind, bool fakeFirst)
    {
        var owner = Generate(4, true);
        var fake = PgpSignaturePacket.CreateV4(PgpSignatureType.PositiveCertification, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(Created.AddHours(1)), Field(kind, [1, 1])], [], 0, new byte[] { 0 });
        var signatures = fakeFirst ? new[] { fake }.Concat(owner.PublicKeyRing.Signatures).ToArray()
            : owner.PublicKeyRing.Signatures.Append(fake).ToArray();
        var ring = PgpPublicKeyRing.Read(Ring(owner, signatures: signatures).ToArray());
        Assert.Equal(Preferences[kind], ReadPreference(ring, kind));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Preferences_MissingAuthenticatedPolicyThrows(int kind)
    {
        var owner = Generate(4);
        var fake = PgpSignaturePacket.CreateV4(PgpSignatureType.PositiveCertification, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(Created), Field(kind, [1, 1])], [], 0, new byte[] { 0 });
        var ring = Ring(owner, signatures: [fake]);
        Assert.Throws<InvalidOperationException>(() => ReadPreference(ring, kind));
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void Preferences_NewestPolicyReplacesOrRemovesOldValues(int version, bool remove)
    {
        var owner = Generate(version, true);
        var fields = remove ? [] : Types.Select((_, i) => Field(i, [1, 1])).ToArray();
        var latest = Sign(owner, version == 6 ? PgpSignatureType.DirectKey : PgpSignatureType.PositiveCertification,
            fields, version == 6 ? null : owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        var ring = PgpPublicKeyRing.Read(owner.PublicKeyRing.AddSignature(latest).ToArray());
        for (int kind = 0; kind < 4; kind++) Assert.Equal(remove ? null : [1, 1], ReadPreference(ring, kind));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Preferences_ConflictingUserPoliciesNeedAnAuthenticatedPrimary(bool marked)
    {
        var owner = Generate(4, true);
        var second = new PgpUserIdPacket("second@example.invalid");
        var fields = Types.Select((_, i) => Field(i, [1, 1])).ToList();
        if (marked) fields.Add(new(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { 1 }));
        var cert = Sign(owner, PgpSignatureType.PositiveCertification, fields.ToArray(), second);
        var ring = PgpPublicKeyRing.Read(owner.PublicKeyRing.AddUserId(second, cert).ToArray());
        if (marked)
        {
            Assert.Equal(second.UserId, ring.GetPrimaryUserId()!.Value.UserId);
            for (int kind = 0; kind < 4; kind++) Assert.Equal(new byte[] { 1, 1 }, ReadPreference(ring, kind));
        }
        else for (int kind = 0; kind < 4; kind++) Assert.Throws<InvalidOperationException>(() => ReadPreference(ring, kind));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PrimaryUserId_FalseAndSupersededMarkersDoNotSelectAUser(bool superseded)
    {
        var owner = Generate(4, true);
        var second = new PgpUserIdPacket("second@example.invalid");
        var first = Sign(owner, PgpSignatureType.PositiveCertification,
            [new(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { superseded ? (byte)1 : (byte)0 })], second);
        var ring = owner.PublicKeyRing.AddUserId(second, first);
        if (superseded) ring = ring.AddSignature(Sign(owner, PgpSignatureType.PositiveCertification,
            [new(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { 0 })], second, time: Created.AddHours(1)));
        Assert.Equal(owner.PublicKeyRing.UserIds[0].UserId, ring.GetPrimaryUserId()!.Value.UserId);
    }

    [Fact]
    public void PrimaryUserId_UncertifiedInjectedUserIsNotSelected()
    {
        var owner = Generate(4);
        var ring = Ring(owner, users: [new("attacker@example.invalid"), owner.PublicKeyRing.UserIds[0]]);
        Assert.Equal(owner.PublicKeyRing.UserIds[0].UserId, ring.GetPrimaryUserId()!.Value.UserId);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Metadata_MalformedCurrentFieldsFailClosed(int kind)
    {
        var owner = Generate(4);
        var fields = kind switch
        {
            0 => new[] { Field(0, [9]), Field(0, [7]) },
            1 => [Field(3, [9, 3, 9])],
            2 => [new PgpSignatureSubpacket(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { 1, 1 })],
            _ => [ new PgpSignatureSubpacket(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { 0 }),
                         new PgpSignatureSubpacket(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { 1 }) ]
        };
        var latest = Sign(owner, PgpSignatureType.PositiveCertification, fields, owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        var ring = owner.PublicKeyRing.AddSignature(latest);
        if (kind < 2) Assert.Throws<InvalidOperationException>(() => ReadPreference(ring, kind == 0 ? 0 : 3));
        else Assert.Throws<InvalidOperationException>(() => ring.GetPrimaryUserId());
    }

    [Fact]
    public void Preferences_UnhashedFieldsDoNotBecomePolicy()
    {
        var owner = Generate(4);
        var cert = Sign(owner, PgpSignatureType.PositiveCertification, [], owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1), unhashed: [Field(0, [9])]);
        Assert.Null(owner.PublicKeyRing.AddSignature(cert).GetPreferredSymmetricAlgorithms());
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(4, true)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void UserSignatures_AreAuthenticatedForTheExactUser(int version, bool reimport)
    {
        var owner = Generate(version);
        var second = new PgpUserIdPacket("second@example.invalid");
        var other = Sign(owner, PgpSignatureType.PositiveCertification, [], second);
        var attacker = Generate(version);
        var foreign = Sign(attacker, PgpSignatureType.PositiveCertification, [], owner.PublicKeyRing.UserIds[0], target: owner.MasterPublicKey);
        var ring = owner.PublicKeyRing.AddUserId(second, other).AddSignature(foreign);
        if (reimport) ring = PgpPublicKeyRing.Read(ring.ToArray());
        Assert.Equal(owner.PublicKeyRing.Signatures.Single(x => x.SignatureType == PgpSignatureType.PositiveCertification).ToArray(), Assert.Single(ring.GetSignaturesForUserId(0)).ToArray());
        Assert.Equal(other.ToArray(), Assert.Single(ring.GetSignaturesForUserId(1)).ToArray());
        Assert.Empty(ring.GetSignaturesForUserId(-1));
        Assert.Empty(ring.GetSignaturesForUserId(2));
        Assert.Contains(ring.Signatures, x => x.ToArray().SequenceEqual(foreign.ToArray()));
    }

    [Fact]
    public void UserRevocations_AreScopedToTheirSignedUser()
    {
        var owner = Generate(4);
        var second = new PgpUserIdPacket("second@example.invalid");
        var cert = Sign(owner, PgpSignatureType.PositiveCertification, [], second);
        var revocation = Sign(owner, PgpSignatureType.CertificationRevocation, [], second);
        var ring = owner.PublicKeyRing.AddUserId(second, cert).AddSignature(revocation);
        Assert.DoesNotContain(ring.GetSignaturesForUserId(0), x => x.SignatureType == PgpSignatureType.CertificationRevocation);
        Assert.Contains(ring.GetSignaturesForUserId(1), x => x.ToArray().SequenceEqual(revocation.ToArray()));
        Assert.Throws<InvalidOperationException>(ring.GetPreferredSymmetricAlgorithms);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SubkeySignatures_AreAuthenticatedForTheExactPair(bool reimport)
    {
        var (owner, ring, _, secondBinding, secondRevocation) = MultiObjectRing();
        if (reimport) ring = PgpPublicKeyRing.Read(ring.ToArray());
        Assert.Single(ring.GetSubkeyBindingSignatures(ring.Subkeys[0].GetKeyId()));
        var second = ring.GetSubkeyBindingSignatures(ring.Subkeys[1].GetKeyId()).ToArray();
        Assert.Equal(2, second.Length);
        Assert.Contains(second, x => x.ToArray().SequenceEqual(secondBinding.ToArray()));
        Assert.Contains(second, x => x.ToArray().SequenceEqual(secondRevocation.ToArray()));
        Assert.Empty(ring.GetSubkeyBindingSignatures(owner.MasterPublicKey.GetKeyId()));
        Assert.Empty(ring.GetSubkeyBindingSignatures(new byte[7]));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Export_InterleavesEachSignatureOnceWithItsActualObject(bool secret, bool reimport)
    {
        var (owner, pub, priv, _, _) = MultiObjectRing();
        if (reimport) { pub = PgpPublicKeyRing.Read(pub.ToArray()); priv = PgpSecretKeyRing.Read(priv.ToArray()); }
        var bytes = secret ? priv.ToArray() : pub.ToArray();
        Assert.Equal(secret ? priv.GetEncodedLength() : pub.GetEncodedLength(), bytes.Length);
        AssertLayout(bytes, owner.MasterPublicKey, pub.Signatures.Count);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ImportedThirdPartyCertification_KeepsDeclaredTargetWithoutBecomingSelfPolicy(bool secret, bool collection)
    {
        var owner = Generate(4);
        var attacker = Generate(4);
        var second = new PgpUserIdPacket("second@example.invalid");
        var secondCert = Sign(owner, PgpSignatureType.PositiveCertification, [], second);
        var foreign = Sign(attacker, PgpSignatureType.PositiveCertification, [], owner.PublicKeyRing.UserIds[0], target: owner.MasterPublicKey);
        using var stream = new MemoryStream();
        using (var writer = new PgpPacketWriter(stream))
        {
            if (secret) owner.MasterSecretKey.WriteTo(writer); else owner.MasterPublicKey.WriteTo(writer);
            owner.PublicKeyRing.UserIds[0].WriteTo(writer);
            owner.PublicKeyRing.Signatures[0].WriteTo(writer);
            foreign.WriteTo(writer);
            second.WriteTo(writer);
            secondCert.WriteTo(writer);
        }
        PgpPublicKeyRing ring;
        byte[] exported;
        var input = stream.ToArray();
        if (secret)
        {
            var priv = collection ? PgpSecretKeyRingCollection.Read(input).KeyRings[0] : PgpSecretKeyRing.Read(input);
            priv = priv.AddSignature(Sign(owner, PgpSignatureType.DirectKey, [], time: Created.AddHours(1)));
            exported = priv.ToArray();
            ring = priv.ExtractPublicKeyRing();
            AssertDeclaredTarget(ring.ToArray(), foreign, owner.PublicKeyRing.UserIds[0]);
        }
        else
        {
            ring = collection ? PgpPublicKeyRingCollection.Read(input).KeyRings[0] : PgpPublicKeyRing.Read(input);
            ring = ring.AddSignature(Sign(owner, PgpSignatureType.DirectKey, [], time: Created.AddHours(1)));
            exported = ring.ToArray();
        }
        Assert.Single(ring.GetSignaturesForUserId(0));
        AssertDeclaredTarget(exported, foreign, owner.PublicKeyRing.UserIds[0]);
    }

    [Fact]
    public void ImportedMisplacedCertification_UsesCryptographicTarget()
    {
        var owner = Generate(4);
        var second = new PgpUserIdPacket("second@example.invalid");
        var secondCert = Sign(owner, PgpSignatureType.PositiveCertification, [], second);
        using var stream = new MemoryStream();
        using (var writer = new PgpPacketWriter(stream))
        {
            owner.MasterPublicKey.WriteTo(writer);
            owner.PublicKeyRing.UserIds[0].WriteTo(writer);
            secondCert.WriteTo(writer);
            second.WriteTo(writer);
            owner.PublicKeyRing.Signatures[0].WriteTo(writer);
        }
        var ring = PgpPublicKeyRing.Read(stream.ToArray());
        Assert.Equal(secondCert.ToArray(), Assert.Single(ring.GetSignaturesForUserId(1)).ToArray());
        AssertLayout(ring.ToArray(), owner.MasterPublicKey, 2);
    }

    [Fact]
    public void ImportedRepeatedRawSignatures_PreserveEachDeclaredOccurrence()
    {
        var owner = Generate(4);
        var second = new PgpUserIdPacket("second@example.invalid");
        var raw = PgpSignaturePacket.CreateV4(PgpSignatureType.PositiveCertification, 1, 8, [], [], 0, new byte[] { 0 });
        using var stream = new MemoryStream();
        using (var writer = new PgpPacketWriter(stream))
        {
            owner.MasterPublicKey.WriteTo(writer);
            owner.PublicKeyRing.UserIds[0].WriteTo(writer);
            raw.WriteTo(writer);
            second.WriteTo(writer);
            raw.WriteTo(writer);
        }
        var ring = PgpPublicKeyRing.Read(stream.ToArray());
        using var output = new MemoryStream(ring.ToArray());
        using var reader = new PgpPacketReader(output);
        var users = new List<string>();
        string? user = null;
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.UserId) user = PgpUserIdPacket.Read(body.Span).UserId;
            if (tag == PgpPacketTag.Signature) users.Add(user!);
        }
        Assert.Equal(new[] { owner.PublicKeyRing.UserIds[0].UserId, second.UserId }, users);
        Assert.Empty(ring.GetSignaturesForUserId(0));
        Assert.Empty(ring.GetSignaturesForUserId(1));
    }

    [Fact]
    public void PrimaryUserId_EqualTimeConflictingMarkersFailClosed()
    {
        var owner = Generate(4);
        var second = new PgpUserIdPacket("second@example.invalid");
        PgpSignatureSubpacket[] fields = [new(PgpSignatureSubpacketType.PrimaryUserId, false, new byte[] { 1 })];
        var firstCert = Sign(owner, PgpSignatureType.PositiveCertification, fields, owner.PublicKeyRing.UserIds[0], time: Created.AddHours(1));
        var secondCert = Sign(owner, PgpSignatureType.PositiveCertification, fields, second, time: Created.AddHours(1));
        var ring = owner.PublicKeyRing.AddSignature(firstCert).AddUserId(second, secondCert);
        Assert.Throws<InvalidOperationException>(() => ring.GetPrimaryUserId());
        Assert.Throws<InvalidOperationException>(ring.GetPreferredSymmetricAlgorithms);
    }

    [Fact]
    public void Preferences_Ed25519V6DirectKeyPolicyIsAuthenticated()
    {
        var owner = PgpKeyGenerator.Create().WithCreationTime(Created).WithUserId("owner@example.invalid")
            .WithPreferredSymmetricAlgorithms(Preferences[0]).WithPreferredHashAlgorithms(Preferences[1])
            .WithPreferredCompressionAlgorithms(Preferences[2]).WithPreferredAeadAlgorithms(Preferences[3])
            .GenerateEd25519();
        var ring = PgpPublicKeyRing.Read(owner.PublicKeyRing.ToArray());
        Assert.Equal(6, ring.Version);
        for (int kind = 0; kind < 4; kind++) Assert.Equal(Preferences[kind], ReadPreference(ring, kind));
    }

    private static PgpKeyGeneratorResult Generate(int version, bool preferences = false)
    {
        var generator = PgpKeyGenerator.Create().WithVersion((byte)version).WithCreationTime(Created).WithUserId("owner@example.invalid").WithKeySize(2048);
        if (preferences) generator.WithPreferredSymmetricAlgorithms(Preferences[0]).WithPreferredHashAlgorithms(Preferences[1])
            .WithPreferredCompressionAlgorithms(Preferences[2]).WithPreferredAeadAlgorithms(Preferences[3]);
        return generator.GenerateRsa();
    }

    private static PgpSignatureSubpacket Field(int kind, byte[] data) => new(Types[kind], false, data);
    private static byte[]? ReadPreference(PgpPublicKeyRing ring, int kind) => kind switch
    {
        0 => ring.GetPreferredSymmetricAlgorithms(),
        1 => ring.GetPreferredHashAlgorithms(),
        2 => ring.GetPreferredCompressionAlgorithms(),
        _ => ring.GetPreferredAeadAlgorithms()
    };
    private static PgpPublicKeyRing Ring(PgpKeyGeneratorResult owner, IReadOnlyList<PgpUserIdPacket>? users = null,
        IReadOnlyList<PgpSignaturePacket>? signatures = null) => new(owner.MasterPublicKey, [], users ?? owner.PublicKeyRing.UserIds, [], signatures ?? owner.PublicKeyRing.Signatures);

    private static (PgpKeyGeneratorResult Owner, PgpPublicKeyRing Public, PgpSecretKeyRing Secret, PgpSignaturePacket Binding, PgpSignaturePacket Revocation) MultiObjectRing()
    {
        var owner = Generate(6);
        var first = PgpKeyGenerator.Create().WithCreationTime(Created).WithUserId("first@example.invalid").GenerateEd25519WithX25519Subkey();
        var second = PgpKeyGenerator.Create().WithCreationTime(Created).WithUserId("second@example.invalid").GenerateEd25519WithX25519Subkey();
        var secondUser = new PgpUserIdPacket("second@example.invalid");
        var a = Sign(owner, PgpSignatureType.SubkeyBinding, [], subkey: first.PublicKeyRing.Subkeys[0]);
        var b = Sign(owner, PgpSignatureType.SubkeyBinding, [], subkey: second.PublicKeyRing.Subkeys[0]);
        var revoked = Sign(owner, PgpSignatureType.SubkeyRevocation, [], subkey: second.PublicKeyRing.Subkeys[0]);
        var signatures = owner.PublicKeyRing.Signatures.Concat([Sign(owner, PgpSignatureType.PositiveCertification, [], secondUser), a, b, revoked]).ToArray();
        var pub = new PgpPublicKeyRing(owner.MasterPublicKey, [first.PublicKeyRing.Subkeys[0], second.PublicKeyRing.Subkeys[0]], [owner.PublicKeyRing.UserIds[0], secondUser], [], signatures);
        var secret = new PgpSecretKeyRing(owner.MasterSecretKey, [first.SecretKeyRing.Subkeys[0], second.SecretKeyRing.Subkeys[0]], pub.UserIds, [], signatures);
        return (owner, pub, secret, b, revoked);
    }

    private static void AssertDeclaredTarget(byte[] bytes, PgpSignaturePacket signature, PgpUserIdPacket user)
    {
        using var reader = new PgpPacketReader(new MemoryStream(bytes));
        string? currentUser = null;
        int found = 0;
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.UserId) currentUser = PgpUserIdPacket.Read(body.Span).UserId;
            if (tag == PgpPacketTag.Signature && body.Span.SequenceEqual(signature.ToArray())) { Assert.Equal(user.UserId, currentUser); found++; }
        }
        Assert.Equal(1, found);
    }

    private static void AssertLayout(byte[] bytes, PgpPublicKeyPacket master, int expectedCount)
    {
        using var reader = new PgpPacketReader(new MemoryStream(bytes));
        using var verifier = PgpSignatureVerifier.Create();
        PgpPacketTag current = default;
        PgpUserIdPacket user = default;
        PgpPublicKeyPacket subkey = default;
        int count = 0;
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag != PgpPacketTag.Signature) current = tag;
            if (tag == PgpPacketTag.UserId) user = PgpUserIdPacket.Read(body.Span);
            if (tag == PgpPacketTag.PublicSubkey) subkey = PgpPublicKeyPacket.Read(body.Span, true);
            if (tag == PgpPacketTag.SecretSubkey) subkey = PgpSecretKeyPacket.Read(body.Span, true).PublicKey;
            if (tag != PgpPacketTag.Signature) continue;
            count++;
            var sig = PgpSignaturePacket.Read(body.Span);
            if (sig.SignatureType == PgpSignatureType.PositiveCertification)
            {
                Assert.Equal(PgpPacketTag.UserId, current);
                Assert.True(verifier.VerifySelfCertification(sig, master, user).IsValid);
            }
            else if (sig.SignatureType == PgpSignatureType.DirectKey)
            {
                Assert.True(current is PgpPacketTag.PublicKey or PgpPacketTag.SecretKey);
                Assert.True(verifier.VerifyDirectKeySignature(sig, master, master).IsValid);
            }
            else
            {
                Assert.True(current is PgpPacketTag.PublicSubkey or PgpPacketTag.SecretSubkey);
                Assert.True((sig.SignatureType == PgpSignatureType.SubkeyBinding ? verifier.VerifySubkeyBinding(sig, master, subkey)
                    : verifier.VerifySubkeyRevocation(sig, master, subkey)).IsValid);
            }
        }
        Assert.Equal(expectedCount, count);
    }

    // Independent RFC key/User-ID framing and platform RSA signing, including V6 salt binding.
    private static PgpSignaturePacket Sign(PgpKeyGeneratorResult signer, PgpSignatureType type, PgpSignatureSubpacket[] fields,
        PgpUserIdPacket? user = null, PgpPublicKeyPacket? subkey = null, DateTimeOffset? time = null,
        PgpSignatureSubpacket[]? unhashed = null, PgpPublicKeyPacket? target = null)
    {
        var version = signer.MasterPublicKey.Version;
        var packets = new[] { PgpSignatureSubpacket.CreateSignatureCreationTime(time ?? Created),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, signer.MasterPublicKey.ComputeFingerprint()) }.Concat(fields).ToArray();
        var hashed = PgpSignatureSubpacket.WriteAll(packets);
        var material = KeyBytes(target ?? signer.MasterPublicKey, version);
        if (subkey.HasValue) material = material.Concat(KeyBytes(subkey.Value, version)).ToArray();
        if (user.HasValue)
        {
            var uid = user.Value.ToArray();
            var prefix = new byte[] { 0xB4, 0, 0, 0, 0 };
            BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)uid.Length);
            material = material.Concat(prefix).Concat(uid).ToArray();
        }
        var header = new byte[version == 4 ? 6 : 8];
        header[0] = version; header[1] = (byte)type; header[2] = 1; header[3] = 8;
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)hashed.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashed.Length);
        var trailer = new byte[] { version, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)(header.Length + hashed.Length));
        byte[] salt = version == 6 ? new byte[16] : [];
        var digest = SHA256.HashData(salt.Concat(material).Concat(header).Concat(hashed).Concat(trailer).ToArray());
        var (d, p, q, _) = signer.MasterSecretKey.ReadRsaSecretKey();
        var (n, e) = signer.MasterPublicKey.ReadRsaKey();
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RsaCore().ToRsaParameters(new RsaPrivateKey(n, d, p, q, e)));
        var raw = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(rsa.VerifyHash(digest, raw, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var mpi = new byte[Mpi.GetEncodedLength(raw)]; Mpi.Write(raw, mpi);
        var prefixHash = BinaryPrimitives.ReadUInt16BigEndian(digest);
        var signature = version == 4 ? PgpSignaturePacket.CreateV4(type, 1, 8, packets, unhashed ?? [], prefixHash, mpi)
            : PgpSignaturePacket.CreateV6(type, 1, 8, packets, unhashed ?? [], prefixHash, salt, mpi);
        using var verifier = PgpSignatureVerifier.Create();
        if (user.HasValue && type != PgpSignatureType.CertificationRevocation)
            Assert.True(verifier.VerifyCertification(signature, signer.MasterPublicKey, target ?? signer.MasterPublicKey, user.Value).IsValid);
        if (type == PgpSignatureType.DirectKey)
            Assert.True(verifier.VerifyDirectKeySignature(signature, signer.MasterPublicKey, target ?? signer.MasterPublicKey).IsValid);
        if (subkey.HasValue)
            Assert.True((type == PgpSignatureType.SubkeyBinding ? verifier.VerifySubkeyBinding(signature, signer.MasterPublicKey, subkey.Value)
                : verifier.VerifySubkeyRevocation(signature, signer.MasterPublicKey, subkey.Value)).IsValid);
        return signature;
    }

    private static byte[] KeyBytes(PgpPublicKeyPacket key, byte version)
    {
        var data = key.ToArray();
        var prefix = new byte[version == 4 ? 3 : 5]; prefix[0] = version == 4 ? (byte)0x99 : (byte)0x9B;
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(1), checked((ushort)data.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)data.Length);
        return prefix.Concat(data).ToArray();
    }
}
