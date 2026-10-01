using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpExpirationSecurityTests
{
    private static readonly DateTimeOffset Created = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Expiration_UnsignedClaims_DoNotOverrideAuthenticatedPolicy(bool suppress, bool reimport)
    {
        var owner = Generate(4, suppress ? 1 : 10);
        var fake = PgpSignaturePacket.CreateV4(PgpSignatureType.PositiveCertification, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(Created.AddHours(1)),
             PgpSignatureSubpacket.CreateKeyExpirationTime(suppress ? TimeSpan.Zero : TimeSpan.FromSeconds(1))], [], 0, new byte[] { 0 });
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, new[] { fake }.Concat(owner.PublicKeyRing.Signatures).ToArray());
        if (reimport) { ring = PgpPublicKeyRing.Read(ring.ToArray()); }
        using var verifier = PgpSignatureVerifier.Create();
        Assert.False(verifier.VerifySelfCertification(fake, ring.MasterKey, ring.UserIds[0]).IsValid);
        Assert.Equal(suppress, ring.IsExpiredAt(Created.AddDays(2)));
        var result = Validate(ring, Created.AddDays(2));
        Assert.True(result.IsValid);
        Assert.Equal(suppress, result.Warnings.Any(x => x.Code == PgpValidationCode.KeyExpired));
    }

    [Theory]
    [InlineData(4, false, false)]
    [InlineData(4, false, true)]
    [InlineData(4, true, false)]
    [InlineData(4, true, true)]
    [InlineData(6, false, false)]
    [InlineData(6, false, true)]
    [InlineData(6, true, false)]
    [InlineData(6, true, true)]
    public void Expiration_GenuineUpdate_SelectsNewestSignature(byte version, bool remove, bool reimport)
    {
        var owner = Generate(version, 1);
        using var updater = PgpKeyExpirationUpdater.Create().WithSecretKeyRing(owner.SecretKeyRing)
            .WithTimestamp(Created.AddHours(1)).WithNewExpiration(remove ? TimeSpan.Zero : TimeSpan.FromDays(10));
        var ring = updater.Update().PublicKeyRing;
        if (reimport) { ring = PgpPublicKeyRing.Read(ring.ToArray()); }
        Assert.Equal(remove ? null : TimeSpan.FromDays(10), ring.GetKeyLifetime());
        Assert.False(ring.IsExpiredAt(Created.AddDays(2)));
        var result = Validate(ring, Created.AddDays(2));
        Assert.True(result.IsValid);
        Assert.DoesNotContain(result.Warnings, x => x.Code == PgpValidationCode.KeyExpired);
        if (version == 6)
        {
            var updatedPolicy = Assert.Single(ring.Signatures, s => s.SignatureType == PgpSignatureType.DirectKey &&
                s.GetCreationTime() == Created.AddHours(1));
            using var verifier = PgpSignatureVerifier.Create();
            Assert.True(verifier.VerifyDirectKeySignature(updatedPolicy, ring.MasterKey, ring.MasterKey).IsValid);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Expiration_StaleAndFutureSignedClaims_DoNotOverrideCurrentSignature(bool future)
    {
        var owner = Generate(4, 1);
        var newer = Sign(owner, owner.PublicKeyRing.UserIds[0], Created.AddHours(1), 10);
        var other = Sign(owner, owner.PublicKeyRing.UserIds[0], future ? Created.AddDays(5) : Created, 0);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, [other, newer]);
        Assert.False(ring.IsExpiredAt(Created.AddDays(2)));
        Assert.True(ring.IsExpiredAt(Created.AddDays(11)) == !future);
    }

    [Fact]
    public void Expiration_OnlyFutureCertification_FailsClosed()
    {
        var owner = Generate(4, 1);
        var future = Sign(owner, owner.PublicKeyRing.UserIds[0], Created.AddDays(5), 0);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, [future]);
        Assert.False(Validate(ring, Created.AddDays(2)).IsValid);
        Assert.Throws<InvalidOperationException>(() => ring.IsExpiredAt(Created.AddDays(2)));
    }

    [Fact]
    public void Expiration_CertificationForUnrelatedUserId_IsIgnored()
    {
        var owner = Generate(4, 1);
        var wrongUser = Sign(owner, new PgpUserIdPacket("unrelated@example.invalid"), Created.AddHours(1), 0);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, new[] { wrongUser }.Concat(owner.PublicKeyRing.Signatures).ToArray());
        Assert.True(ring.IsExpiredAt(Created.AddDays(2)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Expiration_MultipleUserIds_RequiresUnambiguousPolicy(bool conflict)
    {
        var owner = Generate(4, 1);
        var second = new PgpUserIdPacket("second@example.invalid");
        var cert = Sign(owner, second, Created.AddHours(1), conflict ? 0 : 1);
        var ring = Replace(owner.PublicKeyRing, [owner.PublicKeyRing.UserIds[0], second],
            new[] { cert }.Concat(owner.PublicKeyRing.Signatures).ToArray());
        Assert.Equal(!conflict, Validate(ring, Created.AddDays(2)).IsValid);
        if (conflict) { Assert.Throws<InvalidOperationException>(() => ring.GetKeyLifetime()); }
        else { Assert.True(ring.IsExpiredAt(Created.AddDays(2))); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Expiration_EqualTimeConflictingSignatures_FailsRegardlessOfPacketOrder(bool reverse)
    {
        var owner = Generate(4, 1);
        var expires = Sign(owner, owner.PublicKeyRing.UserIds[0], Created.AddHours(1), 1);
        var forever = Sign(owner, owner.PublicKeyRing.UserIds[0], Created.AddHours(1), 0);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, reverse ? [forever, expires] : [expires, forever]);
        Assert.False(Validate(ring, Created.AddDays(2)).IsValid);
        Assert.Throws<InvalidOperationException>(() => ring.GetKeyLifetime());
    }

    [Fact]
    public void Expiration_ExpiredNewestCertification_DoesNotRollBackToOlderPolicy()
    {
        var owner = Generate(4, 10);
        var retired = Sign(owner, owner.PublicKeyRing.UserIds[0], Created.AddHours(1), 0, TimeSpan.FromHours(1));
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, owner.PublicKeyRing.Signatures.Append(retired).ToArray());
        Assert.False(Validate(ring, Created.AddDays(2)).IsValid);
        Assert.Throws<InvalidOperationException>(() => ring.IsExpiredAt(Created.AddDays(2)));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Expiration_NoAuthenticatedEvidence_FailsClosed(byte version)
    {
        var owner = Generate(version, 1);
        var ring = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds, []);
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).CheckExpiration();
        Assert.False(validator.Validate().IsValid);
        Assert.Throws<InvalidOperationException>(() => ring.GetKeyLifetime());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GenerateV6_ProvidesAuthenticatedDirectKeyPolicy(bool ed25519)
    {
        var generator = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").WithCreationTime(Created)
            .WithVersion(6).WithKeySize(2048).WithExpiration(TimeSpan.FromDays(1));
        var owner = ed25519 ? generator.GenerateEd25519WithX25519Subkey() : generator.GenerateRsa();
        var direct = Assert.Single(owner.PublicKeyRing.Signatures, x => x.SignatureType == PgpSignatureType.DirectKey);
        using var verifier = PgpSignatureVerifier.Create();
        Assert.True(verifier.VerifyDirectKeySignature(direct, owner.MasterPublicKey, owner.MasterPublicKey).IsValid);
        Assert.True(owner.PublicKeyRing.IsExpiredAt(Created.AddDays(2)));
        var stripped = Replace(owner.PublicKeyRing, owner.PublicKeyRing.UserIds,
            owner.PublicKeyRing.Signatures.Where(x => x.SignatureType != PgpSignatureType.DirectKey).ToArray());
        Assert.False(Validate(stripped, Created.AddDays(2)).IsValid);
    }

    private static PgpKeyGeneratorResult Generate(byte version, int days) => PgpKeyGenerator.Create()
        .WithUserId("owner@example.invalid").WithCreationTime(Created).WithVersion(version).WithKeySize(2048)
        .WithExpiration(TimeSpan.FromDays(days)).GenerateRsa();

    [Fact]
    public void Expiration_KeyCreationSubseconds_DoNotChangeSignedDeadline()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").WithKeySize(2048)
            .WithCreationTime(Created.AddMilliseconds(500)).WithExpiration(TimeSpan.FromDays(1)).GenerateRsa();
        Assert.Equal(Created.AddDays(1), owner.PublicKeyRing.GetExpirationTime());
        Assert.True(owner.PublicKeyRing.IsExpiredAt(Created.AddDays(1)));
        Assert.Contains(Validate(owner.PublicKeyRing, Created.AddDays(1)).Warnings, x => x.Code == PgpValidationCode.KeyExpired);
    }

    [Fact]
    public void Update_EqualTimestamp_RejectsAmbiguousNewPolicy()
    {
        var owner = Generate(4, 1);
        using var updater = PgpKeyExpirationUpdater.Create().WithSecretKeyRing(owner.SecretKeyRing)
            .WithTimestamp(Created).WithNoExpiration();
        Assert.Throws<InvalidOperationException>(() => updater.Update());
    }

    [Fact]
    public void Update_MultipleUserIds_UsesWholeKeyDirectSignature()
    {
        var owner = Generate(4, 1);
        var second = new PgpUserIdPacket("second@example.invalid");
        var secondCert = Sign(owner, second, Created.AddMinutes(30), 1);
        var secret = new PgpSecretKeyRing(owner.MasterSecretKey, owner.SecretKeyRing.Subkeys,
            [owner.PublicKeyRing.UserIds[0], second], owner.PublicKeyRing.UserAttributes,
            owner.SecretKeyRing.Signatures.Append(secondCert).ToArray());
        using var updater = PgpKeyExpirationUpdater.Create().WithSecretKeyRing(secret)
            .WithTimestamp(Created.AddHours(1)).WithNoExpiration();
        var ring = updater.Update().PublicKeyRing;
        Assert.Equal(PgpSignatureType.DirectKey, ring.Signatures.Last().SignatureType);
        Assert.Null(ring.GetKeyLifetime());
        Assert.False(ring.IsExpiredAt(Created.AddDays(2)));
    }

    private static PgpKeyValidationResult Validate(PgpPublicKeyRing ring, DateTimeOffset time)
    {
        using var validator = PgpKeyValidator.Create().WithPublicKeyRing(ring).CheckExpiration().AtTime(time);
        return validator.Validate();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Expiration_UnsupportedPolicyEvidence_ReturnsExplicitError(bool certificationRevocation)
    {
        var owner = certificationRevocation ? Generate(4, 1) : PgpKeyGenerator.Create()
            .WithUserId("owner@example.invalid").WithCreationTime(Created).WithKeySize(2048)
            .WithExpiration(TimeSpan.FromDays(1)).WithNotationData("policy@example.invalid", "unsupported", isCritical: true).GenerateRsa();
        var ring = owner.PublicKeyRing;
        if (certificationRevocation)
        {
            var unsupported = PgpSignaturePacket.CreateV4(PgpSignatureType.CertificationRevocation, 1, 8,
                [PgpSignatureSubpacket.CreateSignatureCreationTime(Created)], [], 0, new byte[] { 0 });
            ring = ring.AddSignature(unsupported);
        }
        var result = Validate(ring, Created.AddDays(2));
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, x => x.Code == PgpValidationCode.InvalidExpirationEvidence);
        Assert.Throws<InvalidOperationException>(() => ring.GetKeyLifetime());
    }

    [Fact]
    public void Update_UnsignedFlags_AreNotReissuedAsOwnerPolicy()
    {
        var owner = PgpKeyGenerator.Create().WithUserId("owner@example.invalid").WithCreationTime(Created)
            .WithKeySize(2048).WithKeyFlags(PgpKeyCapabilities.Certify).WithExpiration(TimeSpan.FromDays(1)).GenerateRsa();
        var fake = PgpSignaturePacket.CreateV4(PgpSignatureType.PositiveCertification, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(Created.AddHours(1)),
             PgpSignatureSubpacket.CreateKeyFlags(PgpKeyCapabilities.EncryptStorage)], [], 0, new byte[] { 0 });
        var secret = new PgpSecretKeyRing(owner.MasterSecretKey, owner.SecretKeyRing.Subkeys,
            owner.PublicKeyRing.UserIds, owner.PublicKeyRing.UserAttributes,
            new[] { fake }.Concat(owner.SecretKeyRing.Signatures).ToArray());
        using var updater = PgpKeyExpirationUpdater.Create().WithSecretKeyRing(secret)
            .WithTimestamp(Created.AddHours(2)).WithNoExpiration();
        var signature = updater.Update().PublicKeyRing.Signatures.Last();
        Assert.Equal(PgpKeyCapabilities.Certify, signature.GetKeyFlags());
    }

    private static PgpPublicKeyRing Replace(PgpPublicKeyRing ring, IReadOnlyList<PgpUserIdPacket> users,
        IReadOnlyList<PgpSignaturePacket> signatures) => new(ring.MasterKey, ring.Subkeys, users, ring.UserAttributes, signatures);

    // Independently construct an RFC V4 RSA certification using platform signing.
    private static PgpSignaturePacket Sign(PgpKeyGeneratorResult owner, PgpUserIdPacket user,
        DateTimeOffset time, int days, TimeSpan? signatureLifetime = null)
    {
        var packets = new List<PgpSignatureSubpacket> { PgpSignatureSubpacket.CreateSignatureCreationTime(time),
            PgpSignatureSubpacket.CreateKeyExpirationTime(TimeSpan.FromDays(days)) };
        if (signatureLifetime.HasValue)
            packets.Add(new PgpSignatureSubpacket(PgpSignatureSubpacketType.SignatureExpirationTime, false, UInt32((uint)signatureLifetime.Value.TotalSeconds)));
        var hashed = PgpSignatureSubpacket.WriteAll(packets);
        var key = owner.MasterPublicKey.ToArray();
        var uid = user.ToArray();
        var keyPrefix = new byte[] { 0x99, 0, 0 };
        BinaryPrimitives.WriteUInt16BigEndian(keyPrefix.AsSpan(1), checked((ushort)key.Length));
        var userPrefix = new byte[] { 0xB4, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(userPrefix.AsSpan(1), (uint)uid.Length);
        var header = new byte[] { 4, 0x13, 1, 8, 0, 0 };
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)hashed.Length));
        var trailer = new byte[] { 4, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)(header.Length + hashed.Length));
        var digest = SHA256.HashData(keyPrefix.Concat(key).Concat(userPrefix).Concat(uid).Concat(header).Concat(hashed).Concat(trailer).ToArray());
        var (d, p, q, _) = owner.MasterSecretKey.ReadRsaSecretKey();
        var (n, e) = owner.MasterPublicKey.ReadRsaKey();
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RsaCore().ToRsaParameters(new RsaPrivateKey(n, d, p, q, e)));
        var raw = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var mpi = new byte[Mpi.GetEncodedLength(raw)];
        Mpi.Write(raw, mpi);
        var signature = PgpSignaturePacket.CreateV4(PgpSignatureType.PositiveCertification, 1, 8, packets, [],
            BinaryPrimitives.ReadUInt16BigEndian(digest), mpi);
        using var verifier = PgpSignatureVerifier.Create();
        Assert.True(verifier.VerifySelfCertification(signature, owner.MasterPublicKey, user).IsValid);
        return signature;
    }

    private static byte[] UInt32(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }
}
