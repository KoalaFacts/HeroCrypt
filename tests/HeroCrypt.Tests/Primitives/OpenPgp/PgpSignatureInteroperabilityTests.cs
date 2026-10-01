using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpSignatureInteroperabilityTests
{
    private static readonly byte[] Data = "Independent OpenPGP signature"u8.ToArray();

    [Theory]
    [InlineData(4, false)]
    [InlineData(6, false)]
    [InlineData(4, true)]
    [InlineData(6, true)]
    public void Verify_IndependentRsaSignature_EnforcesRfcFraming(byte version, bool legacy)
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);
        var key = PgpPublicKeyPacket.CreateRsa(version, DateTimeOffset.FromUnixTimeSeconds(1700000000),
            new BigInteger(p.Modulus!, true, true), new BigInteger(p.Exponent!, true, true));
        byte[] salt = version == 6 ? Enumerable.Range(1, 16).Select(x => (byte)x).ToArray() : [];
        var template = new PgpSignaturePacket(version, PgpSignatureType.BinaryDocument, 1, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.FromUnixTimeSeconds(1700000000)),
                PgpSignatureSubpacket.CreateIssuerFingerprint(version, key.ComputeFingerprint())], [], 0, ReadOnlyMemory<byte>.Empty, salt);
        var hash = RfcHash(template, Data, legacy);
        var raw = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var mpi = new byte[Mpi.GetEncodedLength(raw)];
        Mpi.Write(raw, mpi);
        var signature = new PgpSignaturePacket(version, template.SignatureType, 1, 8,
            template.HashedSubpackets, [], BinaryPrimitives.ReadUInt16BigEndian(hash), mpi, salt);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        var result = verifier.Verify(Data, PgpSignaturePacket.Read(signature.ToArray()));
        Assert.Equal(!legacy, result.IsValid);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void Sign_Document_UsesIndependentRfcHash(byte version)
    {
        var pair = PgpKeyGenerator.Create().WithVersion(version).WithUserId("interop@example.invalid").GenerateRsa();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        var signature = signer.Sign(Data).Signature;
        AssertIndependentSignature(signature, pair.MasterPublicKey, Data);
    }

    [Fact]
    public void SignText_PreservesWhitespaceAndVerifiesDifferentLineEndings()
    {
        var pair = PgpKeyGenerator.Create().WithUserId("interop@example.invalid").GenerateEd25519();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        var message = signer.SignText("line  \nnext\t\rfinal\r\n");
        byte[] canonical = Encoding.UTF8.GetBytes("line  \r\nnext\t\r\nfinal\r\n");
        AssertIndependentSignature(message.Signature, pair.MasterPublicKey, canonical);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(pair.MasterPublicKey);
        Assert.True(verifier.Verify(Encoding.UTF8.GetBytes("line  \nnext\t\nfinal\n"), message.Signature).IsValid);
        Assert.False(verifier.Verify(Encoding.UTF8.GetBytes("line\nnext\nfinal\n"), message.Signature).IsValid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void V6_KeySignatures_BindSaltAndUseRfcKeyPrefix(bool certification)
    {
        var pair = PgpKeyGenerator.Create().WithUserId("interop@example.invalid").GenerateEd25519();
        var userId = new PgpUserIdPacket(pair.UserId);
        using var certifier = PgpKeyCertifier.Create().WithCertifyingKey(pair.MasterSecretKey)
            .WithTargetKey(pair.MasterPublicKey).WithUserId(userId);
        using var revoker = PgpKeyRevoker.Create().WithSecretKey(pair.MasterSecretKey);
        var signature = certification ? certifier.Certify() : revoker.RevokeKey();
        var material = KeyMaterial(pair.MasterPublicKey, 6);
        if (certification)
        {
            var uid = userId.ToArray();
            var prefix = new byte[5];
            prefix[0] = 0xB4;
            BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)uid.Length);
            material = material.Concat(prefix).Concat(uid).ToArray();
        }
        AssertIndependentSignature(signature, pair.MasterPublicKey, material);
        using var verifier = PgpSignatureVerifier.Create();
        PgpSignatureResult Verify(PgpSignaturePacket value) => certification
            ? verifier.VerifyCertification(value, pair.MasterPublicKey, pair.MasterPublicKey, userId)
            : verifier.VerifyKeyRevocation(value, pair.MasterPublicKey);
        Assert.True(Verify(signature).IsValid);
        var salt = signature.Salt.ToArray();
        salt[0] ^= 1;
        var tampered = new PgpSignaturePacket(6, signature.SignatureType, signature.PublicKeyAlgorithm,
            signature.HashAlgorithm, signature.HashedSubpackets, signature.UnhashedSubpackets,
            signature.HashPrefix, signature.SignatureData, salt);
        Assert.False(Verify(tampered).IsValid);
    }

    [Fact]
    public void Verify_IndependentV6Ed25519Signature_Accepts()
    {
        // Public RFC 8032 test seed, not a production secret.
        var seed = Convert.FromHexString("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60");
        var publicKey = new byte[32];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(seed, 0, publicKey, 0);
        var key = new PgpPublicKeyPacket(6, DateTimeOffset.FromUnixTimeSeconds(1700000000), PgpPublicKeyAlgorithm.Ed25519, publicKey);
        var salt = Enumerable.Range(1, 16).Select(x => (byte)x).ToArray();
        var template = new PgpSignaturePacket(6, PgpSignatureType.BinaryDocument, 27, 8,
            [PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.FromUnixTimeSeconds(1700000000)),
                PgpSignatureSubpacket.CreateIssuerFingerprint(6, key.ComputeFingerprint())], [], 0, ReadOnlyMemory<byte>.Empty, salt);
        var hash = RfcHash(template, Data);
        var raw = new byte[64];
        Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Sign(seed, 0, hash, 0, hash.Length, raw, 0);
        var signature = new PgpSignaturePacket(6, template.SignatureType, 27, 8,
            template.HashedSubpackets, [], BinaryPrimitives.ReadUInt16BigEndian(hash), raw, salt);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(key);
        var result = verifier.Verify(Data, PgpSignaturePacket.Read(signature.ToArray()));
        Assert.True(result.IsValid, result.ErrorMessage);
    }

    [Fact]
    public void V4_RsaDocument_InteroperatesWithBouncyCastleBothDirections()
    {
        var pair = PgpKeyGenerator.Create().WithUserId("interop@example.invalid").GenerateRsa();
        var bcPublic = new Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyRing(pair.ExportPublicKey()).GetPublicKey();
        using var signer = PgpSignatureSigner.Create().WithSecretKey(pair.MasterSecretKey);
        using var stream = new MemoryStream();
        using (var writer = new PgpPacketWriter(stream, leaveOpen: true))
            writer.WritePacket(PgpPacketTag.Signature, signer.Sign(Data).Signature.ToArray());
        var factory = new Org.BouncyCastle.Bcpg.OpenPgp.PgpObjectFactory(stream.ToArray());
        var bcSignature = Assert.IsType<Org.BouncyCastle.Bcpg.OpenPgp.PgpSignatureList>(factory.NextPgpObject())[0];
        bcSignature.InitVerify(bcPublic);
        bcSignature.Update(Data);
        Assert.True(bcSignature.Verify());

        var bcSecret = new Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKeyRing(pair.ExportSecretKey()).GetSecretKey();
        var generator = new Org.BouncyCastle.Bcpg.OpenPgp.PgpSignatureGenerator(
            Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag.RsaGeneral, Org.BouncyCastle.Bcpg.HashAlgorithmTag.Sha256);
        generator.InitSign(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.BinaryDocument, bcSecret.ExtractPrivateKey([]));
        generator.Update(Data);
        using var encoded = new MemoryStream(generator.Generate().GetEncoded());
        using var reader = new PgpPacketReader(encoded);
        Assert.True(reader.ReadNextPacket(out var tag, out var body));
        Assert.Equal(PgpPacketTag.Signature, tag);
        using var verifier = PgpSignatureVerifier.Create().WithPublicKey(pair.MasterPublicKey);
        var result = verifier.Verify(Data, PgpSignaturePacket.Read(body.Span));
        Assert.True(result.IsValid, result.ErrorMessage);
    }

    [Fact]
    public void V6Certification_OfV4Key_UsesSignatureVersionPrefix()
    {
        var signer = PgpKeyGenerator.Create().WithUserId("signer@example.invalid").GenerateEd25519();
        var target = PgpKeyGenerator.Create().WithUserId("target@example.invalid").GenerateRsa();
        var uid = new PgpUserIdPacket(target.UserId);
        using var certifier = PgpKeyCertifier.Create().WithCertifyingKey(signer.MasterSecretKey)
            .WithTargetKey(target.MasterPublicKey).WithUserId(uid);
        var signature = certifier.Certify();
        AssertIndependentSignature(signature, signer.MasterPublicKey, CertificationMaterial(target.MasterPublicKey, target.UserId, 6));
        using var verifier = PgpSignatureVerifier.Create();
        var result = verifier.VerifyCertification(signature, signer.MasterPublicKey, target.MasterPublicKey, uid);
        Assert.True(result.IsValid, result.ErrorMessage);
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(6, false)]
    [InlineData(6, true)]
    public void KeyLifecycle_AllProducers_UseIndependentRfcHashes(byte version, bool ed25519)
    {
        var generator = PgpKeyGenerator.Create().WithVersion(version).WithCreationTime(DateTimeOffset.FromUnixTimeSeconds(1700000000))
            .WithUserId("interop@example.invalid").WithEncryptionSubkey();
        var pair = ed25519 ? generator.GenerateEd25519WithX25519Subkey() : generator.GenerateRsa();
        var certification = Assert.Single(pair.PublicKeyRing.Signatures, x => x.SignatureType == PgpSignatureType.PositiveCertification);
        AssertIndependentSignature(certification, pair.MasterPublicKey, CertificationMaterial(pair.MasterPublicKey, pair.UserId, version));
        var subkey = Assert.Single(pair.PublicKeyRing.Subkeys);
        var binding = Assert.Single(pair.PublicKeyRing.Signatures, x => x.SignatureType == PgpSignatureType.SubkeyBinding);
        AssertIndependentSignature(binding, pair.MasterPublicKey, KeyMaterial(pair.MasterPublicKey, version).Concat(KeyMaterial(subkey, version)).ToArray());
        if (version == 6)
        {
            var direct = Assert.Single(pair.PublicKeyRing.Signatures, x => x.SignatureType == PgpSignatureType.DirectKey);
            AssertIndependentSignature(direct, pair.MasterPublicKey, KeyMaterial(pair.MasterPublicKey, version));
        }

        using var updater = PgpKeyExpirationUpdater.Create().WithSecretKeyRing(pair.SecretKeyRing).WithNewExpiration(TimeSpan.FromDays(365));
        var updated = updater.Update();
        var renewed = updated.PublicKeyRing.Signatures.Last();
        Assert.Equal(version == 6 ? PgpSignatureType.DirectKey : PgpSignatureType.PositiveCertification, renewed.SignatureType);
        AssertIndependentSignature(renewed, pair.MasterPublicKey, version == 6 ? KeyMaterial(pair.MasterPublicKey, version)
            : CertificationMaterial(pair.MasterPublicKey, pair.UserId, version));

        using var revoker = PgpKeyRevoker.Create().WithSecretKey(pair.MasterSecretKey);
        var revoked = revoker.WithSubkey(subkey).RevokeSubkey();
        AssertIndependentSignature(revoked, pair.MasterPublicKey, KeyMaterial(pair.MasterPublicKey, version).Concat(KeyMaterial(subkey, version)).ToArray());

        var nextGenerator = PgpKeyGenerator.Create().WithVersion(version).WithUserId("next@example.invalid");
        var next = ed25519 ? nextGenerator.GenerateEd25519() : nextGenerator.GenerateRsa();
        using var rotator = PgpKeyRotator.Create().FromOldKey(pair.MasterSecretKey).ToNewKey(next);
        AssertIndependentSignature(rotator.Rotate().TransitionSignature, pair.MasterPublicKey, KeyMaterial(next.MasterPublicKey, version));
    }

    private static byte[] CertificationMaterial(PgpPublicKeyPacket key, string userId, byte version)
    {
        var uid = Encoding.UTF8.GetBytes(userId);
        var prefix = new byte[5];
        prefix[0] = 0xB4;
        BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)uid.Length);
        return KeyMaterial(key, version).Concat(prefix).Concat(uid).ToArray();
    }

    private static void AssertIndependentSignature(PgpSignaturePacket signature, PgpPublicKeyPacket key, byte[] material)
    {
        var hash = RfcHash(signature, material);
        Assert.Equal(BinaryPrimitives.ReadUInt16BigEndian(hash), signature.HashPrefix);
        if (key.Algorithm == PgpPublicKeyAlgorithm.Ed25519)
        {
            Assert.True(Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Verify(signature.SignatureData.ToArray(), 0,
                key.ReadNativePublicKey(), 0, hash, 0, hash.Length));
        }
        else
        {
            var (n, e) = key.ReadRsaKey();
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n.ToByteArray(true, true), Exponent = e.ToByteArray(true, true) });
            Assert.True(Mpi.TryRead(signature.SignatureData.Span, out var value, out var consumed));
            Assert.Equal(signature.SignatureData.Length, consumed);
            var raw = value.ToByteArray(true, true);
            var padded = new byte[rsa.KeySize / 8];
            raw.CopyTo(padded, padded.Length - raw.Length);
            Assert.True(rsa.VerifyHash(hash, padded, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    // Independent byte construction from RFC 9580 section 5.2.4; never calls the production hash helper.
    private static byte[] RfcHash(PgpSignaturePacket signature, byte[] material, bool legacy = false)
    {
        var subpackets = PgpSignatureSubpacket.WriteAll(signature.HashedSubpackets);
        int overhead = signature.Version == 4 ? 6 : 8;
        var header = new byte[overhead + subpackets.Length];
        header[0] = signature.Version;
        header[1] = (byte)signature.SignatureType;
        header[2] = signature.PublicKeyAlgorithm;
        header[3] = signature.HashAlgorithm;
        if (signature.Version == 4) BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)subpackets.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)subpackets.Length);
        subpackets.CopyTo(header, overhead);
        var trailer = new byte[] { signature.Version, 255, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)header.Length);
        if (legacy)
        {
            // Reproduce historical document hashing to ensure no legacy fallback accepts it.
            if (signature.Version == 4) BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)(4 + subpackets.Length));
            else
            {
                trailer = new byte[10];
                trailer[0] = 6;
                trailer[1] = 255;
                BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(2), (ulong)(4 + subpackets.Length));
            }
        }
        return SHA256.HashData(signature.Salt.ToArray().Concat(material).Concat(header).Concat(trailer).ToArray());
    }

    private static byte[] KeyMaterial(PgpPublicKeyPacket key, byte signatureVersion)
    {
        var body = key.ToArray();
        var prefix = new byte[signatureVersion == 4 ? 3 : 5];
        prefix[0] = signatureVersion == 4 ? (byte)0x99 : (byte)0x9B;
        if (signatureVersion == 4) BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(1), checked((ushort)body.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)body.Length);
        return prefix.Concat(body).ToArray();
    }
}
