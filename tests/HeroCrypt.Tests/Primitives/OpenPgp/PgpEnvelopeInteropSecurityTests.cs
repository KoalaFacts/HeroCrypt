using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpEnvelopeInteropSecurityTests
{
    // Public fixtures from RFC 9580 Appendix A.11, not operational credentials.
    private static readonly byte[] RfcSkesk = Convert.FromHexString("061a07030b0308e9d39785b2070008ffb42e7c483ef4884457cb3726b9b3db9ff776e5f4d9a40952e2447298851abfff7526df2dd554417579a7799f");
    private static readonly byte[] RfcSeipd = Convert.FromHexString("02070306fcb94490bcb98bbdc9d106c6090266940f72e89edc21b5596b1576b101ed0f9ffc6fc6d65bbfd24dcd0790966e6d1e85a30053784cb1d8b6a0699ef12155a7b2ad6258531b57651fd7777912fa95e35d9b40216f69a4c248db28ff4331f1632907399e6ff9");
    private static readonly byte[] RfcSession = Convert.FromHexString("1936fc8568980274bb900d8319360c77");
    private static readonly byte[] SaltedS2k = [1, 8, 0, 1, 2, 3, 4, 5, 6, 7];
    private static readonly Lazy<RSAParameters> RsaParameters = new(() =>
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportParameters(true);
    });

    [Fact]
    public void Decrypt_Rfc9580AppendixA11_ReturnsPublishedPlaintext()
    {
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("password");
        var decrypted = decryptor.Decrypt(Message((PgpPacketTag.SymmetricKeyEncryptedSessionKey, RfcSkesk),
            (PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, RfcSeipd)));
        Assert.Equal("Hello, world!"u8.ToArray(), decrypted.Data.ToArray());
    }

    [Fact]
    public void DecryptSessionKey_Rfc9580AppendixA11_ReturnsPublishedKey()
    {
        var packet = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(RfcSkesk);
        Assert.Equal(RfcSession, packet.DecryptSessionKey("password"u8));
    }

    [Fact]
    public void Skesk_Rfc9580AppendixA11_PreservesWireEncoding()
    {
        Assert.Equal(RfcSkesk, PgpSymmetricKeyEncryptedSessionKeyPacket.Read(RfcSkesk).ToArray());
    }

    public static IEnumerable<object[]> BadSkeskCounts()
    {
        foreach (byte value in new byte[] { 0, 1, 25, 27, 255 }) yield return [1, value];
        foreach (byte value in new byte[] { 0, 1, 10, 12, 255 }) yield return [4, value];
    }

    [Theory]
    [MemberData(nameof(BadSkeskCounts))]
    public void Skesk_Read_InconsistentCounts_Rejects(int offset, byte value)
    {
        var body = (byte[])RfcSkesk.Clone();
        body[offset] = value;
        Assert.False(PgpSymmetricKeyEncryptedSessionKeyPacket.TryRead(body, out _, out _));
    }

    [Theory]
    [InlineData(17)]
    [InlineData(25)]
    [InlineData(26)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(255)]
    public void Seipd_UnsupportedChunkSize_RejectsBeforeShift(byte chunk)
    {
        var body = (byte[])RfcSeipd.Clone();
        body[3] = chunk;
        Assert.False(PgpSymEncryptedIntegrityProtectedDataPacket.TryRead(body, out _, out _));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(SymmetricCipherAlgorithm.Aes128, AeadAlgorithm.Gcm,
                chunk, new byte[32], new byte[32]));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(0)]
    public void PkeskV6_CountKeyVersionAndFingerprint_FollowRfc(byte version)
    {
        var fingerprint = new byte[version == 4 ? 20 : version == 6 ? 32 : 0];
        byte[] payload = [1, 2, 3];
        var body = version == 0
            ? new byte[] { 6, 0, 1 }.Concat(payload).ToArray()
            : new byte[] { 6, (byte)(fingerprint.Length + 1), version }.Concat(fingerprint).Concat(new byte[] { 1 }).Concat(payload).ToArray();
        var packet = PgpPublicKeyEncryptedSessionKeyPacket.Read(body);
        Assert.Equal(version, packet.KeyVersion);
        Assert.Equal(fingerprint, packet.Fingerprint.ToArray());
        Assert.Equal(payload, packet.EncryptedSessionKey.ToArray());
        Assert.Equal(body, packet.ToArray());
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void SkeskV4_NativeCfb_UsesOnlyAlgorithmAndSessionKey(SymmetricCipherAlgorithm cipher)
    {
        var session = Sequence(KeySize(cipher));
        var created = PgpSymmetricKeyEncryptedSessionKeyPacket.Create("fixture"u8, session, cipher, S2KType.Salted);
        var kek = S2KParameters.Parse(created.S2kSpecifier.Span).DeriveKey("fixture"u8, KeySize(cipher));
        var decoded = NativeCfb(created.EncryptedSessionKey.ToArray(), kek, encrypt: false);
        Assert.Equal(new byte[] { (byte)cipher }.Concat(session).ToArray(), decoded);

        // Independently wrapped AES-128/192/256 sessions under an AES-256 KEK.
        var wrapped = NativeCfb(new byte[] { (byte)cipher }.Concat(session).ToArray(), SaltedKey("fixture"u8, 32), encrypt: true);
        var incoming = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes256, SaltedS2k, wrapped);
        Assert.Equal(session, incoming.DecryptSessionKey("fixture"u8));
    }

    public static IEnumerable<object[]> EnvelopeCases()
    {
        foreach (bool x25519 in new[] { false, true })
            foreach (byte version in new byte[] { 4, 6 })
                foreach (bool gcm in new[] { false, true })
                    foreach (var cipher in new[] { SymmetricCipherAlgorithm.Aes128, SymmetricCipherAlgorithm.Aes192, SymmetricCipherAlgorithm.Aes256 })
                        yield return [x25519, version, gcm, cipher];
    }

    [Theory]
    [MemberData(nameof(EnvelopeCases))]
    public void Encrypt_RecipientEnvelopes_MatchIndependentWireAndCrypto(bool x25519, byte version, bool gcm, SymmetricCipherAlgorithm cipher)
    {
        var (publicKey, secretKey) = Keys(x25519, version);
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(publicKey).WithSymmetricAlgorithm(cipher);
        if (gcm) encryptor.WithAead(AeadAlgorithm.Gcm);
        var wire = encryptor.Encrypt("envelope"u8).ToArray();
        var packets = Packets(wire);
        var pkeskBody = Assert.Single(packets, p => p.Tag == PgpPacketTag.PublicKeyEncryptedSessionKey).Body;
        var container = PgpSymEncryptedIntegrityProtectedDataPacket.Read(Assert.Single(packets,
            p => p.Tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData).Body);
        Assert.Equal(gcm ? 6 : 3, pkeskBody[0]);
        var payloadOffset = gcm ? 3 + publicKey.ComputeFingerprint().Length + 1 : 10;
        if (gcm)
        {
            Assert.Equal(publicKey.ComputeFingerprint().Length + 1, pkeskBody[1]);
            Assert.Equal(version, pkeskBody[2]);
        }
        var payload = pkeskBody[payloadOffset..];
        byte[] session;
        if (x25519)
        {
            var privateKey = secretKey.ReadEcSecretKey();
            var shared = new Curve25519Core().ComputeSharedSecret(privateKey, payload[..32]);
            var ikm = payload[..32].Concat(publicKey.ReadNativePublicKey()).Concat(shared).ToArray();
            var kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, info: "OpenPGP X25519"u8.ToArray());
            Assert.Equal(payload.Length - 33, payload[32]);
            if (!gcm) Assert.Equal((byte)cipher, payload[33]);
            session = NativeUnwrap(kek, payload[(gcm ? 33 : 34)..]);
        }
        else
        {
            var mpi = Mpi.ReadBytes(payload, out var consumed);
            Assert.Equal(payload.Length, consumed);
            var padded = new byte[256];
            mpi.CopyTo(padded.AsSpan(padded.Length - mpi.Length));
            using var rsa = RSA.Create();
            rsa.ImportParameters(RsaParameters.Value);
            var decoded = rsa.Decrypt(padded, RSAEncryptionPadding.Pkcs1);
            Assert.Equal(KeySize(cipher) + (gcm ? 2 : 3), decoded.Length);
            if (!gcm) Assert.Equal((byte)cipher, decoded[0]);
            session = decoded[(gcm ? 0 : 1)..^2];
            Assert.Equal(session.Sum(x => x) & 0xFFFF, BinaryPrimitives.ReadUInt16BigEndian(decoded.AsSpan(decoded.Length - 2)));
        }
        Assert.Equal(KeySize(cipher), session.Length);
        if (gcm)
        {
            Assert.Equal(6, container.ChunkSize);
            Assert.Equal("envelope"u8.ToArray(), LiteralData(ReferenceDecrypt(container, session)));
        }
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(secretKey);
        Assert.Equal("envelope"u8.ToArray(), decryptor.Decrypt(wire).Data.ToArray());
    }

    public static IEnumerable<object[]> ChunkCases()
    {
        for (byte chunk = 0; chunk <= 16; chunk++) yield return [SymmetricCipherAlgorithm.Aes128, chunk, 20];
        foreach (var cipher in new[] { SymmetricCipherAlgorithm.Aes128, SymmetricCipherAlgorithm.Aes192, SymmetricCipherAlgorithm.Aes256 })
            foreach (int length in new[] { 0, 1, 55, 56, 57, 4087, 4088, 8183 })
                yield return [cipher, (byte)(length <= 57 ? 0 : 6), length];
    }

    [Theory]
    [MemberData(nameof(ChunkCases))]
    public void Decrypt_IndependentGcmChunks_AcceptsSupportedSizesAndBoundaries(SymmetricCipherAlgorithm cipher, byte chunk, int length)
    {
        var plaintext = Sequence(length);
        var literal = LiteralWire(plaintext);
        var session = Sequence(KeySize(cipher));
        var skesk = ReferenceSkesk(cipher, session);
        var seipd = ReferenceSeipd(cipher, chunk, literal, session);
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("fixture");
        Assert.Equal(plaintext, decryptor.Decrypt(Message((PgpPacketTag.SymmetricKeyEncryptedSessionKey, skesk),
            (PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipd))).Data.ToArray());
    }

    [Fact]
    public void Decrypt_DirectSkesk_TriesLaterPassphraseAfterPayloadAuthentication()
    {
        var key = SaltedKey("fixture"u8, 16);
        byte[] skesk = [4, 7, .. SaltedS2k];
        var literal = LiteralWire("candidate fallback"u8.ToArray());
        byte[] prefix = [.. Sequence(16), 14, 15];
        byte[] mdcInput = [.. prefix, .. literal, 0xD3, 0x14];
#pragma warning disable CA5350 // SHA-1 is fixed by the SEIPD v1 MDC format.
        var hash = SHA1.HashData(mdcInput);
#pragma warning restore CA5350
        byte[] seipd = [1, .. NativeCfb([.. mdcInput, .. hash], key, true)];
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("wrong").WithMessagePassphrase("fixture");
        Assert.Equal("candidate fallback"u8.ToArray(), decryptor.Decrypt(Message((PgpPacketTag.SymmetricKeyEncryptedSessionKey, skesk),
            (PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipd))).Data.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(35)]
    [InlineData(36)]
    [InlineData(72)]
    [InlineData(88)]
    [InlineData(104)]
    public void Decrypt_ModifiedOfficialContainer_ReturnsNoPlaintext(int offset)
    {
        var seipd = (byte[])RfcSeipd.Clone();
        seipd[offset] ^= 1;
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("password");
        Assert.False(decryptor.TryDecrypt(Message((PgpPacketTag.SymmetricKeyEncryptedSessionKey, RfcSkesk),
            (PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipd)), out var result, out _));
        Assert.True(result.Data.IsEmpty);
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128, false)]
    [InlineData(SymmetricCipherAlgorithm.Aes192, false)]
    [InlineData(SymmetricCipherAlgorithm.Aes256, false)]
    [InlineData(SymmetricCipherAlgorithm.Aes128, true)]
    [InlineData(SymmetricCipherAlgorithm.Aes192, true)]
    [InlineData(SymmetricCipherAlgorithm.Aes256, true)]
    public void Encrypt_PassphraseEnvelope_MatchesNativeSessionUnwrap(SymmetricCipherAlgorithm cipher, bool gcm)
    {
        using var encryptor = PgpMessageEncryptor.Create().WithPassphrase("fixture")
            .WithS2KType(S2KType.Salted).WithSymmetricAlgorithm(cipher);
        if (gcm) encryptor.WithAead();
        var wire = encryptor.Encrypt("passphrase fixture"u8).ToArray();
        var packets = Packets(wire);
        var skesk = PgpSymmetricKeyEncryptedSessionKeyPacket.Read(Assert.Single(packets,
            p => p.Tag == PgpPacketTag.SymmetricKeyEncryptedSessionKey).Body);
        Assert.Equal(gcm ? 6 : 4, skesk.Version);
        var derived = SHA256.HashData(skesk.S2kSpecifier.Span[2..].ToArray().Concat("fixture"u8.ToArray()).ToArray())[..KeySize(cipher)];
        byte[] session;
        if (gcm)
        {
            byte[] aad = [0xC3, 6, (byte)cipher, 3];
            var kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, derived, derived.Length, info: aad);
            session = new byte[KeySize(cipher)];
            using var aes = new System.Security.Cryptography.AesGcm(kek, 16);
            aes.Decrypt(skesk.IV.Span, skesk.EncryptedSessionKey.Span[..^16],
                skesk.EncryptedSessionKey.Span[^16..], session, aad);
            var container = PgpSymEncryptedIntegrityProtectedDataPacket.Read(Assert.Single(packets,
                p => p.Tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData).Body);
            Assert.Equal("passphrase fixture"u8.ToArray(), LiteralData(ReferenceDecrypt(container, session)));
        }
        else
        {
            var decoded = NativeCfb(skesk.EncryptedSessionKey.ToArray(), derived, false);
            Assert.Equal(1 + KeySize(cipher), decoded.Length);
            Assert.Equal((byte)cipher, decoded[0]);
            session = decoded[1..];
        }

        Assert.Equal(session, skesk.DecryptSessionKey("fixture"u8));
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("fixture");
        Assert.Equal("passphrase fixture"u8.ToArray(), decryptor.Decrypt(wire).Data.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void Decrypt_MalformedOrMixedEnvelope_RejectsEvenWithValidCandidate(int mutation)
    {
        byte[] oldSkesk = [4, 7, .. SaltedS2k];
        var skesk = (byte[])RfcSkesk.Clone();
        var packets = new List<(PgpPacketTag, byte[])>();
        if (mutation == 0) packets.Add((PgpPacketTag.SymmetricKeyEncryptedSessionKey, oldSkesk));
        if (mutation == 1) packets.Add((PgpPacketTag.PublicKeyEncryptedSessionKey, [3, .. new byte[8], 1]));
        if (mutation == 2) packets.Add((PgpPacketTag.SymmetricKeyEncryptedSessionKey, [6, 0]));
        if (mutation == 3) skesk[4] = 0; // Historical placeholder S2K count.
        packets.Add((PgpPacketTag.SymmetricKeyEncryptedSessionKey, skesk));
        packets.Add((PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, RfcSeipd));
        if (mutation == 4) packets.Add((PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, RfcSeipd));
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("password");
        Assert.False(decryptor.TryDecrypt(Message(packets.ToArray()), out var result, out _));
        Assert.True(result.Data.IsEmpty);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(33)]
    public void SessionFactories_InvalidAesKeyLength_Reject(int length)
    {
        Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.Create("fixture"u8,
            new byte[length], SymmetricCipherAlgorithm.Aes128));
        Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.CreateV6("fixture"u8, new byte[length]));
        var (key, _) = Keys(true, 6);
        Assert.Throws<ArgumentException>(() => PgpKeyEncryption.EncryptSessionKeyX25519(new byte[length], key));
    }

    [Fact]
    public void SkeskV4_HistoricalChecksumPayload_Rejects()
    {
        byte[] plaintext = [7, .. Sequence(16), 0, 120];
        var packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes128,
            SaltedS2k, NativeCfb(plaintext, SaltedKey("fixture"u8, 16), true));
        Assert.Throws<CryptographicException>(() => packet.DecryptSessionKey("fixture"u8));
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void Decrypt_SkeskV6_WrappingCipherCanDifferFromDataCipher(SymmetricCipherAlgorithm cipher)
    {
        var session = Sequence(KeySize(cipher));
        var skesk = ReferenceSkesk(SymmetricCipherAlgorithm.Aes256, session);
        var seipd = ReferenceSeipd(cipher, 0, LiteralWire("different ciphers"u8.ToArray()), session);
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("fixture");
        Assert.Equal("different ciphers"u8.ToArray(), decryptor.Decrypt(Message(
            (PgpPacketTag.SymmetricKeyEncryptedSessionKey, skesk),
            (PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipd))).Data.ToArray());
    }

    [Fact]
    public void SessionFactories_SimpleS2kGeneration_Rejects()
    {
        Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.Create("fixture"u8,
            null, s2kType: S2KType.Simple));
        Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.Create("fixture"u8,
            new byte[32], s2kType: S2KType.Simple));
        Assert.Throws<ArgumentException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.CreateV6("fixture"u8,
            new byte[32], s2kType: S2KType.Simple));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Decrypt_MixedRecipientsAndPassphrases_EveryRecipientCanAuthenticate(bool gcm)
    {
        var (rsaPublic, rsaSecret) = Keys(false, 4);
        var (xPublic, xSecret) = Keys(true, 6);
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(rsaPublic).AddRecipient(xPublic)
            .WithPassphrase("first fixture").WithPassphrase("second fixture");
        if (gcm) encryptor.WithAead();
        var wire = encryptor.Encrypt("all recipients"u8).ToArray();
        using var rsaDecryptor = PgpMessageDecryptor.Create().WithSecretKey(rsaSecret);
        using var xDecryptor = PgpMessageDecryptor.Create().WithSecretKey(xSecret);
        using var firstDecryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("wrong").WithMessagePassphrase("first fixture");
        using var secondDecryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("wrong").WithMessagePassphrase("second fixture");
        foreach (var decryptor in new[] { rsaDecryptor, xDecryptor, firstDecryptor, secondDecryptor })
        {
            Assert.Equal("all recipients"u8.ToArray(), decryptor.Decrypt(wire).Data.ToArray());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EnvelopePolicy_X25519_RejectsConfiguredForbiddenAgreement(bool gcm)
    {
        var (publicKey, secretKey) = Keys(true, 6);
        using var allowed = PgpMessageEncryptor.Create().AddRecipient(publicKey);
        using var blocked = PgpMessageEncryptor.Create().AddRecipient(publicKey)
            .WithSecurityPolicy(SecurityPolicyOptions.Compliance);
        if (gcm)
        {
            allowed.WithAead();
            blocked.WithAead();
        }

        var wire = allowed.Encrypt("policy fixture"u8).ToArray();
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(secretKey)
            .WithSecurityPolicy(SecurityPolicyOptions.Compliance);
        Assert.False(decryptor.TryDecrypt(wire, out var result, out _));
        Assert.True(result.Data.IsEmpty);
        Assert.Throws<SecurityPolicyException>(() => blocked.Encrypt("policy fixture"u8));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EnvelopePolicy_S2k_RejectsConfiguredForbiddenDerivation(bool gcm)
    {
        using var encryptor = PgpMessageEncryptor.Create().WithPassphrase("fixture")
            .WithArgon2()
            .WithSecurityPolicy(SecurityPolicyOptions.Testing);
        if (gcm) encryptor.WithAead();
        var wire = encryptor.Encrypt("policy fixture"u8).ToArray();
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("fixture")
            .WithSecurityPolicy(SecurityPolicyOptions.Compliance);
        Assert.False(decryptor.TryDecrypt(wire, out var result, out _));
        Assert.True(result.Data.IsEmpty);
        using var blocked = PgpMessageEncryptor.Create().WithPassphrase("fixture").WithArgon2()
            .WithSecurityPolicy(SecurityPolicyOptions.Compliance);
        if (gcm) blocked.WithAead();
        Assert.Throws<SecurityPolicyException>(() => blocked.Encrypt("policy fixture"u8));
    }

    [Fact]
    public void SkeskV6Factory_Policy_RejectsForbiddenArgon2()
    {
        Assert.Throws<SecurityPolicyException>(() => PgpSymmetricKeyEncryptedSessionKeyPacket.CreateV6("fixture"u8,
            new byte[32], s2kType: S2KType.Argon2, securityPolicy: SecurityPolicyOptions.Compliance));
    }

    private static int KeySize(SymmetricCipherAlgorithm cipher) => cipher switch
    {
        SymmetricCipherAlgorithm.Aes128 => 16,
        SymmetricCipherAlgorithm.Aes192 => 24,
        SymmetricCipherAlgorithm.Aes256 => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(cipher))
    };

    private static byte[] Sequence(int length) => Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
    private static byte[] SaltedKey(ReadOnlySpan<byte> password, int size) => SHA256.HashData(SaltedS2k[2..].Concat(password.ToArray()).ToArray())[..size];
    private static byte[] NativeCfb(byte[] input, byte[] key, bool encrypt)
    {
        var padded = new byte[(input.Length + 15) / 16 * 16];
        input.CopyTo(padded, 0);
        using var aes = Aes.Create();
        aes.Key = key;
        return (encrypt ? aes.EncryptCfb(padded, new byte[16], PaddingMode.None, 128) :
            aes.DecryptCfb(padded, new byte[16], PaddingMode.None, 128))[..input.Length];
    }

    private static byte[] ReferenceSkesk(SymmetricCipherAlgorithm cipher, byte[] session)
    {
        byte[] aad = [0xC3, 6, (byte)cipher, 3];
        var kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, SaltedKey("fixture"u8, KeySize(cipher)), KeySize(cipher), info: aad);
        var nonce = Sequence(12);
        var ciphertext = new byte[session.Length];
        var tag = new byte[16];
        using var gcm = new System.Security.Cryptography.AesGcm(kek, 16);
        gcm.Encrypt(nonce, session, ciphertext, tag, aad);
        return [6, 25, (byte)cipher, 3, 10, .. SaltedS2k, .. nonce, .. ciphertext, .. tag];
    }

    private static byte[] ReferenceSeipd(SymmetricCipherAlgorithm cipher, byte chunk, byte[] plaintext, byte[] session)
    {
        var salt = Sequence(32);
        byte[] aad = [0xD2, 2, (byte)cipher, 3, chunk];
        var material = HKDF.DeriveKey(HashAlgorithmName.SHA256, session, KeySize(cipher) + 4, salt, aad);
        var nonce = new byte[12];
        material.AsSpan(KeySize(cipher)).CopyTo(nonce);
        using var gcm = new System.Security.Cryptography.AesGcm(material.AsSpan(0, KeySize(cipher)), 16);
        using var output = new MemoryStream();
        ulong index = 0;
        for (int pos = 0; pos < plaintext.Length; index++)
        {
            var length = Math.Min(1 << (chunk + 6), plaintext.Length - pos);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), index);
            var ciphertext = new byte[length];
            var tag = new byte[16];
            gcm.Encrypt(nonce, plaintext.AsSpan(pos, length), ciphertext, tag, aad);
            output.Write(ciphertext);
            output.Write(tag);
            pos += length;
        }
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), index);
        byte[] finalAad = [.. aad, .. new byte[8]];
        BinaryPrimitives.WriteUInt64BigEndian(finalAad.AsSpan(5), (ulong)plaintext.Length);
        var finalTag = new byte[16];
        ReadOnlySpan<byte> empty = [];
        Span<byte> emptyOutput = [];
        gcm.Encrypt(nonce.AsSpan(), empty, emptyOutput, finalTag.AsSpan(), finalAad.AsSpan());
        output.Write(finalTag);
        return [2, (byte)cipher, 3, chunk, .. salt, .. output.ToArray()];
    }

    private static byte[] ReferenceDecrypt(PgpSymEncryptedIntegrityProtectedDataPacket packet, byte[] session)
    {
        byte[] aad = [0xD2, 2, (byte)packet.CipherAlgorithm, 3, packet.ChunkSize];
        var material = HKDF.DeriveKey(HashAlgorithmName.SHA256, session, session.Length + 4, packet.Salt.ToArray(), aad);
        var nonce = new byte[12];
        material.AsSpan(session.Length).CopyTo(nonce);
        using var gcm = new System.Security.Cryptography.AesGcm(material.AsSpan(0, session.Length), 16);
        var data = packet.EncryptedData.ToArray();
        using var output = new MemoryStream();
        ulong index = 0;
        for (int pos = 0; pos < data.Length - 16; index++)
        {
            int length = Math.Min(1 << (packet.ChunkSize + 6), data.Length - 32 - pos);
            Assert.True(length > 0);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), index);
            var plaintext = new byte[length];
            gcm.Decrypt(nonce, data.AsSpan(pos, length), data.AsSpan(pos + length, 16), plaintext, aad);
            output.Write(plaintext);
            pos += length + 16;
        }
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), index);
        byte[] finalAad = [.. aad, .. new byte[8]];
        BinaryPrimitives.WriteUInt64BigEndian(finalAad.AsSpan(5), (ulong)output.Length);
        ReadOnlySpan<byte> empty = [];
        Span<byte> emptyOutput = [];
        gcm.Decrypt(nonce.AsSpan(), empty, data.AsSpan(data.Length - 16), emptyOutput, finalAad.AsSpan());
        return output.ToArray();
    }

    private static byte[] NativeUnwrap(byte[] kek, byte[] wrapped)
    {
        int blocks = wrapped.Length / 8 - 1;
        var a = wrapped[..8];
        var r = wrapped[8..];
        using var aes = Aes.Create();
        aes.Key = kek;
        for (int round = 5; round >= 0; round--)
            for (int i = blocks; i >= 1; i--)
            {
                var value = BinaryPrimitives.ReadUInt64BigEndian(a) ^ (ulong)(blocks * round + i);
                var input = new byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(input, value);
                r.AsSpan((i - 1) * 8, 8).CopyTo(input.AsSpan(8));
                var block = aes.DecryptEcb(input, PaddingMode.None);
                a = block[..8];
                block.AsSpan(8).CopyTo(r.AsSpan((i - 1) * 8, 8));
            }
        Assert.Equal(Enumerable.Repeat((byte)0xA6, 8).ToArray(), a);
        return r;
    }

    private static (PgpPublicKeyPacket, PgpSecretKeyPacket) Keys(bool x25519, byte version)
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(1700000000);
        if (x25519)
        {
            var secret = Sequence(32);
            var key = new PgpPublicKeyPacket(version, time, PgpPublicKeyAlgorithm.X25519, new Curve25519Core().DerivePublicKey(secret));
            return (key, PgpSecretKeyPacket.CreateUnencrypted(key, secret));
        }
        var p = RsaParameters.Value;
        var publicKey = PgpPublicKeyPacket.CreateRsa(version, time, new BigInteger(p.Modulus!, true, true), new BigInteger(p.Exponent!, true, true));
        var primeP = new BigInteger(p.P!, true, true);
        var primeQ = new BigInteger(p.Q!, true, true);
        var material = Mpi.Encode(p.D!).Concat(Mpi.Encode(p.P!)).Concat(Mpi.Encode(p.Q!))
            .Concat(Mpi.Encode(BigInteger.ModPow(primeP, primeQ - 2, primeQ).ToByteArray(true, true))).ToArray();
        return (publicKey, PgpSecretKeyPacket.CreateUnencrypted(publicKey, material));
    }

    private static byte[] LiteralWire(byte[] data)
    {
        using var output = new MemoryStream();
        using var writer = new PgpPacketWriter(output);
        new PgpLiteralDataPacket(PgpLiteralDataFormat.Binary, string.Empty, DateTimeOffset.FromUnixTimeSeconds(1700000000), data).WriteTo(writer);
        return output.ToArray();
    }

    private static byte[] LiteralData(byte[] wire) => PgpLiteralDataPacket.Read(Assert.Single(Packets(wire), p => p.Tag == PgpPacketTag.LiteralData).Body).Data.ToArray();
    private static List<(PgpPacketTag Tag, byte[] Body)> Packets(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var reader = new PgpPacketReader(input);
        var packets = new List<(PgpPacketTag, byte[])>();
        while (reader.ReadNextPacket(out var tag, out var body)) packets.Add((tag, body.ToArray()));
        return packets;
    }

    private static byte[] Message(params (PgpPacketTag Tag, byte[] Body)[] packets)
    {
        using var output = new MemoryStream();
        using var writer = new PgpPacketWriter(output);
        foreach (var packet in packets) writer.WritePacket(packet.Tag, packet.Body);
        return output.ToArray();
    }
}
