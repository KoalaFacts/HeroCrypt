using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpDataCipherPolicySecurityTests
{
    private const string Passphrase = "data-cipher fixture";
    private static readonly byte[] Plaintext = "independent data-cipher policy fixture"u8.ToArray();
    // Salted SHA-256 S2K, with a fixed public test salt.
    private static readonly byte[] S2k = [1, 8, 0, 1, 2, 3, 4, 5, 6, 7];
    private static readonly Lazy<RSAParameters> RsaParameters = new(() =>
    {
        using var rsa = RSA.Create(3072);
        return rsa.ExportParameters(true);
    });
    private static readonly Lazy<(PgpPublicKeyPacket Public, PgpSecretKeyPacket Secret)> Recipient = new(CreateRecipient);

    public static IEnumerable<object[]> RejectionCases()
    {
        foreach (var envelope in new[] { "RSA", "Direct SKESK", "AES-wrapped SKESK" })
            foreach (var level in new[] { SecurityLevel.Standard, SecurityLevel.Strict, SecurityLevel.Compliance })
                foreach (bool policyFirst in new[] { false, true })
                    yield return [envelope, level, policyFirst];
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("Direct SKESK")]
    [InlineData("AES-wrapped SKESK")]
    public void TryDecrypt_TripleDesData_DefaultPolicyRejects(string envelope)
    {
        using var decryptor = PgpMessageDecryptor.Create();
        if (envelope == "RSA") decryptor.WithSecretKey(Recipient.Value.Secret);
        else decryptor.WithMessagePassphrase(Passphrase);
        Assert.False(decryptor.TryDecrypt(LegacyMessage(envelope), out var result, out _));
        Assert.True(result.Data.IsEmpty);
    }

    [Theory]
    [MemberData(nameof(RejectionCases))]
    public void TryDecrypt_TripleDesData_RejectsUnderConfiguredPolicyAndRemainsReusable(
        string envelope, SecurityLevel level, bool policyFirst)
    {
        var wire = LegacyMessage(envelope);
        using var decryptor = ConfigureDecryptor(envelope, new SecurityPolicyOptions(level), policyFirst);
        Assert.False(decryptor.TryDecrypt(wire, out var result, out var error));
        Assert.True(result.Data.IsEmpty);

        // A policy rejection is indistinguishable from an integrity failure.
        var invalidAes = AesMessage(envelope);
        invalidAes[^1] ^= 1;
        Assert.False(decryptor.TryDecrypt(invalidAes, out var invalidResult, out var invalidError));
        Assert.True(invalidResult.Data.IsEmpty);
        Assert.False(string.IsNullOrEmpty(error));
        Assert.Equal(invalidError, error);
        var exception = Assert.Throws<CryptographicException>(() => decryptor.Decrypt(wire));
        Assert.Equal(error, exception.Message);
        Assert.Null(exception.InnerException);

        Assert.Equal(Plaintext, decryptor.Decrypt(AesMessage(envelope)).Data.ToArray());
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("Direct SKESK")]
    [InlineData("AES-wrapped SKESK")]
    public void Decrypt_IndependentTripleDesFixture_RequiresCurrentExplicitLegacyPolicy(string envelope)
    {
        var wire = LegacyMessage(envelope);
        var legacyPolicy = new SecurityPolicyOptions(SecurityLevel.None);
        using var decryptor = ConfigureDecryptor(envelope, legacyPolicy, policyFirst: true);
        // This proves the native CFB64/MDC fixture is valid, rather than malformed input.
        Assert.Equal(Plaintext, decryptor.Decrypt(wire).Data.ToArray());

        decryptor.WithSecurityPolicy(SecurityPolicyOptions.Strict);
        Assert.False(decryptor.TryDecrypt(wire, out var rejected, out _));
        Assert.True(rejected.Data.IsEmpty);
        Assert.Equal(Plaintext, decryptor.Decrypt(AesMessage(envelope)).Data.ToArray());

        decryptor.WithSecurityPolicy(legacyPolicy);
        Assert.Equal(Plaintext, decryptor.Decrypt(wire).Data.ToArray());
    }

    public static IEnumerable<object[]> AesProducerCases()
    {
        foreach (var cipher in new[] { SymmetricCipherAlgorithm.Aes128, SymmetricCipherAlgorithm.Aes192, SymmetricCipherAlgorithm.Aes256 })
            foreach (var level in new[] { SecurityLevel.Standard, SecurityLevel.Strict, SecurityLevel.Compliance })
                foreach (bool policyFirst in new[] { false, true })
                    yield return [cipher, level, policyFirst];
    }

    [Theory]
    [MemberData(nameof(AesProducerCases))]
    public void Encrypt_AesSelectionAndPolicyInEitherOrder_EmitsNativeDecryptableData(
        SymmetricCipherAlgorithm cipher, SecurityLevel level, bool policyFirst)
    {
        var policy = new SecurityPolicyOptions(level);
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.Public);
        if (policyFirst) encryptor.WithSecurityPolicy(policy).WithSymmetricAlgorithm(cipher);
        else encryptor.WithSymmetricAlgorithm(cipher).WithSecurityPolicy(policy);
        var encrypted = encryptor.Encrypt(Plaintext);
        var packets = Packets(encrypted.ToArray());
        var pkesk = PgpPublicKeyEncryptedSessionKeyPacket.Read(Assert.Single(packets,
            p => p.Tag == PgpPacketTag.PublicKeyEncryptedSessionKey).Body);
        var mpi = Mpi.ReadBytes(pkesk.EncryptedSessionKey.Span, out var consumed);
        Assert.Equal(pkesk.EncryptedSessionKey.Length, consumed);
        var padded = new byte[RsaParameters.Value.Modulus!.Length];
        mpi.CopyTo(padded.AsSpan(padded.Length - mpi.Length));
        using var rsa = RSA.Create();
        rsa.ImportParameters(RsaParameters.Value);
        var session = rsa.Decrypt(padded, RSAEncryptionPadding.Pkcs1);
        Assert.Equal((byte)cipher, session[0]);
        Assert.Equal(KeySize(cipher) + 3, session.Length);
        Assert.Equal(session[1..^2].Sum(value => value) & 0xFFFF,
            BinaryPrimitives.ReadUInt16BigEndian(session.AsSpan(session.Length - 2)));

        var seipd = PgpSymEncryptedIntegrityProtectedDataPacket.Read(Assert.Single(packets,
            p => p.Tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData).Body);
        Assert.Equal(1, seipd.Version);
        var decoded = NativeCfb(seipd.EncryptedData.ToArray(), session[1..^2], tripleDes: false, encrypt: false);
        Assert.Equal(decoded[14..16], decoded[16..18]);
        Assert.Equal(new byte[] { 0xD3, 0x14 }, decoded[^22..^20]);
        Assert.Equal(Mdc(decoded[..^20]), decoded[^20..]);
        var literal = Assert.Single(Packets(decoded[18..^22]));
        Assert.Equal(PgpPacketTag.LiteralData, literal.Tag);
        Assert.Equal(Plaintext, PgpLiteralDataPacket.Read(literal.Body).Data.ToArray());

        using var decryptor = ConfigureDecryptor("RSA", policy, policyFirst);
        Assert.Equal(Plaintext, decryptor.Decrypt(encrypted).Data.ToArray());
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Twofish, false)]
    [InlineData(SymmetricCipherAlgorithm.Twofish, true)]
    [InlineData(SymmetricCipherAlgorithm.Camellia128, false)]
    [InlineData(SymmetricCipherAlgorithm.Camellia128, true)]
    [InlineData(SymmetricCipherAlgorithm.Camellia192, false)]
    [InlineData(SymmetricCipherAlgorithm.Camellia192, true)]
    [InlineData(SymmetricCipherAlgorithm.Camellia256, false)]
    [InlineData(SymmetricCipherAlgorithm.Camellia256, true)]
    public void Encrypt_UnsupportedCipherAndPolicyInEitherOrder_Rejects(SymmetricCipherAlgorithm cipher, bool policyFirst)
    {
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.Public);
        if (policyFirst) encryptor.WithSecurityPolicy(SecurityPolicyOptions.Strict).WithSymmetricAlgorithm(cipher);
        else encryptor.WithSymmetricAlgorithm(cipher).WithSecurityPolicy(SecurityPolicyOptions.Strict);
        Assert.Throws<NotSupportedException>(() => encryptor.Encrypt(Plaintext));
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Twofish)]
    [InlineData(SymmetricCipherAlgorithm.Camellia128)]
    [InlineData(SymmetricCipherAlgorithm.Camellia192)]
    [InlineData(SymmetricCipherAlgorithm.Camellia256)]
    public void TryDecrypt_HistoricalNonAesLabelOnAesBytes_DoesNotReinterpretEvenWithLegacyPolicy(SymmetricCipherAlgorithm label)
    {
        var session = Sequence(KeySize(label));
        var wire = Message(RsaEnvelope(label, session), DataContainer(session, tripleDes: false));
        using var decryptor = ConfigureDecryptor("RSA", new SecurityPolicyOptions(SecurityLevel.None), policyFirst: true);
        Assert.False(decryptor.TryDecrypt(wire, out var result, out _));
        Assert.True(result.Data.IsEmpty);
    }

    private static PgpMessageDecryptor ConfigureDecryptor(string envelope, SecurityPolicyOptions policy, bool policyFirst)
    {
        var decryptor = PgpMessageDecryptor.Create();
        if (policyFirst) decryptor.WithSecurityPolicy(policy);
        if (envelope == "RSA") decryptor.WithSecretKey(Recipient.Value.Secret);
        else decryptor.WithMessagePassphrase(Passphrase);
        if (!policyFirst) decryptor.WithSecurityPolicy(policy);
        return decryptor;
    }

    private static byte[] LegacyMessage(string envelope)
    {
#pragma warning disable CS0618 // Deliberate legacy-cipher acceptance regression fixture.
        return ReferenceMessage(envelope, SymmetricCipherAlgorithm.TripleDes, tripleDes: true);
#pragma warning restore CS0618
    }

    private static byte[] AesMessage(string envelope) => ReferenceMessage(envelope, SymmetricCipherAlgorithm.Aes256, tripleDes: false);

    private static byte[] ReferenceMessage(string envelope, SymmetricCipherAlgorithm cipher, bool tripleDes)
    {
        var session = envelope == "Direct SKESK" ? SaltedKey(KeySize(cipher)) : Sequence(KeySize(cipher));
        (PgpPacketTag Tag, byte[] Body) keyPacket = envelope switch
        {
            "RSA" => RsaEnvelope(cipher, session),
            "Direct SKESK" => (PgpPacketTag.SymmetricKeyEncryptedSessionKey, [4, (byte)cipher, .. S2k]),
            "AES-wrapped SKESK" => (PgpPacketTag.SymmetricKeyEncryptedSessionKey,
                [4, 9, .. S2k, .. NativeCfb([(byte)cipher, .. session], SaltedKey(32), tripleDes: false, encrypt: true)]),
            _ => throw new ArgumentOutOfRangeException(nameof(envelope))
        };
        return Message(keyPacket, DataContainer(session, tripleDes));
    }

    private static (PgpPacketTag Tag, byte[] Body) RsaEnvelope(SymmetricCipherAlgorithm cipher, byte[] session)
    {
        byte[] decoded = [(byte)cipher, .. session, 0, 0];
        BinaryPrimitives.WriteUInt16BigEndian(decoded.AsSpan(decoded.Length - 2), (ushort)session.Sum(value => value));
        using var rsa = RSA.Create();
        rsa.ImportParameters(RsaParameters.Value);
        var encrypted = rsa.Encrypt(decoded, RSAEncryptionPadding.Pkcs1);
        return (PgpPacketTag.PublicKeyEncryptedSessionKey,
            new PgpPublicKeyEncryptedSessionKeyPacket(Recipient.Value.Public.GetKeyId(),
                PgpPublicKeyAlgorithm.RsaEncryptOrSign, Mpi.Encode(encrypted)).ToArray());
    }

    private static (PgpPacketTag Tag, byte[] Body) DataContainer(byte[] session, bool tripleDes)
    {
        int blockSize = tripleDes ? 8 : 16;
        var prefix = Sequence(blockSize);
        // Literal packet header and payload are fixed independently of the producer.
        byte[] literal = [0xCB, (byte)(Plaintext.Length + 6), (byte)'b', 0, 0, 0, 0, 0, .. Plaintext];
        byte[] mdcInput = [.. prefix, .. prefix[^2..], .. literal, 0xD3, 0x14];
        return (PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData,
            [1, .. NativeCfb([.. mdcInput, .. Mdc(mdcInput)], session, tripleDes, encrypt: true)]);
    }

    private static byte[] Mdc(byte[] input)
    {
#pragma warning disable CA5350 // SHA-1 is fixed by the SEIPD v1 MDC wire format.
        return SHA1.HashData(input);
#pragma warning restore CA5350
    }

    private static byte[] NativeCfb(byte[] input, byte[] key, bool tripleDes, bool encrypt)
    {
#pragma warning disable CA5350 // Native 3DES is used only to construct independent legacy fixtures.
        using SymmetricAlgorithm cipher = tripleDes ? TripleDES.Create() : Aes.Create();
#pragma warning restore CA5350
        cipher.Key = key;
        int blockSize = cipher.BlockSize / 8;
        var padded = new byte[(input.Length + blockSize - 1) / blockSize * blockSize];
        input.CopyTo(padded, 0);
        return (encrypt ? cipher.EncryptCfb(padded, new byte[blockSize], PaddingMode.None, cipher.BlockSize)
            : cipher.DecryptCfb(padded, new byte[blockSize], PaddingMode.None, cipher.BlockSize))[..input.Length];
    }

    private static byte[] SaltedKey(int size) => SHA256.HashData(S2k[2..].Concat(System.Text.Encoding.UTF8.GetBytes(Passphrase)).ToArray())[..size];
    private static byte[] Sequence(int length) => Enumerable.Range(0, length).Select(value => (byte)value).ToArray();

    private static int KeySize(SymmetricCipherAlgorithm cipher) => cipher switch
    {
#pragma warning disable CS0618 // Legacy fixture key size.
        SymmetricCipherAlgorithm.TripleDes or SymmetricCipherAlgorithm.Aes192 or SymmetricCipherAlgorithm.Camellia192 => 24,
#pragma warning restore CS0618
        SymmetricCipherAlgorithm.Aes128 or SymmetricCipherAlgorithm.Camellia128 => 16,
        _ => 32
    };

    private static (PgpPublicKeyPacket Public, PgpSecretKeyPacket Secret) CreateRecipient()
    {
        var parameters = RsaParameters.Value;
        var publicKey = PgpPublicKeyPacket.CreateRsa(4, DateTimeOffset.FromUnixTimeSeconds(1700000000),
            new BigInteger(parameters.Modulus!, true, true), new BigInteger(parameters.Exponent!, true, true));
        var primeP = new BigInteger(parameters.P!, true, true);
        var primeQ = new BigInteger(parameters.Q!, true, true);
        var material = Mpi.Encode(parameters.D!).Concat(Mpi.Encode(parameters.P!)).Concat(Mpi.Encode(parameters.Q!))
            .Concat(Mpi.Encode(BigInteger.ModPow(primeP, primeQ - 2, primeQ).ToByteArray(true, true))).ToArray();
        return (publicKey, PgpSecretKeyPacket.CreateUnencrypted(publicKey, material));
    }

    private static List<(PgpPacketTag Tag, byte[] Body)> Packets(byte[] wire)
    {
        using var input = new MemoryStream(wire);
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
