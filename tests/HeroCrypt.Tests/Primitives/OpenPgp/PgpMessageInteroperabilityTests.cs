using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Bc = Org.BouncyCastle.Bcpg.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpMessageInteroperabilityTests
{
    private static readonly byte[] Plaintext = "independent OpenPGP message interoperability"u8.ToArray();
    private static readonly Lazy<PgpKeyGeneratorResult> Recipient = new(() => PgpKeyGenerator.Create()
        .WithVersion(4).WithKeySize(2048).WithUserId("message-interop@example.invalid").GenerateRsa());

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void Encrypt_V4RsaAes_BouncyCastleReadsAndAuthenticatesWholeMessage(SymmetricCipherAlgorithm cipher)
    {
        var decrypted = ReadWithBouncyCastle(EncryptWithHeroCrypt(cipher));
        Assert.True(decrypted.Authenticated);
        Assert.Equal(Plaintext, decrypted.Data);
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void Decrypt_V4RsaAes_ReadsWholeBouncyCastleMessage(SymmetricCipherAlgorithm cipher)
    {
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(Recipient.Value.MasterSecretKey);
        var decrypted = decryptor.Decrypt(EncryptWithBouncyCastle(cipher));
        Assert.Equal(1, decrypted.SeipdVersion);
        Assert.Equal(Plaintext, decrypted.Data.ToArray());
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void Encrypt_ModifiedMdc_BouncyCastleRejectsIntegrity(SymmetricCipherAlgorithm cipher)
    {
        Assert.False(ReadWithBouncyCastle(CorruptMdc(EncryptWithHeroCrypt(cipher))).Authenticated);
    }

    [Theory]
    [InlineData(SymmetricCipherAlgorithm.Aes128)]
    [InlineData(SymmetricCipherAlgorithm.Aes192)]
    [InlineData(SymmetricCipherAlgorithm.Aes256)]
    public void Decrypt_BouncyCastleMessageWithModifiedMdc_ReturnsNoPlaintext(SymmetricCipherAlgorithm cipher)
    {
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(Recipient.Value.MasterSecretKey);
        Assert.False(decryptor.TryDecrypt(CorruptMdc(EncryptWithBouncyCastle(cipher)), out var result, out _));
        Assert.True(result.Data.IsEmpty);
    }

    private static byte[] EncryptWithHeroCrypt(SymmetricCipherAlgorithm cipher)
    {
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.MasterPublicKey)
            .WithSymmetricAlgorithm(cipher);
        return encryptor.Encrypt(Plaintext).ToArray();
    }

    private static byte[] EncryptWithBouncyCastle(SymmetricCipherAlgorithm cipher)
    {
        var publicKey = new Bc.PgpPublicKeyRing(Recipient.Value.ExportPublicKey()).GetPublicKey();
        var generator = new Bc.PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(byte)cipher,
            withIntegrityPacket: true, new SecureRandom());
        generator.AddMethod(publicKey);
        using var output = new MemoryStream();
        using (var encrypted = generator.Open(output, new byte[4096]))
        {
            var literalGenerator = new Bc.PgpLiteralDataGenerator();
            using var literal = literalGenerator.Open(encrypted, Bc.PgpLiteralData.Binary, string.Empty,
                Plaintext.Length, DateTime.UnixEpoch);
            literal.Write(Plaintext, 0, Plaintext.Length);
        }
        return output.ToArray();
    }

    private static (byte[] Data, bool Authenticated) ReadWithBouncyCastle(byte[] wire)
    {
        var secretKey = new Bc.PgpSecretKeyRing(Recipient.Value.ExportSecretKey()).GetSecretKey();
        var factory = new Bc.PgpObjectFactory(wire);
        var methods = Assert.IsType<Bc.PgpEncryptedDataList>(factory.NextPgpObject());
        Assert.Equal(1, methods.Count);
        var encrypted = Assert.IsType<Bc.PgpPublicKeyEncryptedData>(methods[0]);
        Assert.True(encrypted.IsIntegrityProtected());
        using var clear = encrypted.GetDataStream(secretKey.ExtractPrivateKey([]));
        var literal = Assert.IsType<Bc.PgpLiteralData>(new Bc.PgpObjectFactory(clear).NextPgpObject());
        using var plaintext = new MemoryStream();
        literal.GetInputStream().CopyTo(plaintext);
        bool authenticated = encrypted.Verify();
        return (plaintext.ToArray(), authenticated);
    }

    private static byte[] CorruptMdc(byte[] wire)
    {
        using var input = new MemoryStream(wire);
        using var reader = new PgpPacketReader(input);
        using var output = new MemoryStream();
        using var writer = new PgpPacketWriter(output);
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            var bytes = body.ToArray();
            if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData) bytes[^1] ^= 1;
            writer.WritePacket(tag, bytes);
        }
        return output.ToArray();
    }
}
