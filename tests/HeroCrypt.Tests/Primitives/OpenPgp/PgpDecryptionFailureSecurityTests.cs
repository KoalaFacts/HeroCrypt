using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpDecryptionFailureSecurityTests
{
    private static readonly Lazy<PgpKeyGeneratorResult> Recipient = new(() => PgpKeyGenerator.Create()
        .WithVersion(4).WithKeySize(2048).WithUserId("decryption-fixture@example.invalid").GenerateRsa());
    private static readonly Lazy<byte[]> Message = new(() =>
    {
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.MasterPublicKey);
        return encryptor.Encrypt("decryption failure regression"u8).ToArray();
    });

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Decrypt_PrefixMdcAndRsaFailures_HaveSamePublicError(int mutation)
    {
        var prefixFailure = MutateMessage(0);
        var otherFailure = MutateMessage(mutation);
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(Recipient.Value.MasterSecretKey);

        Assert.False(decryptor.TryDecrypt(prefixFailure, out var prefixResult, out var prefixError));
        Assert.True(prefixResult.Data.IsEmpty);
        Assert.False(decryptor.TryDecrypt(otherFailure, out var otherResult, out var otherError));
        Assert.True(otherResult.Data.IsEmpty);

        var prefixException = Assert.Throws<CryptographicException>(() => decryptor.Decrypt(prefixFailure));
        var otherException = Assert.Throws<CryptographicException>(() => decryptor.Decrypt(otherFailure));
        Assert.Equal(prefixError, otherError);
        Assert.Equal(prefixException.Message, otherException.Message);
        Assert.Null(prefixException.InnerException);
        Assert.Null(otherException.InnerException);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(39)]
    public void TryDecrypt_TruncatedCfbContainer_ReturnsFalseWithoutThrowing(int encryptedLength)
    {
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(Recipient.Value.MasterSecretKey);
        Assert.False(decryptor.TryDecrypt(MutateMessage(0, encryptedLength), out var result, out var error));
        Assert.True(result.Data.IsEmpty);
        Assert.False(string.IsNullOrEmpty(error));
    }

    private static byte[] MutateMessage(int mutation, int? encryptedLength = null)
    {
        using var input = new MemoryStream(Message.Value);
        using var reader = new PgpPacketReader(input);
        using var output = new MemoryStream();
        using var writer = new PgpPacketWriter(output);
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.PublicKeyEncryptedSessionKey && mutation == 3)
            {
                var packet = PgpPublicKeyEncryptedSessionKeyPacket.Read(body.Span);
                // The MPI is the integer one: valid MPI framing, invalid RSA padding.
                writer.WritePacket(tag, new PgpPublicKeyEncryptedSessionKeyPacket(packet.KeyId,
                    packet.Algorithm, new byte[] { 0, 1, 1 }).ToArray());
            }
            else if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData && mutation != 3)
            {
                var packet = PgpSymEncryptedIntegrityProtectedDataPacket.Read(body.Span);
                var encrypted = packet.EncryptedData.ToArray();
                if (encryptedLength.HasValue) encrypted = encrypted[..encryptedLength.Value];
                else
                {
                    int offset = mutation switch
                    {
                        0 => 16, // Corrupt a quick-check octet while keeping PKESK intact.
                        1 => encrypted.Length - 1, // Corrupt MDC digest only.
                        _ => encrypted.Length - 22 // Corrupt MDC packet header.
                    };
                    encrypted[offset] ^= 1;
                }
                writer.WritePacket(tag, PgpSymEncryptedIntegrityProtectedDataPacket.CreateV1(encrypted).ToArray());
            }
            else writer.WritePacket(tag, body.Span);
        }
        return output.ToArray();
    }
}
