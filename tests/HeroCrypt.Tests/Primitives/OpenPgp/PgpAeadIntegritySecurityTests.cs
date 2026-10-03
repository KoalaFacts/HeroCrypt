using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpAeadIntegritySecurityTests
{
    private const string Password = "AEAD integrity regression fixture";
    private static readonly Lazy<byte[]> FullChunkMessage = new(() => Encrypt(4087));
    private static readonly Lazy<byte[]> TwoChunkMessage = new(() => Encrypt(8183));
    private static readonly Lazy<byte[]> PartialChunkMessage = new(() => Encrypt(4088));

    public static IEnumerable<object[]> Insertions()
    {
        for (int count = 1; count <= 16; count++)
        {
            yield return [count, false];
            yield return [count, true];
        }
    }

    public static IEnumerable<object[]> TagOffsets()
    {
        for (int offset = 0; offset < 16; offset++)
        {
            yield return [offset, false];
            yield return [offset, true];
        }
    }

    [Theory]
    [MemberData(nameof(Insertions))]
    public void TryDecrypt_BytesInsertedBeforeFinalTag_RejectsWithoutPlaintext(int count, bool twoChunks)
    {
        var original = twoChunks ? TwoChunkMessage.Value : FullChunkMessage.Value;
        var modified = RewriteEncryptedData(original, data =>
            data[..^16].Concat(Enumerable.Repeat((byte)0xA5, count)).Concat(data[^16..]).ToArray());

        AssertRejected(modified);
    }

    [Theory]
    [MemberData(nameof(Insertions))]
    public void TryDecrypt_TruncatedFinalTag_RejectsWithoutPlaintext(int count, bool twoChunks)
    {
        var original = twoChunks ? TwoChunkMessage.Value : FullChunkMessage.Value;
        AssertRejected(RewriteEncryptedData(original, data => data[..^count]));
    }

    [Theory]
    [MemberData(nameof(TagOffsets))]
    public void TryDecrypt_ModifiedChunkOrFinalTag_RejectsWithoutPlaintext(int offset, bool finalTag)
    {
        AssertRejected(RewriteEncryptedData(FullChunkMessage.Value, data =>
        {
            data[data.Length - (finalTag ? 16 : 32) + offset] ^= 1;
            return data;
        }));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    public void TryDecrypt_MissingRequiredTags_RejectsWithoutPlaintext(int length)
    {
        AssertRejected(RewriteEncryptedData(FullChunkMessage.Value, data => data[..length]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(32)]
    public void TryDecrypt_InsertionAfterPartialChunk_RejectsWithoutPlaintext(int count)
    {
        AssertRejected(RewriteEncryptedData(PartialChunkMessage.Value, data =>
            data[..^16].Concat(new byte[count]).Concat(data[^16..]).ToArray()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4086)]
    [InlineData(4087)]
    [InlineData(4088)]
    [InlineData(8183)]
    public void Decrypt_UntamperedBoundaryMessages_ReturnsOriginalData(int length)
    {
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase(Password);
        var message = decryptor.Decrypt(Encrypt(length));
        Assert.Equal(Enumerable.Repeat((byte)0x42, length).ToArray(), message.Data.ToArray());
    }

    private static byte[] Encrypt(int length)
    {
        using var encryptor = PgpMessageEncryptor.Create()
            .WithPassphrase(Password)
            .WithAead(AeadAlgorithm.Gcm)
            .WithFileName(string.Empty)
            .WithFileDate(DateTimeOffset.FromUnixTimeSeconds(1700000000));
        // A literal packet adds nine bytes at these boundaries: 4087 yields one
        // complete 4096-byte plaintext chunk, and 8183 yields two complete chunks.
        return encryptor.Encrypt(Enumerable.Repeat((byte)0x42, length).ToArray()).ToArray();
    }

    private static byte[] RewriteEncryptedData(byte[] message, Func<byte[], byte[]> mutate)
    {
        using var input = new MemoryStream(message);
        using var reader = new PgpPacketReader(input);
        using var output = new MemoryStream();
        using var writer = new PgpPacketWriter(output);
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData)
            {
                var packet = PgpSymEncryptedIntegrityProtectedDataPacket.Read(body.Span);
                var modified = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                    packet.CipherAlgorithm, packet.AeadAlgorithm, packet.ChunkSize, packet.Salt,
                    mutate(packet.EncryptedData.ToArray()));
                writer.WritePacket(tag, modified.ToArray());
            }
            else
            {
                writer.WritePacket(tag, body.Span);
            }
        }

        return output.ToArray();
    }

    private static void AssertRejected(byte[] message)
    {
        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase(Password);
        Assert.False(decryptor.TryDecrypt(message, out var plaintext, out var error));
        Assert.True(plaintext.Data.IsEmpty);
        Assert.False(string.IsNullOrEmpty(error));
    }
}
