using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Collection("Global security policy")]
public class PgpS2KResourceSecurityTests
{
    private static readonly byte[] Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] Plaintext = "bounded S2K fixture"u8.ToArray();
    private static readonly Lazy<PgpKeyGeneratorResult> Recipient = new(() => PgpKeyGenerator.Create()
        .WithVersion(4).WithKeySize(2048).WithUserId("s2k-fixture@example.invalid").GenerateRsa());
    private static readonly S2KResourceLimits ExactLimits = new() { MaxArgon2MemoryKiB = 8, MaxArgon2WorkKiB = 16 };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Message_RejectsOverBudgetAndAcceptsExactBudget(bool memoryLimit)
    {
        var key = Parameters().DeriveKey("public fixture"u8, 16);
        var skesk = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes128, Parameters().Serialize());
        var literal = Packet(PgpPacketTag.LiteralData, [0x62, 0, 0, 0, 0, 0, .. Plaintext]);
        byte[] mdcInput = [.. new byte[18], .. literal, 0xD3, 0x14];
#pragma warning disable CA5350 // SEIPD v1 requires SHA-1 for its MDC.
        byte[] protectedData = [1, .. NativeCfb([.. mdcInput, .. SHA1.HashData(mdcInput)], key)];
#pragma warning restore CA5350
        byte[] wire = [.. Packet(PgpPacketTag.SymmetricKeyEncryptedSessionKey, skesk.ToArray()),
            .. Packet(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, protectedData)];

        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("public fixture")
            .WithSecurityPolicy(SecurityPolicyOptions.Testing with { S2KLimits = LowerLimit(memoryLimit) });
        Assert.False(decryptor.TryDecrypt(wire, out var rejected, out _));
        Assert.True(rejected.Data.IsEmpty);
        decryptor.WithSecurityPolicy(SecurityPolicyOptions.Default with { S2KLimits = ExactLimits });
        Assert.Equal(Plaintext, decryptor.Decrypt(wire).Data.ToArray());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SecretKey_RejectsOverBudgetAndAcceptsExactBudget(bool memoryLimit)
    {
        var encrypted = ProtectedSecret();
        var ex = Assert.Throws<CryptographicException>(() => encrypted.Decrypt("public fixture", LowerLimit(memoryLimit)));
        Assert.Contains("limit", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Recipient.Value.MasterSecretKey.SecretKeyMaterial.ToArray(),
            encrypted.Decrypt("public fixture", ExactLimits).SecretKeyMaterial.ToArray());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MessageV6_RejectsOverBudgetAndAcceptsExactBudget(bool memoryLimit)
    {
        byte[] aad = [0xC3, 6, 7, 3];
        var derived = Parameters().DeriveKey("public fixture"u8, 16);
        var kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, derived, 16, info: aad);
        var session = new byte[16];
        var nonce = new byte[12];
        var wrapped = new byte[16];
        var tag = new byte[16];
        using (var gcm = new System.Security.Cryptography.AesGcm(kek, 16))
        {
            gcm.Encrypt(nonce, session, wrapped, tag, aad);
        }
        var skesk = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes128,
            AeadAlgorithm.Gcm, Parameters().Serialize(), nonce, wrapped.Concat(tag).ToArray());
        var literal = Packet(PgpPacketTag.LiteralData, [0x62, 0, 0, 0, 0, 0, .. Plaintext]);
        var salt = new byte[32];
        var data = PgpSeipdAead.Encrypt(literal, session, SymmetricCipherAlgorithm.Aes128,
            AeadAlgorithm.Gcm, 6, salt, SecurityPolicyOptions.Default);
        var seipd = new PgpSymEncryptedIntegrityProtectedDataPacket(SymmetricCipherAlgorithm.Aes128,
            AeadAlgorithm.Gcm, 6, salt, data);
        byte[] wire = [.. Packet(PgpPacketTag.SymmetricKeyEncryptedSessionKey, skesk.ToArray()),
            .. Packet(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipd.ToArray())];

        using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase("public fixture")
            .WithSecurityPolicy(SecurityPolicyOptions.Testing with { S2KLimits = LowerLimit(memoryLimit) });
        Assert.False(decryptor.TryDecrypt(wire, out var rejected, out _));
        Assert.True(rejected.Data.IsEmpty);
        decryptor.WithSecurityPolicy(SecurityPolicyOptions.Default with { S2KLimits = ExactLimits });
        Assert.Equal(Plaintext, decryptor.Decrypt(wire).Data.ToArray());

        // Keep authentication tags unchanged: the old masked shift accepted this alias.
        var aliasedParameters = Parameters().Serialize();
        aliasedParameters[19] = 35;
        var aliasedSkesk = new PgpSymmetricKeyEncryptedSessionKeyPacket(SymmetricCipherAlgorithm.Aes128,
            AeadAlgorithm.Gcm, aliasedParameters, nonce, wrapped.Concat(tag).ToArray());
        byte[] aliasedWire = [.. Packet(PgpPacketTag.SymmetricKeyEncryptedSessionKey, aliasedSkesk.ToArray()),
            .. Packet(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipd.ToArray())];
        Assert.False(decryptor.TryDecrypt(aliasedWire, out var aliasRejected, out _));
        Assert.True(aliasRejected.Data.IsEmpty);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Message_PropagatesBudgetToEncryptedSecretKey(bool memoryLimit)
    {
        using var encryptor = PgpMessageEncryptor.Create().AddRecipient(Recipient.Value.MasterPublicKey);
        var wire = encryptor.Encrypt(Plaintext).ToArray();
        using var decryptor = PgpMessageDecryptor.Create().WithSecretKey(ProtectedSecret()).WithPassphrase("public fixture")
            .WithSecurityPolicy(SecurityPolicyOptions.Default with { S2KLimits = LowerLimit(memoryLimit) });
        Assert.False(decryptor.TryDecrypt(wire, out var rejected, out _));
        Assert.True(rejected.Data.IsEmpty);
        decryptor.WithSecurityPolicy(SecurityPolicyOptions.Default with { S2KLimits = ExactLimits });
        Assert.Equal(Plaintext, decryptor.Decrypt(wire).Data.ToArray());
    }

    [Theory]
    [InlineData(35)]
    [InlineData(67)]
    [InlineData(99)]
    public void SecretKey_RejectsManuallyConstructedExponentAlias(byte exponent)
    {
        var encrypted = ProtectedSecret(exponent);
        Assert.ThrowsAny<ArgumentException>(() => encrypted.Decrypt("public fixture"));
    }

    [Fact]
    public void KeyGenerator_HonorsCallerBudget()
    {
        var generator = PgpKeyGenerator.Create().WithUserId("s2k-fixture@example.invalid")
            .WithArgon2Passphrase("public fixture", passes: 2, parallelism: 1, memoryExponent: 3)
            .WithSecurityPolicy(SecurityPolicyOptions.Default with { S2KLimits = LowerLimit(true) });
        Assert.Throws<CryptographicException>(() => generator.GenerateEd25519());
    }

    [Fact]
    public void AlgorithmPolicyScope_PreservesCallerResourceLimits()
    {
        var previous = SecurityPolicy.GlobalPolicy;
        try
        {
            SecurityPolicy.GlobalPolicy = previous with { S2KLimits = LowerLimit(true) };
            using var scope = SecurityPolicy.TestingScope();
            Assert.Throws<CryptographicException>(() => Parameters().DeriveKey("public fixture"u8, 16));
            var encrypted = ProtectedSecret();
            Assert.Throws<CryptographicException>(() => encrypted.Decrypt("public fixture"));
        }
        finally
        {
            SecurityPolicy.GlobalPolicy = previous;
        }
    }

    private static S2KResourceLimits LowerLimit(bool memory)
        => memory ? ExactLimits with { MaxArgon2MemoryKiB = 7 } : ExactLimits with { MaxArgon2WorkKiB = 15 };

    private static S2KParameters Parameters() => new()
    {
        Type = S2KType.Argon2,
        Salt = Salt,
        Argon2TimePasses = 2,
        Argon2Parallelism = 1,
        Argon2MemoryExponent = 3
    };

    private static PgpSecretKeyPacket ProtectedSecret(byte exponent = 3)
    {
        var key = Parameters().DeriveKey("public fixture"u8, 32, SecurityPolicyOptions.Default);
        var material = Recipient.Value.MasterSecretKey.SecretKeyMaterial.Span[..^2].ToArray();
#pragma warning disable CA5350 // Secret key usage 254 requires SHA-1.
        var ciphertext = NativeCfb([.. material, .. SHA1.HashData(material)], key);
#pragma warning restore CA5350
        var specifier = new PgpS2KSpecifier(S2KType.Argon2, 8, Salt, argon2Params: (2, 1, exponent));
        return PgpSecretKeyPacket.CreateEncrypted(Recipient.Value.MasterPublicKey, PgpS2KUsage.Sha1Hash,
            9, specifier, new byte[16], ciphertext);
    }

    private static byte[] NativeCfb(byte[] input, byte[] key)
    {
        var padded = new byte[(input.Length + 15) / 16 * 16];
        input.CopyTo(padded, 0);
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptCfb(padded, new byte[16], PaddingMode.None, 128)[..input.Length];
    }

    private static byte[] Packet(PgpPacketTag tag, byte[] body)
    {
        using var stream = new MemoryStream();
        using var writer = new PgpPacketWriter(stream, leaveOpen: true);
        writer.WritePacket(tag, body);
        return stream.ToArray();
    }
}
