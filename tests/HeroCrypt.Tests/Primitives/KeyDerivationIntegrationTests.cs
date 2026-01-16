using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Primitives.Pbkdf2;
using HeroCrypt.Primitives.Scrypt;

namespace HeroCrypt.Tests.Primitives;

/// <summary>
/// Unit tests for key derivation using the fluent builders and core primitives (no services).
/// </summary>
public class KeyDerivationIntegrationTests
{
    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void PBKDF2_DerivesCorrectLength()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678salt");

        using var builder = Pbkdf2Builder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(1000)
            .WithOutputLength(32)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .AllowWeakParameters();
        var key = builder.DeriveKey();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void PBKDF2_IsDeterministic()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678salt");

        using var builder1 = Pbkdf2Builder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(1000)
            .WithOutputLength(32)
            .AllowWeakParameters();
        var key1 = builder1.DeriveKey();

        using var builder2 = Pbkdf2Builder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(1000)
            .WithOutputLength(32)
            .AllowWeakParameters();
        var key2 = builder2.DeriveKey();

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void HKDF_DerivesCorrectLength()
    {
        var ikm = Encoding.UTF8.GetBytes("input_key_material");
        var salt = Encoding.UTF8.GetBytes("salt");
        var info = Encoding.UTF8.GetBytes("info");

        using var builder = HkdfBuilder.Create()
            .WithInputKeyMaterial(ikm)
            .WithSalt(salt)
            .WithInfo(info)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .WithOutputLength(32);
        var key = builder.DeriveKey();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void HKDF_IsDeterministic()
    {
        var ikm = Encoding.UTF8.GetBytes("input_key_material");

        using var builder1 = HkdfBuilder.Create()
            .WithInputKeyMaterial(ikm)
            .WithOutputLength(32);
        var key1 = builder1.DeriveKey();

        using var builder2 = HkdfBuilder.Create()
            .WithInputKeyMaterial(ikm)
            .WithOutputLength(32);
        var key2 = builder2.DeriveKey();

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void DeriveKey_WithContext_ProducesConsistentResults()
    {
        var masterKey = Encoding.UTF8.GetBytes("master_key_material");
        var context = "encryption";

        using var builder1 = HkdfBuilder.Create()
            .WithInputKeyMaterial(masterKey)
            .WithInfo(context)
            .WithOutputLength(32);
        var key1 = builder1.DeriveKey();

        using var builder2 = HkdfBuilder.Create()
            .WithInputKeyMaterial(masterKey)
            .WithInfo(context)
            .WithOutputLength(32);
        var key2 = builder2.DeriveKey();

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void DeriveKey_DifferentContexts_ProduceDifferentKeys()
    {
        var masterKey = Encoding.UTF8.GetBytes("master_key_material");

        using var encryptionBuilder = HkdfBuilder.Create()
            .WithInputKeyMaterial(masterKey)
            .WithInfo("encryption")
            .WithOutputLength(32);
        var encryptionKey = encryptionBuilder.DeriveKey();

        using var authBuilder = HkdfBuilder.Create()
            .WithInputKeyMaterial(masterKey)
            .WithInfo("authentication")
            .WithOutputLength(32);
        var authenticationKey = authBuilder.DeriveKey();

        Assert.False(encryptionKey.AsSpan().SequenceEqual(authenticationKey));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Scrypt_DerivesCorrectLength()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt1234567890123456");

        using var builder = ScryptBuilder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithN(16)
            .WithR(1)
            .WithP(1)
            .WithOutputLength(32);
        var key = builder.DeriveKey();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Scrypt_IsDeterministic()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt1234567890123456");

        using var builder1 = ScryptBuilder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithN(16)
            .WithR(1)
            .WithP(1)
            .WithOutputLength(32);
        var key1 = builder1.DeriveKey();

        using var builder2 = ScryptBuilder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithN(16)
            .WithR(1)
            .WithP(1)
            .WithOutputLength(32);
        var key2 = builder2.DeriveKey();

        Assert.Equal(key1, key2);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public void Scrypt_Rfc7914_Vector1()
    {
        var password = Array.Empty<byte>();
        var salt = Array.Empty<byte>();

        using var builder = ScryptBuilder.Create()
            .WithPassword(password)
            .WithSalt(salt)
            .WithN(16)
            .WithR(1)
            .WithP(1)
            .WithOutputLength(64);
        var key = builder.DeriveKey();

        var expected = Convert.FromHexString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
        Assert.Equal(expected, key);
    }
}
