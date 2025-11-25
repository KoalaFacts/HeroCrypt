using System.Text;
using HeroCrypt;
using HeroCrypt.Cryptography.Protocols.KeyManagement;

namespace HeroCrypt.Tests.Cryptography.Primitives.Kdf;

/// <summary>
/// Unit tests for key derivation using the fluent builders and core primitives (no services).
/// </summary>
public class KeyDerivationTests
{
    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void PBKDF2_DerivesCorrectLength()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678");

        var key = HeroCryptBuilder.DeriveKey()
            .UsePBKDF2()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(1000)
            .WithKeyLength(32)
            .WithHashAlgorithm(CryptographicHashName.SHA256)
            .Build();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void PBKDF2_IsDeterministic()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678");

        var key1 = HeroCryptBuilder.DeriveKey()
            .UsePBKDF2()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(1000)
            .WithKeyLength(32)
            .Build();

        var key2 = HeroCryptBuilder.DeriveKey()
            .UsePBKDF2()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(1000)
            .WithKeyLength(32)
            .Build();

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void HKDF_DerivesCorrectLength()
    {
        var ikm = Encoding.UTF8.GetBytes("input_key_material");
        var salt = Encoding.UTF8.GetBytes("salt");
        var info = Encoding.UTF8.GetBytes("info");

        var key = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(ikm)
            .WithSalt(salt)
            .WithInfo(info)
            .WithHashAlgorithm(CryptographicHashName.SHA256)
            .WithKeyLength(32)
            .Build();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void HKDF_IsDeterministic()
    {
        var ikm = Encoding.UTF8.GetBytes("input_key_material");

        var key1 = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(ikm)
            .WithKeyLength(32)
            .Build();

        var key2 = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(ikm)
            .WithKeyLength(32)
            .Build();

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void DeriveKey_WithContext_ProducesConsistentResults()
    {
        var masterKey = Encoding.UTF8.GetBytes("master_key_material");
        var context = "encryption";

        var key1 = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(masterKey)
            .WithInfo(Encoding.UTF8.GetBytes(context))
            .WithKeyLength(32)
            .Build();

        var key2 = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(masterKey)
            .WithInfo(Encoding.UTF8.GetBytes(context))
            .WithKeyLength(32)
            .Build();

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void DeriveKey_DifferentContexts_ProduceDifferentKeys()
    {
        var masterKey = Encoding.UTF8.GetBytes("master_key_material");

        var encryptionKey = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(masterKey)
            .WithInfo(Encoding.UTF8.GetBytes("encryption"))
            .WithKeyLength(32)
            .Build();

        var authenticationKey = HeroCryptBuilder.DeriveKey()
            .UseHKDF()
            .WithInputKeyingMaterial(masterKey)
            .WithInfo(Encoding.UTF8.GetBytes("authentication"))
            .WithKeyLength(32)
            .Build();

        Assert.False(encryptionKey.AsSpan().SequenceEqual(authenticationKey));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Scrypt_DerivesCorrectLength()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var key = HeroCryptBuilder.DeriveKey()
            .UseScrypt()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(16) // N
            .WithBlockSize(1)   // r
            .WithParallelism(1) // p
            .WithKeyLength(32)
            .Build();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Scrypt_IsDeterministic()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var builder = HeroCryptBuilder.DeriveKey()
            .UseScrypt()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(16)
            .WithBlockSize(1)
            .WithParallelism(1)
            .WithKeyLength(32);

        var key1 = builder.Build();
        var key2 = builder.Build();

        Assert.Equal(key1, key2);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public void Scrypt_Rfc7914_Vector1()
    {
        var password = Array.Empty<byte>();
        var salt = Array.Empty<byte>();

        var key = HeroCryptBuilder.DeriveKey()
            .UseScrypt()
            .WithPassword(password)
            .WithSalt(salt)
            .WithIterations(16)
            .WithBlockSize(1)
            .WithParallelism(1)
            .WithKeyLength(64)
            .Build();

        var expected = Convert.FromHexString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
        Assert.Equal(expected, key);
    }
}
