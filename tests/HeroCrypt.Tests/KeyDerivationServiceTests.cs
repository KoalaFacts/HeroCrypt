using System;
using System.Text;
using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using Xunit.v3;

namespace HeroCrypt.Tests;

/// <summary>
/// Unit tests for Key Derivation Service functionality
/// </summary>
public class KeyDerivationServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void PBKDF2_DerivesCorrectLength()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678");

        var key = service.DerivePbkdf2(password, salt, 1000, 32);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void PBKDF2_IsDeterministic()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678");

        var key1 = service.DerivePbkdf2(password, salt, 1000, 32);
        var key2 = service.DerivePbkdf2(password, salt, 1000, 32);

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void PBKDF2_DifferentSaltProducesDifferentKeys()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt1 = Encoding.UTF8.GetBytes("salt1");
        var salt2 = Encoding.UTF8.GetBytes("salt2");

        var key1 = service.DerivePbkdf2(password, salt1, 1000, 32);
        var key2 = service.DerivePbkdf2(password, salt2, 1000, 32);

        Assert.False(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void HKDF_DerivesCorrectLength()
    {
        var service = new KeyDerivationService();
        var ikm = Encoding.UTF8.GetBytes("input_key_material");
        var salt = Encoding.UTF8.GetBytes("salt");
        var info = Encoding.UTF8.GetBytes("info");

        var key = service.DeriveHkdf(ikm, 32, salt, info);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void HKDF_IsDeterministic()
    {
        var service = new KeyDerivationService();
        var ikm = Encoding.UTF8.GetBytes("input_key_material");

        var key1 = service.DeriveHkdf(ikm, 32);
        var key2 = service.DeriveHkdf(ikm, 32);

        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void DeriveKey_WithContext_ProducesConsistentResults()
    {
        var service = new KeyDerivationService();
        var masterKey = Encoding.UTF8.GetBytes("master_key_material");
        var context = "encryption";

        var key1 = service.DeriveKey(masterKey, context, 32);
        var key2 = service.DeriveKey(masterKey, context, 32);

        Assert.Equal(32, key1.Length);
        Assert.True(key1.AsSpan().SequenceEqual(key2));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void DeriveKey_DifferentContexts_ProduceDifferentKeys()
    {
        var service = new KeyDerivationService();
        var masterKey = Encoding.UTF8.GetBytes("master_key_material");

        var encryptionKey = service.DeriveKey(masterKey, "encryption", 32);
        var authenticationKey = service.DeriveKey(masterKey, "authentication", 32);

        Assert.False(encryptionKey.AsSpan().SequenceEqual(authenticationKey));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void PBKDF2_ThrowsOnNullPassword()
    {
        var service = new KeyDerivationService();
        var salt = Encoding.UTF8.GetBytes("salt");

        var ex = Assert.Throws<ArgumentNullException>(() =>
            service.DerivePbkdf2(null!, salt, 1000, 32));

        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void PBKDF2_ThrowsOnInvalidIterations()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var ex = Assert.Throws<ArgumentException>(() =>
            service.DerivePbkdf2(password, salt, 0, 32));

        Assert.Contains("Iterations must be positive", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void HKDF_ThrowsOnNullIkm()
    {
        var service = new KeyDerivationService();

        var ex = Assert.Throws<ArgumentNullException>(() =>
            service.DeriveHkdf(null!, 32));

        Assert.Equal("ikm", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void DeriveKey_ThrowsOnEmptyContext()
    {
        var service = new KeyDerivationService();
        var masterKey = Encoding.UTF8.GetBytes("master_key");

        var ex = Assert.Throws<ArgumentException>(() =>
            service.DeriveKey(masterKey, "", 32));

        Assert.Contains("Context cannot be null or empty", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsNotImplementedException()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var ex = Assert.Throws<NotImplementedException>(() =>
            service.DeriveScrypt(password, salt, 16384, 8, 1, 32));

        Assert.Contains("Scrypt implementation requires", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public async Task PBKDF2_Async_WorksCorrectly()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt12345678");

        var key = await service.DerivePbkdf2Async(password, salt, 1000, 32);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public async Task HKDF_Async_WorksCorrectly()
    {
        var service = new KeyDerivationService();
        var ikm = Encoding.UTF8.GetBytes("input_key_material");

        var key = await service.DeriveHkdfAsync(ikm, 32);

        Assert.Equal(32, key.Length);
    }
}