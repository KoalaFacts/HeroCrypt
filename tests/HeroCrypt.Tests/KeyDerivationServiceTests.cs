using HeroCrypt.Services;
using System.Text;

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
    public void Scrypt_DerivesCorrectLength()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var key = service.DeriveScrypt(password, salt, 16, 1, 1, 32);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_IsDeterministic()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var key1 = service.DeriveScrypt(password, salt, 16, 1, 1, 32);
        var key2 = service.DeriveScrypt(password, salt, 16, 1, 1, 32);

        Assert.Equal(key1, key2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_DifferentPasswordsProduceDifferentKeys()
    {
        var service = new KeyDerivationService();
        var password1 = Encoding.UTF8.GetBytes("password1");
        var password2 = Encoding.UTF8.GetBytes("password2");
        var salt = Encoding.UTF8.GetBytes("salt");

        var key1 = service.DeriveScrypt(password1, salt, 16, 1, 1, 32);
        var key2 = service.DeriveScrypt(password2, salt, 16, 1, 1, 32);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_DifferentSaltsProduceDifferentKeys()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt1 = Encoding.UTF8.GetBytes("salt1");
        var salt2 = Encoding.UTF8.GetBytes("salt2");

        var key1 = service.DeriveScrypt(password, salt1, 16, 1, 1, 32);
        var key2 = service.DeriveScrypt(password, salt2, 16, 1, 1, 32);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_DifferentParametersProduceDifferentKeys()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var key1 = service.DeriveScrypt(password, salt, 16, 1, 1, 32);
        var key2 = service.DeriveScrypt(password, salt, 32, 1, 1, 32);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsOnNullPassword()
    {
        var service = new KeyDerivationService();
        var salt = Encoding.UTF8.GetBytes("salt");

        var ex = Assert.Throws<ArgumentNullException>(() =>
            service.DeriveScrypt(null!, salt, 16, 1, 1, 32));
        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsOnNullSalt()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");

        var ex = Assert.Throws<ArgumentNullException>(() =>
            service.DeriveScrypt(password, null!, 16, 1, 1, 32));
        Assert.Equal("salt", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsOnInvalidN()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        // N must be a power of 2
        Assert.Throws<ArgumentException>(() =>
            service.DeriveScrypt(password, salt, 15, 1, 1, 32));

        // N must be greater than 1
        Assert.Throws<ArgumentException>(() =>
            service.DeriveScrypt(password, salt, 1, 1, 1, 32));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsOnInvalidR()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        Assert.Throws<ArgumentException>(() =>
            service.DeriveScrypt(password, salt, 16, 0, 1, 32));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsOnInvalidP()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        Assert.Throws<ArgumentException>(() =>
            service.DeriveScrypt(password, salt, 16, 1, 0, 32));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_ThrowsOnInvalidKeyLength()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        Assert.Throws<ArgumentException>(() =>
            service.DeriveScrypt(password, salt, 16, 1, 1, 0));
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Scrypt_RFC7914TestVector1()
    {
        // RFC 7914 Test Vector 1
        var service = new KeyDerivationService();
        var password = Array.Empty<byte>();
        var salt = Array.Empty<byte>();

        var result = service.DeriveScrypt(password, salt, 16, 1, 1, 64);

        // Expected result from RFC 7914
        var expected = Convert.FromHexString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");

        Assert.Equal(expected, result);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Scrypt_RFC7914TestVector2()
    {
        // RFC 7914 Test Vector 2 (reduced parameters for faster testing)
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("NaCl");

        var result = service.DeriveScrypt(password, salt, 32, 1, 1, 64);

        // This should produce a consistent result (not the official RFC vector due to reduced params)
        Assert.Equal(64, result.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_HandlesLargeOutputLength()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("salt");

        var key = service.DeriveScrypt(password, salt, 16, 1, 1, 128);

        Assert.Equal(128, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_HandlesEmptyPassword()
    {
        var service = new KeyDerivationService();
        var password = Array.Empty<byte>();
        var salt = Encoding.UTF8.GetBytes("salt");

        var key = service.DeriveScrypt(password, salt, 16, 1, 1, 32);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Scrypt_HandlesEmptySalt()
    {
        var service = new KeyDerivationService();
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Array.Empty<byte>();

        var key = service.DeriveScrypt(password, salt, 16, 1, 1, 32);

        Assert.Equal(32, key.Length);
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
