using HeroCrypt.Encryption;
using HeroCrypt.Extensions;
using HeroCrypt.Hashing;
using HeroCrypt.KeyManagement;
using HeroCrypt.Signatures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for service registration and dependency injection functionality
/// </summary>
public class ServiceRegistrationTests
{
    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void AddHeroCrypt_RegistersBlake2bService()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();

        var serviceProvider = services.BuildServiceProvider();
        var blake2bService = serviceProvider.GetService<IBlake2bService>();

        Assert.NotNull(blake2bService);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void AddHeroCrypt_RegistersKeyDerivationService()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();

        var serviceProvider = services.BuildServiceProvider();
        var keyDerivationService = serviceProvider.GetService<IKeyDerivationService>();

        Assert.NotNull(keyDerivationService);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void AddHeroCrypt_RegistersCoreServices()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();

        var serviceProvider = services.BuildServiceProvider();

        var hashingService = serviceProvider.GetService<IPasswordHashingService>();
        var cryptoService = serviceProvider.GetService<ICryptographyService>();
        var keyGenService = serviceProvider.GetService<IPgpKeyGenerator>();
        var digitalSignatureService = serviceProvider.GetService<IDigitalSignatureService>();
        var cryptoKeyGenService = serviceProvider.GetService<ICryptographicKeyGenerator>();

        Assert.NotNull(hashingService);
        Assert.NotNull(cryptoService);
        Assert.NotNull(keyGenService);
        Assert.NotNull(digitalSignatureService);
        Assert.NotNull(cryptoKeyGenService);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void Blake2bService_ViaInjection_WorksCorrectly()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();
        services.AddLogging(builder => builder.AddConsole());

        var serviceProvider = services.BuildServiceProvider();
        var blake2bService = serviceProvider.GetRequiredService<IBlake2bService>();

        var testData = Encoding.UTF8.GetBytes("Dependency Injection Test");
        var hash = blake2bService.ComputeHash(testData, 32);

        Assert.Equal(32, hash.Length);
        Assert.NotEqual(new byte[32], hash);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void KeyDerivationService_ViaInjection_WorksCorrectly()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();
        services.AddLogging();

        var serviceProvider = services.BuildServiceProvider();
        var keyDerivationService = serviceProvider.GetRequiredService<IKeyDerivationService>();

        var password = Encoding.UTF8.GetBytes("injection_password");
        var salt = Encoding.UTF8.GetBytes("injection_salt_123");
        var key = keyDerivationService.DerivePbkdf2(password, salt, 1000, 32);

        Assert.Equal(32, key.Length);
        Assert.NotEqual(new byte[32], key);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void DigitalSignatureService_ViaInjection_WorksCorrectly()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();
        services.AddLogging();

        var serviceProvider = services.BuildServiceProvider();
        var digitalSignatureService = serviceProvider.GetRequiredService<IDigitalSignatureService>();

        var (privateKey, publicKey) = digitalSignatureService.GenerateKeyPair();
        var testData = Encoding.UTF8.GetBytes("Dependency Injection Signature Test");
        var signature = digitalSignatureService.Sign(testData, privateKey);
        var isValid = digitalSignatureService.Verify(signature, testData, publicKey);

        Assert.True(isValid);
        Assert.Equal("RSA-SHA256", digitalSignatureService.AlgorithmName);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void CryptographicKeyGenerationService_ViaInjection_WorksCorrectly()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();
        services.AddLogging();

        var serviceProvider = services.BuildServiceProvider();
        var keyGenService = serviceProvider.GetRequiredService<ICryptographicKeyGenerator>();

        var randomBytes = keyGenService.GenerateRandomBytes(32);
        var symmetricKey = keyGenService.GenerateSymmetricKey(CryptographicAlgorithm.Aes256);
        var salt = keyGenService.GenerateSalt();
        var securePassword = keyGenService.GenerateSecurePassword(16);

        Assert.Equal(32, randomBytes.Length);
        Assert.Equal(32, symmetricKey.Length);
        Assert.Equal(32, salt.Length);
        Assert.Equal(16, securePassword.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ServicesWithLogging_FunctionCorrectly()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        var serviceProvider = services.BuildServiceProvider();
        var blake2bService = serviceProvider.GetRequiredService<IBlake2bService>();
        var keyDerivationService = serviceProvider.GetRequiredService<IKeyDerivationService>();

        // Test that services work with logging configured
        var testData = Encoding.UTF8.GetBytes("Logging Test");
        var hash = blake2bService.ComputeHash(testData, 32);
        var isValid = blake2bService.VerifyHash(testData, hash);

        var password = Encoding.UTF8.GetBytes("log_password");
        var salt = Encoding.UTF8.GetBytes("log_salt_123");
        var key = keyDerivationService.DerivePbkdf2(password, salt, 1000, 32);

        Assert.Equal(32, hash.Length);
        Assert.True(isValid);
        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ServiceLifetimes_AreCorrect()
    {
        var services = new ServiceCollection();
        services.AddHeroCrypt();

        var serviceProvider = services.BuildServiceProvider();

        // Test that scoped services return same instance within scope
        using (var scope = serviceProvider.CreateScope())
        {
            var blake2bService1 = scope.ServiceProvider.GetRequiredService<IBlake2bService>();
            var blake2bService2 = scope.ServiceProvider.GetRequiredService<IBlake2bService>();

            Assert.Same(blake2bService1, blake2bService2);
        }

        // Test that scoped services are different across scopes
        IBlake2bService? scopedService1;
        using (var scope1 = serviceProvider.CreateScope())
        {
            scopedService1 = scope1.ServiceProvider.GetRequiredService<IBlake2bService>();
        }

        using (var scope2 = serviceProvider.CreateScope())
        {
            var scopedService2 = scope2.ServiceProvider.GetRequiredService<IBlake2bService>();
            Assert.NotSame(scopedService1, scopedService2);
        }
    }
}