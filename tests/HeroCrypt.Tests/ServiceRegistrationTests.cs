using System;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using HeroCrypt.Abstractions;
using HeroCrypt.Extensions;
using Xunit.v3;

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

        var hashingService = serviceProvider.GetService<IHashingService>();
        var cryptoService = serviceProvider.GetService<ICryptographyService>();
        var keyGenService = serviceProvider.GetService<IKeyGenerationService>();
        var memoryManager = serviceProvider.GetService<ISecureMemoryManager>();
        var telemetry = serviceProvider.GetService<ICryptoTelemetry>();

        Assert.NotNull(hashingService);
        Assert.NotNull(cryptoService);
        Assert.NotNull(keyGenService);
        Assert.NotNull(memoryManager);
        Assert.NotNull(telemetry);
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
        var key = keyDerivationService.DerivePbkdf2(password, salt, 100, 32);

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

        // Test that singleton services are truly singleton
        var memoryManager1 = serviceProvider.GetService<ISecureMemoryManager>();
        var memoryManager2 = serviceProvider.GetService<ISecureMemoryManager>();

        Assert.Same(memoryManager1, memoryManager2);
    }
}