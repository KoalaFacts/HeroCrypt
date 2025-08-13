using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using HeroCrypt.Extensions;
using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;

namespace HeroCrypt.Examples;

/// <summary>
/// Demonstrates the new fluent API and DI capabilities of HeroCrypt
/// </summary>
public static class FluentApiDemo
{
    public static async Task RunDemoAsync()
    {
        Console.WriteLine("🚀 HeroCrypt Fluent API and DI Demo");
        Console.WriteLine("=====================================\n");

        // Setup Dependency Injection
        var serviceCollection = new ServiceCollection();
        
        // Add HeroCrypt with High Security Level
        serviceCollection.AddHeroCrypt(SecurityLevel.High);
        
        // Add logging (optional)
        serviceCollection.AddLogging();

        var serviceProvider = serviceCollection.BuildServiceProvider();

        // Get the main HeroCrypt service
        var heroCrypt = serviceProvider.GetRequiredService<IHeroCrypt>();

        // Display system capabilities
        await DisplaySystemCapabilitiesAsync(heroCrypt);

        // Demonstrate Argon2 Fluent API
        await DemonstrateArgon2FluentApiAsync(heroCrypt);

        // Demonstrate PGP Fluent API
        await DemonstratePgpFluentApiAsync(heroCrypt);

        // Run benchmarks
        await RunBenchmarksAsync(heroCrypt);

        Console.WriteLine("✅ Demo completed successfully!\n");
    }

    private static async Task DisplaySystemCapabilitiesAsync(IHeroCrypt heroCrypt)
    {
        Console.WriteLine("🔍 System Capabilities");
        Console.WriteLine("-----------------------");
        Console.WriteLine($"Hardware: {heroCrypt.HardwareCapabilities}");
        
        var validation = await heroCrypt.ValidateSystemAsync();
        Console.WriteLine($"System Valid: {validation.IsValid}");
        Console.WriteLine($"Hardware Acceleration: {validation.HardwareAccelerationAvailable}");
        
        if (validation.Messages.Count > 0)
        {
            Console.WriteLine("Messages:");
            foreach (var message in validation.Messages)
            {
                Console.WriteLine($"  [{message.Severity}] {message.Component}: {message.Message}");
            }
        }
        Console.WriteLine();
    }

    private static async Task DemonstrateArgon2FluentApiAsync(IHeroCrypt heroCrypt)
    {
        Console.WriteLine("🔐 Argon2 Fluent API Demo");
        Console.WriteLine("--------------------------");

        try
        {
            var password = "MySecurePassword123!";
            
            // Hash with fluent API using security level
            Console.WriteLine("Hashing with High security level...");
            var hash = await heroCrypt.Argon2
                .WithPassword(password)
                .WithSecurityLevel(SecurityLevel.High)
                .WithHardwareAcceleration()
                .HashAsync();
            
            Console.WriteLine($"Hash: {hash[..50]}... (truncated)");

            // Verify the hash
            Console.WriteLine("Verifying hash...");
            var isValid = await heroCrypt.Argon2
                .WithPassword(password)
                .WithSecurityLevel(SecurityLevel.High)
                .VerifyAsync(hash);
            
            Console.WriteLine($"Hash verification: {isValid}");

            // Hash with custom parameters
            Console.WriteLine("\nHashing with custom parameters...");
            var customHash = await heroCrypt.Argon2
                .WithPassword(password)
                .WithMemory(128.MB())
                .WithIterations(4)
                .WithParallelism(2)
                .WithHashSize(64)
                .HashAsync();
            
            Console.WriteLine($"Custom hash: {customHash[..50]}... (truncated)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Argon2 demo error: {ex.Message}");
        }
        Console.WriteLine();
    }

    private static async Task DemonstratePgpFluentApiAsync(IHeroCrypt heroCrypt)
    {
        Console.WriteLine("🔒 PGP Fluent API Demo");
        Console.WriteLine("-----------------------");

        try
        {
            // Generate key pair with fluent API
            Console.WriteLine("Generating PGP key pair...");
            var keyPair = await heroCrypt.PGP
                .WithIdentity("demo@herocrypt.com")
                .WithPassphrase("mypassphrase")
                .WithSecurityLevel(SecurityLevel.Medium) // Use Medium for faster demo
                .WithHardwareAcceleration()
                .GenerateKeyPairAsync();
            
            Console.WriteLine("✅ Key pair generated");

            // Encrypt data
            var secretMessage = "This is a confidential message encrypted with HeroCrypt!";
            Console.WriteLine($"Original message: {secretMessage}");
            
            Console.WriteLine("Encrypting message...");
            var encryptedMessage = await heroCrypt.PGP
                .WithData(secretMessage)
                .WithPublicKey(keyPair.PublicKey)
                .WithHardwareAcceleration()
                .EncryptAsync();
            
            Console.WriteLine($"Encrypted: {encryptedMessage[..100]}... (truncated)");

            // Decrypt data
            Console.WriteLine("Decrypting message...");
            var decryptedMessage = await heroCrypt.PGP
                .WithEncryptedData(encryptedMessage)
                .WithPrivateKey(keyPair.PrivateKey)
                .WithHardwareAcceleration()
                .DecryptAsync();
            
            Console.WriteLine($"Decrypted: {decryptedMessage}");
            Console.WriteLine($"Match: {secretMessage == decryptedMessage}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ PGP demo error: {ex.Message}");
        }
        Console.WriteLine();
    }

    private static async Task RunBenchmarksAsync(IHeroCrypt heroCrypt)
    {
        Console.WriteLine("⚡ Performance Benchmarks");
        Console.WriteLine("-------------------------");

        try
        {
            var benchmarks = await heroCrypt.GetBenchmarksAsync();
            
            Console.WriteLine("Argon2 Benchmarks (ms):");
            foreach (var benchmark in benchmarks.Argon2Benchmarks)
            {
                Console.WriteLine($"  {benchmark.Key}: {benchmark.Value:F2}ms");
            }
            
            Console.WriteLine("\nPGP Benchmarks (ms):");
            foreach (var benchmark in benchmarks.PgpBenchmarks)
            {
                Console.WriteLine($"  {benchmark.Key}: {benchmark.Value:F2}ms");
            }
            
            Console.WriteLine("\nHardware Acceleration:");
            foreach (var benchmark in benchmarks.HardwareAccelerationBenchmarks)
            {
                Console.WriteLine($"  {benchmark.Key}: {benchmark.Value:F2}ms");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Benchmark error: {ex.Message}");
        }
        Console.WriteLine();
    }
}

/// <summary>
/// Alternative DI setup example for ASP.NET Core or other hosting scenarios
/// </summary>
public static class AdvancedDiSetupExample
{
    public static void ConfigureServices(IServiceCollection services)
    {
        // Configure HeroCrypt with custom options
        services.AddHeroCrypt(options =>
        {
            options.DefaultSecurityLevel = SecurityLevel.High;
            options.EnableHardwareAcceleration = true;
            options.EnableDetailedLogging = false;
            options.MaxMemoryUsageKb = 512 * 1024; // 512MB max
            options.DefaultRsaKeySize = 3072; // Higher security
        });

        // Or use security level-based setup
        // services.AddHeroCrypt(SecurityLevel.Military);
        
        // Add custom hardware accelerator if needed
        // services.AddHeroCryptHardwareAccelerator<CustomHardwareAccelerator>();
    }

    public static async Task UseHeroCryptInControllerAsync(IHeroCrypt heroCrypt)
    {
        // Example of using HeroCrypt in a controller or service
        
        // Hash a password
        var hashedPassword = await heroCrypt.Argon2
            .WithPassword("user_password")
            .WithSecurityLevel(SecurityLevel.High)
            .HashAsync();

        // Encrypt sensitive data
        var keyPair = await heroCrypt.PGP
            .WithIdentity("service@myapp.com")
            .WithKeySize(3072)
            .GenerateKeyPairAsync();

        var encryptedData = await heroCrypt.PGP
            .WithData("sensitive user data")
            .WithPublicKey(keyPair.PublicKey)
            .EncryptAsync();

        // Store encryptedData and keyPair.PrivateKey securely
    }
}