using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HeroCrypt.Examples;

public class DependencyInjectionExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=== Dependency Injection Example ===\n");
        
        // Create a host with HeroCrypt services
        var host = Host.CreateDefaultBuilder()
            .ConfigureServices((context, services) =>
            {
                // Option 1: Add with default configuration
                services.AddHeroCrypt();
                
                // Option 2: Add with custom configuration
                services.AddHeroCrypt(options =>
                {
                    options.HashingService = HashingServiceType.Argon2;
                    options.CryptographyService = CryptographyServiceType.PGP;
                    
                    // Configure Argon2 options
                    options.Argon2.Iterations = 4;
                    options.Argon2.MemorySize = 131072; // 128 MB
                    options.Argon2.Parallelism = 8;
                    options.Argon2.HashSize = 64;
                    options.Argon2.Type = Argon2Type.Argon2id;
                    
                    // Configure PGP options
                    options.Pgp.DefaultKeySize = 4096;
                    options.Pgp.UseCompression = true;
                    options.Pgp.UseArmor = true;
                });
                
                // Register your application services
                services.AddTransient<PasswordService>();
                services.AddTransient<EncryptionService>();
            })
            .Build();
        
        // Resolve and use services
        using var scope = host.Services.CreateScope();
        var passwordService = scope.ServiceProvider.GetRequiredService<PasswordService>();
        var encryptionService = scope.ServiceProvider.GetRequiredService<EncryptionService>();
        
        // Example usage
        await passwordService.DemoAsync();
        await encryptionService.DemoAsync();
    }
}

// Example service that uses IHashingService
public class PasswordService
{
    private readonly IHashingService _hashingService;
    
    public PasswordService(IHashingService hashingService)
    {
        _hashingService = hashingService;
    }
    
    public async Task DemoAsync()
    {
        Console.WriteLine("Password Service Demo:");
        
        var password = "MySecurePassword123!";
        var hash = await _hashingService.HashAsync(password);
        
        Console.WriteLine($"Password hash: {hash[..32]}...");
        
        var isValid = await _hashingService.VerifyAsync(password, hash);
        Console.WriteLine($"Password verification: {(isValid ? "SUCCESS" : "FAILED")}");
        
        var wrongPassword = "WrongPassword";
        var isInvalid = await _hashingService.VerifyAsync(wrongPassword, hash);
        Console.WriteLine($"Wrong password verification: {(isInvalid ? "FAILED (unexpected)" : "SUCCESS (expected failure)")}\n");
    }
}

// Example service that uses ICryptographyService
public class EncryptionService
{
    private readonly ICryptographyService _cryptographyService;
    private readonly IKeyGenerationService _keyGenerationService;
    
    public EncryptionService(ICryptographyService cryptographyService, IKeyGenerationService keyGenerationService)
    {
        _cryptographyService = cryptographyService;
        _keyGenerationService = keyGenerationService;
    }
    
    public async Task DemoAsync()
    {
        Console.WriteLine("Encryption Service Demo:");
        
        // Generate key pair
        var keyPair = await _keyGenerationService.GenerateKeyPairAsync(2048);
        Console.WriteLine("Generated RSA key pair (2048-bit)");
        
        // Encrypt and decrypt
        var plainText = "Secret message for dependency injection demo!";
        var encrypted = await _cryptographyService.EncryptTextAsync(plainText, keyPair.PublicKey);
        Console.WriteLine($"Encrypted: {encrypted[..50]}...");
        
        var decrypted = await _cryptographyService.DecryptTextAsync(encrypted, keyPair.PrivateKey);
        Console.WriteLine($"Decrypted: {decrypted}");
        Console.WriteLine($"Decryption verification: {(decrypted == plainText ? "SUCCESS" : "FAILED")}\n");
    }
}