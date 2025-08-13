using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;

namespace HeroCrypt.Configuration;

/// <summary>
/// Provides security policy configurations for different security levels
/// </summary>
public static class SecurityPolicies
{
    /// <summary>
    /// Gets Argon2 options based on security level
    /// </summary>
    /// <param name="level">The desired security level</param>
    /// <returns>Configured Argon2 options</returns>
    public static Argon2Options GetArgon2Policy(SecurityLevel level) => level switch
    {
        SecurityLevel.Low => new Argon2Options
        {
            Type = Argon2Type.Argon2id,
            Iterations = 1,
            MemorySize = 32 * 1024,    // 32 MB
            Parallelism = 1,
            HashSize = 32,
            SaltSize = 16
        },
        
        SecurityLevel.Medium => new Argon2Options
        {
            Type = Argon2Type.Argon2id,
            Iterations = 2,
            MemorySize = 64 * 1024,    // 64 MB
            Parallelism = 2,
            HashSize = 32,
            SaltSize = 16
        },
        
        SecurityLevel.High => new Argon2Options
        {
            Type = Argon2Type.Argon2id,
            Iterations = 3,
            MemorySize = 256 * 1024,   // 256 MB
            Parallelism = 4,
            HashSize = 32,
            SaltSize = 16
        },
        
        SecurityLevel.Military => new Argon2Options
        {
            Type = Argon2Type.Argon2id,
            Iterations = 6,
            MemorySize = 1024 * 1024,  // 1 GB
            Parallelism = 8,
            HashSize = 64,
            SaltSize = 32
        },
        
        _ => GetArgon2Policy(SecurityLevel.High)
    };

    /// <summary>
    /// Gets RSA key size based on security level
    /// </summary>
    /// <param name="level">The desired security level</param>
    /// <returns>Recommended RSA key size in bits</returns>
    public static int GetRsaKeySize(SecurityLevel level) => level switch
    {
        SecurityLevel.Low => 1024,
        SecurityLevel.Medium => 2048,
        SecurityLevel.High => 3072,
        SecurityLevel.Military => 4096,
        _ => 2048
    };

    /// <summary>
    /// Validates if the provided options meet the minimum security requirements
    /// </summary>
    /// <param name="options">The Argon2 options to validate</param>
    /// <param name="minimumLevel">The minimum required security level</param>
    /// <returns>True if options meet or exceed the minimum level</returns>
    public static bool ValidateArgon2Security(Argon2Options options, SecurityLevel minimumLevel)
    {
        var minimumPolicy = GetArgon2Policy(minimumLevel);
        
        return options.Iterations >= minimumPolicy.Iterations &&
               options.MemorySize >= minimumPolicy.MemorySize &&
               options.HashSize >= minimumPolicy.HashSize &&
               options.SaltSize >= minimumPolicy.SaltSize;
    }

    /// <summary>
    /// Gets security recommendations based on current year and threat landscape
    /// </summary>
    /// <returns>Current recommended security level</returns>
    public static SecurityLevel GetCurrentRecommendedLevel()
    {
        // As of 2024, High security is recommended for most applications
        // This could be updated based on current cryptographic standards
        return SecurityLevel.High;
    }
}