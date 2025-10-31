using HeroCrypt.Services;

namespace HeroCrypt.Configuration;

/// <summary>
/// Configuration options for HeroCrypt library
/// </summary>
public class HeroCryptOptions
{
    /// <summary>
    /// Default Argon2 configuration
    /// </summary>
    public Argon2Options DefaultArgon2Options { get; set; } = new();

    /// <summary>
    /// Default RSA key size for new key generation
    /// </summary>
    public int DefaultRsaKeySize { get; set; } = 2048;

    /// <summary>
    /// Enable hardware acceleration when available
    /// </summary>
    public bool EnableHardwareAcceleration { get; set; } = true;

    /// <summary>
    /// Default security level for operations
    /// </summary>
    public SecurityLevel DefaultSecurityLevel { get; set; } = SecurityLevel.High;

    /// <summary>
    /// Enable detailed logging of cryptographic operations
    /// </summary>
    public bool EnableDetailedLogging { get; set; }

    /// <summary>
    /// Maximum memory usage for Argon2 operations (in KB)
    /// </summary>
    public int MaxMemoryUsageKb { get; set; } = 1024 * 1024; // 1GB default
}

/// <summary>
/// Security levels for cryptographic operations.
/// </summary>
/// <remarks>
/// Higher security levels use stronger parameters (more iterations, more memory)
/// but result in slower operations. Choose based on your security requirements
/// and acceptable performance characteristics.
/// </remarks>
public enum SecurityLevel
{
    /// <summary>
    /// Low security - Faster operations, minimal security (testing only).
    /// Not recommended for production use.
    /// </summary>
    Low = 1,

    /// <summary>
    /// Medium security - Balanced performance and security.
    /// Suitable for resource-constrained environments.
    /// </summary>
    Medium = 2,

    /// <summary>
    /// High security - Strong security with reasonable performance (recommended).
    /// Recommended default for most production applications.
    /// </summary>
    High = 3,

    /// <summary>
    /// Military grade security - Maximum security at the cost of performance.
    /// Very slow operations, use only for highest-value secrets.
    /// </summary>
    Military = 4
}