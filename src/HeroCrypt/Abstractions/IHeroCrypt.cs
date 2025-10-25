using HeroCrypt.Hardware;

namespace HeroCrypt.Abstractions;

/// <summary>
/// Main interface for the HeroCrypt cryptographic library
/// </summary>
public interface IHeroCrypt
{
    /// <summary>
    /// Fluent API for Argon2 hashing operations
    /// </summary>
    IArgon2FluentBuilder Argon2 { get; }

    /// <summary>
    /// Fluent API for PGP encryption/decryption operations
    /// </summary>
    IPgpFluentBuilder PGP { get; }

    /// <summary>
    /// Direct access to hashing services
    /// </summary>
    IHashingService HashingService { get; }

    /// <summary>
    /// Direct access to cryptography services
    /// </summary>
    ICryptographyService CryptographyService { get; }

    /// <summary>
    /// Direct access to key generation services
    /// </summary>
    IKeyGenerationService KeyGenerationService { get; }

    /// <summary>
    /// Hardware acceleration information
    /// </summary>
    HardwareCapabilities HardwareCapabilities { get; }

    /// <summary>
    /// Validates the current configuration and system capabilities
    /// </summary>
    /// <returns>Validation results</returns>
    Task<ValidationResult> ValidateSystemAsync();

    /// <summary>
    /// Gets performance benchmarks for the current system
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Benchmark results</returns>
    Task<BenchmarkResult> GetBenchmarksAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// System validation result
/// </summary>
public class ValidationResult
{
    /// <summary>
    /// Whether the system validation passed
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// List of validation messages
    /// </summary>
    public List<ValidationMessage> Messages { get; set; } = new();

    /// <summary>
    /// Hardware acceleration status
    /// </summary>
    public bool HardwareAccelerationAvailable { get; set; }

    /// <summary>
    /// Supported algorithms
    /// </summary>
    public List<string> SupportedAlgorithms { get; set; } = new();
}

/// <summary>
/// Validation message
/// </summary>
public class ValidationMessage
{
    /// <summary>
    /// Message severity
    /// </summary>
    public ValidationSeverity Severity { get; set; }

    /// <summary>
    /// Validation message text
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Component that generated the message
    /// </summary>
    public string Component { get; set; } = string.Empty;
}

/// <summary>
/// Validation message severity
/// </summary>
public enum ValidationSeverity
{
    /// <summary>
    /// Informational message that does not indicate a problem
    /// </summary>
    Info,

    /// <summary>
    /// Warning message indicating a potential issue that should be reviewed
    /// </summary>
    Warning,

    /// <summary>
    /// Error message indicating a critical problem that must be addressed
    /// </summary>
    Error
}

/// <summary>
/// Benchmark result
/// </summary>
public class BenchmarkResult
{
    /// <summary>
    /// Argon2 hashing benchmark results
    /// </summary>
    public Dictionary<string, double> Argon2Benchmarks { get; set; } = new();

    /// <summary>
    /// PGP operations benchmark results
    /// </summary>
    public Dictionary<string, double> PgpBenchmarks { get; set; } = new();

    /// <summary>
    /// Hardware acceleration benchmark results
    /// </summary>
    public Dictionary<string, double> HardwareAccelerationBenchmarks { get; set; } = new();

    /// <summary>
    /// System information
    /// </summary>
    public string SystemInfo { get; set; } = string.Empty;
}