using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Hardware;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Text;

namespace HeroCrypt.Services;

/// <summary>
/// Main implementation of the HeroCrypt cryptographic library facade.
/// Provides unified access to all cryptographic services and capabilities.
/// </summary>
public class HeroCryptService : IHeroCrypt
{
    private readonly HeroCryptOptions _options;
    private readonly IServiceProvider _serviceProvider;
    private readonly Lazy<HardwareCapabilities> _hardwareCapabilities;

    /// <summary>
    /// Initializes a new instance of the <see cref="HeroCryptService"/> class.
    /// </summary>
    /// <param name="options">Configuration options for HeroCrypt.</param>
    /// <param name="serviceProvider">Service provider for dependency injection.</param>
    /// <param name="hashingService">The hashing service implementation.</param>
    /// <param name="cryptographyService">The cryptography service implementation.</param>
    /// <param name="keyGenerationService">The key generation service implementation.</param>
    public HeroCryptService(
        IOptions<HeroCryptOptions> options,
        IServiceProvider serviceProvider,
        IHashingService hashingService,
        ICryptographyService cryptographyService,
        IKeyGenerationService keyGenerationService)
    {
        _options = options.Value;
        _serviceProvider = serviceProvider;
        HashingService = hashingService;
        CryptographyService = cryptographyService;
        KeyGenerationService = keyGenerationService;

        _hardwareCapabilities = new Lazy<HardwareCapabilities>(() =>
            HardwareAccelerationDetector.GetCapabilities());
    }

    /// <summary>
    /// Gets the fluent builder for Argon2 password hashing operations.
    /// </summary>
    /// <value>
    /// A fluent interface for configuring and executing Argon2 operations.
    /// </value>
    public IArgon2FluentBuilder Argon2 =>
        (IArgon2FluentBuilder)_serviceProvider.GetService(typeof(IArgon2FluentBuilder))!;

    /// <summary>
    /// Gets the fluent builder for PGP cryptographic operations.
    /// </summary>
    /// <value>
    /// A fluent interface for configuring and executing PGP encryption/decryption.
    /// </value>
    public IPgpFluentBuilder PGP =>
        (IPgpFluentBuilder)_serviceProvider.GetService(typeof(IPgpFluentBuilder))!;

    public IHashingService HashingService { get; }

    public ICryptographyService CryptographyService { get; }

    public IKeyGenerationService KeyGenerationService { get; }

    /// <summary>
    /// Gets the hardware acceleration capabilities detected on the current system.
    /// </summary>
    /// <value>
    /// Information about available hardware cryptographic acceleration features
    /// such as AES-NI, AVX2, and other CPU instruction sets.
    /// </value>
    public HardwareCapabilities HardwareCapabilities => _hardwareCapabilities.Value;

    /// <summary>
    /// Validates the HeroCrypt system configuration and capabilities.
    /// </summary>
    /// <returns>
    /// A validation result containing system status, available algorithms,
    /// hardware acceleration information, and any configuration warnings or errors.
    /// </returns>
    /// <remarks>
    /// This method performs comprehensive validation including:
    /// <list type="bullet">
    /// <item>Hardware acceleration availability</item>
    /// <item>Argon2 functionality test</item>
    /// <item>PGP encryption/decryption test</item>
    /// <item>Configuration parameter validation</item>
    /// <item>Supported algorithm enumeration</item>
    /// </list>
    /// Use this method to verify the system is ready for production use.
    /// </remarks>
    public async Task<ValidationResult> ValidateSystemAsync()
    {
        var result = new ValidationResult();

        try
        {
            // Validate hardware acceleration
            var hardwareAccelerator = (IHardwareAccelerator)_serviceProvider.GetService(typeof(IHardwareAccelerator))!;
            result.HardwareAccelerationAvailable = hardwareAccelerator.IsAvailable;

            if (result.HardwareAccelerationAvailable)
            {
                result.Messages.Add(new ValidationMessage
                {
                    Severity = ValidationSeverity.Info,
                    Component = "Hardware",
                    Message = $"Hardware acceleration available: {hardwareAccelerator.Description}"
                });
            }
            else
            {
                result.Messages.Add(new ValidationMessage
                {
                    Severity = ValidationSeverity.Warning,
                    Component = "Hardware",
                    Message = "Hardware acceleration not available, using software implementation"
                });
            }

            // Validate algorithms
            await ValidateArgon2Async(result);
            await ValidatePgpAsync(result);

            // Check supported algorithms
            var supportedAlgorithms = new[] { "Argon2d", "Argon2i", "Argon2id", "RSA", "AES", "SHA256" };
            result.SupportedAlgorithms.AddRange(supportedAlgorithms);

            // Validate configuration
            ValidateConfiguration(result);

            result.IsValid = !result.Messages.Any(m => m.Severity == ValidationSeverity.Error);
        }
        catch (Exception ex)
        {
            result.Messages.Add(new ValidationMessage
            {
                Severity = ValidationSeverity.Error,
                Component = "System",
                Message = $"Validation failed with exception: {ex.Message}"
            });
            result.IsValid = false;
        }

        return result;
    }

    /// <summary>
    /// Runs performance benchmarks on cryptographic operations.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop benchmarking.</param>
    /// <returns>
    /// Benchmark results including timing information for Argon2, PGP,
    /// and hardware-accelerated operations.
    /// </returns>
    /// <remarks>
    /// Benchmarks performed:
    /// <list type="bullet">
    /// <item>Argon2 hashing with various memory sizes (32MB, 64MB, 128MB)</item>
    /// <item>PGP key generation (1024-bit for speed)</item>
    /// <item>PGP encryption/decryption (1KB test data)</item>
    /// <item>Hardware-accelerated SHA256 (if available)</item>
    /// </list>
    /// Results are useful for capacity planning and performance optimization.
    /// </remarks>
    public async Task<BenchmarkResult> GetBenchmarksAsync(CancellationToken cancellationToken = default)
    {
        var result = new BenchmarkResult
        {
            SystemInfo = HardwareCapabilities.ToString()
        };

        try
        {
            // Benchmark Argon2
            await BenchmarkArgon2Async(result, cancellationToken);

            // Benchmark PGP operations
            await BenchmarkPgpAsync(result, cancellationToken);

            // Benchmark hardware acceleration if available
            await BenchmarkHardwareAccelerationAsync(result, cancellationToken);
        }
        catch (Exception ex)
        {
            result.SystemInfo += $"\nBenchmark error: {ex.Message}";
        }

        return result;
    }

    private async Task ValidateArgon2Async(ValidationResult result)
    {
        try
        {
            // Test basic Argon2 functionality
            var testPassword = "test_password_123";
            var hash = await Argon2
                .WithPassword(testPassword)
                .WithIterations(1)
                .WithMemory(32.MB())
                .WithParallelism(1)
                .HashAsync();

            var isValid = await Argon2
                .WithPassword(testPassword)
                .WithIterations(1)
                .WithMemory(32.MB())
                .WithParallelism(1)
                .VerifyAsync(hash);

            if (isValid)
            {
                result.Messages.Add(new ValidationMessage
                {
                    Severity = ValidationSeverity.Info,
                    Component = "Argon2",
                    Message = "Argon2 hashing validation successful"
                });
            }
            else
            {
                result.Messages.Add(new ValidationMessage
                {
                    Severity = ValidationSeverity.Error,
                    Component = "Argon2",
                    Message = "Argon2 hashing validation failed"
                });
            }
        }
        catch (Exception ex)
        {
            result.Messages.Add(new ValidationMessage
            {
                Severity = ValidationSeverity.Error,
                Component = "Argon2",
                Message = $"Argon2 validation error: {ex.Message}"
            });
        }
    }

    private async Task ValidatePgpAsync(ValidationResult result)
    {
        try
        {
            // Test basic PGP functionality with small key size for speed
            var keyPair = await PGP
                .WithIdentity("test@example.com")
                .WithKeySize(1024) // Small key for validation
                .GenerateKeyPairAsync();

            var testData = "Hello, HeroCrypt!";
            var encrypted = await PGP
                .WithData(testData)
                .WithPublicKey(keyPair.PublicKey)
                .EncryptAsync();

            var decrypted = await PGP
                .WithEncryptedData(encrypted)
                .WithPrivateKey(keyPair.PrivateKey)
                .DecryptAsync();

            if (decrypted == testData)
            {
                result.Messages.Add(new ValidationMessage
                {
                    Severity = ValidationSeverity.Info,
                    Component = "PGP",
                    Message = "PGP encryption/decryption validation successful"
                });
            }
            else
            {
                result.Messages.Add(new ValidationMessage
                {
                    Severity = ValidationSeverity.Error,
                    Component = "PGP",
                    Message = "PGP encryption/decryption validation failed"
                });
            }
        }
        catch (Exception ex)
        {
            result.Messages.Add(new ValidationMessage
            {
                Severity = ValidationSeverity.Error,
                Component = "PGP",
                Message = $"PGP validation error: {ex.Message}"
            });
        }
    }

    private void ValidateConfiguration(ValidationResult result)
    {
        // Validate Argon2 configuration
        if (_options.DefaultArgon2Options.MemorySize < 8 * _options.DefaultArgon2Options.Parallelism)
        {
            result.Messages.Add(new ValidationMessage
            {
                Severity = ValidationSeverity.Warning,
                Component = "Configuration",
                Message = "Argon2 memory size may be too low for configured parallelism"
            });
        }

        // Validate RSA key size
        if (_options.DefaultRsaKeySize < 2048)
        {
            result.Messages.Add(new ValidationMessage
            {
                Severity = ValidationSeverity.Warning,
                Component = "Configuration",
                Message = "RSA key size below recommended minimum (2048 bits)"
            });
        }

        // Check security level
        if (_options.DefaultSecurityLevel == SecurityLevel.Low)
        {
            result.Messages.Add(new ValidationMessage
            {
                Severity = ValidationSeverity.Warning,
                Component = "Configuration",
                Message = "Security level set to Low - consider using Medium or High for production"
            });
        }
    }

    private async Task BenchmarkArgon2Async(BenchmarkResult result, CancellationToken cancellationToken)
    {
        var testPassword = "benchmark_password_12345";
        var iterations = 3;

        // Benchmark different memory sizes
        var memorySizes = new[] { 32.MB(), 64.MB(), 128.MB() };

        foreach (var memorySize in memorySizes)
        {
            if (cancellationToken.IsCancellationRequested) return;

            var stopwatch = Stopwatch.StartNew();

            await Argon2
                .WithPassword(testPassword)
                .WithIterations(iterations)
                .WithMemory(memorySize)
                .WithParallelism(2)
                .HashAsync(cancellationToken);

            stopwatch.Stop();

            result.Argon2Benchmarks[$"Argon2_{memorySize.ValueInKb / 1024}MB"] = stopwatch.ElapsedMilliseconds;
        }
    }

    private async Task BenchmarkPgpAsync(BenchmarkResult result, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return;

        try
        {
            // Benchmark key generation (small key for speed)
            var keyGenStopwatch = Stopwatch.StartNew();
            var keyPair = await PGP
                .WithIdentity("benchmark@test.com")
                .WithKeySize(1024)
                .GenerateKeyPairAsync(cancellationToken);
            keyGenStopwatch.Stop();

            result.PgpBenchmarks["KeyGeneration_1024"] = keyGenStopwatch.ElapsedMilliseconds;

            // Benchmark encryption/decryption
            var testData = new string('A', 1000); // 1KB test data

            var encryptStopwatch = Stopwatch.StartNew();
            var encrypted = await PGP
                .WithData(testData)
                .WithPublicKey(keyPair.PublicKey)
                .EncryptAsync(cancellationToken);
            encryptStopwatch.Stop();

            result.PgpBenchmarks["Encryption_1KB"] = encryptStopwatch.ElapsedMilliseconds;

            var decryptStopwatch = Stopwatch.StartNew();
            await PGP
                .WithEncryptedData(encrypted)
                .WithPrivateKey(keyPair.PrivateKey)
                .DecryptAsync(cancellationToken);
            decryptStopwatch.Stop();

            result.PgpBenchmarks["Decryption_1KB"] = decryptStopwatch.ElapsedMilliseconds;
        }
        catch (Exception ex)
        {
            result.PgpBenchmarks["Error"] = -1;
            result.SystemInfo += $"\nPGP Benchmark Error: {ex.Message}";
        }
    }

    private async Task BenchmarkHardwareAccelerationAsync(BenchmarkResult result, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return;

        var hardwareAccelerator = (IHardwareAccelerator)_serviceProvider.GetService(typeof(IHardwareAccelerator))!;

        if (!hardwareAccelerator.IsAvailable)
        {
            result.HardwareAccelerationBenchmarks["Available"] = 0;
            return;
        }

        try
        {
            var testData = Encoding.UTF8.GetBytes(new string('B', 1000));

            // Benchmark SHA256 if supported
            if (hardwareAccelerator.SupportsAlgorithm("SHA256"))
            {
                var stopwatch = Stopwatch.StartNew();
                await hardwareAccelerator.AcceleratedHashAsync(testData, "SHA256", cancellationToken);
                stopwatch.Stop();
                result.HardwareAccelerationBenchmarks["SHA256_1KB"] = stopwatch.ElapsedMilliseconds;
            }

            result.HardwareAccelerationBenchmarks["Available"] = 1;
        }
        catch (Exception ex)
        {
            result.HardwareAccelerationBenchmarks["Error"] = -1;
            result.SystemInfo += $"\nHardware Acceleration Benchmark Error: {ex.Message}";
        }
    }
}