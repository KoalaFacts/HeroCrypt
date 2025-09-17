namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for hardware acceleration capabilities
/// </summary>
public interface IHardwareAccelerator
{
    /// <summary>
    /// Gets whether hardware acceleration is available on this system
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Gets the type of hardware acceleration supported
    /// </summary>
    HardwareAccelerationType AccelerationType { get; }

    /// <summary>
    /// Gets a human-readable description of the acceleration capabilities
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Performs hardware-accelerated hashing if supported
    /// </summary>
    /// <param name="data">The data to hash</param>
    /// <param name="algorithm">The hashing algorithm to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The computed hash, or null if not supported</returns>
    Task<byte[]?> AcceleratedHashAsync(byte[] data, string algorithm, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs hardware-accelerated encryption if supported
    /// </summary>
    /// <param name="data">The data to encrypt</param>
    /// <param name="key">The encryption key</param>
    /// <param name="algorithm">The encryption algorithm to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The encrypted data, or null if not supported</returns>
    Task<byte[]?> AcceleratedEncryptAsync(byte[] data, byte[] key, string algorithm, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a specific algorithm is hardware-accelerated
    /// </summary>
    /// <param name="algorithm">The algorithm name to check</param>
    /// <returns>True if hardware acceleration is available for this algorithm</returns>
    bool SupportsAlgorithm(string algorithm);
}

/// <summary>
/// Types of hardware acceleration
/// </summary>
public enum HardwareAccelerationType
{
    /// <summary>
    /// No hardware acceleration available
    /// </summary>
    None = 0,

    /// <summary>
    /// Intel AES-NI instruction set
    /// </summary>
    IntelAesNi = 1,

    /// <summary>
    /// ARM Crypto Extensions
    /// </summary>
    ArmCrypto = 2,

    /// <summary>
    /// GPU acceleration (CUDA/OpenCL)
    /// </summary>
    Gpu = 4,

    /// <summary>
    /// Hardware Security Module
    /// </summary>
    Hsm = 8,

    /// <summary>
    /// Intel AVX2 (Advanced Vector Extensions 2)
    /// </summary>
    IntelAvx2 = 16,

    /// <summary>
    /// Intel AVX-512 (Advanced Vector Extensions 512-bit)
    /// </summary>
    IntelAvx512 = 32,

    /// <summary>
    /// Intel RDRAND/RDSEED (Hardware Random Number Generator)
    /// </summary>
    IntelRdrand = 64,

    /// <summary>
    /// Intel SHA extensions
    /// </summary>
    IntelSha = 128,

    /// <summary>
    /// ARM SVE (Scalable Vector Extension)
    /// </summary>
    ArmSve = 256,

    /// <summary>
    /// Custom hardware acceleration
    /// </summary>
    Custom = 16
}