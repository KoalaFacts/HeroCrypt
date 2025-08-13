#if NET5_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif
using System.Runtime.InteropServices;
using HeroCrypt.Abstractions;

namespace HeroCrypt.Hardware;

/// <summary>
/// Detects available hardware acceleration capabilities
/// </summary>
public static class HardwareAccelerationDetector
{
    private static readonly Lazy<HardwareAccelerationType> _availableAcceleration = 
        new(() => DetectAvailableAcceleration());

    /// <summary>
    /// Gets the available hardware acceleration types
    /// </summary>
    public static HardwareAccelerationType AvailableAcceleration => _availableAcceleration.Value;

    /// <summary>
    /// Checks if Intel AES-NI is available
    /// </summary>
#if NET5_0_OR_GREATER
    public static bool IsAesNiAvailable => Aes.IsSupported;
#else
    public static bool IsAesNiAvailable => false; // Not detectable in .NET Standard 2.0
#endif

    /// <summary>
    /// Checks if AVX2 instructions are available
    /// </summary>
#if NET5_0_OR_GREATER
    public static bool IsAvx2Available => Avx2.IsSupported;
#else
    public static bool IsAvx2Available => false; // Not detectable in .NET Standard 2.0
#endif

    /// <summary>
    /// Checks if ARM crypto extensions are available
    /// </summary>
    public static bool IsArmCryptoAvailable => RuntimeInformation.ProcessArchitecture == Architecture.Arm64 && 
                                               CheckArmCryptoSupport();

    /// <summary>
    /// Gets a summary of available hardware capabilities
    /// </summary>
    /// <returns>Hardware capabilities summary</returns>
    public static HardwareCapabilities GetCapabilities()
    {
        return new HardwareCapabilities
        {
            AccelerationType = AvailableAcceleration,
            AesNiSupported = IsAesNiAvailable,
            Avx2Supported = IsAvx2Available,
            ArmCryptoSupported = IsArmCryptoAvailable,
            ProcessorArchitecture = RuntimeInformation.ProcessArchitecture,
            OperatingSystem = RuntimeInformation.OSDescription,
            ProcessorCount = Environment.ProcessorCount
        };
    }

    private static HardwareAccelerationType DetectAvailableAcceleration()
    {
        var acceleration = HardwareAccelerationType.None;

        // Check for Intel AES-NI
        if (IsAesNiAvailable)
        {
            acceleration |= HardwareAccelerationType.IntelAesNi;
        }

        // Check for ARM crypto extensions
        if (IsArmCryptoAvailable)
        {
            acceleration |= HardwareAccelerationType.ArmCrypto;
        }

        return acceleration;
    }

    private static bool CheckArmCryptoSupport()
    {
        // This would need platform-specific implementation
        // For now, we assume ARM64 has crypto extensions
        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
    }

    /// <summary>
    /// Creates an appropriate hardware accelerator instance
    /// </summary>
    /// <returns>Hardware accelerator instance</returns>
    public static IHardwareAccelerator CreateAccelerator()
    {
        return new DefaultHardwareAccelerator(AvailableAcceleration);
    }
}

/// <summary>
/// Hardware capabilities information
/// </summary>
public class HardwareCapabilities
{
    /// <summary>
    /// Available acceleration types
    /// </summary>
    public HardwareAccelerationType AccelerationType { get; set; }

    /// <summary>
    /// Whether Intel AES-NI is supported
    /// </summary>
    public bool AesNiSupported { get; set; }

    /// <summary>
    /// Whether AVX2 instructions are supported
    /// </summary>
    public bool Avx2Supported { get; set; }

    /// <summary>
    /// Whether ARM crypto extensions are supported
    /// </summary>
    public bool ArmCryptoSupported { get; set; }

    /// <summary>
    /// Processor architecture
    /// </summary>
    public Architecture ProcessorArchitecture { get; set; }

    /// <summary>
    /// Operating system description
    /// </summary>
    public string OperatingSystem { get; set; } = string.Empty;

    /// <summary>
    /// Number of processor cores
    /// </summary>
    public int ProcessorCount { get; set; }

    /// <summary>
    /// Gets a human-readable summary
    /// </summary>
    /// <returns>Capabilities summary</returns>
    public override string ToString()
    {
        var capabilities = new List<string>();
        
        if (AesNiSupported) capabilities.Add("AES-NI");
        if (Avx2Supported) capabilities.Add("AVX2");
        if (ArmCryptoSupported) capabilities.Add("ARM Crypto");
        
        var capabilityString = capabilities.Count > 0 ? string.Join(", ", capabilities) : "None";
        
        return $"Architecture: {ProcessorArchitecture}, " +
               $"Cores: {ProcessorCount}, " +
               $"Hardware Acceleration: {capabilityString}";
    }
}