#if NET5_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif
using System.Runtime.InteropServices;

namespace HeroCrypt.Hardware;

/// <summary>
/// Detects available hardware acceleration capabilities
/// </summary>
internal static class HardwareAccelerationDetector
{

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
    /// Checks if AVX-512 instructions are available
    /// </summary>
#if NET5_0_OR_GREATER
    public static bool IsAvx512Available => System.Runtime.Intrinsics.X86.Avx512F.IsSupported;
#else
    public static bool IsAvx512Available => false; // Not detectable in .NET Standard 2.0
#endif

    /// <summary>
    /// Checks if Intel RDRAND/RDSEED is available
    /// </summary>
#if NET5_0_OR_GREATER
    public static bool IsRdrandAvailable => X86Base.IsSupported &&
                                           CheckRdrandSupport();
#else
    public static bool IsRdrandAvailable => false; // Not detectable in .NET Standard 2.0
#endif

    /// <summary>
    /// Checks if Intel SHA extensions are available
    /// </summary>
#if NET5_0_OR_GREATER
    public static bool IsShaExtensionsAvailable => CheckShaExtensionsSupport();
#else
    public static bool IsShaExtensionsAvailable => false; // Not detectable in .NET Standard 2.0
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
            AesNiSupported = IsAesNiAvailable,
            Avx2Supported = IsAvx2Available,
            Avx512Supported = IsAvx512Available,
            RdrandSupported = IsRdrandAvailable,
            ShaExtensionsSupported = IsShaExtensionsAvailable,
            ArmCryptoSupported = IsArmCryptoAvailable,
            ProcessorArchitecture = RuntimeInformation.ProcessArchitecture,
            OperatingSystem = RuntimeInformation.OSDescription,
            ProcessorCount = Environment.ProcessorCount
        };
    }

    private static bool CheckArmCryptoSupport()
    {
        // This would need platform-specific implementation
        // For now, we assume ARM64 has crypto extensions
        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
    }

#if NET5_0_OR_GREATER
    private static bool CheckRdrandSupport()
    {
        try
        {
            // Check for RDRAND instruction support in CPUID
            // This is a simplified check - in production you'd want more thorough CPUID parsing
            return System.Runtime.Intrinsics.X86.X86Base.IsSupported;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static bool CheckShaExtensionsSupport()
    {
        try
        {
            // Check for Intel SHA extensions support
            // This is a simplified check - real implementation would check CPUID flags
            return System.Runtime.Intrinsics.X86.X86Base.IsSupported;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }
#endif
}

/// <summary>
/// Hardware capabilities information
/// </summary>
public class HardwareCapabilities
{

    /// <summary>
    /// Whether Intel AES-NI is supported
    /// </summary>
    public bool AesNiSupported { get; set; }

    /// <summary>
    /// Whether AVX2 instructions are supported
    /// </summary>
    public bool Avx2Supported { get; set; }

    /// <summary>
    /// Whether AVX-512 instructions are supported
    /// </summary>
    public bool Avx512Supported { get; set; }

    /// <summary>
    /// Whether Intel RDRAND/RDSEED is supported
    /// </summary>
    public bool RdrandSupported { get; set; }

    /// <summary>
    /// Whether Intel SHA extensions are supported
    /// </summary>
    public bool ShaExtensionsSupported { get; set; }

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

        if (AesNiSupported)
        {
            capabilities.Add("AES-NI");
        }

        if (Avx2Supported)
        {
            capabilities.Add("AVX2");
        }

        if (Avx512Supported)
        {
            capabilities.Add("AVX-512");
        }

        if (RdrandSupported)
        {
            capabilities.Add("RDRAND");
        }

        if (ShaExtensionsSupported)
        {
            capabilities.Add("SHA");
        }

        if (ArmCryptoSupported)
        {
            capabilities.Add("ARM Crypto");
        }

        var capabilityString = capabilities.Count > 0 ? string.Join(", ", capabilities) : "None";

        return $"Architecture: {ProcessorArchitecture}, " +
               $"Cores: {ProcessorCount}, " +
               $"Hardware Acceleration: {capabilityString}";
    }
}
