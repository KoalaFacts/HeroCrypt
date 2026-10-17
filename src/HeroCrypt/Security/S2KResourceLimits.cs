using System.Security.Cryptography;

namespace HeroCrypt.Security;

/// <summary>
/// Resource limits for each OpenPGP Argon2 S2K derivation, including legacy consumption.
/// </summary>
/// <remarks>
/// Limits cover the requested Argon2 memory and memory multiplied by passes, not
/// total process memory, elapsed time, or aggregate work across multiple derivations.
/// Raise them only for trusted inputs within the application's resource budget.
/// </remarks>
public sealed record S2KResourceLimits
{
    /// <summary>Gets the default limits: 512 MiB and three passes at that memory size.</summary>
    public static S2KResourceLimits Default { get; } = new();

    /// <summary>Gets the maximum requested Argon2 memory in KiB per derivation.</summary>
    public long MaxArgon2MemoryKiB
    {
        get;
        init => field = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    } = 524288;

    /// <summary>Gets the maximum requested memory in KiB multiplied by passes per derivation.</summary>
    public long MaxArgon2WorkKiB
    {
        get;
        init => field = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    } = 1572864;

    internal void ValidateArgon2(long memoryKiB, byte passes)
    {
        if (memoryKiB > MaxArgon2MemoryKiB || checked(memoryKiB * passes) > MaxArgon2WorkKiB)
        {
            throw new CryptographicException("Argon2 S2K exceeds the configured memory or work limit.");
        }
    }
}
