using HeroCrypt.Abstractions;
using System.Security.Cryptography;

namespace HeroCrypt.Hardware;

/// <summary>
/// Default implementation of hardware accelerator
/// </summary>
internal sealed class DefaultHardwareAccelerator : IHardwareAccelerator
{
    private readonly HardwareAccelerationType _accelerationType;

    public DefaultHardwareAccelerator(HardwareAccelerationType accelerationType)
    {
        _accelerationType = accelerationType;
    }

    /// <inheritdoc />
    public bool IsAvailable => _accelerationType != HardwareAccelerationType.None;

    /// <inheritdoc />
    public HardwareAccelerationType AccelerationType => _accelerationType;

    /// <inheritdoc />
    public string Description => GetAccelerationDescription();

    /// <inheritdoc />
    public Task<byte[]?> AcceleratedHashAsync(byte[] data, string algorithm, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
            return Task.FromResult<byte[]?>(null);

        return algorithm.ToUpperInvariant() switch
        {
            "SHA256" when SupportsAlgorithm("SHA256") => Task.FromResult<byte[]?>(ComputeSha256Accelerated(data)),
            "SHA512" when SupportsAlgorithm("SHA512") => Task.FromResult<byte[]?>(ComputeSha512Accelerated(data)),
            _ => Task.FromResult<byte[]?>(null)
        };
    }

    /// <inheritdoc />
    public Task<byte[]?> AcceleratedEncryptAsync(byte[] data, byte[] key, string algorithm, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
            return Task.FromResult<byte[]?>(null);

        return algorithm.ToUpperInvariant() switch
        {
            "AES" when SupportsAlgorithm("AES") => Task.FromResult<byte[]?>(EncryptAesAccelerated(data, key)),
            _ => Task.FromResult<byte[]?>(null)
        };
    }

    /// <inheritdoc />
    public bool SupportsAlgorithm(string algorithm)
    {
        if (!IsAvailable)
            return false;

        return algorithm.ToUpperInvariant() switch
        {
            "SHA256" => (_accelerationType & HardwareAccelerationType.IntelAesNi) != 0 ||
                       (_accelerationType & HardwareAccelerationType.ArmCrypto) != 0,
            "SHA512" => (_accelerationType & HardwareAccelerationType.IntelAesNi) != 0 ||
                       (_accelerationType & HardwareAccelerationType.ArmCrypto) != 0,
            "AES" => (_accelerationType & HardwareAccelerationType.IntelAesNi) != 0 ||
                    (_accelerationType & HardwareAccelerationType.ArmCrypto) != 0,
            _ => false
        };
    }

    private static byte[] ComputeSha256Accelerated(byte[] data)
    {
        // Use .NET's hardware-accelerated SHA256 implementation
        // The .NET runtime automatically uses hardware acceleration when available
#if NET5_0_OR_GREATER
        return SHA256.HashData(data);
#else
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
#endif
    }

    private static byte[] ComputeSha512Accelerated(byte[] data)
    {
        // Use .NET's hardware-accelerated SHA512 implementation
#if NET5_0_OR_GREATER
        return SHA512.HashData(data);
#else
        using var sha512 = SHA512.Create();
        return sha512.ComputeHash(data);
#endif
    }

    private static byte[]? EncryptAesAccelerated(byte[] data, byte[] key)
    {
        try
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            
            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            
            // Prepend IV to the encrypted data
            ms.Write(aes.IV, 0, aes.IV.Length);
            
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            
            return ms.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private string GetAccelerationDescription()
    {
        if (!IsAvailable)
            return "No hardware acceleration available";

        var descriptions = new List<string>();

        if ((_accelerationType & HardwareAccelerationType.IntelAesNi) != 0)
            descriptions.Add("Intel AES-NI");

        if ((_accelerationType & HardwareAccelerationType.ArmCrypto) != 0)
            descriptions.Add("ARM Crypto Extensions");

        if ((_accelerationType & HardwareAccelerationType.Gpu) != 0)
            descriptions.Add("GPU Acceleration");

        if ((_accelerationType & HardwareAccelerationType.Hsm) != 0)
            descriptions.Add("Hardware Security Module");

        return descriptions.Count > 0 
            ? $"Hardware acceleration: {string.Join(", ", descriptions)}"
            : "Hardware acceleration available";
    }
}