using System.Security.Cryptography;

namespace HeroCrypt.Protocols.KeyManagement;

/// <summary>
/// Key policy configuration
/// </summary>
public class KeyPolicy
{
    /// <summary>Maximum key age before mandatory rotation</summary>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Recommended key rotation interval</summary>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Minimum key size in bytes</summary>
    public int MinKeySize { get; set; } = 32;

    /// <summary>Maximum number of old keys to retain</summary>
    public int MaxRetainedKeys { get; set; } = 5;

    /// <summary>Whether to enforce secure key generation</summary>
    public bool EnforceSecureGeneration { get; set; } = true;

    /// <summary>Optional minimum empirical byte entropy; zero disables this short-sample check.</summary>
    public double MinEntropy { get; set; }

    /// <summary>Hash algorithm for key derivation</summary>
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>Custom validation rules</summary>
    public Func<byte[], bool>? CustomValidator { get; set; }
}
