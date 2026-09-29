namespace HeroCrypt.Protocols.KeyManagement;

/// <summary>
/// Result of policy validation
/// </summary>
public class PolicyValidationResult
{
    /// <summary>Whether the key meets policy requirements</summary>
    public bool IsValid { get; set; }

    /// <summary>List of policy violations</summary>
    public string[] Issues { get; set; } = [];

    /// <summary>Whether the key should be rotated</summary>
    public bool ShouldRotate { get; set; }

    /// <summary>Age of the key</summary>
    public TimeSpan KeyAge { get; set; }
}
