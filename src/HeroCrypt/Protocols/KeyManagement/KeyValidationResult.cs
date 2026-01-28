namespace HeroCrypt.Protocols.KeyManagement;

/// <summary>
/// Result of key validation
/// </summary>
public class KeyValidationResult
{
    /// <summary>Whether the key is valid</summary>
    public bool IsValid { get; set; }

    /// <summary>List of validation issues</summary>
    public string[] Issues { get; set; } = [];

    /// <summary>Key strength score (0-100)</summary>
    public int Score { get; set; }

    /// <summary>Empirical sample entropy in bits per byte, not a measure of generator quality.</summary>
    public double Entropy { get; set; }
}
