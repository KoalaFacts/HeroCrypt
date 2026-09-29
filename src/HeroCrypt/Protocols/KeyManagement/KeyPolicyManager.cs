using HeroCrypt.Security;

namespace HeroCrypt.Protocols.KeyManagement;

/// <summary>
/// Key policy manager for enforcing key lifecycle rules
/// </summary>
public class KeyPolicyManager
{
    private readonly KeyPolicy policy;

    internal KeyPolicyManager(KeyPolicy policy)
    {
        this.policy = policy;
    }

    /// <summary>
    /// Validates a key against the policy
    /// </summary>
    /// <param name="keyMaterial">Key to validate</param>
    /// <param name="createdAt">When key was created</param>
    /// <returns>Validation result</returns>
    public PolicyValidationResult ValidateKey(ReadOnlySpan<byte> keyMaterial, DateTimeOffset createdAt)
    {
        var issues = new List<string>();
        var now = DateTimeOffset.UtcNow;

        // Check age
        var age = now - createdAt;
        if (age > policy.MaxAge)
        {
            issues.Add($"Key is too old ({age.TotalDays:F1} days, max: {policy.MaxAge.TotalDays} days)");
        }

        var shouldRotate = age > policy.RotationInterval;

        // Check size
        if (keyMaterial.Length < policy.MinKeySize)
        {
            issues.Add($"Key is too small ({keyMaterial.Length} bytes, min: {policy.MinKeySize} bytes)");
        }

        // Validate entropy if enforcing secure generation
        if (policy.EnforceSecureGeneration)
        {
            var validation = KeyManager.ValidateKey(keyMaterial);
            if (policy.MinEntropy > 0 && validation.Entropy < policy.MinEntropy)
            {
                issues.Add($"Key entropy too low ({validation.Entropy:F2}, min: {policy.MinEntropy})");
            }

            issues.AddRange(validation.Issues);
        }

        // Custom validation
        if (policy.CustomValidator != null && !policy.CustomValidator(keyMaterial.ToArray()))
        {
            issues.Add("Custom validation failed");
        }

        return new PolicyValidationResult
        {
            IsValid = issues.Count == 0,
            Issues = [.. issues],
            ShouldRotate = shouldRotate,
            KeyAge = age
        };
    }

    /// <summary>
    /// Generates a key that complies with the policy
    /// </summary>
    /// <returns>Policy-compliant key</returns>
    public byte[] GenerateCompliantKey()
    {
        var keySize = Math.Max(policy.MinKeySize, 32);
        var maximumSampleEntropy = Math.Log(Math.Min(keySize, 256), 2);
        if (policy.EnforceSecureGeneration && policy.MinEntropy > maximumSampleEntropy)
        {
            throw new InvalidOperationException("The requested minimum sample entropy is impossible for this key size.");
        }

        const int maxAttempts = 32;
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            var key = KeyManager.GenerateSecureKey(keySize);
            var validation = ValidateKey(key, DateTimeOffset.UtcNow);
            if (validation.IsValid)
            {
                return key;
            }

            SecureMemoryOperations.SecureClear(key);
        }

        throw new InvalidOperationException("Unable to generate a key that satisfies the policy after 32 attempts.");
    }
}
