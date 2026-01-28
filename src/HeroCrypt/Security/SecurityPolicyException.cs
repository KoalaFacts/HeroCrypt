namespace HeroCrypt.Security;

/// <summary>
/// Exception thrown when an algorithm violates the current security policy.
/// </summary>
public class SecurityPolicyException : InvalidOperationException
{
    /// <summary>Gets the blocked algorithm.</summary>
    public string Algorithm { get; }

    /// <summary>Gets the recommended alternative.</summary>
    public string Alternative { get; }

    /// <summary>Gets the reason the algorithm was blocked.</summary>
    public string Reason { get; }

    /// <summary>Gets the security level that blocked the algorithm.</summary>
    public SecurityLevel Level { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="SecurityPolicyException"/>.
    /// </summary>
    public SecurityPolicyException(string algorithm, string alternative, string reason, SecurityLevel level)
        : base($"Security policy ({level}) violation: '{algorithm}' is not permitted. {reason}. Use '{alternative}' instead.")
    {
        Algorithm = algorithm;
        Alternative = alternative;
        Reason = reason;
        Level = level;
    }
}
