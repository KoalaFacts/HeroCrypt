namespace HeroCrypt.Tests;

/// <summary>
/// Test categories for filtering test execution
/// </summary>
public static class TestCategories
{
    /// <summary>
    /// FAST tests that complete in milliseconds (no key generation, minimal iterations)
    /// </summary>
    public const string FAST = "Fast";

    /// <summary>
    /// SLOW tests that involve RSA key generation or intensive computations
    /// </summary>
    public const string SLOW = "Slow";

    /// <summary>
    /// RFC COMPLIANCE tests that verify standard COMPLIANCE
    /// </summary>
    public const string COMPLIANCE = "Compliance";

    /// <summary>
    /// INTEGRATION tests that test multiple components together
    /// </summary>
    public const string INTEGRATION = "Integration";

    /// <summary>
    /// UNIT tests that test individual components in isolation
    /// </summary>
    public const string UNIT = "Unit";

    /// <summary>
    /// SECURITY tests that verify cryptographic security properties (timing, constant-time, etc.)
    /// </summary>
    public const string SECURITY = "Security";

    /// <summary>
    /// MEMORY tests that verify proper memory hygiene (clearing sensitive data)
    /// </summary>
    public const string MEMORY = "Memory";

    /// <summary>
    /// EDGE_CASE tests that verify boundary conditions and edge cases
    /// </summary>
    public const string EDGE_CASE = "EdgeCase";

    /// <summary>
    /// KNOWN_ANSWER tests using official test vectors from standards
    /// </summary>
    public const string KNOWN_ANSWER = "KnownAnswer";

    /// <summary>
    /// THREAD_SAFETY tests that verify concurrent access to shared builders
    /// </summary>
    public const string THREAD_SAFETY = "ThreadSafety";
}
