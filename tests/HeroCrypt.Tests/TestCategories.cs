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
}
