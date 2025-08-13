namespace HeroCrypt.Tests;

/// <summary>
/// Test categories for filtering test execution
/// </summary>
public static class TestCategories
{
    /// <summary>
    /// Fast tests that complete in milliseconds (no key generation, minimal iterations)
    /// </summary>
    public const string Fast = "Fast";
    
    /// <summary>
    /// Slow tests that involve RSA key generation or intensive computations
    /// </summary>
    public const string Slow = "Slow";
    
    /// <summary>
    /// RFC compliance tests that verify standard compliance
    /// </summary>
    public const string Compliance = "Compliance";
    
    /// <summary>
    /// Integration tests that test multiple components together
    /// </summary>
    public const string Integration = "Integration";
    
    /// <summary>
    /// Unit tests that test individual components in isolation
    /// </summary>
    public const string Unit = "Unit";
}