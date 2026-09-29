using HeroCrypt.Security;

namespace HeroCrypt;

/// <summary>
/// Provides access to global HeroCrypt default settings.
/// </summary>
/// <remarks>
/// <para>
/// Use this class to configure library-wide defaults that affect all cryptographic operations.
/// Settings can be overridden per-operation using builder methods like <c>WithSecurityPolicy()</c>.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Set global security policy to strict
/// HeroCrypt.Defaults.SecurityPolicy = SecurityPolicyOptions.Strict;
///
/// // Or set just the security level
/// HeroCrypt.Defaults.SecurityLevel = SecurityLevel.Compliance;
///
/// // All subsequent operations use this policy by default
/// var result = HeroCryptBuilder.Encrypt()
///     .WithAesGcm()
///     .WithKey(key)
///     .Encrypt(data);
///
/// // Override for a specific operation
/// var result = HeroCryptBuilder.Encrypt()
///     .WithAesGcm()
///     .WithKey(key)
///     .WithSecurityPolicy(opt => opt with { Level = SecurityLevel.None })
///     .Encrypt(data);
/// </code>
/// </example>
public static class Defaults
{
    /// <summary>
    /// Gets or sets the global security level.
    /// Default is <see cref="SecurityLevel.Standard"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a convenience property that sets/gets the <see cref="SecurityPolicy.Current"/> level.
    /// For more granular control, use <see cref="SecurityPolicy"/> instead.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Set to compliance mode (FIPS-only algorithms)
    /// HeroCrypt.Defaults.SecurityLevel = SecurityLevel.Compliance;
    ///
    /// // Set to strict mode
    /// HeroCrypt.Defaults.SecurityLevel = SecurityLevel.Strict;
    /// </code>
    /// </example>
    public static SecurityLevel SecurityLevel
    {
        get => Security.SecurityPolicy.Current;
        set => Security.SecurityPolicy.Current = value;
    }

    /// <summary>
    /// Gets or sets the global security policy options.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When setting, this updates the global <see cref="SecurityPolicy.Current"/> level
    /// from the provided options. When getting, it returns the effective options based on
    /// <see cref="SecurityPolicy.Current"/>.
    /// </para>
    /// <para>
    /// For per-operation overrides, use <c>WithSecurityPolicy()</c> on the builder instead.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Set global policy to strict
    /// HeroCrypt.Defaults.SecurityPolicy = SecurityPolicyOptions.Strict;
    ///
    /// // Or use a custom policy
    /// HeroCrypt.Defaults.SecurityPolicy = SecurityPolicyOptions.Default with
    /// {
    ///     Level = SecurityLevel.Strict
    /// };
    /// </code>
    /// </example>
    public static SecurityPolicyOptions SecurityPolicy
    {
        get => Security.SecurityPolicy.GetEffective(null);
        set => Security.SecurityPolicy.Current = value.Level;
    }
}
