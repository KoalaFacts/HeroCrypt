using System.Security.Cryptography;

namespace HeroCrypt.Security;

/// <summary>
/// Provides global security policy defaults and scoped overrides.
/// </summary>
/// <remarks>
/// <para>
/// Use <see cref="GetEffective"/> to resolve the effective policy for an operation.
/// Prefer passing <see cref="SecurityPolicyOptions"/> explicitly to builders and primitives.
/// </para>
/// </remarks>
public static class SecurityPolicy
{
    private static readonly AsyncLocal<SecurityLevel?> CurrentLevel = new();

    /// <summary>
    /// Gets or sets the current global security level.
    /// Default is <see cref="SecurityLevel.Standard"/>.
    /// </summary>
    public static SecurityLevel Current
    {
        get => CurrentLevel.Value ?? SecurityLevel.Standard;
        set => CurrentLevel.Value = value;
    }

    /// <summary>
    /// Gets whether the underlying operating system has FIPS mode enabled.
    /// </summary>
    public static bool IsSystemFipsEnabled => CryptoConfig.AllowOnlyFipsAlgorithms;

    /// <summary>
    /// Gets the current effective security policy options based on the global settings.
    /// </summary>
    public static SecurityPolicyOptions CurrentPolicy => GetEffective(null);

    /// <summary>
    /// Gets the effective security policy options, using the provided override or falling back to global settings.
    /// </summary>
    /// <param name="options">Optional override. If <c>null</c>, returns options based on <see cref="Current"/>.</param>
    /// <returns>The effective security policy options to use.</returns>
    public static SecurityPolicyOptions GetEffective(SecurityPolicyOptions? options)
    {
        if (options != null)
        {
            return options;
        }

        // Create options based on current global settings
        var level = Current;
        return new SecurityPolicyOptions(
            Level: level,
            AllowDeterministicNonSiv: level == SecurityLevel.None);
    }

    /// <summary>
    /// Creates a disposable scope that temporarily overrides the security level.
    /// </summary>
    /// <param name="level">The security level to use within the scope.</param>
    /// <returns>An <see cref="IDisposable"/> that restores the previous level when disposed.</returns>
    public static IDisposable Override(SecurityLevel level)
    {
        return new SecurityPolicyScope(level);
    }

    /// <summary>
    /// Creates a disposable scope that temporarily enables compliance mode.
    /// </summary>
    public static IDisposable ComplianceScope() => Override(SecurityLevel.Compliance);

    /// <summary>
    /// Creates a disposable scope that temporarily disables all restrictions.
    /// Use with caution for legacy compatibility only.
    /// </summary>
    public static IDisposable LegacyScope() => Override(SecurityLevel.None);

    /// <summary>
    /// Creates a disposable scope that temporarily disables all security restrictions for testing.
    /// </summary>
    public static IDisposable TestingScope() => Override(SecurityLevel.None);

    /// <summary>
    /// Executes an action with a temporary security level override.
    /// </summary>
    public static void WithLevel(SecurityLevel level, Action action)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(action);
#else
        if (action == null) throw new ArgumentNullException(nameof(action));
#endif

        using var _ = Override(level);
        action();
    }

    /// <summary>
    /// Executes a function with a temporary security level override.
    /// </summary>
    public static T WithLevel<T>(SecurityLevel level, Func<T> func)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(func);
#else
        if (func == null) throw new ArgumentNullException(nameof(func));
#endif

        using var _ = Override(level);
        return func();
    }

    private sealed class SecurityPolicyScope : IDisposable
    {
        private readonly SecurityLevel previousLevel;
        private bool disposed;

        public SecurityPolicyScope(SecurityLevel level)
        {
            previousLevel = Current;
            Current = level;
        }

        public void Dispose()
        {
            if (!disposed)
            {
                Current = previousLevel;
                disposed = true;
            }
        }
    }
}
