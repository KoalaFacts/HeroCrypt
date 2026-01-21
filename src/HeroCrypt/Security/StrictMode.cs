namespace HeroCrypt.Security;

/// <summary>
/// Controls strict security mode for HeroCrypt.
/// When enabled (default), legacy and deprecated cryptographic algorithms are blocked.
/// </summary>
/// <remarks>
/// <para>
/// Strict mode is <b>enabled by default</b> to enforce FIPS-compliant and secure algorithm usage.
/// This prevents accidental use of broken algorithms like MD5, SHA-1, 3DES, and Blowfish.
/// </para>
/// <para>
/// To use legacy algorithms for compatibility purposes (e.g., OpenPGP interoperability),
/// you must explicitly disable strict mode:
/// </para>
/// <code>
/// StrictMode.Enabled = false;
/// </code>
/// <para>
/// <b>Warning:</b> Disabling strict mode should only be done when absolutely necessary
/// for legacy system compatibility. Re-enable it as soon as possible.
/// </para>
/// </remarks>
public static class StrictMode
{
    private static bool enabled = true;

    /// <summary>
    /// Gets or sets whether strict mode is enabled.
    /// When true (default), legacy algorithms will throw <see cref="StrictModeException"/>.
    /// </summary>
    /// <remarks>
    /// <para>Default: <c>true</c></para>
    /// <para>
    /// Blocked algorithms in strict mode:
    /// <list type="bullet">
    ///   <item>MD5 - cryptographically broken</item>
    ///   <item>SHA-1 - collision attacks practical</item>
    ///   <item>3DES - 64-bit block size vulnerable</item>
    ///   <item>Blowfish - 64-bit block size vulnerable</item>
    ///   <item>CAST5 - 64-bit block size vulnerable</item>
    ///   <item>IDEA - 64-bit block size vulnerable</item>
    /// </list>
    /// </para>
    /// </remarks>
    public static bool Enabled
    {
        get => enabled;
        set => enabled = value;
    }

    /// <summary>
    /// Throws <see cref="StrictModeException"/> if strict mode is enabled.
    /// </summary>
    /// <param name="algorithm">Name of the blocked algorithm.</param>
    /// <param name="recommendation">Recommended alternative algorithm.</param>
    /// <exception cref="StrictModeException">Thrown when strict mode is enabled.</exception>
    public static void ThrowIfEnabled(string algorithm, string recommendation)
    {
        if (enabled)
        {
            throw new StrictModeException(algorithm, recommendation);
        }
    }

    /// <summary>
    /// Temporarily disables strict mode for a specific operation, then re-enables it.
    /// </summary>
    /// <param name="action">The action to execute with strict mode disabled.</param>
    /// <remarks>
    /// Use this for legacy compatibility scenarios where you need to perform
    /// a single operation with deprecated algorithms.
    /// <code>
    /// StrictMode.WithLegacyMode(() =>
    /// {
    ///     // Legacy operation using MD5 or SHA-1
    /// });
    /// </code>
    /// </remarks>
    public static void WithLegacyMode(Action action)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(action);
#else
        if (action == null)
        {
            throw new ArgumentNullException(nameof(action));
        }
#endif

        var previousState = enabled;
        try
        {
            enabled = false;
            action();
        }
        finally
        {
            enabled = previousState;
        }
    }

    /// <summary>
    /// Temporarily disables strict mode for a specific operation, then re-enables it.
    /// </summary>
    /// <typeparam name="T">Return type of the operation.</typeparam>
    /// <param name="func">The function to execute with strict mode disabled.</param>
    /// <returns>The result of the function.</returns>
    /// <remarks>
    /// Use this for legacy compatibility scenarios where you need to perform
    /// a single operation with deprecated algorithms.
    /// <code>
    /// var hash = StrictMode.WithLegacyMode(() =>
    /// {
    ///     return HeroCryptBuilder.Hash().WithMd5().ComputeHash(data);
    /// });
    /// </code>
    /// </remarks>
    public static T WithLegacyMode<T>(Func<T> func)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(func);
#else
        if (func == null)
        {
            throw new ArgumentNullException(nameof(func));
        }
#endif

        var previousState = enabled;
        try
        {
            enabled = false;
            return func();
        }
        finally
        {
            enabled = previousState;
        }
    }

    /// <summary>
    /// Creates a disposable scope that temporarily disables strict mode.
    /// </summary>
    /// <returns>An IDisposable that restores strict mode when disposed.</returns>
    /// <remarks>
    /// <code>
    /// using (StrictMode.LegacyScope())
    /// {
    ///     // Legacy operations here
    /// }
    /// // Strict mode is automatically restored
    /// </code>
    /// </remarks>
    public static IDisposable LegacyScope()
    {
        return new StrictModeScope();
    }

    private sealed class StrictModeScope : IDisposable
    {
        private readonly bool previousState;
        private bool disposed;

        public StrictModeScope()
        {
            previousState = enabled;
            enabled = false;
        }

        public void Dispose()
        {
            if (!disposed)
            {
                enabled = previousState;
                disposed = true;
            }
        }
    }
}

/// <summary>
/// Exception thrown when attempting to use a deprecated algorithm while strict mode is enabled.
/// </summary>
public class StrictModeException : InvalidOperationException
{
    /// <summary>
    /// Gets the name of the blocked algorithm.
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// Gets the recommended alternative algorithm.
    /// </summary>
    public string Recommendation { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="StrictModeException"/>.
    /// </summary>
    /// <param name="algorithm">The blocked algorithm name.</param>
    /// <param name="recommendation">The recommended alternative.</param>
    public StrictModeException(string algorithm, string recommendation)
        : base($"Strict mode is enabled: '{algorithm}' is a deprecated/insecure algorithm. {recommendation} To use legacy algorithms, set StrictMode.Enabled = false or use StrictMode.WithLegacyMode().")
    {
        Algorithm = algorithm;
        Recommendation = recommendation;
    }
}
