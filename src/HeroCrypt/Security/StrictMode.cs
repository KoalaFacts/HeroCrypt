namespace HeroCrypt.Security;

/// <summary>
/// Legacy static class for controlling strict security mode.
/// </summary>
/// <remarks>
/// <para>
/// <b>DEPRECATED:</b> Use builder-level configuration instead of this static class.
/// For example, use <c>HashBuilder.AllowLegacyAlgorithms()</c> to enable legacy algorithms
/// on a per-operation basis without shared state.
/// </para>
/// <code>
/// // Preferred: Builder-level configuration (no shared state)
/// var hash = HeroCryptBuilder.Hash()
///     .AllowLegacyAlgorithms()
///     .WithMd5()
///     .ComputeHash(data);
///
/// // Deprecated: Static configuration (shared state)
/// StrictMode.WithLegacyMode(() => { ... });
/// </code>
/// </remarks>
[Obsolete("Use builder-level AllowLegacyAlgorithms() instead of static StrictMode for stateless operation.")]
public static class StrictMode
{
    // AsyncLocal provides thread-isolated state that flows with async/await context.
    // Each thread/async context gets its own value, preventing race conditions in parallel tests.
    // null means "use default" (true), which avoids allocating for the common case.
    private static readonly AsyncLocal<bool?> EnabledState = new();

    /// <summary>
    /// Gets or sets whether strict mode is enabled globally.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>DEPRECATED:</b> Use builder-level <c>AllowLegacyAlgorithms()</c> instead.
    /// </para>
    /// </remarks>
    [Obsolete("Use builder-level AllowLegacyAlgorithms() instead.")]
    public static bool Enabled
    {
        get => EnabledState.Value ?? true;
        set => EnabledState.Value = value;
    }

    /// <summary>
    /// Throws <see cref="StrictModeException"/> if strict mode is enabled.
    /// </summary>
    /// <param name="algorithm">Name of the blocked algorithm.</param>
    /// <param name="recommendation">Recommended alternative algorithm.</param>
    /// <exception cref="StrictModeException">Thrown when strict mode is enabled.</exception>
    [Obsolete("Use builder-level AllowLegacyAlgorithms() instead.")]
    public static void ThrowIfEnabled(string algorithm, string recommendation)
    {
        if (Enabled)
        {
            throw new StrictModeException(algorithm, recommendation);
        }
    }

    /// <summary>
    /// Temporarily disables strict mode for a specific operation, then re-enables it.
    /// </summary>
    /// <param name="action">The action to execute with strict mode disabled.</param>
    /// <remarks>
    /// <para>
    /// <b>DEPRECATED:</b> Use builder-level <c>AllowLegacyAlgorithms()</c> instead.
    /// </para>
    /// <code>
    /// // Preferred approach:
    /// var hash = HeroCryptBuilder.Hash()
    ///     .AllowLegacyAlgorithms()
    ///     .WithMd5()
    ///     .ComputeHash(data);
    /// </code>
    /// </remarks>
    [Obsolete("Use builder-level AllowLegacyAlgorithms() instead.")]
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

        var previousState = Enabled;
        try
        {
            Enabled = false;
            action();
        }
        finally
        {
            Enabled = previousState;
        }
    }

    /// <summary>
    /// Temporarily disables strict mode for a specific operation, then re-enables it.
    /// </summary>
    /// <typeparam name="T">Return type of the operation.</typeparam>
    /// <param name="func">The function to execute with strict mode disabled.</param>
    /// <returns>The result of the function.</returns>
    /// <remarks>
    /// <para>
    /// <b>DEPRECATED:</b> Use builder-level <c>AllowLegacyAlgorithms()</c> instead.
    /// </para>
    /// </remarks>
    [Obsolete("Use builder-level AllowLegacyAlgorithms() instead.")]
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

        var previousState = Enabled;
        try
        {
            Enabled = false;
            return func();
        }
        finally
        {
            Enabled = previousState;
        }
    }

    /// <summary>
    /// Creates a disposable scope that temporarily disables strict mode.
    /// </summary>
    /// <returns>An IDisposable that restores strict mode when disposed.</returns>
    /// <remarks>
    /// <para>
    /// <b>DEPRECATED:</b> Use builder-level <c>AllowLegacyAlgorithms()</c> instead.
    /// </para>
    /// </remarks>
    [Obsolete("Use builder-level AllowLegacyAlgorithms() instead.")]
    public static IDisposable LegacyScope()
    {
        return new StrictModeScope();
    }

    /// <summary>
    /// Scope that temporarily disables strict mode.
    /// </summary>
    private sealed class StrictModeScope : IDisposable
    {
        private readonly bool previousState;
        private bool disposed;

        /// <summary>
        /// Initializes a new strict mode scope, saving the current state and disabling strict mode.
        /// </summary>
        public StrictModeScope()
        {
#pragma warning disable CS0618 // Obsolete
            previousState = Enabled;
            Enabled = false;
#pragma warning restore CS0618
        }

        /// <summary>
        /// Restores the previous strict mode state.
        /// </summary>
        public void Dispose()
        {
            if (!disposed)
            {
#pragma warning disable CS0618 // Obsolete
                Enabled = previousState;
#pragma warning restore CS0618
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
