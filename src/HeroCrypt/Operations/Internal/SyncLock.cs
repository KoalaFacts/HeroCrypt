namespace HeroCrypt.Operations.Internal;

/// <summary>
/// Thread synchronization lock wrapper that uses System.Threading.Lock on .NET 9+
/// and falls back to object-based locking on earlier frameworks.
/// </summary>
/// <remarks>
/// <para>
/// This class provides a unified locking API across different .NET versions:
/// </para>
/// <list type="bullet">
///   <item>
///     <term>.NET 9+</term>
///     <description>Uses the new <c>System.Threading.Lock</c> type for improved performance</description>
///   </item>
///   <item>
///     <term>.NET 8 and earlier</term>
///     <description>Uses traditional <c>Monitor.Enter/Exit</c> with object-based locking</description>
///   </item>
/// </list>
/// <para>
/// <b>Usage pattern:</b>
/// </para>
/// <code>
/// private readonly SyncLock _lock = new();
///
/// public void ThreadSafeMethod()
/// {
///     using var scope = _lock.EnterScope();
///     // Protected code here
/// }
/// </code>
/// <para>
/// The returned scope implements <c>IDisposable</c>, so it can be used with
/// <c>using</c> statements or declarations for automatic lock release.
/// </para>
/// </remarks>
internal sealed class SyncLock
{
#if NET9_0_OR_GREATER
    private readonly Lock @lock = new();

    /// <summary>
    /// Enters the lock and returns a scope that releases the lock when disposed.
    /// </summary>
    public Lock.Scope EnterScope() => @lock.EnterScope();
#else
    private readonly object @lock = new();

    /// <summary>
    /// Enters the lock and returns a scope that releases the lock when disposed.
    /// </summary>
    public LockScope EnterScope()
    {
        Monitor.Enter(@lock);
        return new LockScope(@lock);
    }

    /// <summary>
    /// Disposable scope that releases the lock when disposed.
    /// </summary>
    internal readonly struct LockScope(object lockObj) : IDisposable
    {
        /// <summary>
        /// Releases the lock.
        /// </summary>
        public void Dispose() => Monitor.Exit(lockObj);
    }
#endif
}
