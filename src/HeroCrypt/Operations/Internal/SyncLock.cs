namespace HeroCrypt.Operations.Internal;

/// <summary>
/// Thread synchronization lock wrapper that uses System.Threading.Lock on .NET 9+
/// and falls back to object-based locking on earlier frameworks.
/// </summary>
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
    internal readonly struct LockScope : IDisposable
    {
        private readonly object @lock;

        public LockScope(object lockObj)
        {
            @lock = lockObj;
        }

        public void Dispose() => Monitor.Exit(@lock);
    }
#endif
}
