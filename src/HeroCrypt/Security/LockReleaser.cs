namespace HeroCrypt.Security;

#if !NET9_0_OR_GREATER
/// <summary>
/// Disposable wrapper around <see cref="Monitor"/> that mirrors .NET 9 lock scopes.
/// </summary>
internal sealed class LockReleaser : IDisposable
{
    private readonly object target;

    public LockReleaser(object target)
    {
        this.target = target ?? throw new ArgumentNullException(nameof(target));
        Monitor.Enter(this.target);
    }

    /// <summary>
    /// Releases the monitor lock acquired during construction.
    /// </summary>
    public void Dispose()
    {
        Monitor.Exit(target);
    }
}
#endif
