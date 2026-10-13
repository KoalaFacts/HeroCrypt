using System.Security.Cryptography;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhConcurrencyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentAcceptance_SucceedsExactlyOnceAsync(bool opk)
    {
        using var pair = new X3dhHandshakeTests.Pair(); using var init = pair.Start(opk);
        var start = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            await start.Task;
            try { return pair.Accept(init.InitialMessage); }
            catch (CryptographicException) { return null; }
        }, TestContext.Current.CancellationToken)).ToArray();
        start.SetResult(true); var all = await Task.WhenAll(tasks);
        using var accepted = Assert.Single(all, a => a != null)!;
        Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
    }

    [Fact]
    public async Task ConcurrentStoreDisposal_ReturnsCompleteResultOrDisposedAsync()
    {
        using var pair = new X3dhHandshakeTests.Pair(); using var init = pair.Start(true);
        var start = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var acceptance = Task.Run(async () =>
        {
            await start.Task;
            try { return pair.Accept(init.InitialMessage); }
            catch (ObjectDisposedException) { return null; }
        }, TestContext.Current.CancellationToken);
        var disposal = Task.Run(async () => { await start.Task; pair.Store.Dispose(); }, TestContext.Current.CancellationToken);
        start.SetResult(true); await disposal;
        using var accepted = await acceptance;
        if (accepted != null)
        {
            Assert.Equal("hello"u8.ToArray(), accepted.Plaintext);
            Assert.Equal("post-disposal"u8.ToArray(), accepted.Session.Decrypt(init.Session.Encrypt("post-disposal"u8)));
        }
        Assert.Throws<ObjectDisposedException>(() => pair.Accept(init.InitialMessage));
    }
}
