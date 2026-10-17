using HeroCrypt.Security;

namespace HeroCrypt.Protocols.DoubleRatchet;

/// <summary>Owned ratchet keys and counters, copied transactionally before each operation.</summary>
internal sealed class DoubleRatchetState : IDisposable
{
    internal byte[] Root = [];
    internal byte[] PrivateKey = [];
    internal byte[] PublicKey = [];
    internal byte[]? RemoteKey;
    internal byte[]? SendingChain;
    internal byte[]? ReceivingChain;
    internal uint SendCount;
    internal uint ReceiveCount;
    internal uint PreviousSendCount;
    internal readonly Dictionary<(string PublicKey, uint Number), byte[]> Skipped = [];

    internal DoubleRatchetState Clone()
    {
        var copy = new DoubleRatchetState();
        try
        {
            copy.Root = Root.AsSpan().ToArray();
            copy.PrivateKey = PrivateKey.AsSpan().ToArray();
            copy.PublicKey = PublicKey.AsSpan().ToArray();
            copy.RemoteKey = RemoteKey?.AsSpan().ToArray();
            copy.SendingChain = SendingChain?.AsSpan().ToArray();
            copy.ReceivingChain = ReceivingChain?.AsSpan().ToArray();
            copy.SendCount = SendCount;
            copy.ReceiveCount = ReceiveCount;
            copy.PreviousSendCount = PreviousSendCount;
            foreach (var entry in Skipped)
                copy.Skipped.Add(entry.Key, entry.Value.AsSpan().ToArray());
            return copy;
        }
        catch
        {
            copy.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Clear(Root); Clear(PrivateKey); Clear(PublicKey); Clear(RemoteKey);
        Clear(SendingChain); Clear(ReceivingChain);
        foreach (var key in Skipped.Values) Clear(key);
        Skipped.Clear();
        Root = []; PrivateKey = []; PublicKey = [];
        RemoteKey = null; SendingChain = null; ReceivingChain = null;
        SendCount = 0; ReceiveCount = 0; PreviousSendCount = 0;
    }

    internal static void Clear(byte[]? value)
    {
        if (value != null) SecureMemoryOperations.SecureClear(value);
    }
}
