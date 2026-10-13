using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

internal sealed class X3dhPreKeyMaterial(byte[] privateKey, byte[] publicKey, byte[] signature) : IDisposable
{
    internal readonly byte[] PrivateKey = privateKey;
    internal readonly byte[] PublicKey = publicKey;
    internal readonly byte[] Signature = signature;
    public void Dispose()
    {
        SecureMemoryOperations.SecureClear(PrivateKey.AsSpan()); SecureMemoryOperations.SecureClear(PublicKey.AsSpan());
        SecureMemoryOperations.SecureClear(Signature.AsSpan());
    }
}
