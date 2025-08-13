namespace HeroCrypt.Abstractions;

public interface IKeyGenerationService
{
    Task<KeyPair> GenerateKeyPairAsync(int keySize = 4096, CancellationToken cancellationToken = default);
    Task<KeyPair> GenerateKeyPairAsync(string identity, string passphrase, int keySize = 4096, CancellationToken cancellationToken = default);
}

public class KeyPair
{
    public KeyPair(string publicKey, string privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    public string PublicKey { get; }
    public string PrivateKey { get; }
}