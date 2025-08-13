namespace HeroCrypt.Abstractions;

public interface IKeyGenerationService
{
    Task<KeyPair> GenerateKeyPairAsync(int keySize = 4096, CancellationToken cancellationToken = default);
    Task<KeyPair> GenerateKeyPairAsync(string identity, string passphrase, int keySize = 4096, CancellationToken cancellationToken = default);
}

public record KeyPair(string PublicKey, string PrivateKey);