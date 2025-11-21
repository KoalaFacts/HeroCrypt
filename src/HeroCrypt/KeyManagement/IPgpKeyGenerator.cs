namespace HeroCrypt.KeyManagement;

/// <summary>
/// Interface for cryptographic key generation operations
/// </summary>
public interface IPgpKeyGenerator
{
    /// <summary>
    /// Generates a new cryptographic key pair
    /// </summary>
    /// <param name="keySize">Size of the key in bits (default: 4096)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Generated key pair containing public and private keys</returns>
    Task<KeyPair> GenerateKeyPairAsync(int keySize = 4096, CancellationToken cancellationToken = default);
    /// <summary>
    /// Generates a new cryptographic key pair with identity and passphrase protection
    /// </summary>
    /// <param name="identity">Identity information for the key pair</param>
    /// <param name="passphrase">Passphrase to protect the private key</param>
    /// <param name="keySize">Size of the key in bits (default: 4096)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Generated key pair containing public and private keys</returns>
    Task<KeyPair> GenerateKeyPairAsync(string identity, string passphrase, int keySize = 4096, CancellationToken cancellationToken = default);
}

/// <summary>
/// Represents a cryptographic key pair containing both public and private keys
/// </summary>
/// <remarks>
/// Initializes a new instance of the KeyPair class
/// </remarks>
/// <param name="publicKey">The public key</param>
/// <param name="privateKey">The private key</param>
public class KeyPair(string publicKey, string privateKey)
{


    /// <summary>
    /// Gets the public key
    /// </summary>
    public string PublicKey { get; } = publicKey;
    /// <summary>
    /// Gets the private key
    /// </summary>
    public string PrivateKey { get; } = privateKey;
}
