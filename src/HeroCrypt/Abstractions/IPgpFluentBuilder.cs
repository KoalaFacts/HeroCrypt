using HeroCrypt.Configuration;

namespace HeroCrypt.Abstractions;

/// <summary>
/// Fluent builder interface for PGP encryption/decryption operations
/// </summary>
public interface IPgpFluentBuilder
{
    /// <summary>
    /// Sets the data to encrypt (string)
    /// </summary>
    /// <param name="data">The data to encrypt</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithData(string data);

    /// <summary>
    /// Sets the data to encrypt (byte array)
    /// </summary>
    /// <param name="data">The data to encrypt</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithData(byte[] data);

    /// <summary>
    /// Sets the encrypted data to decrypt (string)
    /// </summary>
    /// <param name="encryptedData">The encrypted data</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithEncryptedData(string encryptedData);

    /// <summary>
    /// Sets the encrypted data to decrypt (byte array)
    /// </summary>
    /// <param name="encryptedData">The encrypted data</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithEncryptedData(byte[] encryptedData);

    /// <summary>
    /// Sets the public key for encryption
    /// </summary>
    /// <param name="publicKey">The PGP public key</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithPublicKey(string publicKey);

    /// <summary>
    /// Sets the private key for decryption
    /// </summary>
    /// <param name="privateKey">The PGP private key</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithPrivateKey(string privateKey);

    /// <summary>
    /// Sets the identity for key generation
    /// </summary>
    /// <param name="identity">The identity (e.g., email address)</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithIdentity(string identity);

    /// <summary>
    /// Sets the passphrase for key generation/usage
    /// </summary>
    /// <param name="passphrase">The passphrase</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithPassphrase(string passphrase);

    /// <summary>
    /// Sets the RSA key size for key generation
    /// </summary>
    /// <param name="keySize">The key size in bits (e.g., 2048, 3072, 4096)</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithKeySize(int keySize);

    /// <summary>
    /// Uses a predefined security level for key generation
    /// </summary>
    /// <param name="securityLevel">The security level</param>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithSecurityLevel(SecurityLevel securityLevel);

    /// <summary>
    /// Enables hardware acceleration if available
    /// </summary>
    /// <returns>Builder for method chaining</returns>
    IPgpFluentBuilder WithHardwareAcceleration();

    /// <summary>
    /// Encrypts the data and returns as string
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted data as string</returns>
    Task<string> EncryptAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Encrypts the data and returns as byte array
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted data as byte array</returns>
    Task<byte[]> EncryptBytesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts the data and returns as string
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted data as string</returns>
    Task<string> DecryptAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts the data and returns as byte array
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted data as byte array</returns>
    Task<byte[]> DecryptBytesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a new PGP key pair
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Generated key pair</returns>
    Task<KeyPair> GenerateKeyPairAsync(CancellationToken cancellationToken = default);
}