namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for cryptographic operations including encryption and decryption
/// </summary>
public interface ICryptographyService
{
    /// <summary>
    /// Encrypts data using the specified public key
    /// </summary>
    /// <param name="data">Data to encrypt</param>
    /// <param name="publicKey">Public key for encryption</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted data</returns>
    Task<byte[]> EncryptAsync(byte[] data, string publicKey, CancellationToken cancellationToken = default);
    /// <summary>
    /// Decrypts data using the specified private key
    /// </summary>
    /// <param name="encryptedData">Encrypted data to decrypt</param>
    /// <param name="privateKey">Private key for decryption</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted data</returns>
    Task<byte[]> DecryptAsync(byte[] encryptedData, string privateKey, CancellationToken cancellationToken = default);
    /// <summary>
    /// Decrypts data using the specified private key with passphrase
    /// </summary>
    /// <param name="encryptedData">Encrypted data to decrypt</param>
    /// <param name="privateKey">Private key for decryption</param>
    /// <param name="passphrase">Passphrase for the private key</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted data</returns>
    Task<byte[]> DecryptAsync(byte[] encryptedData, string privateKey, string? passphrase, CancellationToken cancellationToken = default);
    /// <summary>
    /// Encrypts text using the specified public key
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="publicKey">Public key for encryption</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted text as base64 string</returns>
    Task<string> EncryptTextAsync(string plainText, string publicKey, CancellationToken cancellationToken = default);
    /// <summary>
    /// Decrypts text using the specified private key
    /// </summary>
    /// <param name="encryptedText">Encrypted text to decrypt</param>
    /// <param name="privateKey">Private key for decryption</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted plain text</returns>
    Task<string> DecryptTextAsync(string encryptedText, string privateKey, CancellationToken cancellationToken = default);
    /// <summary>
    /// Decrypts text using the specified private key with passphrase
    /// </summary>
    /// <param name="encryptedText">Encrypted text to decrypt</param>
    /// <param name="privateKey">Private key for decryption</param>
    /// <param name="passphrase">Passphrase for the private key</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted plain text</returns>
    Task<string> DecryptTextAsync(string encryptedText, string privateKey, string? passphrase, CancellationToken cancellationToken = default);
}
