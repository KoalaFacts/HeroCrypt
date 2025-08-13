namespace HeroCrypt.Abstractions;

public interface ICryptographyService
{
    Task<byte[]> EncryptAsync(byte[] data, string publicKey, CancellationToken cancellationToken = default);
    Task<byte[]> DecryptAsync(byte[] encryptedData, string privateKey, CancellationToken cancellationToken = default);
    Task<string> EncryptTextAsync(string plainText, string publicKey, CancellationToken cancellationToken = default);
    Task<string> DecryptTextAsync(string encryptedText, string privateKey, CancellationToken cancellationToken = default);
}