namespace HeroCrypt.Abstractions;

public interface IHashingService
{
    Task<string> HashAsync(string input, CancellationToken cancellationToken = default);
    Task<string> HashAsync(byte[] input, CancellationToken cancellationToken = default);
    Task<bool> VerifyAsync(string input, string hash, CancellationToken cancellationToken = default);
    Task<bool> VerifyAsync(byte[] input, string hash, CancellationToken cancellationToken = default);
}