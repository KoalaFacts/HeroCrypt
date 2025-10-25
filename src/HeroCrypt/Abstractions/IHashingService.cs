namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for cryptographic hashing operations
/// </summary>
public interface IHashingService
{
    /// <summary>
    /// Computes the hash of the input string
    /// </summary>
    /// <param name="input">String to hash</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Hash value as string</returns>
    Task<string> HashAsync(string input, CancellationToken cancellationToken = default);
    /// <summary>
    /// Computes the hash of the input byte array
    /// </summary>
    /// <param name="input">Byte array to hash</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Hash value as string</returns>
    Task<string> HashAsync(byte[] input, CancellationToken cancellationToken = default);
    /// <summary>
    /// Verifies that a string input matches the provided hash
    /// </summary>
    /// <param name="input">Input string to verify</param>
    /// <param name="hash">Hash to verify against</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if the input matches the hash, false otherwise</returns>
    Task<bool> VerifyAsync(string input, string hash, CancellationToken cancellationToken = default);
    /// <summary>
    /// Verifies that a byte array input matches the provided hash
    /// </summary>
    /// <param name="input">Input byte array to verify</param>
    /// <param name="hash">Hash to verify against</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if the input matches the hash, false otherwise</returns>
    Task<bool> VerifyAsync(byte[] input, string hash, CancellationToken cancellationToken = default);
}