namespace HeroCrypt.Hashing;

/// <summary>
/// Interface for Blake2b hashing operations.
/// Implements RFC 7693 specification for Blake2b cryptographic hash function.
/// </summary>
public interface IBlake2bService
{
    /// <summary>
    /// Computes a Blake2b hash of the specified data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="outputLength">The desired output length in bytes (1-64).</param>
    /// <param name="key">Optional key for keyed hashing (0-64 bytes).</param>
    /// <param name="salt">Optional salt value (16 bytes).</param>
    /// <param name="personalization">Optional personalization value (16 bytes).</param>
    /// <returns>The computed hash.</returns>
    byte[] ComputeHash(
        byte[] data,
        int outputLength = 64,
        byte[]? key = null,
        byte[]? salt = null,
        byte[]? personalization = null);

    /// <summary>
    /// Computes a Blake2b hash of the specified data asynchronously.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="outputLength">The desired output length in bytes (1-64).</param>
    /// <param name="key">Optional key for keyed hashing (0-64 bytes).</param>
    /// <param name="salt">Optional salt value (16 bytes).</param>
    /// <param name="personalization">Optional personalization value (16 bytes).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The computed hash.</returns>
    Task<byte[]> ComputeHashAsync(
        byte[] data,
        int outputLength = 64,
        byte[]? key = null,
        byte[]? salt = null,
        byte[]? personalization = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Computes a variable-length Blake2b hash (H' function as per Argon2 spec).
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="outputLength">The desired output length in bytes (can be > 64).</param>
    /// <returns>The computed hash of the specified length.</returns>
    byte[] ComputeLongHash(byte[] data, int outputLength);

    /// <summary>
    /// Verifies that a hash matches the expected value using constant-time comparison.
    /// </summary>
    /// <param name="data">The data to verify.</param>
    /// <param name="expectedHash">The expected hash value.</param>
    /// <param name="key">Optional key if the hash was keyed.</param>
    /// <returns>True if the hash matches; otherwise, false.</returns>
    bool VerifyHash(byte[] data, byte[] expectedHash, byte[]? key = null);
}
