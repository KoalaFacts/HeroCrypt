using HeroCrypt.Cryptography.Argon2;

namespace HeroCrypt.Abstractions;

/// <summary>
/// Fluent builder interface for Argon2 hashing operations
/// </summary>
public interface IArgon2FluentBuilder
{
    /// <summary>
    /// Sets the password to hash
    /// </summary>
    /// <param name="password">The password string</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithPassword(string password);

    /// <summary>
    /// Sets the password to hash from byte array
    /// </summary>
    /// <param name="password">The password bytes</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithPassword(byte[] password);

    /// <summary>
    /// Sets a custom salt
    /// </summary>
    /// <param name="salt">The salt string</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithSalt(string salt);

    /// <summary>
    /// Sets a custom salt from byte array
    /// </summary>
    /// <param name="salt">The salt bytes</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithSalt(byte[] salt);

    /// <summary>
    /// Sets the memory usage in KB
    /// </summary>
    /// <param name="memoryKb">Memory usage in kilobytes</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithMemory(int memoryKb);

    /// <summary>
    /// Sets the memory usage using fluent size extensions
    /// </summary>
    /// <param name="memorySize">Memory size (e.g., 64.MB(), 1.GB())</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithMemory(MemorySize memorySize);

    /// <summary>
    /// Sets the number of iterations
    /// </summary>
    /// <param name="iterations">Number of iterations</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithIterations(int iterations);

    /// <summary>
    /// Sets the parallelism level
    /// </summary>
    /// <param name="parallelism">Parallelism level</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithParallelism(int parallelism);

    /// <summary>
    /// Sets the output hash size
    /// </summary>
    /// <param name="hashSize">Hash size in bytes</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithHashSize(int hashSize);

    /// <summary>
    /// Sets the Argon2 variant
    /// </summary>
    /// <param name="type">Argon2 type</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithType(Argon2Type type);

    /// <summary>
    /// Sets associated data
    /// </summary>
    /// <param name="associatedData">Associated data</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithAssociatedData(byte[] associatedData);

    /// <summary>
    /// Sets secret key
    /// </summary>
    /// <param name="secret">Secret key</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithSecret(byte[] secret);

    /// <summary>
    /// Uses a predefined security level configuration
    /// </summary>
    /// <param name="securityLevel">Security level</param>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithSecurityLevel(Configuration.SecurityLevel securityLevel);

    /// <summary>
    /// Enables hardware acceleration if available
    /// </summary>
    /// <returns>Builder for method chaining</returns>
    IArgon2FluentBuilder WithHardwareAcceleration();

    /// <summary>
    /// Computes the hash asynchronously
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The computed hash as base64 string</returns>
    Task<string> HashAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Computes the hash and returns raw bytes
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The computed hash as byte array</returns>
    Task<byte[]> HashBytesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a password against a hash
    /// </summary>
    /// <param name="hash">The hash to verify against</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if password matches the hash</returns>
    Task<bool> VerifyAsync(string hash, CancellationToken cancellationToken = default);
}

/// <summary>
/// Memory size helper for fluent API
/// </summary>
public readonly struct MemorySize
{
    public int ValueInKb { get; }

    public MemorySize(int valueInKb)
    {
        ValueInKb = valueInKb;
    }

    public static implicit operator int(MemorySize size) => size.ValueInKb;
}

/// <summary>
/// Extension methods for creating memory sizes
/// </summary>
public static class MemorySizeExtensions
{
    /// <summary>
    /// Creates a memory size in kilobytes
    /// </summary>
    public static MemorySize KB(this int value) => new(value);

    /// <summary>
    /// Creates a memory size in megabytes
    /// </summary>
    public static MemorySize MB(this int value) => new(value * 1024);

    /// <summary>
    /// Creates a memory size in gigabytes
    /// </summary>
    public static MemorySize GB(this int value) => new(value * 1024 * 1024);
}