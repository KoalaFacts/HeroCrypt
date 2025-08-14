using HeroCrypt.Memory;

namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for secure memory management operations
/// </summary>
public interface ISecureMemoryManager
{
    /// <summary>
    /// Allocates a secure buffer of the specified size
    /// </summary>
    /// <param name="size">Size in bytes</param>
    /// <returns>Secure buffer</returns>
    SecureBuffer Allocate(int size);

    /// <summary>
    /// Allocates a secure buffer and copies data from the source array
    /// </summary>
    /// <param name="source">Source data to copy</param>
    /// <returns>Secure buffer with copied data</returns>
    SecureBuffer AllocateFrom(byte[] source);

    /// <summary>
    /// Allocates a secure buffer and copies data from the source span
    /// </summary>
    /// <param name="source">Source data to copy</param>
    /// <returns>Secure buffer with copied data</returns>
    SecureBuffer AllocateFrom(ReadOnlySpan<byte> source);

    /// <summary>
    /// Creates a pooled secure buffer for temporary operations
    /// </summary>
    /// <param name="size">Size in bytes</param>
    /// <returns>Pooled secure buffer</returns>
    IPooledSecureBuffer GetPooled(int size);

    /// <summary>
    /// Gets memory usage statistics
    /// </summary>
    /// <returns>Memory usage information</returns>
    MemoryUsageInfo GetMemoryUsage();

    /// <summary>
    /// Forces cleanup of any unreferenced secure memory
    /// </summary>
    void ForceCleanup();
}

/// <summary>
/// Pooled secure buffer that automatically returns to pool on disposal
/// </summary>
public interface IPooledSecureBuffer : IDisposable
{
    /// <summary>
    /// Gets a span view of the secure buffer
    /// </summary>
    /// <returns>Span of the buffer contents</returns>
    Span<byte> AsSpan();

    /// <summary>
    /// Gets a read-only span view of the secure buffer
    /// </summary>
    /// <returns>Read-only span of the buffer contents</returns>
    ReadOnlySpan<byte> AsReadOnlySpan();

    /// <summary>
    /// Size of the buffer in bytes
    /// </summary>
    int Size { get; }

    /// <summary>
    /// Clears the buffer contents (fills with zeros)
    /// </summary>
    void Clear();
}

/// <summary>
/// Memory usage information
/// </summary>
public class MemoryUsageInfo
{
    /// <summary>
    /// Total secure memory allocated in bytes
    /// </summary>
    public long TotalAllocatedBytes { get; set; }

    /// <summary>
    /// Number of active secure buffers
    /// </summary>
    public int ActiveBufferCount { get; set; }

    /// <summary>
    /// Number of buffers in the pool
    /// </summary>
    public int PooledBufferCount { get; set; }

    /// <summary>
    /// Peak memory usage in bytes
    /// </summary>
    public long PeakMemoryUsage { get; set; }

    /// <summary>
    /// Memory efficiency ratio (0-1, higher is better)
    /// </summary>
    public double EfficiencyRatio { get; set; }
}