using HeroCrypt.Abstractions;
using System.Collections.Concurrent;

namespace HeroCrypt.Memory;

/// <summary>
/// Default implementation of secure memory manager with pooling
/// </summary>
public sealed class DefaultSecureMemoryManager : ISecureMemoryManager, IDisposable
{
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<int, ConcurrentQueue<SecureBuffer>> _bufferPools = new();
    private readonly ConcurrentDictionary<SecureBuffer, DateTime> _activeBuffers = new();

    // Memory tracking
    private long _totalAllocatedBytes;
    private long _peakMemoryUsage;
    private int _activeBufferCount;
    private bool _disposed;

    // Pool configuration
    private readonly int _maxPoolSize = 100;
    private readonly TimeSpan _bufferTimeout = TimeSpan.FromMinutes(5);
    private readonly int[] _commonSizes = { 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 };

    /// <summary>
    /// Allocates a new secure buffer of the specified size.
    /// </summary>
    /// <param name="size">The size in bytes of the buffer to allocate.</param>
    /// <returns>A new <see cref="SecureBuffer"/> instance.</returns>
    /// <exception cref="ArgumentException">Thrown when size is not positive.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public SecureBuffer Allocate(int size)
    {
        ThrowIfDisposed();

        if (size <= 0)
            throw new ArgumentException("Size must be positive", nameof(size));

        var buffer = new SecureBuffer(size);
        TrackBuffer(buffer, size);
        return buffer;
    }

    /// <summary>
    /// Allocates a new secure buffer and copies data from the source byte array.
    /// </summary>
    /// <param name="source">The source byte array to copy from.</param>
    /// <returns>A new <see cref="SecureBuffer"/> containing a copy of the source data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when source is null.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public SecureBuffer AllocateFrom(byte[] source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        ThrowIfDisposed();

        var buffer = new SecureBuffer(source);
        TrackBuffer(buffer, source.Length);
        return buffer;
    }

    /// <summary>
    /// Allocates a new secure buffer and copies data from the source span.
    /// </summary>
    /// <param name="source">The source span to copy from.</param>
    /// <returns>A new <see cref="SecureBuffer"/> containing a copy of the source data.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public SecureBuffer AllocateFrom(ReadOnlySpan<byte> source)
    {
        ThrowIfDisposed();

        var buffer = new SecureBuffer(source);
        TrackBuffer(buffer, source.Length);
        return buffer;
    }

    /// <summary>
    /// Gets a pooled secure buffer of at least the specified size. The buffer is automatically returned to the pool when disposed.
    /// </summary>
    /// <param name="size">The minimum size in bytes of the buffer to retrieve.</param>
    /// <returns>A pooled <see cref="IPooledSecureBuffer"/> instance.</returns>
    /// <exception cref="ArgumentException">Thrown when size is not positive.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public IPooledSecureBuffer GetPooled(int size)
    {
        ThrowIfDisposed();

        if (size <= 0)
            throw new ArgumentException("Size must be positive", nameof(size));

        // Try to get from pool first
        var poolSize = GetOptimalPoolSize(size);
        if (_bufferPools.TryGetValue(poolSize, out var pool) && pool.TryDequeue(out var pooledBuffer))
        {
            // Make sure the buffer is clean
            pooledBuffer.Clear();
            return new PooledSecureBufferWrapper(pooledBuffer, this);
        }

        // Create new buffer
        var buffer = new SecureBuffer(poolSize);
        TrackBuffer(buffer, poolSize);
        return new PooledSecureBufferWrapper(buffer, this);
    }

    /// <summary>
    /// Gets detailed information about current memory usage and buffer statistics.
    /// </summary>
    /// <returns>A <see cref="MemoryUsageInfo"/> instance containing usage statistics.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public MemoryUsageInfo GetMemoryUsage()
    {
        ThrowIfDisposed();

        lock (_lock)
        {
            var pooledCount = _bufferPools.Values.Sum(pool => pool.Count);
            var totalPooledBytes = _bufferPools.Sum(kvp => kvp.Key * kvp.Value.Count);

            return new MemoryUsageInfo
            {
                TotalAllocatedBytes = _totalAllocatedBytes,
                ActiveBufferCount = _activeBufferCount,
                PooledBufferCount = pooledCount,
                PeakMemoryUsage = _peakMemoryUsage,
                EfficiencyRatio = _totalAllocatedBytes > 0
                    ? (_totalAllocatedBytes - totalPooledBytes) / (double)_totalAllocatedBytes
                    : 1.0
            };
        }
    }

    /// <summary>
    /// Forces cleanup of timed-out buffers and excess pooled buffers, then triggers garbage collection.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public void ForceCleanup()
    {
        ThrowIfDisposed();

        lock (_lock)
        {
            // Clean up timed-out active buffers
            var timeoutThreshold = DateTime.UtcNow - _bufferTimeout;
            var timedOutBuffers = _activeBuffers
                .Where(kvp => kvp.Value < timeoutThreshold)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var buffer in timedOutBuffers)
            {
                if (_activeBuffers.TryRemove(buffer, out _))
                {
                    buffer.Dispose();
                    Interlocked.Decrement(ref _activeBufferCount);
                    Interlocked.Add(ref _totalAllocatedBytes, -buffer.Size);
                }
            }

            // Clean up excess pooled buffers
            foreach (var kvp in _bufferPools)
            {
                var size = kvp.Key;
                var pool = kvp.Value;
                while (pool.Count > _maxPoolSize && pool.TryDequeue(out var excessBuffer))
                {
                    excessBuffer.Dispose();
                }
            }

            // Force garbage collection
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }

    internal void ReturnToPool(SecureBuffer buffer)
    {
        if (_disposed || buffer.IsDisposed)
            return;

        var size = GetOptimalPoolSize(buffer.Size);
        var pool = _bufferPools.GetOrAdd(size, _ => new ConcurrentQueue<SecureBuffer>());

        if (pool.Count < _maxPoolSize)
        {
            buffer.Clear(); // Clear sensitive data
            pool.Enqueue(buffer);
        }
        else
        {
            // Pool is full, dispose the buffer
            buffer.Dispose();
        }

        // Remove from active tracking
        _activeBuffers.TryRemove(buffer, out _);
        Interlocked.Decrement(ref _activeBufferCount);
        Interlocked.Add(ref _totalAllocatedBytes, -buffer.Size);
    }

    private void TrackBuffer(SecureBuffer buffer, int size)
    {
        _activeBuffers.TryAdd(buffer, DateTime.UtcNow);
        Interlocked.Increment(ref _activeBufferCount);
        Interlocked.Add(ref _totalAllocatedBytes, size);

        // Update peak usage
        var currentTotal = _totalAllocatedBytes;
        if (currentTotal > _peakMemoryUsage)
        {
            Interlocked.Exchange(ref _peakMemoryUsage, currentTotal);
        }
    }

    private int GetOptimalPoolSize(int requestedSize)
    {
        // Find the smallest common size that fits the requested size
        foreach (var commonSize in _commonSizes)
        {
            if (commonSize >= requestedSize)
                return commonSize;
        }

        // For very large sizes, round up to nearest 1KB
        return ((requestedSize - 1) / 1024 + 1) * 1024;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(DefaultSecureMemoryManager));
    }

    /// <summary>
    /// Releases all resources used by the <see cref="DefaultSecureMemoryManager"/> and securely disposes all managed buffers.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            lock (_lock)
            {
                if (!_disposed)
                {
                    // Dispose all active buffers
                    foreach (var buffer in _activeBuffers.Keys)
                    {
                        buffer.Dispose();
                    }
                    _activeBuffers.Clear();

                    // Dispose all pooled buffers
                    foreach (var pool in _bufferPools.Values)
                    {
                        while (pool.TryDequeue(out var buffer))
                        {
                            buffer.Dispose();
                        }
                    }
                    _bufferPools.Clear();

                    _disposed = true;
                }
            }
        }
    }

    ~DefaultSecureMemoryManager()
    {
        Dispose();
    }
}

/// <summary>
/// Wrapper for pooled secure buffers that automatically returns to pool
/// </summary>
internal sealed class PooledSecureBufferWrapper : IPooledSecureBuffer
{
    private readonly SecureBuffer _buffer;
    private readonly DefaultSecureMemoryManager _manager;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="PooledSecureBufferWrapper"/> class.
    /// </summary>
    /// <param name="buffer">The secure buffer to wrap.</param>
    /// <param name="manager">The memory manager that owns the pool.</param>
    public PooledSecureBufferWrapper(SecureBuffer buffer, DefaultSecureMemoryManager manager)
    {
        _buffer = buffer;
        _manager = manager;
    }

    /// <summary>
    /// Returns a mutable span view of the buffer's contents.
    /// </summary>
    /// <returns>A <see cref="Span{T}"/> of bytes representing the buffer contents.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the wrapper has been disposed.</exception>
    public Span<byte> AsSpan()
    {
        ThrowIfDisposed();
        return _buffer.AsSpan();
    }

    /// <summary>
    /// Returns a read-only span view of the buffer's contents.
    /// </summary>
    /// <returns>A <see cref="ReadOnlySpan{T}"/> of bytes representing the buffer contents.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the wrapper has been disposed.</exception>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ThrowIfDisposed();
        return _buffer.AsReadOnlySpan();
    }

    /// <summary>
    /// Gets the size of the buffer in bytes.
    /// </summary>
    public int Size => _buffer.Size;

    /// <summary>
    /// Securely clears all data in the buffer by overwriting with zeros.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the wrapper has been disposed.</exception>
    public void Clear()
    {
        ThrowIfDisposed();
        _buffer.Clear();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PooledSecureBufferWrapper));
    }

    /// <summary>
    /// Returns the buffer to the pool for reuse. After disposal, the wrapper cannot be used.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _manager.ReturnToPool(_buffer);
            _disposed = true;
        }
    }
}