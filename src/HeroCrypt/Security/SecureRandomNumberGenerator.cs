using System;
using System.Security.Cryptography;
using System.Threading;
using HeroCrypt.Abstractions;
using Microsoft.Extensions.Logging;

namespace HeroCrypt.Security;

/// <summary>
/// Enhanced secure random number generator with entropy pooling and health monitoring
/// </summary>
public sealed class SecureRandomNumberGenerator : IDisposable
{
    private readonly ILogger<SecureRandomNumberGenerator>? _logger;
    private readonly RandomNumberGenerator _primaryRng;
    private readonly RandomNumberGenerator _secondaryRng;
    private readonly Timer _healthCheckTimer;
    private volatile bool _disposed;
    private volatile bool _healthCheckPassed = true;

    // Entropy pool for additional randomness
    private readonly byte[] _entropyPool = new byte[4096];
    private readonly object _entropyLock = new object();
    private int _entropyIndex;
    private long _bytesGenerated;
    private DateTime _lastHealthCheck = DateTime.UtcNow;

    /// <summary>
    /// Initializes a new instance of the secure random number generator
    /// </summary>
    /// <param name="logger">Optional logger instance</param>
    public SecureRandomNumberGenerator(ILogger<SecureRandomNumberGenerator>? logger = null)
    {
        _logger = logger;
        _primaryRng = RandomNumberGenerator.Create();
        _secondaryRng = RandomNumberGenerator.Create();

        // Initialize entropy pool
        InitializeEntropyPool();

        // Set up health check timer (every 5 minutes)
        _healthCheckTimer = new Timer(PerformHealthCheck, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

        _logger?.LogDebug("Secure random number generator initialized with health monitoring");
    }

    /// <summary>
    /// Gets statistics about the random number generator
    /// </summary>
    public RandomNumberGeneratorStats Statistics => new RandomNumberGeneratorStats(
        _bytesGenerated,
        _healthCheckPassed,
        _lastHealthCheck,
        (_entropyIndex / (double)_entropyPool.Length) * 100
    );

    /// <summary>
    /// Generates cryptographically secure random bytes
    /// </summary>
    /// <param name="buffer">Buffer to fill with random bytes</param>
    public void GetBytes(byte[] buffer)
    {
        ThrowIfDisposed();
        InputValidator.ValidateByteArray(buffer, nameof(buffer), allowEmpty: true);

        if (buffer.Length == 0) return;

        if (!_healthCheckPassed)
        {
            _logger?.LogWarning("Random number generator health check failed, performing immediate re-check");
            PerformImmediateHealthCheck();

            if (!_healthCheckPassed)
                throw new CryptographicException("Random number generator failed health check");
        }

        try
        {
            // Use primary RNG
            _primaryRng.GetBytes(buffer);

            // XOR with entropy pool for additional security
            XorWithEntropyPool(buffer);

            // Update statistics
            Interlocked.Add(ref _bytesGenerated, buffer.Length);

            _logger?.LogDebug("Generated {ByteCount} random bytes", buffer.Length);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate random bytes");
            throw;
        }
    }

    /// <summary>
    /// Generates cryptographically secure random bytes
    /// </summary>
    /// <param name="span">Span to fill with random bytes</param>
    public void GetBytes(Span<byte> span)
    {
        ThrowIfDisposed();

        if (span.Length == 0) return;

        if (!_healthCheckPassed)
        {
            _logger?.LogWarning("Random number generator health check failed, performing immediate re-check");
            PerformImmediateHealthCheck();

            if (!_healthCheckPassed)
                throw new CryptographicException("Random number generator failed health check");
        }

        try
        {
#if NET6_0_OR_GREATER
            // Use primary RNG
            _primaryRng.GetBytes(span);
#else
            // For older frameworks, convert to array
            var buffer = new byte[span.Length];
            _primaryRng.GetBytes(buffer);
            buffer.CopyTo(span);
#endif

            // XOR with entropy pool for additional security
            XorWithEntropyPool(span);

            // Update statistics
            Interlocked.Add(ref _bytesGenerated, span.Length);

            _logger?.LogDebug("Generated {ByteCount} random bytes", span.Length);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate random bytes");
            throw;
        }
    }

    /// <summary>
    /// Generates a single random integer
    /// </summary>
    /// <returns>Random integer</returns>
    public int GetInt32()
    {
#if NET6_0_OR_GREATER
        Span<byte> buffer = stackalloc byte[4];
        GetBytes(buffer);
        return BitConverter.ToInt32(buffer);
#else
        var buffer = new byte[4];
        GetBytes(buffer);
        return BitConverter.ToInt32(buffer, 0);
#endif
    }

    /// <summary>
    /// Generates a random integer within a specified range
    /// </summary>
    /// <param name="minValue">Minimum value (inclusive)</param>
    /// <param name="maxValue">Maximum value (exclusive)</param>
    /// <returns>Random integer in the specified range</returns>
    public int GetInt32(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue must be less than maxValue");

        var range = (uint)(maxValue - minValue);
        if (range == 0) return minValue;

        // Use rejection sampling to avoid modulo bias
        var mask = uint.MaxValue - (uint.MaxValue % range);
        uint randomValue;

        do
        {
#if NET6_0_OR_GREATER
            Span<byte> buffer = stackalloc byte[4];
            GetBytes(buffer);
            randomValue = BitConverter.ToUInt32(buffer);
#else
            var buffer = new byte[4];
            GetBytes(buffer);
            randomValue = BitConverter.ToUInt32(buffer, 0);
#endif
        } while (randomValue >= mask);

        return (int)(randomValue % range) + minValue;
    }

    /// <summary>
    /// Adds entropy to the pool from external sources
    /// </summary>
    /// <param name="entropy">Entropy data to add</param>
    public void AddEntropy(byte[] entropy)
    {
        ThrowIfDisposed();
        InputValidator.ValidateByteArray(entropy, nameof(entropy));

        lock (_entropyLock)
        {
            for (var i = 0; i < entropy.Length; i++)
            {
                _entropyPool[_entropyIndex] ^= entropy[i];
                _entropyIndex = (_entropyIndex + 1) % _entropyPool.Length;
            }
        }

        _logger?.LogDebug("Added {EntropyBytes} bytes of entropy to pool", entropy.Length);
    }

    /// <summary>
    /// Performs immediate health check of the random number generator
    /// </summary>
    public void PerformImmediateHealthCheck()
    {
        PerformHealthCheck(null);
    }

    private void InitializeEntropyPool()
    {
        // Initialize entropy pool with system randomness
        _primaryRng.GetBytes(_entropyPool);

        // Add additional entropy sources
        var additionalEntropy = new byte[256];

        // System time entropy
        var timeBytes = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
        timeBytes.CopyTo(additionalEntropy, 0);

        // Process ID entropy
#if NET5_0_OR_GREATER
        var processBytes = BitConverter.GetBytes(Environment.ProcessId);
        processBytes.CopyTo(additionalEntropy, 8);
#else
        var processBytes = BitConverter.GetBytes(System.Diagnostics.Process.GetCurrentProcess().Id);
        processBytes.CopyTo(additionalEntropy, 8);
#endif

        // Thread ID entropy
        var threadBytes = BitConverter.GetBytes(Thread.CurrentThread.ManagedThreadId);
        threadBytes.CopyTo(additionalEntropy, 12);

        // High-resolution timer entropy
#if NET5_0_OR_GREATER
        var perfCounterBytes = BitConverter.GetBytes(Environment.TickCount64);
#else
        var perfCounterBytes = BitConverter.GetBytes((long)Environment.TickCount);
#endif
        perfCounterBytes.CopyTo(additionalEntropy, 16);

        // GC collection count entropy
        var gcBytes = BitConverter.GetBytes(GC.CollectionCount(0) + GC.CollectionCount(1) + GC.CollectionCount(2));
        gcBytes.CopyTo(additionalEntropy, 24);

        // Add to entropy pool
        for (var i = 0; i < additionalEntropy.Length; i++)
        {
            _entropyPool[i % _entropyPool.Length] ^= additionalEntropy[i];
        }

        _logger?.LogDebug("Entropy pool initialized with {PoolSize} bytes", _entropyPool.Length);
    }

    private void XorWithEntropyPool(Span<byte> buffer)
    {
        lock (_entropyLock)
        {
            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] ^= _entropyPool[_entropyIndex];
                _entropyIndex = (_entropyIndex + 1) % _entropyPool.Length;
            }
        }
    }

    private void PerformHealthCheck(object? state)
    {
        if (_disposed) return;

        try
        {
            _logger?.LogDebug("Performing random number generator health check");

            // Generate test data
            var testData1 = new byte[1024];
            var testData2 = new byte[1024];

            _primaryRng.GetBytes(testData1);
            _secondaryRng.GetBytes(testData2);

            // Basic health checks
            var passed = true;

            // Check for all-zero output (catastrophic failure)
            if (IsAllSame(testData1, 0) || IsAllSame(testData2, 0))
            {
                _logger?.LogError("Health check failed: RNG producing all-zero output");
                passed = false;
            }

            // Check for all-same output
            if (IsAllSame(testData1, testData1[0]) || IsAllSame(testData2, testData2[0]))
            {
                _logger?.LogError("Health check failed: RNG producing identical bytes");
                passed = false;
            }

            // Check for identical outputs between generators
            if (SecureMemoryOperations.ConstantTimeEquals(testData1, testData2))
            {
                _logger?.LogError("Health check failed: Primary and secondary RNGs producing identical output");
                passed = false;
            }

            // Simple entropy check - count unique bytes
            var uniqueBytes1 = CountUniqueBytes(testData1);
            var uniqueBytes2 = CountUniqueBytes(testData2);

            if (uniqueBytes1 < 128 || uniqueBytes2 < 128) // Expect at least 50% unique bytes
            {
                _logger?.LogWarning("Health check warning: Low entropy detected (unique bytes: {Unique1}, {Unique2})",
                    uniqueBytes1, uniqueBytes2);
            }

            _healthCheckPassed = passed;
            _lastHealthCheck = DateTime.UtcNow;

            if (passed)
            {
                _logger?.LogDebug("Random number generator health check passed");
            }
            else
            {
                _logger?.LogError("Random number generator health check failed");
            }

            // Clear test data
            SecureMemoryOperations.SecureClear(testData1);
            SecureMemoryOperations.SecureClear(testData2);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error during random number generator health check");
            _healthCheckPassed = false;
        }
    }

    private static bool IsAllSame(byte[] data, byte value)
    {
        foreach (var b in data)
        {
            if (b != value) return false;
        }
        return true;
    }

    private static int CountUniqueBytes(byte[] data)
    {
        var seen = new bool[256];
        var count = 0;

        foreach (var b in data)
        {
            if (!seen[b])
            {
                seen[b] = true;
                count++;
            }
        }

        return count;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(SecureRandomNumberGenerator));
    }

    /// <summary>
    /// Disposes the secure random number generator
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;

            _healthCheckTimer?.Dispose();
            _primaryRng?.Dispose();
            _secondaryRng?.Dispose();

            // Clear entropy pool
            lock (_entropyLock)
            {
                SecureMemoryOperations.SecureClear(_entropyPool);
            }

            _logger?.LogDebug("Secure random number generator disposed");
        }
    }
}

/// <summary>
/// Statistics about the random number generator
/// </summary>
public readonly struct RandomNumberGeneratorStats
{
    /// <summary>
    /// Total bytes generated since initialization
    /// </summary>
    public long BytesGenerated { get; }

    /// <summary>
    /// Whether the last health check passed
    /// </summary>
    public bool HealthCheckPassed { get; }

    /// <summary>
    /// Timestamp of the last health check
    /// </summary>
    public DateTime LastHealthCheck { get; }

    /// <summary>
    /// Entropy pool utilization percentage
    /// </summary>
    public double EntropyPoolUtilization { get; }

    /// <summary>
    /// Initializes a new instance of RandomNumberGeneratorStats
    /// </summary>
    public RandomNumberGeneratorStats(long bytesGenerated, bool healthCheckPassed, DateTime lastHealthCheck, double entropyPoolUtilization)
    {
        BytesGenerated = bytesGenerated;
        HealthCheckPassed = healthCheckPassed;
        LastHealthCheck = lastHealthCheck;
        EntropyPoolUtilization = entropyPoolUtilization;
    }
}