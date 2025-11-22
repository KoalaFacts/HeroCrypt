using System.Security.Cryptography;

#if NET9_0_OR_GREATER
using Lock = System.Threading.Lock;
using LockScope = System.Threading.Lock.Scope;
#endif

namespace HeroCrypt.Security;

/// <summary>
/// Enhanced secure random number generator with entropy pooling and health monitoring
/// </summary>
public sealed class SecureRandomNumberGenerator : IDisposable
{
    private readonly RandomNumberGenerator primaryRng;
    private readonly RandomNumberGenerator secondaryRng;
    private readonly Timer healthCheckTimer;
    private volatile bool disposed;
    private volatile bool healthCheckPassed = true;

    // Entropy pool for additional randomness
    private readonly byte[] entropyPool = new byte[4096];
#if NET9_0_OR_GREATER
    private readonly Lock entropyLock = new();
#else
    private readonly object entropyLock = new();
#endif
    private int entropyIndex;
    private long bytesGenerated;
    private DateTime lastHealthCheck = DateTime.UtcNow;

#if NET9_0_OR_GREATER
    private LockScope EnterEntropyLock() => entropyLock.EnterScope();
#else
    private LockReleaser EnterEntropyLock() => new(entropyLock);
#endif

    /// <summary>
    /// Initializes a new instance of the secure random number generator
    /// </summary>
    public SecureRandomNumberGenerator()
    {
        primaryRng = RandomNumberGenerator.Create();
        secondaryRng = RandomNumberGenerator.Create();

        // Initialize entropy pool
        InitializeEntropyPool();

        // Set up health check timer (every 5 minutes)
        healthCheckTimer = new Timer(PerformHealthCheck, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// Gets statistics about the random number generator
    /// </summary>
    public RandomNumberGeneratorStats Statistics => new(
        bytesGenerated,
        healthCheckPassed,
        lastHealthCheck,
        (entropyIndex / (double)entropyPool.Length) * 100
    );

    /// <summary>
    /// Generates cryptographically secure random bytes
    /// </summary>
    /// <param name="buffer">Buffer to fill with random bytes</param>
    public void GetBytes(byte[] buffer)
    {
        ThrowIfDisposed();
        InputValidator.ValidateByteArray(buffer, nameof(buffer), allowEmpty: true);

        if (buffer.Length == 0)
        {
            return;
        }

        if (!healthCheckPassed)
        {
            PerformImmediateHealthCheck();

            if (!healthCheckPassed)
            {
                throw new CryptographicException("Random number generator failed health check");
            }
        }

        try
        {
            // Use primary RNG
            primaryRng.GetBytes(buffer);

            // XOR with entropy pool for additional security
            XorWithEntropyPool(buffer);

            // Update statistics
            Interlocked.Add(ref bytesGenerated, buffer.Length);
        }
        catch
        {
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

        if (span.Length == 0)
        {
            return;
        }

        if (!healthCheckPassed)
        {

            PerformImmediateHealthCheck();

            if (!healthCheckPassed)
            {
                throw new CryptographicException("Random number generator failed health check");
            }
        }

        try
        {
#if !NETSTANDARD2_0
            // Use primary RNG
            primaryRng.GetBytes(span);

            // XOR with entropy pool for additional security
            XorWithEntropyPool(span);

            // Update statistics
            Interlocked.Add(ref bytesGenerated, span.Length);
#else
            // .NET Standard 2.0: Convert span to array
            var buffer = span.ToArray();
            primaryRng.GetBytes(buffer);

            // XOR with entropy pool for additional security
            XorWithEntropyPool(buffer);
            buffer.CopyTo(span);

            // Update statistics
            Interlocked.Add(ref bytesGenerated, span.Length);
#endif

        }
        catch
        {

            throw;
        }
    }

    /// <summary>
    /// Generates a single random integer
    /// </summary>
    /// <returns>Random integer</returns>
    public int GetInt32()
    {
        Span<byte> buffer = stackalloc byte[4];
        GetBytes(buffer);
#if !NETSTANDARD2_0
        return BitConverter.ToInt32(buffer);
#else
        var array = buffer.ToArray();
        return BitConverter.ToInt32(array, 0);
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
        {
            throw new ArgumentException("minValue must be less than maxValue");
        }

        var range = (uint)(maxValue - minValue);
        if (range == 0)
        {
            return minValue;
        }

        // Use rejection sampling to avoid modulo bias
        var mask = uint.MaxValue - (uint.MaxValue % range);
        uint randomValue;
        Span<byte> buffer = stackalloc byte[4];

        do
        {
            GetBytes(buffer);
#if !NETSTANDARD2_0
            randomValue = BitConverter.ToUInt32(buffer);
#else
            var array = buffer.ToArray();
            randomValue = BitConverter.ToUInt32(array, 0);
#endif
        }
        while (randomValue >= mask);

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

        using var guard = EnterEntropyLock();
        for (var i = 0; i < entropy.Length; i++)
        {
            entropyPool[entropyIndex] ^= entropy[i];
            entropyIndex = (entropyIndex + 1) % entropyPool.Length;
        }
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
        primaryRng.GetBytes(entropyPool);

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
        var threadBytes = BitConverter.GetBytes(Environment.CurrentManagedThreadId);
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
            entropyPool[i % entropyPool.Length] ^= additionalEntropy[i];
        }


    }

    private void XorWithEntropyPool(Span<byte> buffer)
    {
        using var guard = EnterEntropyLock();
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] ^= entropyPool[entropyIndex];
            entropyIndex = (entropyIndex + 1) % entropyPool.Length;
        }
    }

#if NETSTANDARD2_0
    private void XorWithEntropyPool(byte[] buffer)
    {
        using var guard = EnterEntropyLock();
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] ^= entropyPool[entropyIndex];
            entropyIndex = (entropyIndex + 1) % entropyPool.Length;
        }
    }
#endif

    private void PerformHealthCheck(object? state)
    {
        if (disposed)
        {
            return;
        }

        try
        {
            // Generate test data
            var testData1 = new byte[1024];
            var testData2 = new byte[1024];

            primaryRng.GetBytes(testData1);
            secondaryRng.GetBytes(testData2);

            // Basic health checks
            var passed = true;

            // Check for all-zero output (catastrophic failure)
            if (IsAllSame(testData1, 0) || IsAllSame(testData2, 0))
            {
                passed = false;
            }

            // Check for all-same output
            if (IsAllSame(testData1, testData1[0]) || IsAllSame(testData2, testData2[0]))
            {
                passed = false;
            }

            // Check for identical outputs between generators
            if (SecureMemoryOperations.ConstantTimeEquals(testData1, testData2))
            {
                passed = false;
            }

            // Simple entropy check - count unique bytes
            var uniqueBytes1 = CountUniqueBytes(testData1);
            var uniqueBytes2 = CountUniqueBytes(testData2);

            if (uniqueBytes1 < 128 || uniqueBytes2 < 128) // Expect at least 50% unique bytes
            {
                passed = false;
            }

            healthCheckPassed = passed;
            lastHealthCheck = DateTime.UtcNow;

            // Clear test data
            SecureMemoryOperations.SecureClear(testData1);
            SecureMemoryOperations.SecureClear(testData2);
        }
        catch (CryptographicException)
        {
            healthCheckPassed = false;
        }
    }

    private static bool IsAllSame(byte[] data, byte value)
    {
        foreach (var b in data)
        {
            if (b != value)
            {
                return false;
            }
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
#if !NETSTANDARD2_0
        ObjectDisposedException.ThrowIf(disposed, nameof(SecureRandomNumberGenerator));
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(SecureRandomNumberGenerator));
        }
#endif
    }

    /// <summary>
    /// Disposes the secure random number generator
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;

            healthCheckTimer?.Dispose();
            primaryRng?.Dispose();
            secondaryRng?.Dispose();

            // Clear entropy pool
            using var guard = EnterEntropyLock();
            SecureMemoryOperations.SecureClear(entropyPool);


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
