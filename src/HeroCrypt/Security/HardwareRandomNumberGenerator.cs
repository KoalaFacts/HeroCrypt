using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Hardware;
using Microsoft.Extensions.Logging;

namespace HeroCrypt.Security;

/// <summary>
/// Hardware-accelerated random number generator using Intel RDRAND/RDSEED instructions
/// Falls back to system RNG when hardware acceleration is not available
/// </summary>
public sealed class HardwareRandomNumberGenerator : IDisposable
{
    private readonly ILogger<HardwareRandomNumberGenerator>? _logger;
    private readonly RandomNumberGenerator _fallbackRng;
    private readonly bool _hardwareAvailable;
    private volatile bool _disposed;

    // Statistics
    private long _hardwareGeneratedBytes;
    private long _fallbackGeneratedBytes;
    private int _hardwareFailureCount;

    /// <summary>
    /// Initializes a new instance of the hardware random number generator
    /// </summary>
    /// <param name="logger">Optional logger instance</param>
    public HardwareRandomNumberGenerator(ILogger<HardwareRandomNumberGenerator>? logger = null)
    {
        _logger = logger;
        _fallbackRng = RandomNumberGenerator.Create();
        _hardwareAvailable = HardwareAccelerationDetector.IsRdrandAvailable;

        _logger?.LogInformation("Hardware RNG initialized. Hardware available: {HardwareAvailable}", _hardwareAvailable);
    }

    /// <summary>
    /// Gets statistics about hardware vs fallback usage
    /// </summary>
    public HardwareRngStatistics Statistics => new(
        _hardwareAvailable,
        _hardwareGeneratedBytes,
        _fallbackGeneratedBytes,
        _hardwareFailureCount,
        _hardwareGeneratedBytes + _fallbackGeneratedBytes > 0
            ? _hardwareGeneratedBytes / (double)(_hardwareGeneratedBytes + _fallbackGeneratedBytes)
            : 0.0
    );

    /// <summary>
    /// Generates cryptographically secure random bytes using hardware acceleration when available
    /// </summary>
    /// <param name="buffer">Buffer to fill with random bytes</param>
    public void GetBytes(byte[] buffer)
    {
        ThrowIfDisposed();

        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));

        if (buffer.Length == 0) return;

        if (_hardwareAvailable)
        {
            try
            {
                if (TryGetHardwareBytes(buffer))
                {
                    Interlocked.Add(ref _hardwareGeneratedBytes, buffer.Length);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Hardware RNG failed, falling back to system RNG");
                Interlocked.Increment(ref _hardwareFailureCount);
            }
        }

        // Fallback to system RNG
        _fallbackRng.GetBytes(buffer);
        Interlocked.Add(ref _fallbackGeneratedBytes, buffer.Length);
    }

    /// <summary>
    /// Generates cryptographically secure random bytes using hardware acceleration when available
    /// </summary>
    /// <param name="span">Span to fill with random bytes</param>
    public void GetBytes(Span<byte> span)
    {
        ThrowIfDisposed();

        if (span.Length == 0) return;

        if (_hardwareAvailable)
        {
            try
            {
                if (TryGetHardwareBytes(span))
                {
                    Interlocked.Add(ref _hardwareGeneratedBytes, span.Length);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Hardware RNG failed, falling back to system RNG");
                Interlocked.Increment(ref _hardwareFailureCount);
            }
        }

        // Fallback to system RNG
#if NET6_0_OR_GREATER
        _fallbackRng.GetBytes(span);
#else
        var buffer = new byte[span.Length];
        _fallbackRng.GetBytes(buffer);
        buffer.CopyTo(span);
#endif
        Interlocked.Add(ref _fallbackGeneratedBytes, span.Length);
    }

    /// <summary>
    /// Generates a single random 32-bit unsigned integer
    /// </summary>
    /// <returns>Random 32-bit unsigned integer</returns>
    public uint GetUInt32()
    {
        ThrowIfDisposed();

        if (_hardwareAvailable)
        {
            try
            {
                if (TryGetHardwareUInt32(out var value))
                {
                    Interlocked.Add(ref _hardwareGeneratedBytes, 4);
                    return value;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Hardware RNG failed for UInt32, falling back to system RNG");
                Interlocked.Increment(ref _hardwareFailureCount);
            }
        }

        // Fallback to system RNG
        Span<byte> buffer = stackalloc byte[4];
#if NET6_0_OR_GREATER
        _fallbackRng.GetBytes(buffer);
        var result = BitConverter.ToUInt32(buffer);
#else
        var bufferArray = new byte[4];
        _fallbackRng.GetBytes(bufferArray);
        var result = BitConverter.ToUInt32(bufferArray, 0);
#endif
        Interlocked.Add(ref _fallbackGeneratedBytes, 4);
        return result;
    }

    /// <summary>
    /// Generates a single random 64-bit unsigned integer
    /// </summary>
    /// <returns>Random 64-bit unsigned integer</returns>
    public ulong GetUInt64()
    {
        ThrowIfDisposed();

        if (_hardwareAvailable)
        {
            try
            {
                if (TryGetHardwareUInt64(out var value))
                {
                    Interlocked.Add(ref _hardwareGeneratedBytes, 8);
                    return value;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Hardware RNG failed for UInt64, falling back to system RNG");
                Interlocked.Increment(ref _hardwareFailureCount);
            }
        }

        // Fallback to system RNG
        Span<byte> buffer = stackalloc byte[8];
#if NET6_0_OR_GREATER
        _fallbackRng.GetBytes(buffer);
        var result = BitConverter.ToUInt64(buffer);
#else
        var bufferArray = new byte[8];
        _fallbackRng.GetBytes(bufferArray);
        var result = BitConverter.ToUInt64(bufferArray, 0);
#endif
        Interlocked.Add(ref _fallbackGeneratedBytes, 8);
        return result;
    }

    /// <summary>
    /// RDRAND intrinsics are not available in .NET
    /// System.Runtime.Intrinsics.X86 does not expose Rdrand class in any .NET version
    /// Always returns false to use the cryptographically secure RandomNumberGenerator fallback
    /// </summary>
    /// <remarks>
    /// RandomNumberGenerator.Create() uses OS-level RNG which may leverage RDRAND internally
    /// on supported platforms (Windows CNG, Linux/macOS /dev/urandom).
    /// This provides the same security guarantees without requiring direct intrinsic access.
    /// </remarks>
    private bool TryGetHardwareBytes(Span<byte> buffer)
    {
        return false; // RDRAND intrinsics not exposed in .NET
    }

    private static bool TryGetHardwareUInt32(out uint value)
    {
        value = 0;
        return false; // RDRAND intrinsics not exposed in .NET
    }

    private static bool TryGetHardwareUInt64(out ulong value)
    {
        value = 0;
        return false; // RDRAND intrinsics not exposed in .NET
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(HardwareRandomNumberGenerator));
    }

    /// <summary>
    /// Disposes the hardware random number generator
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _fallbackRng?.Dispose();
            _disposed = true;

            _logger?.LogDebug("Hardware RNG disposed. Stats - Hardware: {HardwareBytes} bytes, Fallback: {FallbackBytes} bytes, Failures: {Failures}",
                _hardwareGeneratedBytes, _fallbackGeneratedBytes, _hardwareFailureCount);
        }
    }
}

/// <summary>
/// Statistics about hardware random number generator usage
/// </summary>
public readonly struct HardwareRngStatistics
{
    /// <summary>
    /// Initializes a new instance of HardwareRngStatistics
    /// </summary>
    public HardwareRngStatistics(bool hardwareAvailable, long hardwareGeneratedBytes,
        long fallbackGeneratedBytes, int hardwareFailureCount, double efficiencyRatio)
    {
        HardwareAvailable = hardwareAvailable;
        HardwareGeneratedBytes = hardwareGeneratedBytes;
        FallbackGeneratedBytes = fallbackGeneratedBytes;
        HardwareFailureCount = hardwareFailureCount;
        EfficiencyRatio = efficiencyRatio;
    }

    /// <summary>
    /// Whether hardware acceleration is available
    /// </summary>
    public bool HardwareAvailable { get; }

    /// <summary>
    /// Bytes generated using hardware acceleration
    /// </summary>
    public long HardwareGeneratedBytes { get; }

    /// <summary>
    /// Bytes generated using fallback system RNG
    /// </summary>
    public long FallbackGeneratedBytes { get; }

    /// <summary>
    /// Number of times hardware RNG failed
    /// </summary>
    public int HardwareFailureCount { get; }

    /// <summary>
    /// Ratio of hardware-generated bytes to total bytes (0.0 to 1.0)
    /// </summary>
    public double EfficiencyRatio { get; }

    /// <summary>
    /// Total bytes generated
    /// </summary>
    public long TotalBytesGenerated => HardwareGeneratedBytes + FallbackGeneratedBytes;

    /// <summary>
    /// Gets a human-readable summary
    /// </summary>
    public override string ToString()
    {
        return $"Hardware: {HardwareAvailable}, " +
               $"Total: {TotalBytesGenerated} bytes, " +
               $"Hardware Efficiency: {EfficiencyRatio:P1}, " +
               $"Failures: {HardwareFailureCount}";
    }
}
