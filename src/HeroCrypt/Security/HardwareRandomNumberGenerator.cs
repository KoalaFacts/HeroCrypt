using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Hardware;
using Microsoft.Extensions.Logging;

#if NET5_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

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
    public HardwareRngStatistics Statistics => new HardwareRngStatistics(
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

#if NET5_0_OR_GREATER
    /// <summary>
    /// Attempts to generate random bytes using hardware RDRAND/RDSEED instructions
    /// </summary>
    /// <param name="buffer">Buffer to fill</param>
    /// <returns>True if successful, false if hardware failed</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool TryGetHardwareBytes(Span<byte> buffer)
    {
        if (!Rdrand.X64.IsSupported) return false;

        var offset = 0;
        var remaining = buffer.Length;

        // Fill 8-byte chunks using RDRAND64
        while (remaining >= 8)
        {
            if (!TryGetHardwareUInt64(out var value))
                return false;

            BitConverter.TryWriteBytes(buffer.Slice(offset, 8), value);
            offset += 8;
            remaining -= 8;
        }

        // Fill 4-byte chunks using RDRAND32
        while (remaining >= 4)
        {
            if (!TryGetHardwareUInt32(out var value))
                return false;

            BitConverter.TryWriteBytes(buffer.Slice(offset, 4), value);
            offset += 4;
            remaining -= 4;
        }

        // Handle remaining bytes
        if (remaining > 0)
        {
            if (!TryGetHardwareUInt32(out var value))
                return false;

            Span<byte> temp = stackalloc byte[4];
            BitConverter.TryWriteBytes(temp, value);
            temp.Slice(0, remaining).CopyTo(buffer.Slice(offset));
        }

        return true;
    }

    /// <summary>
    /// Attempts to generate a 32-bit random value using RDRAND
    /// </summary>
    /// <param name="value">Generated value</param>
    /// <returns>True if successful</returns>
    /// <remarks>
    /// Uses the RDRAND CPU instruction via System.Runtime.Intrinsics.X86.Rdrand.
    /// Implements retry logic as recommended by Intel (up to 10 attempts).
    /// The carry flag is automatically checked by the intrinsic to verify instruction success.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryGetHardwareUInt32(out uint value)
    {
        if (!Rdrand.IsSupported)
        {
            value = 0;
            return false;
        }

        // Intel recommends up to 10 retries for RDRAND
        for (var attempt = 0; attempt < 10; attempt++)
        {
            if (Rdrand.RdRand32(out value) != 0)
            {
                return true;
            }
        }

        value = 0;
        return false;
    }

    /// <summary>
    /// Attempts to generate a 64-bit random value using RDRAND
    /// </summary>
    /// <param name="value">Generated value</param>
    /// <returns>True if successful</returns>
    /// <remarks>
    /// Uses the RDRAND CPU instruction via System.Runtime.Intrinsics.X86.Rdrand.
    /// Implements retry logic as recommended by Intel (up to 10 attempts).
    /// The carry flag is automatically checked by the intrinsic to verify instruction success.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryGetHardwareUInt64(out ulong value)
    {
        if (!Rdrand.X64.IsSupported)
        {
            value = 0;
            return false;
        }

        // Intel recommends up to 10 retries for RDRAND
        for (var attempt = 0; attempt < 10; attempt++)
        {
            if (Rdrand.X64.RdRand64(out value) != 0)
            {
                return true;
            }
        }

        value = 0;
        return false;
    }
#else
    /// <summary>
    /// Fallback implementation for older .NET versions
    /// </summary>
    private bool TryGetHardwareBytes(Span<byte> buffer)
    {
        return false; // Hardware not available in older .NET versions
    }

    private static bool TryGetHardwareUInt32(out uint value)
    {
        value = 0;
        return false;
    }

    private static bool TryGetHardwareUInt64(out ulong value)
    {
        value = 0;
        return false;
    }
#endif

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