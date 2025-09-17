using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Cryptography.Blake2b;
using HeroCrypt.Cryptography;
using HeroCrypt.Security;
using HeroCrypt.Hardware;
using Microsoft.Extensions.Logging;

#if NET5_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

namespace HeroCrypt.Performance;

/// <summary>
/// Comprehensive benchmarking suite for HeroCrypt performance analysis
/// Measures hardware acceleration improvements across all major operations
/// </summary>
public class HeroCryptBenchmark : IDisposable
{
    private readonly ILogger<HeroCryptBenchmark>? _logger;
    private readonly HardwareRandomNumberGenerator _hardwareRng;
    private readonly RandomNumberGenerator _systemRng;

    /// <summary>
    /// Initializes the benchmark suite
    /// </summary>
    /// <param name="logger">Optional logger for detailed results</param>
    public HeroCryptBenchmark(ILogger<HeroCryptBenchmark>? logger = null)
    {
        _logger = logger;
        _hardwareRng = new HardwareRandomNumberGenerator();
        _systemRng = RandomNumberGenerator.Create();
    }

    /// <summary>
    /// Runs the complete benchmark suite
    /// </summary>
    /// <returns>Comprehensive benchmark results</returns>
    public BenchmarkResults RunCompleteBenchmark()
    {
        _logger?.LogInformation("Starting HeroCrypt comprehensive benchmark suite");

        var results = new BenchmarkResults
        {
            SystemInfo = GetSystemInfo(),
            HardwareCapabilities = HardwareAccelerationDetector.GetCapabilities()
        };

        // Benchmark random number generation
        results.RandomNumberGeneration = BenchmarkRandomNumberGeneration();

        // Benchmark Blake2b hashing
        results.Blake2bHashing = BenchmarkBlake2bHashing();

        // Benchmark constant-time operations
        results.ConstantTimeOperations = BenchmarkConstantTimeOperations();

        // Benchmark memory operations
        results.MemoryOperations = BenchmarkMemoryOperations();

        _logger?.LogInformation("Benchmark suite completed");
        return results;
    }

    /// <summary>
    /// Benchmarks random number generation performance
    /// </summary>
    private RandomNumberBenchmark BenchmarkRandomNumberGeneration()
    {
        _logger?.LogInformation("Benchmarking random number generation");

        var sizes = new[] { 16, 32, 64, 256, 1024, 4096, 16384 };
        var iterations = 10000;

        var hardwareResults = new Dictionary<int, double>();
        var systemResults = new Dictionary<int, double>();

        foreach (var size in sizes)
        {
            var buffer = new byte[size];

            // Benchmark hardware RNG
            var hardwareTime = MeasureOperation(() => _hardwareRng.GetBytes(buffer), iterations);
            hardwareResults[size] = hardwareTime;

            // Benchmark system RNG
            var systemTime = MeasureOperation(() => _systemRng.GetBytes(buffer), iterations);
            systemResults[size] = systemTime;
        }

        var stats = _hardwareRng.Statistics;

        return new RandomNumberBenchmark
        {
            HardwareAvailable = stats.HardwareAvailable,
            HardwareResults = hardwareResults,
            SystemResults = systemResults,
            HardwareEfficiencyRatio = stats.EfficiencyRatio,
            HardwareFailureCount = stats.HardwareFailureCount
        };
    }

    /// <summary>
    /// Benchmarks Blake2b hashing performance
    /// </summary>
    private Blake2bBenchmark BenchmarkBlake2bHashing()
    {
        _logger?.LogInformation("Benchmarking Blake2b hashing");

        var sizes = new[] { 64, 256, 1024, 4096, 16384, 65536 };
        var iterations = 1000;

        var scalarResults = new Dictionary<int, double>();
        var avx2Results = new Dictionary<int, double>();

#if NET5_0_OR_GREATER
        var avx2Available = Blake2bAvx2.IsSupported;
#else
        var avx2Available = false;
#endif

        foreach (var size in sizes)
        {
            var data = new byte[size];
            _systemRng.GetBytes(data);
            var output = new byte[64];

            // Benchmark scalar Blake2b
            var scalarTime = MeasureOperation(() => {
                var result = Blake2bCore.ComputeHash(data, 64);
                result.CopyTo(output, 0);
            }, iterations);
            scalarResults[size] = scalarTime;

            // Benchmark AVX2 Blake2b if available
            if (avx2Available)
            {
#if NET5_0_OR_GREATER
                var avx2Time = MeasureOperation(() => Blake2bAvx2.HashStream(data, output), iterations);
                avx2Results[size] = avx2Time;
#endif
            }
        }

        return new Blake2bBenchmark
        {
            Avx2Available = avx2Available,
            ScalarResults = scalarResults,
            Avx2Results = avx2Results
        };
    }

    /// <summary>
    /// Benchmarks constant-time operations performance
    /// </summary>
    private ConstantTimeBenchmark BenchmarkConstantTimeOperations()
    {
        _logger?.LogInformation("Benchmarking constant-time operations");

        var sizes = new[] { 16, 32, 64, 128, 256, 512, 1024 };
        var iterations = 100000;

        var scalarResults = new Dictionary<string, Dictionary<int, double>>();
        var simdResults = new Dictionary<string, Dictionary<int, double>>();

        // Initialize result dictionaries
        scalarResults["ArrayEquals"] = new Dictionary<int, double>();
        scalarResults["XorArrays"] = new Dictionary<int, double>();
        scalarResults["SecureClear"] = new Dictionary<int, double>();

        simdResults["ArrayEquals"] = new Dictionary<int, double>();
        simdResults["XorArrays"] = new Dictionary<int, double>();
        simdResults["SecureClear"] = new Dictionary<int, double>();

        foreach (var size in sizes)
        {
            var array1 = new byte[size];
            var array2 = new byte[size];
            var result = new byte[size];
            _systemRng.GetBytes(array1);
            _systemRng.GetBytes(array2);

            // Benchmark scalar operations
            var scalarEqualsTime = MeasureOperation(() =>
                ConstantTimeOperations.ConstantTimeArrayEquals(array1, array2), iterations);
            scalarResults["ArrayEquals"][size] = scalarEqualsTime;

            var scalarXorTime = MeasureOperation(() => {
                for (var i = 0; i < size; i++)
                    result[i] = (byte)(array1[i] ^ array2[i]);
            }, iterations);
            scalarResults["XorArrays"][size] = scalarXorTime;

            var scalarClearTime = MeasureOperation(() =>
                SecureMemoryOperations.SecureClear(result), iterations);
            scalarResults["SecureClear"][size] = scalarClearTime;

            // Benchmark SIMD operations
            var simdEqualsTime = MeasureOperation(() =>
                SimdConstantTimeOperations.ConstantTimeArrayEquals(array1, array2), iterations);
            simdResults["ArrayEquals"][size] = simdEqualsTime;

            var simdXorTime = MeasureOperation(() =>
                SimdConstantTimeOperations.XorArrays(array1, array2, result), iterations);
            simdResults["XorArrays"][size] = simdXorTime;

            var simdClearTime = MeasureOperation(() =>
                SecureMemoryOperations.SecureClear(result), iterations);
            simdResults["SecureClear"][size] = simdClearTime;
        }

        return new ConstantTimeBenchmark
        {
            SimdAvailable = SimdConstantTimeOperations.IsAvailable,
            ScalarResults = scalarResults,
            SimdResults = simdResults
        };
    }

    /// <summary>
    /// Benchmarks memory operations performance
    /// </summary>
    private MemoryBenchmark BenchmarkMemoryOperations()
    {
        _logger?.LogInformation("Benchmarking memory operations");

        var sizes = new[] { 1024, 4096, 16384, 65536, 262144 };
        var iterations = 1000;

        var allocationResults = new Dictionary<int, double>();
        var clearResults = new Dictionary<int, double>();

        foreach (var size in sizes)
        {
            // Benchmark memory allocation
            var allocTime = MeasureOperation(() => {
                var buffer = new byte[size];
                GC.KeepAlive(buffer);
            }, iterations);
            allocationResults[size] = allocTime;

            // Benchmark memory clearing
            var buffer = new byte[size];
            var clearTime = MeasureOperation(() =>
                SecureMemoryOperations.SecureClear(buffer), iterations);
            clearResults[size] = clearTime;
        }

        return new MemoryBenchmark
        {
            AllocationResults = allocationResults,
            ClearResults = clearResults
        };
    }

    /// <summary>
    /// Measures the execution time of an operation
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static double MeasureOperation(Action operation, int iterations)
    {
        // Warm up
        for (var i = 0; i < Math.Min(iterations / 10, 100); i++)
        {
            operation();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var stopwatch = Stopwatch.StartNew();

        for (var i = 0; i < iterations; i++)
        {
            operation();
        }

        stopwatch.Stop();

        return stopwatch.Elapsed.TotalMilliseconds / iterations;
    }

    /// <summary>
    /// Gets system information for benchmark context
    /// </summary>
    private static SystemInfo GetSystemInfo()
    {
        return new SystemInfo
        {
            ProcessorCount = Environment.ProcessorCount,
            OperatingSystem = Environment.OSVersion.ToString(),
            Is64BitProcess = Environment.Is64BitProcess,
            WorkingSet = Environment.WorkingSet,
            RuntimeVersion = Environment.Version.ToString()
        };
    }

    /// <summary>
    /// Disposes benchmark resources
    /// </summary>
    public void Dispose()
    {
        _hardwareRng?.Dispose();
        _systemRng?.Dispose();
    }
}

/// <summary>
/// Complete benchmark results
/// </summary>
public class BenchmarkResults
{
    public SystemInfo SystemInfo { get; set; } = new();
    public HardwareCapabilities HardwareCapabilities { get; set; } = new();
    public RandomNumberBenchmark RandomNumberGeneration { get; set; } = new();
    public Blake2bBenchmark Blake2bHashing { get; set; } = new();
    public ConstantTimeBenchmark ConstantTimeOperations { get; set; } = new();
    public MemoryBenchmark MemoryOperations { get; set; } = new();

    /// <summary>
    /// Generates a performance summary report
    /// </summary>
    public string GenerateReport()
    {
        var report = new System.Text.StringBuilder();

        report.AppendLine("=== HeroCrypt Performance Benchmark Report ===");
        report.AppendLine($"System: {SystemInfo.OperatingSystem}");
        report.AppendLine($"Processor Cores: {SystemInfo.ProcessorCount}");
        report.AppendLine($"Hardware Capabilities: {HardwareCapabilities}");
        report.AppendLine();

        // Random Number Generation Summary
        report.AppendLine("Random Number Generation:");
        if (RandomNumberGeneration.HardwareAvailable)
        {
            report.AppendLine($"  Hardware Efficiency: {RandomNumberGeneration.HardwareEfficiencyRatio:P1}");
            report.AppendLine($"  Hardware Failures: {RandomNumberGeneration.HardwareFailureCount}");
        }
        else
        {
            report.AppendLine("  Hardware acceleration not available");
        }
        report.AppendLine();

        // Blake2b Summary
        report.AppendLine("Blake2b Hashing:");
        if (Blake2bHashing.Avx2Available && Blake2bHashing.Avx2Results.Count > 0)
        {
            var speedup = CalculateAverageSpeedup(Blake2bHashing.ScalarResults, Blake2bHashing.Avx2Results);
            report.AppendLine($"  AVX2 Average Speedup: {speedup:F2}x");
        }
        else
        {
            report.AppendLine("  AVX2 acceleration not available");
        }
        report.AppendLine();

        // Constant-time Operations Summary
        report.AppendLine("Constant-time Operations:");
        if (ConstantTimeOperations.SimdAvailable)
        {
            foreach (var operation in ConstantTimeOperations.ScalarResults.Keys)
            {
                var speedup = CalculateAverageSpeedup(
                    ConstantTimeOperations.ScalarResults[operation],
                    ConstantTimeOperations.SimdResults[operation]);
                report.AppendLine($"  {operation} SIMD Speedup: {speedup:F2}x");
            }
        }
        else
        {
            report.AppendLine("  SIMD acceleration not available");
        }

        return report.ToString();
    }

    private static double CalculateAverageSpeedup(Dictionary<int, double> scalar, Dictionary<int, double> optimized)
    {
        var speedups = new List<double>();

        foreach (var kvp in scalar)
        {
            if (optimized.TryGetValue(kvp.Key, out var optimizedTime) && optimizedTime > 0)
            {
                speedups.Add(kvp.Value / optimizedTime);
            }
        }

        return speedups.Count > 0 ? speedups.Average() : 1.0;
    }
}

/// <summary>
/// System information for benchmark context
/// </summary>
public class SystemInfo
{
    public int ProcessorCount { get; set; }
    public string OperatingSystem { get; set; } = string.Empty;
    public bool Is64BitProcess { get; set; }
    public long WorkingSet { get; set; }
    public string RuntimeVersion { get; set; } = string.Empty;
}

/// <summary>
/// Random number generation benchmark results
/// </summary>
public class RandomNumberBenchmark
{
    public bool HardwareAvailable { get; set; }
    public Dictionary<int, double> HardwareResults { get; set; } = new();
    public Dictionary<int, double> SystemResults { get; set; } = new();
    public double HardwareEfficiencyRatio { get; set; }
    public int HardwareFailureCount { get; set; }
}

/// <summary>
/// Blake2b hashing benchmark results
/// </summary>
public class Blake2bBenchmark
{
    public bool Avx2Available { get; set; }
    public Dictionary<int, double> ScalarResults { get; set; } = new();
    public Dictionary<int, double> Avx2Results { get; set; } = new();
}

/// <summary>
/// Constant-time operations benchmark results
/// </summary>
public class ConstantTimeBenchmark
{
    public bool SimdAvailable { get; set; }
    public Dictionary<string, Dictionary<int, double>> ScalarResults { get; set; } = new();
    public Dictionary<string, Dictionary<int, double>> SimdResults { get; set; } = new();
}

/// <summary>
/// Memory operations benchmark results
/// </summary>
public class MemoryBenchmark
{
    public Dictionary<int, double> AllocationResults { get; set; } = new();
    public Dictionary<int, double> ClearResults { get; set; } = new();
}