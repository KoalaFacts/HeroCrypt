using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using HeroCrypt.Performance;
using HeroCrypt.Hardware;

namespace HeroCrypt.Benchmarks;

/// <summary>
/// Benchmark console application for HeroCrypt performance analysis
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("HeroCrypt Performance Benchmark Suite");
        Console.WriteLine("=====================================");
        Console.WriteLine();

        // Setup logging
        var serviceProvider = new ServiceCollection()
            .AddLogging(builder => builder
                .AddConsole()
                .SetMinimumLevel(LogLevel.Information))
            .BuildServiceProvider();

        var logger = serviceProvider.GetService<ILogger<HeroCryptBenchmark>>();

        // Display hardware capabilities
        Console.WriteLine("Hardware Capabilities:");
        var capabilities = HardwareAccelerationDetector.GetCapabilities();
        Console.WriteLine(capabilities.ToString());
        Console.WriteLine();

        // Run benchmarks
        using var benchmark = new HeroCryptBenchmark(logger);

        Console.WriteLine("Running comprehensive benchmark suite...");
        Console.WriteLine("This may take a few minutes...");
        Console.WriteLine();

        var results = benchmark.RunCompleteBenchmark();

        // Display results
        Console.WriteLine(results.GenerateReport());

        // Detailed results
        if (args.Length > 0 && args[0] == "--detailed")
        {
            DisplayDetailedResults(results);
        }

        Console.WriteLine();
        Console.WriteLine("Benchmark completed. Press any key to exit...");
        Console.ReadKey();
    }

    static void DisplayDetailedResults(BenchmarkResults results)
    {
        Console.WriteLine();
        Console.WriteLine("=== Detailed Results ===");

        // Random Number Generation Details
        Console.WriteLine();
        Console.WriteLine("Random Number Generation (ms per operation):");
        Console.WriteLine($"{"Size (bytes)",-12} {"Hardware",-12} {"System",-12} {"Speedup",-12}");
        Console.WriteLine(new string('-', 50));

        foreach (var size in results.RandomNumberGeneration.HardwareResults.Keys)
        {
            var hardwareTime = results.RandomNumberGeneration.HardwareResults[size];
            var systemTime = results.RandomNumberGeneration.SystemResults[size];
            var speedup = systemTime / hardwareTime;

            Console.WriteLine($"{size,-12} {hardwareTime,-12:F6} {systemTime,-12:F6} {speedup,-12:F2}x");
        }

        // Blake2b Details
        Console.WriteLine();
        Console.WriteLine("Blake2b Hashing (ms per operation):");
        Console.WriteLine($"{"Size (bytes)",-12} {"Scalar",-12} {"AVX2",-12} {"Speedup",-12}");
        Console.WriteLine(new string('-', 50));

        foreach (var size in results.Blake2bHashing.ScalarResults.Keys)
        {
            var scalarTime = results.Blake2bHashing.ScalarResults[size];

            if (results.Blake2bHashing.Avx2Results.TryGetValue(size, out var avx2Time))
            {
                var speedup = scalarTime / avx2Time;
                Console.WriteLine($"{size,-12} {scalarTime,-12:F6} {avx2Time,-12:F6} {speedup,-12:F2}x");
            }
            else
            {
                Console.WriteLine($"{size,-12} {scalarTime,-12:F6} {"N/A",-12} {"N/A",-12}");
            }
        }

        // Constant-time Operations Details
        Console.WriteLine();
        Console.WriteLine("Constant-time Operations (ms per operation):");

        foreach (var operation in results.ConstantTimeOperations.ScalarResults.Keys)
        {
            Console.WriteLine();
            Console.WriteLine($"{operation}:");
            Console.WriteLine($"{"Size (bytes)",-12} {"Scalar",-12} {"SIMD",-12} {"Speedup",-12}");
            Console.WriteLine(new string('-', 50));

            foreach (var size in results.ConstantTimeOperations.ScalarResults[operation].Keys)
            {
                var scalarTime = results.ConstantTimeOperations.ScalarResults[operation][size];

                if (results.ConstantTimeOperations.SimdResults[operation].TryGetValue(size, out var simdTime))
                {
                    var speedup = scalarTime / simdTime;
                    Console.WriteLine($"{size,-12} {scalarTime,-12:F6} {simdTime,-12:F6} {speedup,-12:F2}x");
                }
                else
                {
                    Console.WriteLine($"{size,-12} {scalarTime,-12:F6} {"N/A",-12} {"N/A",-12}");
                }
            }
        }

        // Memory Operations Details
        Console.WriteLine();
        Console.WriteLine("Memory Operations (ms per operation):");
        Console.WriteLine($"{"Size (bytes)",-12} {"Allocation",-12} {"Clear",-12}");
        Console.WriteLine(new string('-', 38));

        foreach (var size in results.MemoryOperations.AllocationResults.Keys)
        {
            var allocTime = results.MemoryOperations.AllocationResults[size];
            var clearTime = results.MemoryOperations.ClearResults[size];

            Console.WriteLine($"{size,-12} {allocTime,-12:F6} {clearTime,-12:F6}");
        }
    }
}