using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using HeroCrypt.Performance.Batch;
using HeroCrypt.Cryptography.Blake2b;
using HeroCrypt.Cryptography.ECC.Ed25519;

namespace HeroCrypt.Performance;

#if !NETSTANDARD2_0

/// <summary>
/// Comprehensive benchmark suite for batch cryptographic operations.
/// Measures throughput, latency, and scalability across different batch sizes and data sizes.
/// </summary>
public class BatchOperationsBenchmark
{
        private const int WarmupIterations = 5;
        private const int BenchmarkIterations = 100;

        // Test data sizes in bytes
        private static readonly int[] DataSizes = { 64, 256, 1024, 4096, 16384 }; // 64B to 16KB

        // Batch sizes to test
        private static readonly int[] BatchSizes = { 10, 50, 100, 500 };

        // Parallelism degrees to test
        private static readonly int[] ParallelismDegrees = { 1, 2, 4, 8, 0 }; // 0 = auto

        /// <summary>
        /// Represents the benchmark result for a single batch operation test.
        /// </summary>
        public class BatchBenchmarkResult
        {
            public string OperationName { get; set; } = string.Empty;
            public int DataSize { get; set; }
            public int BatchSize { get; set; }
            public int ParallelismDegree { get; set; }
            public double AverageTimeMs { get; set; }
            public double ThroughputMBps { get; set; }
            public double OperationsPerSecond { get; set; }
            public double LatencyPerOperationUs { get; set; }
            public double SpeedupVsSequential { get; set; }
        }

        /// <summary>
        /// Contains comprehensive benchmark results for all tested batch operations.
        /// </summary>
        public class BatchBenchmarkResults
        {
            public DateTime Timestamp { get; set; }
            public string RuntimeVersion { get; set; } = string.Empty;
            public int ProcessorCount { get; set; }
            public string OperatingSystem { get; set; } = string.Empty;
            public List<BatchBenchmarkResult> Results { get; set; } = new List<BatchBenchmarkResult>();

            /// <summary>
            /// Prints a formatted summary of all benchmark results to the console.
            /// </summary>
            /// <remarks>
            /// Displays results grouped by operation type with detailed metrics including
            /// throughput, latency, and speedup compared to sequential execution.
            /// </remarks>
            public void PrintSummary()
            {
                Console.WriteLine("\n=== Batch Operations Benchmark Results ===");
                Console.WriteLine($"Timestamp: {Timestamp}");
                Console.WriteLine($"Runtime: {RuntimeVersion}");
                Console.WriteLine($"Processors: {ProcessorCount}");
                Console.WriteLine($"OS: {OperatingSystem}");
                Console.WriteLine();

                var groupedResults = Results.GroupBy(r => r.OperationName);

                foreach (var group in groupedResults)
                {
                    Console.WriteLine($"\n--- {group.Key} ---");
                    Console.WriteLine($"{"Data Size",-12} {"Batch Size",-12} {"Parallel",-10} {"Avg Time (ms)",-15} {"Throughput",-15} {"Ops/Sec",-15} {"Latency (µs)",-15} {"Speedup",-10}");
                    Console.WriteLine(new string('-', 130));

                    foreach (var result in group.OrderBy(r => r.DataSize).ThenBy(r => r.BatchSize).ThenBy(r => r.ParallelismDegree))
                    {
                        string parallel = result.ParallelismDegree == 0 ? "Auto" : result.ParallelismDegree.ToString();
                        Console.WriteLine($"{result.DataSize,-12} {result.BatchSize,-12} {parallel,-10} {result.AverageTimeMs,-15:F3} {result.ThroughputMBps,-15:F2} {result.OperationsPerSecond,-15:F0} {result.LatencyPerOperationUs,-15:F2} {result.SpeedupVsSequential,-10:F2}x");
                    }
                }
            }
        }

        /// <summary>
        /// Runs all batch operation benchmarks.
        /// </summary>
        public static async Task<BatchBenchmarkResults> RunAllBenchmarksAsync()
        {
            var results = new BatchBenchmarkResults
            {
                Timestamp = DateTime.UtcNow,
                RuntimeVersion = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                ProcessorCount = Environment.ProcessorCount,
                OperatingSystem = Environment.OSVersion.ToString()
            };

            Console.WriteLine("Starting Batch Operations Benchmarks...");
            Console.WriteLine($"Warmup iterations: {WarmupIterations}, Benchmark iterations: {BenchmarkIterations}");
            Console.WriteLine($"Data sizes: {string.Join(", ", DataSizes.Select(s => $"{s}B"))}");
            Console.WriteLine($"Batch sizes: {string.Join(", ", BatchSizes)}");
            Console.WriteLine();

            // Hash Operations
            results.Results.AddRange(await BenchmarkBatchHashOperationsAsync());

            // HMAC Operations
            results.Results.AddRange(await BenchmarkBatchHmacOperationsAsync());

            // Encryption Operations
            results.Results.AddRange(await BenchmarkBatchEncryptionOperationsAsync());

            // Signature Operations (Ed25519 only for performance)
            results.Results.AddRange(await BenchmarkBatchSignatureOperationsAsync());

            // Key Derivation Operations
            results.Results.AddRange(await BenchmarkBatchKeyDerivationOperationsAsync());

            return results;
        }

        #region Hash Operations Benchmarks

        private static async Task<List<BatchBenchmarkResult>> BenchmarkBatchHashOperationsAsync()
        {
            Console.WriteLine("=== Benchmarking Batch Hash Operations ===\n");
            var results = new List<BatchBenchmarkResult>();

            foreach (var dataSize in DataSizes)
            {
                foreach (var batchSize in BatchSizes)
                {
                    // SHA-256 Batch
                    var sha256Result = await BenchmarkSha256BatchAsync(dataSize, batchSize);
                    results.Add(sha256Result);
                    Console.WriteLine($"SHA-256 Batch: DataSize={dataSize}B, BatchSize={batchSize}, Time={sha256Result.AverageTimeMs:F3}ms, Throughput={sha256Result.ThroughputMBps:F2} MB/s");

                    // BLAKE2b Batch
                    var blake2bResult = await BenchmarkBlake2bBatchAsync(dataSize, batchSize);
                    results.Add(blake2bResult);
                    Console.WriteLine($"BLAKE2b Batch: DataSize={dataSize}B, BatchSize={batchSize}, Time={blake2bResult.AverageTimeMs:F3}ms, Throughput={blake2bResult.ThroughputMBps:F2} MB/s");
                }
            }

            return results;
        }

        private static async Task<BatchBenchmarkResult> BenchmarkSha256BatchAsync(int dataSize, int batchSize)
        {
            var dataItems = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(dataSize)))
                .ToArray();

            // Measure batch operation
            double avgTimeMs = await MeasureOperationAsync(() => BatchHashOperations.Sha256BatchAsync(dataItems));

            // Measure sequential for comparison
            double sequentialTimeMs = await MeasureSequentialHashAsync(dataItems);
            double speedup = sequentialTimeMs / avgTimeMs;

            return CreateBenchmarkResult("SHA-256 Batch", dataSize, batchSize, avgTimeMs, speedup);
        }

        private static Task<BatchBenchmarkResult> BenchmarkBlake2bBatchAsync(int dataSize, int batchSize)
        {
            var dataItems = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(dataSize)))
                .ToArray();

            // Measure batch operation (sync operation, so use sync helper)
            double avgTimeMs = MeasureOperation(() => BatchHashOperations.Blake2bBatch(dataItems));

            // Measure sequential for comparison
            double sequentialTimeMs = MeasureSequentialBlake2b(dataItems);
            double speedup = sequentialTimeMs / avgTimeMs;

            return Task.FromResult(CreateBenchmarkResult("BLAKE2b Batch", dataSize, batchSize, avgTimeMs, speedup));
        }

        private static Task<double> MeasureSequentialHashAsync(ReadOnlyMemory<byte>[] dataItems)
        {
            using var sha256 = SHA256.Create();
            var sw = Stopwatch.StartNew();
            foreach (var data in dataItems)
            {
                sha256.ComputeHash(data.ToArray());
            }
            sw.Stop();
            return Task.FromResult(sw.Elapsed.TotalMilliseconds);
        }

        private static double MeasureSequentialBlake2b(ReadOnlyMemory<byte>[] dataItems)
        {
            var sw = Stopwatch.StartNew();
            foreach (var data in dataItems)
            {
                Blake2bCore.ComputeHash(data.ToArray());
            }
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds;
        }

        #endregion

        #region HMAC Operations Benchmarks

        private static async Task<List<BatchBenchmarkResult>> BenchmarkBatchHmacOperationsAsync()
        {
            Console.WriteLine("\n=== Benchmarking Batch HMAC Operations ===\n");
            var results = new List<BatchBenchmarkResult>();
            var key = GetRandomBytes(32);

            foreach (var dataSize in DataSizes)
            {
                foreach (var batchSize in BatchSizes)
                {
                    var hmacResult = await BenchmarkHmacSha256BatchAsync(dataSize, batchSize, key);
                    results.Add(hmacResult);
                    Console.WriteLine($"HMAC-SHA256 Batch: DataSize={dataSize}B, BatchSize={batchSize}, Time={hmacResult.AverageTimeMs:F3}ms, Throughput={hmacResult.ThroughputMBps:F2} MB/s");
                }
            }

            return results;
        }

        private static Task<BatchBenchmarkResult> BenchmarkHmacSha256BatchAsync(int dataSize, int batchSize, byte[] key)
        {
            var dataItems = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(dataSize)))
                .ToArray();

            // Measure batch operation (sync operation)
            double avgTimeMs = MeasureOperation(() => BatchHmacOperations.HmacSha256Batch(key, dataItems));

            // Measure sequential for comparison
            double sequentialTimeMs = MeasureSequentialHmac(dataItems, key);
            double speedup = sequentialTimeMs / avgTimeMs;

            return Task.FromResult(CreateBenchmarkResult("HMAC-SHA256 Batch", dataSize, batchSize, avgTimeMs, speedup));
        }

        private static double MeasureSequentialHmac(ReadOnlyMemory<byte>[] dataItems, byte[] key)
        {
            using var hmac = new HMACSHA256(key);
            var sw = Stopwatch.StartNew();
            foreach (var data in dataItems)
            {
                hmac.ComputeHash(data.ToArray());
            }
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds;
        }

        #endregion

        #region Encryption Operations Benchmarks

        private static async Task<List<BatchBenchmarkResult>> BenchmarkBatchEncryptionOperationsAsync()
        {
            Console.WriteLine("\n=== Benchmarking Batch Encryption Operations ===\n");
            var results = new List<BatchBenchmarkResult>();

            foreach (var dataSize in DataSizes)
            {
                foreach (var batchSize in new[] { 10, 50, 100 }) // Fewer batch sizes for encryption
                {
                    // AES-GCM Encryption
                    var aesResult = await BenchmarkAesGcmEncryptBatchAsync(dataSize, batchSize);
                    results.Add(aesResult);
                    Console.WriteLine($"AES-GCM Encrypt Batch: DataSize={dataSize}B, BatchSize={batchSize}, Time={aesResult.AverageTimeMs:F3}ms, Throughput={aesResult.ThroughputMBps:F2} MB/s");

                    // ChaCha20-Poly1305 Encryption
                    var chachaResult = await BenchmarkChaCha20Poly1305EncryptBatchAsync(dataSize, batchSize);
                    results.Add(chachaResult);
                    Console.WriteLine($"ChaCha20-Poly1305 Encrypt Batch: DataSize={dataSize}B, BatchSize={batchSize}, Time={chachaResult.AverageTimeMs:F3}ms, Throughput={chachaResult.ThroughputMBps:F2} MB/s");
                }
            }

            return results;
        }

        private static async Task<BatchBenchmarkResult> BenchmarkAesGcmEncryptBatchAsync(int dataSize, int batchSize)
        {
            var masterKey = new ReadOnlyMemory<byte>(GetRandomBytes(32));
            var masterNonce = new ReadOnlyMemory<byte>(GetRandomBytes(12));
            var plaintexts = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(dataSize)))
                .ToArray();
            var aad = new ReadOnlyMemory<byte>(Array.Empty<byte>());

            // Measure batch operation
            double avgTimeMs = await MeasureOperationAsync(() =>
                BatchEncryptionOperations.AesGcmEncryptBatchAsync(masterKey, masterNonce, plaintexts, aad));

            return CreateBenchmarkResult("AES-GCM Encrypt Batch", dataSize, batchSize, avgTimeMs);
        }

        private static async Task<BatchBenchmarkResult> BenchmarkChaCha20Poly1305EncryptBatchAsync(int dataSize, int batchSize)
        {
            var masterKey = new ReadOnlyMemory<byte>(GetRandomBytes(32));
            var masterNonce = new ReadOnlyMemory<byte>(GetRandomBytes(12));
            var plaintexts = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(dataSize)))
                .ToArray();
            var aad = new ReadOnlyMemory<byte>(Array.Empty<byte>());

            // Measure batch operation
            double avgTimeMs = await MeasureOperationAsync(() =>
                BatchEncryptionOperations.ChaCha20Poly1305EncryptBatchAsync(masterKey, masterNonce, plaintexts, aad));

            return CreateBenchmarkResult("ChaCha20-Poly1305 Encrypt Batch", dataSize, batchSize, avgTimeMs);
        }

        #endregion

        #region Signature Operations Benchmarks

        private static async Task<List<BatchBenchmarkResult>> BenchmarkBatchSignatureOperationsAsync()
        {
            Console.WriteLine("\n=== Benchmarking Batch Signature Operations ===\n");
            var results = new List<BatchBenchmarkResult>();

            // Only benchmark Ed25519 for practical performance testing
            var dataSize = 256; // Fixed message size for signatures
            foreach (var batchSize in new[] { 10, 50, 100 })
            {
                var ed25519Result = await BenchmarkEd25519VerifyBatchAsync(dataSize, batchSize);
                results.Add(ed25519Result);
                Console.WriteLine($"Ed25519 Verify Batch: BatchSize={batchSize}, Time={ed25519Result.AverageTimeMs:F3}ms, Ops/Sec={ed25519Result.OperationsPerSecond:F0}");
            }

            return results;
        }

        private static Task<BatchBenchmarkResult> BenchmarkEd25519VerifyBatchAsync(int dataSize, int batchSize)
        {
            // Generate key pair and signatures
            var keyPair = Ed25519Core.GenerateKeyPair();

            var messages = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(dataSize)))
                .ToArray();

            var signatures = messages
                .Select(msg => new ReadOnlyMemory<byte>(Ed25519Core.Sign(msg.ToArray(), keyPair.privateKey)))
                .ToArray();

            // Create array of public keys (same key repeated for each message)
            var publicKeys = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(keyPair.publicKey))
                .ToArray();

            // Measure batch operation (sync operation)
            double avgTimeMs = MeasureOperation(() => BatchSignatureOperations.VerifyEd25519Batch(publicKeys, messages, signatures));

            // Measure sequential for comparison
            double sequentialTimeMs = MeasureSequentialEd25519Verify(messages, signatures, keyPair.publicKey);
            double speedup = sequentialTimeMs / avgTimeMs;

            return Task.FromResult(CreateBenchmarkResultNoThroughput("Ed25519 Verify Batch", dataSize, batchSize, avgTimeMs, speedup));
        }

        private static double MeasureSequentialEd25519Verify(ReadOnlyMemory<byte>[] messages, ReadOnlyMemory<byte>[] signatures, byte[] publicKey)
        {
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < messages.Length; i++)
            {
                Ed25519Core.Verify(messages[i].ToArray(), signatures[i].ToArray(), publicKey);
            }
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds;
        }

        #endregion

        #region Key Derivation Operations Benchmarks

        private static async Task<List<BatchBenchmarkResult>> BenchmarkBatchKeyDerivationOperationsAsync()
        {
            Console.WriteLine("\n=== Benchmarking Batch Key Derivation Operations ===\n");
            var results = new List<BatchBenchmarkResult>();

            foreach (var batchSize in new[] { 10, 50, 100 })
            {
                // PBKDF2 Batch (lighter iterations for benchmarking)
                var pbkdf2Result = await BenchmarkPbkdf2BatchAsync(batchSize);
                results.Add(pbkdf2Result);
                Console.WriteLine($"PBKDF2 Batch: BatchSize={batchSize}, Time={pbkdf2Result.AverageTimeMs:F3}ms, Ops/Sec={pbkdf2Result.OperationsPerSecond:F0}");

                // HKDF Batch
                var hkdfResult = await BenchmarkHkdfBatchAsync(batchSize);
                results.Add(hkdfResult);
                Console.WriteLine($"HKDF Batch: BatchSize={batchSize}, Time={hkdfResult.AverageTimeMs:F3}ms, Ops/Sec={hkdfResult.OperationsPerSecond:F0}");
            }

            return results;
        }

        private static async Task<BatchBenchmarkResult> BenchmarkPbkdf2BatchAsync(int batchSize)
        {
            var passwordBytes = Encoding.UTF8.GetBytes("benchmark_password");
            var passwords = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(passwordBytes))
                .ToArray();
            var salts = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(16)))
                .ToArray();
            const int iterations = 10000; // Reduced for benchmarking
            const int keyLength = 32;

            // Measure batch operation
            double avgTimeMs = await MeasureOperationAsync(() =>
                BatchKeyDerivationOperations.Pbkdf2BatchAsync(passwords, salts, iterations, keyLength, HashAlgorithmName.SHA256));

            return CreateBenchmarkResultNoThroughput("PBKDF2 Batch", keyLength, batchSize, avgTimeMs);
        }

        private static Task<BatchBenchmarkResult> BenchmarkHkdfBatchAsync(int batchSize)
        {
            var masterKey = GetRandomBytes(32);
            var salts = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(GetRandomBytes(16)))
                .ToArray();
            var infos = Enumerable.Range(0, batchSize)
                .Select(_ => new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes($"benchmark_info_{_}")))
                .ToArray();
            var outputLengths = Enumerable.Repeat(32, batchSize).ToArray();

            // Measure batch operation (sync operation)
            double avgTimeMs = MeasureOperation(() =>
                BatchKeyDerivationOperations.HkdfBatch(masterKey, salts, infos, outputLengths, HashAlgorithmName.SHA256));

            return Task.FromResult(CreateBenchmarkResultNoThroughput("HKDF Batch", outputLengths[0], batchSize, avgTimeMs));
        }

        #endregion

        #region Helper Methods

        private static byte[] GetRandomBytes(int length)
        {
            var buffer = new byte[length];
            RandomNumberGenerator.Fill(buffer);
            return buffer;
        }

        /// <summary>
        /// Generic benchmark helper that measures async operation with warmup and GC collection.
        /// </summary>
        private static async Task<double> MeasureOperationAsync(Func<Task> operation, int warmupIterations = WarmupIterations, int benchmarkIterations = BenchmarkIterations)
        {
            // Warmup
            for (int i = 0; i < warmupIterations; i++)
            {
                await operation();
            }

            // Benchmark
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < benchmarkIterations; i++)
            {
                await operation();
            }
            sw.Stop();

            return sw.Elapsed.TotalMilliseconds / benchmarkIterations;
        }

        /// <summary>
        /// Generic benchmark helper that measures sync operation with warmup and GC collection.
        /// </summary>
        private static double MeasureOperation(Action operation, int warmupIterations = WarmupIterations, int benchmarkIterations = BenchmarkIterations)
        {
            // Warmup
            for (int i = 0; i < warmupIterations; i++)
            {
                operation();
            }

            // Benchmark
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < benchmarkIterations; i++)
            {
                operation();
            }
            sw.Stop();

            return sw.Elapsed.TotalMilliseconds / benchmarkIterations;
        }

        /// <summary>
        /// Creates a benchmark result with calculated metrics.
        /// </summary>
        private static BatchBenchmarkResult CreateBenchmarkResult(
            string operationName,
            int dataSize,
            int batchSize,
            double avgTimeMs,
            double speedup = 1.0)
        {
            long totalBytes = (long)dataSize * batchSize;
            double throughputMBps = (totalBytes / (1024.0 * 1024.0)) / (avgTimeMs / 1000.0);
            double opsPerSec = batchSize / (avgTimeMs / 1000.0);
            double latencyPerOpUs = (avgTimeMs * 1000.0) / batchSize;

            return new BatchBenchmarkResult
            {
                OperationName = operationName,
                DataSize = dataSize,
                BatchSize = batchSize,
                ParallelismDegree = 0, // Auto
                AverageTimeMs = avgTimeMs,
                ThroughputMBps = throughputMBps,
                OperationsPerSecond = opsPerSec,
                LatencyPerOperationUs = latencyPerOpUs,
                SpeedupVsSequential = speedup
            };
        }

        /// <summary>
        /// Creates a benchmark result without throughput calculation (for non-data operations).
        /// </summary>
        private static BatchBenchmarkResult CreateBenchmarkResultNoThroughput(
            string operationName,
            int dataSize,
            int batchSize,
            double avgTimeMs,
            double speedup = 1.0)
        {
            double opsPerSec = batchSize / (avgTimeMs / 1000.0);
            double latencyPerOpUs = (avgTimeMs * 1000.0) / batchSize;

            return new BatchBenchmarkResult
            {
                OperationName = operationName,
                DataSize = dataSize,
                BatchSize = batchSize,
                ParallelismDegree = 0,
                AverageTimeMs = avgTimeMs,
                ThroughputMBps = 0, // Not applicable
                OperationsPerSecond = opsPerSec,
                LatencyPerOperationUs = latencyPerOpUs,
                SpeedupVsSequential = speedup
            };
        }

        #endregion

        /// <summary>
        /// Example program to run benchmarks and display results.
        /// </summary>
        public static async Task Main(string[] args)
        {
            Console.WriteLine("HeroCrypt Batch Operations Benchmark Suite");
            Console.WriteLine("===========================================\n");

            try
            {
                var results = await RunAllBenchmarksAsync();
                results.PrintSummary();

                Console.WriteLine("\n=== Benchmark Complete ===");
                Console.WriteLine($"Total operations benchmarked: {results.Results.Count}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nBenchmark failed with error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }

#endif
