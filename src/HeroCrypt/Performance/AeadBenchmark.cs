using HeroCrypt.Cryptography.Symmetric.ChaCha20Poly1305;
using HeroCrypt.Cryptography.Symmetric.XChaCha20Poly1305;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Security.Cryptography;

namespace HeroCrypt.Performance;

/// <summary>
/// Benchmark suite for AEAD algorithms
/// Measures performance of ChaCha20-Poly1305, AES-GCM, and XChaCha20-Poly1305
/// </summary>
public class AeadBenchmark
{
    private readonly ILogger<AeadBenchmark>? _logger;
    private readonly RandomNumberGenerator _rng;

    public AeadBenchmark(ILogger<AeadBenchmark>? logger = null)
    {
        _logger = logger;
        _rng = RandomNumberGenerator.Create();
    }

    /// <summary>
    /// Runs comprehensive AEAD benchmarks
    /// </summary>
    /// <returns>Benchmark results</returns>
    public async Task<AeadBenchmarkResults> RunBenchmarksAsync()
    {
        _logger?.LogInformation("Starting AEAD performance benchmarks");

        var results = new AeadBenchmarkResults();
        var dataSizes = new[] { 64, 1024, 16 * 1024, 64 * 1024, 1024 * 1024 };

        foreach (var size in dataSizes)
        {
            _logger?.LogInformation("Benchmarking {Size} byte messages", size);

            var data = new byte[size];
            _rng.GetBytes(data);

            // Benchmark ChaCha20-Poly1305
            var chachaResult = await BenchmarkChaCha20Poly1305Async(data);
            results.ChaCha20Poly1305Results.Add(size, chachaResult);

            // Benchmark XChaCha20-Poly1305
            var xchachaResult = await BenchmarkXChaCha20Poly1305Async(data);
            results.XChaCha20Poly1305Results.Add(size, xchachaResult);

            // Benchmark AES-GCM (if available)
#if NET6_0_OR_GREATER
            var aes128Result = await BenchmarkAes128GcmAsync(data);
            results.Aes128GcmResults.Add(size, aes128Result);

            var aes256Result = await BenchmarkAes256GcmAsync(data);
            results.Aes256GcmResults.Add(size, aes256Result);
#else
            _logger?.LogWarning("AES-GCM not available in this .NET version");
#endif
        }

        _logger?.LogInformation("AEAD benchmarks completed");
        LogResults(results);

        return results;
    }

    /// <summary>
    /// Benchmarks ChaCha20-Poly1305 performance
    /// </summary>
    private Task<AlgorithmBenchmarkResult> BenchmarkChaCha20Poly1305Async(byte[] data)
    {
        var key = new byte[ChaCha20Poly1305Core.KeySize];
        var nonce = new byte[ChaCha20Poly1305Core.NonceSize];
        _rng.GetBytes(key);
        _rng.GetBytes(nonce);

        var ciphertext = new byte[data.Length + ChaCha20Poly1305Core.TagSize];
        var decrypted = new byte[data.Length];

        const int iterations = 1000;
        var encryptTimes = new double[iterations];
        var decryptTimes = new double[iterations];

        // Warm up
        for (var i = 0; i < 10; i++)
        {
            ChaCha20Poly1305Core.Encrypt(ciphertext, data, key, nonce);
            ChaCha20Poly1305Core.Decrypt(decrypted, ciphertext, key, nonce);
        }

        // Benchmark encryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            ChaCha20Poly1305Core.Encrypt(ciphertext, data, key, nonce);
            stopwatch.Stop();
            encryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        // Benchmark decryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            ChaCha20Poly1305Core.Decrypt(decrypted, ciphertext, key, nonce);
            stopwatch.Stop();
            decryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        return Task.FromResult(new AlgorithmBenchmarkResult
        {
            Algorithm = "ChaCha20-Poly1305",
            DataSize = data.Length,
            EncryptionTimes = encryptTimes,
            DecryptionTimes = decryptTimes,
            HardwareAccelerated = false // ChaCha20 is always software in our implementation
        });
    }

    /// <summary>
    /// Benchmarks XChaCha20-Poly1305 performance
    /// </summary>
    private Task<AlgorithmBenchmarkResult> BenchmarkXChaCha20Poly1305Async(byte[] data)
    {
        var key = new byte[XChaCha20Poly1305Core.KeySize];
        var nonce = new byte[XChaCha20Poly1305Core.NonceSize];
        _rng.GetBytes(key);
        _rng.GetBytes(nonce);

        var ciphertext = new byte[data.Length + XChaCha20Poly1305Core.TagSize];
        var decrypted = new byte[data.Length];

        const int iterations = 1000;
        var encryptTimes = new double[iterations];
        var decryptTimes = new double[iterations];

        // Warm up
        for (var i = 0; i < 10; i++)
        {
            XChaCha20Poly1305Core.Encrypt(ciphertext, data, key, nonce);
            XChaCha20Poly1305Core.Decrypt(decrypted, ciphertext, key, nonce);
        }

        // Benchmark encryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            XChaCha20Poly1305Core.Encrypt(ciphertext, data, key, nonce);
            stopwatch.Stop();
            encryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        // Benchmark decryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            XChaCha20Poly1305Core.Decrypt(decrypted, ciphertext, key, nonce);
            stopwatch.Stop();
            decryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        return Task.FromResult(new AlgorithmBenchmarkResult
        {
            Algorithm = "XChaCha20-Poly1305",
            DataSize = data.Length,
            EncryptionTimes = encryptTimes,
            DecryptionTimes = decryptTimes,
            HardwareAccelerated = false
        });
    }

    /// <summary>
    /// Benchmarks AES-128-GCM performance
    /// </summary>
    private Task<AlgorithmBenchmarkResult> BenchmarkAes128GcmAsync(byte[] data)
    {
#if NET6_0_OR_GREATER
        var key = new byte[16]; // AES-128 key size
        var nonce = new byte[12]; // AES-GCM nonce size
        _rng.GetBytes(key);
        _rng.GetBytes(nonce);

        var ciphertext = new byte[data.Length + 16]; // + tag size
        var decrypted = new byte[data.Length];

        const int iterations = 1000;
        var encryptTimes = new double[iterations];
        var decryptTimes = new double[iterations];

        using var aes = new AesGcm(key);

        // Warm up
        for (var i = 0; i < 10; i++)
        {
            var tag = ciphertext.AsSpan(data.Length, 16);
            var actualCiphertext = ciphertext.AsSpan(0, data.Length);
            aes.Encrypt(nonce, data, actualCiphertext, tag);
            aes.Decrypt(nonce, actualCiphertext, tag, decrypted);
        }

        // Benchmark encryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            var tag = ciphertext.AsSpan(data.Length, 16);
            var actualCiphertext = ciphertext.AsSpan(0, data.Length);
            aes.Encrypt(nonce, data, actualCiphertext, tag);
            stopwatch.Stop();
            encryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        // Benchmark decryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            var tag = ciphertext.AsSpan(data.Length, 16);
            var actualCiphertext = ciphertext.AsSpan(0, data.Length);
            aes.Decrypt(nonce, actualCiphertext, tag, decrypted);
            stopwatch.Stop();
            decryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        return Task.FromResult(new AlgorithmBenchmarkResult
        {
            Algorithm = "AES-128-GCM",
            DataSize = data.Length,
            EncryptionTimes = encryptTimes,
            DecryptionTimes = decryptTimes,
            HardwareAccelerated = true // AES-GCM hardware acceleration in .NET 6+
        });
#else
        return Task.FromException<AlgorithmBenchmarkResult>(new NotSupportedException("AES-GCM requires .NET 6 or higher"));
#endif
    }

    /// <summary>
    /// Benchmarks AES-256-GCM performance
    /// </summary>
    private Task<AlgorithmBenchmarkResult> BenchmarkAes256GcmAsync(byte[] data)
    {
#if NET6_0_OR_GREATER
        var key = new byte[32]; // AES-256 key size
        var nonce = new byte[12]; // AES-GCM nonce size
        _rng.GetBytes(key);
        _rng.GetBytes(nonce);

        var ciphertext = new byte[data.Length + 16]; // + tag size
        var decrypted = new byte[data.Length];

        const int iterations = 1000;
        var encryptTimes = new double[iterations];
        var decryptTimes = new double[iterations];

        using var aes = new AesGcm(key);

        // Warm up
        for (var i = 0; i < 10; i++)
        {
            var tag = ciphertext.AsSpan(data.Length, 16);
            var actualCiphertext = ciphertext.AsSpan(0, data.Length);
            aes.Encrypt(nonce, data, actualCiphertext, tag);
            aes.Decrypt(nonce, actualCiphertext, tag, decrypted);
        }

        // Benchmark encryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            var tag = ciphertext.AsSpan(data.Length, 16);
            var actualCiphertext = ciphertext.AsSpan(0, data.Length);
            aes.Encrypt(nonce, data, actualCiphertext, tag);
            stopwatch.Stop();
            encryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        // Benchmark decryption
        for (var i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            var tag = ciphertext.AsSpan(data.Length, 16);
            var actualCiphertext = ciphertext.AsSpan(0, data.Length);
            aes.Decrypt(nonce, actualCiphertext, tag, decrypted);
            stopwatch.Stop();
            decryptTimes[i] = stopwatch.Elapsed.TotalMilliseconds * 1000;
        }

        return Task.FromResult(new AlgorithmBenchmarkResult
        {
            Algorithm = "AES-256-GCM",
            DataSize = data.Length,
            EncryptionTimes = encryptTimes,
            DecryptionTimes = decryptTimes,
            HardwareAccelerated = true // AES-GCM hardware acceleration in .NET 6+
        });
#else
        return Task.FromException<AlgorithmBenchmarkResult>(new NotSupportedException("AES-GCM requires .NET 6 or higher"));
#endif
    }

    /// <summary>
    /// Logs benchmark results
    /// </summary>
    private void LogResults(AeadBenchmarkResults results)
    {
        _logger?.LogInformation("=== AEAD Benchmark Results ===");

        foreach (var kvp in results.ChaCha20Poly1305Results)
        {
            LogAlgorithmResult(kvp.Value);
        }

        foreach (var kvp in results.XChaCha20Poly1305Results)
        {
            LogAlgorithmResult(kvp.Value);
        }

        foreach (var kvp in results.Aes128GcmResults)
        {
            LogAlgorithmResult(kvp.Value);
        }

        foreach (var kvp in results.Aes256GcmResults)
        {
            LogAlgorithmResult(kvp.Value);
        }
    }

    /// <summary>
    /// Logs results for a specific algorithm
    /// </summary>
    private void LogAlgorithmResult(AlgorithmBenchmarkResult result)
    {
        var avgEncrypt = CalculateAverage(result.EncryptionTimes);
        var avgDecrypt = CalculateAverage(result.DecryptionTimes);
        var encryptThroughput = (result.DataSize / 1024.0 / 1024.0) / (avgEncrypt / 1_000_000.0); // MB/s
        var decryptThroughput = (result.DataSize / 1024.0 / 1024.0) / (avgDecrypt / 1_000_000.0); // MB/s

        _logger?.LogInformation(
            "{Algorithm} ({DataSize} bytes): Encrypt {EncryptTime:F2}μs ({EncryptThroughput:F2} MB/s), " +
            "Decrypt {DecryptTime:F2}μs ({DecryptThroughput:F2} MB/s), HW Accel: {HardwareAccelerated}",
            result.Algorithm, result.DataSize, avgEncrypt, encryptThroughput,
            avgDecrypt, decryptThroughput, result.HardwareAccelerated);
    }

    /// <summary>
    /// Calculates the average of an array of values
    /// </summary>
    private static double CalculateAverage(double[] values)
    {
        var sum = 0.0;
        foreach (var value in values)
        {
            sum += value;
        }
        return sum / values.Length;
    }

    /// <summary>
    /// Disposes resources
    /// </summary>
    public void Dispose()
    {
        _rng?.Dispose();
    }
}

/// <summary>
/// Complete benchmark results for all AEAD algorithms
/// </summary>
public class AeadBenchmarkResults
{
    public Dictionary<int, AlgorithmBenchmarkResult> ChaCha20Poly1305Results { get; } = new();
    public Dictionary<int, AlgorithmBenchmarkResult> XChaCha20Poly1305Results { get; } = new();
    public Dictionary<int, AlgorithmBenchmarkResult> Aes128GcmResults { get; } = new();
    public Dictionary<int, AlgorithmBenchmarkResult> Aes256GcmResults { get; } = new();
}

/// <summary>
/// Benchmark result for a specific algorithm and data size
/// </summary>
public class AlgorithmBenchmarkResult
{
    public string Algorithm { get; set; } = string.Empty;
    public int DataSize { get; set; }
    public double[] EncryptionTimes { get; set; } = Array.Empty<double>();
    public double[] DecryptionTimes { get; set; } = Array.Empty<double>();
    public bool HardwareAccelerated { get; set; }

    public double AverageEncryptionTime => EncryptionTimes.Length > 0 ? EncryptionTimes.Average() : 0;
    public double AverageDecryptionTime => DecryptionTimes.Length > 0 ? DecryptionTimes.Average() : 0;
    public double EncryptionThroughputMBps => DataSize > 0 ? (DataSize / 1024.0 / 1024.0) / (AverageEncryptionTime / 1_000_000.0) : 0;
    public double DecryptionThroughputMBps => DataSize > 0 ? (DataSize / 1024.0 / 1024.0) / (AverageDecryptionTime / 1_000_000.0) : 0;
}