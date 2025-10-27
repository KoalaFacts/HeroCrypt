using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;
using HeroCrypt.Performance.Simd;
using HeroCrypt.Performance.Memory;
using HeroCrypt.Performance.Parallel;
using HeroCrypt.Performance.Batch;

namespace HeroCrypt.Tests;

/// <summary>
/// Performance tests for SIMD, memory pooling, parallel, and batch operations
///
/// These tests verify correctness and provide basic performance metrics.
/// For detailed benchmarks, use BenchmarkDotNet with the companion benchmark project.
/// </summary>
public class PerformanceTests
{
    private readonly ITestOutputHelper _output;

    public PerformanceTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region SIMD Tests

    [Fact]
    public void SimdXor_ProducesCorrectResults()
    {
        // Arrange
        var source = new byte[256];
        var key = new byte[256];
        var expected = new byte[256];
        var actual = new byte[256];

        RandomNumberGenerator.Fill(source);
        RandomNumberGenerator.Fill(key);

        // Calculate expected result with scalar XOR
        for (int i = 0; i < source.Length; i++)
        {
            expected[i] = (byte)(source[i] ^ key[i]);
        }

        // Act
        SimdAccelerator.Xor(source, key, actual);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(16)]      // SSE2 size
    [InlineData(32)]      // AVX2 size
    [InlineData(64)]      // AVX-512 size
    [InlineData(100)]     // Odd size
    [InlineData(1024)]    // Large size
    public void SimdXor_HandlesVariousSizes(int size)
    {
        // Arrange
        var source = new byte[size];
        var key = new byte[size];
        var result = new byte[size];

        RandomNumberGenerator.Fill(source);
        RandomNumberGenerator.Fill(key);

        // Act & Assert (should not throw)
        SimdAccelerator.Xor(source, key, result);

        // Verify at least some bytes were XORed
        Assert.NotEqual(new byte[size], result);
    }

    [Fact]
    public void SimdConstantTimeEquals_ReturnsTrueForEqualArrays()
    {
        // Arrange
        var a = new byte[256];
        RandomNumberGenerator.Fill(a);
        var b = a.ToArray();

        // Act
        var result = SimdAccelerator.ConstantTimeEquals(a, b);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void SimdConstantTimeEquals_ReturnsFalseForDifferentArrays()
    {
        // Arrange
        var a = new byte[256];
        var b = new byte[256];
        RandomNumberGenerator.Fill(a);
        RandomNumberGenerator.Fill(b);

        // Act
        var result = SimdAccelerator.ConstantTimeEquals(a, b);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void SimdConstantTimeEquals_ReturnsFalseForDifferentLengths()
    {
        // Arrange
        var a = new byte[256];
        var b = new byte[128];

        // Act
        var result = SimdAccelerator.ConstantTimeEquals(a, b);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void SimdCapabilities_ReportsCorrectly()
    {
        // Act
        var caps = SimdAccelerator.Capabilities;

        // Assert
        _output.WriteLine($"SIMD Capabilities:");
        _output.WriteLine($"  AVX-512: {caps.HasAvx512}");
        _output.WriteLine($"  AVX2: {caps.HasAvx2}");
        _output.WriteLine($"  SSE2: {caps.HasSse2}");
        _output.WriteLine($"  ARM NEON: {caps.HasNeon}");

        // At least one capability should be present on modern hardware
        Assert.True(caps.HasSse2 || caps.HasNeon || caps.HasAvx2 || caps.HasAvx512);
    }

    [Fact]
    public void SimdXor_PerformanceBenchmark()
    {
        // Arrange
        const int size = 1024 * 1024; // 1 MB
        const int iterations = 100;

        var source = new byte[size];
        var key = new byte[size];
        var result = new byte[size];

        RandomNumberGenerator.Fill(source);
        RandomNumberGenerator.Fill(key);

        // Warmup
        SimdAccelerator.Xor(source, key, result);

        // Act
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            SimdAccelerator.Xor(source, key, result);
        }
        sw.Stop();

        // Report
        var throughput = (size * iterations / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"SIMD XOR throughput: {throughput:F2} MB/s");
        _output.WriteLine($"Average time per operation: {sw.ElapsedMilliseconds / (double)iterations:F3} ms");

        // Note: This is an informational benchmark. Performance varies significantly by environment:
        // - Modern physical hardware with AVX2/AVX-512: 1,000-10,000 MB/s
        // - Virtualized/CI environments: 200-1,000 MB/s (limited SIMD support)
        // - Older CPUs without advanced SIMD: 500-2,000 MB/s
        // Correctness is validated by SimdXor_ProducesCorrectResults and related tests.
        _output.WriteLine($"Performance class: {(throughput >= 1000 ? "Excellent (native SIMD)" : throughput >= 500 ? "Good" : "Limited (virtualized/old CPU)")}");
    }

    #endregion

    #region Memory Pool Tests

    [Fact]
    public void CryptoMemoryPool_RentAndReturn_WorksCorrectly()
    {
        // Arrange & Act
        var buffer = CryptoMemoryPool.Rent(1024);

        // Assert
        Assert.NotNull(buffer);
        Assert.True(buffer.Length >= 1024);

        // All bytes should be zero (clearBuffer = true by default)
        Assert.All(buffer.Take(1024), b => Assert.Equal(0, b));

        // Cleanup
        CryptoMemoryPool.Return(buffer);
    }

    [Fact]
    public void CryptoMemoryPool_RentWithoutClear_MayContainGarbage()
    {
        // Arrange
        var buffer1 = CryptoMemoryPool.Rent(1024, clearBuffer: false);

        // Fill with data
        for (int i = 0; i < 1024; i++)
        {
            buffer1[i] = 0xFF;
        }

        // Return without clearing
        CryptoMemoryPool.Return(buffer1, clearBuffer: false);

        // Act - rent again without clearing
        var buffer2 = CryptoMemoryPool.Rent(1024, clearBuffer: false);

        // Assert - might be same buffer with data still present
        // (Not guaranteed, but possible with ArrayPool)
        Assert.NotNull(buffer2);

        // Cleanup
        CryptoMemoryPool.Return(buffer2);
    }

    [Fact]
    public void PooledBuffer_AutomaticallyReturnsOnDispose()
    {
        // Arrange & Act
        byte[] capturedBuffer;
        using (var pooled = CryptoMemoryPool.RentScoped(1024))
        {
            capturedBuffer = new byte[pooled.Length];
            pooled.Span.CopyTo(capturedBuffer);

            Assert.True(pooled.Length >= 1024);
            Assert.NotEqual(0, pooled.Span.Length);
        }

        // Assert - after dispose, buffer is returned
        // We can't directly verify this, but no exceptions should occur
        Assert.NotNull(capturedBuffer);
    }

    [Fact]
    public void PooledBuffer_SpanWithLength_ReturnsCorrectSlice()
    {
        // Arrange
        using var pooled = CryptoMemoryPool.RentScoped(1024);

        // Act
        var span = pooled.GetSpan(512);

        // Assert
        Assert.Equal(512, span.Length);
    }

    [Fact]
    public void StackBuffer_Create_WorksForSmallSizes()
    {
        // Arrange & Act
        using var buffer = StackBuffer.Create(256);

        // Assert
        Assert.Equal(256, buffer.Length);
        Assert.NotEqual(0, buffer.Span.Length);

        // Should be stack-allocated for <= 1KB
        // (Can't directly verify, but should not throw)
    }

    [Fact]
    public void StackBuffer_Create_WorksForLargeSizes()
    {
        // Arrange & Act
        using var buffer = StackBuffer.Create(2048);

        // Assert
        Assert.Equal(2048, buffer.Length);

        // For > 1KB, uses pooled buffer internally
    }

    [Fact]
    public void PinnedBuffer_Address_IsValid()
    {
        // Arrange & Act
        using var buffer = CryptoMemoryUtilities.AllocatePinned(1024);

        // Assert
        Assert.NotEqual(IntPtr.Zero, buffer.Address);
        Assert.Equal(1024, buffer.Length);
        Assert.Equal(1024, buffer.Span.Length);
    }

    [Fact]
    public void CryptoMemoryUtilities_AlignToCacheLine_WorksCorrectly()
    {
        // Act & Assert
        Assert.Equal(64, CryptoMemoryUtilities.AlignToCacheLine(1));
        Assert.Equal(64, CryptoMemoryUtilities.AlignToCacheLine(64));
        Assert.Equal(128, CryptoMemoryUtilities.AlignToCacheLine(65));
        Assert.Equal(128, CryptoMemoryUtilities.AlignToCacheLine(128));
    }

    [Fact]
    public void CryptoMemoryUtilities_GetSimdAlignedSize_WorksCorrectly()
    {
        // Act & Assert
        Assert.Equal(64, CryptoMemoryUtilities.GetSimdAlignedSize(1));
        Assert.Equal(64, CryptoMemoryUtilities.GetSimdAlignedSize(64));
        Assert.Equal(128, CryptoMemoryUtilities.GetSimdAlignedSize(65));
    }

    [Fact]
    public void CryptoMemoryUtilities_GetMemoryPressure_ReturnsValidValue()
    {
        // Act
        var pressure = CryptoMemoryUtilities.GetMemoryPressure();

        // Assert
        Assert.True(Enum.IsDefined(typeof(MemoryPressure), pressure));
        _output.WriteLine($"Current memory pressure: {pressure}");
    }

    #endregion

    #region Parallel Operations Tests

    [Fact]
    public async Task ParallelCryptoOperations_ProcessInParallelAsync_WorksCorrectly()
    {
        // Arrange
        const long dataLength = 1024 * 1024; // 1 MB
        var processedChunks = 0;

        // Act
        await ParallelCryptoOperations.ProcessInParallelAsync(
            dataLength,
            async (offset, length) =>
            {
                await Task.Delay(1); // Simulate work
                Interlocked.Increment(ref processedChunks);
            });

        // Assert
        Assert.True(processedChunks > 0);
        _output.WriteLine($"Processed {processedChunks} chunks");
    }

    [Fact]
    public void ParallelCryptoOperations_ProcessInParallel_WorksCorrectly()
    {
        // Arrange
        const long dataLength = 1024 * 1024;
        var processedBytes = 0L;

        // Act
        ParallelCryptoOperations.ProcessInParallel(
            dataLength,
            (offset, length) =>
            {
                Interlocked.Add(ref processedBytes, length);
            });

        // Assert
        Assert.Equal(dataLength, processedBytes);
    }

    [Fact]
    public async Task ParallelCryptoOperations_ProcessBatchAsync_WorksCorrectly()
    {
        // Arrange
        var inputs = Enumerable.Range(0, 100)
            .Select(i => new ReadOnlyMemory<byte>(new byte[] { (byte)i }))
            .ToArray();

        // Act
        var results = await ParallelCryptoOperations.ProcessBatchAsync<ReadOnlyMemory<byte>, byte>(
            inputs,
            async input => await Task.FromResult((byte)(input.Span[0] * 2)));

        // Assert
        Assert.Equal(100, results.Length);
        for (int i = 0; i < 100; i++)
        {
            Assert.Equal((byte)(i * 2), results[i]);
        }
    }

    [Fact]
    public void ParallelCryptoOperations_ProcessBatch_WorksCorrectly()
    {
        // Arrange
        var inputs = Enumerable.Range(0, 100).ToArray();

        // Act
        var results = ParallelCryptoOperations.ProcessBatch<int, int>(
            inputs,
            x => x * 2);

        // Assert
        Assert.Equal(100, results.Length);
        for (int i = 0; i < 100; i++)
        {
            Assert.Equal(i * 2, results[i]);
        }
    }

    [Fact]
    public void ParallelCryptoOperations_CalculateChunkSize_ReturnsReasonableValues()
    {
        // Act & Assert
        // For very small data, chunk size should equal data size (no point splitting 1KB into 64KB chunks)
        var tiny = ParallelCryptoOperations.CalculateChunkSize(1024, 4);
        Assert.Equal(1024, tiny);

        // For data larger than minimum chunk size, enforce minimum
        var small = ParallelCryptoOperations.CalculateChunkSize(256 * 1024, 4);
        Assert.True(small >= 64 * 1024); // Minimum chunk size

        // For very large data, enforce maximum chunk size
        var large = ParallelCryptoOperations.CalculateChunkSize(100 * 1024 * 1024, 4);
        Assert.True(large <= 10 * 1024 * 1024); // Maximum chunk size

        // For medium data, should be reasonable
        var optimal = ParallelCryptoOperations.CalculateChunkSize(4 * 1024 * 1024, 4);
        Assert.True(optimal > 0);

        _output.WriteLine($"Chunk sizes: tiny={tiny}, small={small}, large={large}, optimal={optimal}");
    }

    #endregion

    #region Batch Operations Tests

    [Fact]
    public async Task BatchHashOperations_Sha256Batch_WorksCorrectly()
    {
        // Arrange
        var inputs = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 },
            new byte[] { 7, 8, 9 }
        };

        // Act
        var results = await BatchHashOperations.Sha256BatchAsync(inputs);

        // Assert
        Assert.Equal(3, results.Length);
        Assert.All(results, hash => Assert.Equal(32, hash.Length)); // SHA-256 = 32 bytes

        // Verify each hash individually
        for (int i = 0; i < inputs.Length; i++)
        {
            var expected = SHA256.HashData(inputs[i].Span);
            Assert.Equal(expected, results[i]);
        }
    }

    [Fact]
    public void BatchHashOperations_Sha256BatchSync_WorksCorrectly()
    {
        // Arrange
        var inputs = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 }
        };

        // Act
        var results = BatchHashOperations.Sha256Batch(inputs);

        // Assert
        Assert.Equal(2, results.Length);
        Assert.All(results, hash => Assert.Equal(32, hash.Length));
    }

    [Fact]
    public async Task BatchHashOperations_Sha512Batch_WorksCorrectly()
    {
        // Arrange
        var inputs = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 }
        };

        // Act
        var results = await BatchHashOperations.Sha512BatchAsync(inputs);

        // Assert
        Assert.Single(results);
        Assert.Equal(64, results[0].Length); // SHA-512 = 64 bytes
    }

    [Fact]
    public void BatchHashOperations_VerifyHashBatch_WorksCorrectly()
    {
        // Arrange
        var inputs = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 }
        };

        var expectedHashes = inputs
            .Select(input => new ReadOnlyMemory<byte>(SHA256.HashData(input.Span)))
            .ToArray();

        // Act
        var results = BatchHashOperations.VerifyHashBatch(
            inputs,
            expectedHashes,
            HashAlgorithmName.SHA256);

        // Assert
        Assert.All(results, result => Assert.True(result));
    }

    [Fact]
    public void BatchHashOperations_VerifyHashBatch_DetectsInvalidHashes()
    {
        // Arrange
        var inputs = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 }
        };

        var wrongHash = new ReadOnlyMemory<byte>[]
        {
            new byte[32] // All zeros - wrong hash
        };

        // Act
        var results = BatchHashOperations.VerifyHashBatch(
            inputs,
            wrongHash,
            HashAlgorithmName.SHA256);

        // Assert
        Assert.All(results, result => Assert.False(result));
    }

    [Fact]
    public void BatchHmacOperations_HmacSha256Batch_WorksCorrectly()
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var messages = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 }
        };

        // Act
        var results = BatchHmacOperations.HmacSha256Batch(key, messages);

        // Assert
        Assert.Equal(2, results.Length);
        Assert.All(results, hmac => Assert.Equal(32, hmac.Length));

        // Verify correctness
        using var hmacAlg = new HMACSHA256(key);
        var expected = hmacAlg.ComputeHash(messages[0].ToArray());
        Assert.Equal(expected, results[0]);
    }

    [Fact]
    public void BatchHmacOperations_VerifyHmacBatch_WorksCorrectly()
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var messages = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 }
        };

        var expectedTags = BatchHmacOperations.HmacSha256Batch(key, messages)
            .Select(tag => new ReadOnlyMemory<byte>(tag))
            .ToArray();

        // Act
        var results = BatchHmacOperations.VerifyHmacBatch(key, messages, expectedTags);

        // Assert
        Assert.All(results, result => Assert.True(result));
    }

    [Fact]
    public async Task BatchEncryptionOperations_AesGcmEncryptBatch_WorksCorrectly()
    {
        // Arrange
        var key = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        var plaintexts = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3, 4, 5 },
            new byte[] { 6, 7, 8, 9, 10 }
        };

        // Act
        var results = await BatchEncryptionOperations.AesGcmEncryptBatchAsync(
            key, nonce, plaintexts);

        // Assert
        Assert.Equal(2, results.Length);
        Assert.All(results, result =>
        {
            Assert.NotNull(result.Ciphertext);
            Assert.Equal(12, result.Nonce.Length);
            Assert.Equal(16, result.Tag.Length);
        });
    }

    [Fact]
    public async Task BatchSignatureOperations_SignAndVerifyBatch_WorksCorrectly()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var messages = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 }
        };

        // Act - Sign
        var signatures = await BatchSignatureOperations.SignBatchAsync(
            rsa,
            messages,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Act - Verify
        var results = await BatchSignatureOperations.VerifyBatchAsync(
            rsa,
            messages,
            signatures.Select(s => new ReadOnlyMemory<byte>(s)).ToArray(),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Assert
        Assert.Equal(2, signatures.Length);
        Assert.All(results, result => Assert.True(result));
    }

    [Fact]
    public async Task BatchKeyDerivationOperations_Pbkdf2Batch_WorksCorrectly()
    {
        // Arrange
        var passwords = new ReadOnlyMemory<byte>[]
        {
            "password1"u8.ToArray(),
            "password2"u8.ToArray()
        };

        var salt1 = new byte[16];
        var salt2 = new byte[16];
        RandomNumberGenerator.Fill(salt1);
        RandomNumberGenerator.Fill(salt2);

        var salts = new ReadOnlyMemory<byte>[]
        {
            salt1,
            salt2
        };

        // Act
        var results = await BatchKeyDerivationOperations.Pbkdf2BatchAsync(
            passwords,
            salts,
            iterations: 10000,
            outputLength: 32,
            HashAlgorithmName.SHA256);

        // Assert
        Assert.Equal(2, results.Length);
        Assert.All(results, key => Assert.Equal(32, key.Length));

        // Verify correctness for first key
        using var pbkdf2 = new Rfc2898DeriveBytes(
            passwords[0].ToArray(),
            salts[0].ToArray(),
            10000,
            HashAlgorithmName.SHA256);
        var expected = pbkdf2.GetBytes(32);
        Assert.Equal(expected, results[0]);
    }

    #endregion

    #region Performance Benchmarks

    [Fact]
    public void Benchmark_SimdVsScalarXor()
    {
        // Arrange
        const int size = 1024 * 1024;
        const int iterations = 100;

        var source = new byte[size];
        var key = new byte[size];
        var result = new byte[size];

        RandomNumberGenerator.Fill(source);
        RandomNumberGenerator.Fill(key);

        // SIMD XOR
        var simdSw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            SimdAccelerator.Xor(source, key, result);
        }
        simdSw.Stop();

        // Scalar XOR
        var scalarSw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            for (int j = 0; j < size; j++)
            {
                result[j] = (byte)(source[j] ^ key[j]);
            }
        }
        scalarSw.Stop();

        // Report
        _output.WriteLine($"SIMD XOR: {simdSw.ElapsedMilliseconds} ms");
        _output.WriteLine($"Scalar XOR: {scalarSw.ElapsedMilliseconds} ms");
        var speedup = scalarSw.ElapsedMilliseconds / (double)simdSw.ElapsedMilliseconds;
        _output.WriteLine($"Speedup: {speedup:F2}x");

        // Note: This is an informational benchmark. SIMD performance varies significantly by environment.
        // In virtualized/CI environments, SIMD may be slower due to CPU limitations or hypervisor overhead.
        // On modern physical hardware with AVX2/AVX-512, SIMD typically achieves 2-10x speedup.
        // Correctness is validated by other tests (SimdXor_ProducesCorrectResults, etc.)
        _output.WriteLine($"Environment: {(speedup >= 1.0 ? "SIMD beneficial" : "Scalar faster (virtualized/limited CPU)")}");
    }

    [Fact]
    public async Task Benchmark_BatchVsSequentialHashing()
    {
        // Arrange
        const int count = 100;
        var inputs = Enumerable.Range(0, count)
            .Select(_ =>
            {
                var data = new byte[1024];
                RandomNumberGenerator.Fill(data);
                return new ReadOnlyMemory<byte>(data);
            })
            .ToArray();

        // Sequential hashing
        var sequentialSw = Stopwatch.StartNew();
        var sequentialResults = new byte[count][];
        for (int i = 0; i < count; i++)
        {
            sequentialResults[i] = SHA256.HashData(inputs[i].Span);
        }
        sequentialSw.Stop();

        // Batch hashing
        var batchSw = Stopwatch.StartNew();
        var batchResults = await BatchHashOperations.Sha256BatchAsync(inputs);
        batchSw.Stop();

        // Report
        _output.WriteLine($"Sequential hashing: {sequentialSw.ElapsedMilliseconds} ms");
        _output.WriteLine($"Batch hashing: {batchSw.ElapsedMilliseconds} ms");
        _output.WriteLine($"Speedup: {sequentialSw.ElapsedMilliseconds / (double)batchSw.ElapsedMilliseconds:F2}x");

        // Verify correctness
        for (int i = 0; i < count; i++)
        {
            Assert.Equal(sequentialResults[i], batchResults[i]);
        }
    }

    #endregion
}
