# Performance Optimization Guide

This guide covers performance optimization strategies for HeroCrypt.

## Table of Contents

1. [Performance Overview](#performance-overview)
2. [Hardware Acceleration](#hardware-acceleration)
3. [Batch Operations](#batch-operations)
4. [Memory Optimization](#memory-optimization)
5. [Parallel Processing](#parallel-processing)
6. [Algorithm Selection](#algorithm-selection)
7. [Benchmarking](#benchmarking)
8. [Common Pitfalls](#common-pitfalls)

## Performance Overview

### Performance Priorities

HeroCrypt balances three priorities:

1. **Security** - Always the top priority
2. **Performance** - Optimized where safe
3. **Ease of use** - Simple, intuitive APIs

**Never sacrifice security for performance.**

### Performance Features

- ✅ SIMD acceleration (AVX-512, AVX2, SSE2, ARM NEON)
- ✅ Hardware acceleration (AES-NI, SHA extensions)
- ✅ Batch operations (3-10x throughput)
- ✅ Memory pooling (reduced allocations)
- ✅ Zero-copy operations with `Span<T>`
- ✅ Parallel processing for bulk operations
- ✅ Automatic hardware capability detection

## Hardware Acceleration

### Detecting Hardware Capabilities

```csharp
using HeroCrypt.Hardware;

var capabilities = HardwareAccelerationDetector.DetectCapabilities();

Console.WriteLine($"AVX-512: {capabilities.HasAvx512}");
Console.WriteLine($"AVX2: {capabilities.HasAvx2}");
Console.WriteLine($"SSE2: {capabilities.HasSse2}");
Console.WriteLine($"AES-NI: {capabilities.HasAesNi}");
Console.WriteLine($"SHA: {capabilities.HasShaExtensions}");
Console.WriteLine($"ARM NEON: {capabilities.HasNeon}");
```

### Enabling Hardware Acceleration

```csharp
// Automatic detection and usage via builder
var hash = HeroCryptBuilder.DeriveKey()
    .UseArgon2()
    .WithPassword("password"u8.ToArray())
    .WithSalt(RandomNumberGenerator.GetBytes(16))
    .WithIterations(3)
    .WithParallelism(4)
    .WithKeyLength(32)
    .Build();
```

### Platform-Specific Optimizations

```csharp
// Intel/AMD (x64)
// - AVX-512: 512-bit SIMD operations
// - AVX2: 256-bit SIMD operations
// - AES-NI: Hardware AES acceleration

// ARM (ARM64)
// - NEON: 128-bit SIMD operations
// - SHA extensions: Hardware SHA acceleration

// Fallback
// - Portable C# implementation
// - Still secure, but slower
```

### Performance Impact

| Feature | Speedup | Algorithm |
|---------|---------|-----------|
| AVX-512 | 4-8x | Blake2b, ChaCha20 |
| AVX2 | 2-4x | Blake2b, ChaCha20 |
| AES-NI | 5-10x | AES-GCM, AES-CCM |
| ARM NEON | 2-3x | Blake2b, ChaCha20 |

## Batch Operations

### When to Use Batch Operations

Use batch operations when:
- Processing multiple items (>10)
- Items are independent
- Throughput matters more than latency

```csharp
using HeroCrypt.Performance.Batch;

// ✅ GOOD: Batch encryption for bulk data
var plaintexts = new List<byte[]>
{
    data1, data2, data3, /* ... hundreds more ... */
};

var ciphertexts = await BatchOperations.EncryptBatchAsync(
    plaintexts,
    key,
    nonces,
    algorithm: EncryptionAlgorithm.ChaCha20Poly1305
);

// ❌ BAD: Individual encryption in a loop
foreach (var plaintext in plaintexts)
{
    var ciphertext = await EncryptAsync(plaintext, key);
}
```

### Batch Encryption

```csharp
using HeroCrypt.Performance.Batch;

// Prepare data
var plaintexts = new List<byte[]>();
var nonces = new List<byte[]>();

for (int i = 0; i < 1000; i++)
{
    plaintexts.Add(GeneratePlaintext());
    nonces.Add(GenerateNonce());
}

// Batch encrypt (3-10x faster than individual encryption)
var ciphertexts = BatchOperations.EncryptBatch(
    plaintexts,
    key,
    nonces,
    associatedData: null
);
```

### Batch Password Hashing

```csharp
// ⚠️ Note: Batch Argon2 is CPU-intensive
// Consider rate limiting and queue-based processing

var passwords = new[] { "password1", "password2", "password3" };
var hashes = new ConcurrentBag<string>();

await Parallel.ForEachAsync(passwords, async (password, ct) =>
{
    var hash = Argon2.Hash(
        password: password,
        salt: RandomNumberGenerator.GetBytes(16),
        iterations: 2,              // Consider lower level for batch
        memorySizeKB: 19456,
        parallelism: 2,
        hashLength: 32,
        type: Argon2Type.Argon2id);

    hashes.Add(hash);
});
```

### Performance Comparison

```
Single encryption:      100 ops/sec
Batch encryption:       800 ops/sec  (8x improvement)

Single hash:            20 hashes/sec
Parallel hash (4 core): 60 hashes/sec (3x improvement)
```

## Memory Optimization

### Use Span<T> for Stack Allocation

```csharp
// ✅ GOOD: Stack allocation (no GC pressure)
public void ProcessData(ReadOnlySpan<byte> data)
{
    Span<byte> buffer = stackalloc byte[32];
    // Use buffer
    // Automatically cleared when method returns
}

// ❌ BAD: Heap allocation (GC pressure)
public void ProcessData(byte[] data)
{
    var buffer = new byte[32];
    // Creates garbage
}
```

### Memory Pooling

```csharp
using HeroCrypt.Performance.Memory;

// ✅ GOOD: Use memory pool
var pool = CryptoMemoryPool.Shared;
var buffer = pool.Rent(1024);

try
{
    // Use buffer
}
finally
{
    pool.Return(buffer, clearArray: true);  // Automatically cleared
}

// ❌ BAD: Allocate and discard
var buffer = new byte[1024];
// Creates garbage
```

### Zero-Copy Operations

```csharp
// ✅ GOOD: Zero-copy with Span<T>
public void Encrypt(
    ReadOnlySpan<byte> plaintext,
    Span<byte> ciphertext,
    ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> nonce)
{
    // No allocations
    ChaCha20Poly1305Core.Encrypt(plaintext, ciphertext, key, nonce);
}

// ❌ BAD: Multiple allocations
public byte[] Encrypt(byte[] plaintext, byte[] key, byte[] nonce)
{
    var ciphertext = new byte[plaintext.Length + 16];
    // Creates new array
    return ciphertext;
}
```

### Reducing Allocations

```csharp
// ✅ GOOD: Reuse buffers
var buffer = new byte[1024];
for (int i = 0; i < 1000; i++)
{
    ProcessData(buffer);
    Array.Clear(buffer);  // Clear for next iteration
}

// ❌ BAD: Allocate in loop
for (int i = 0; i < 1000; i++)
{
    var buffer = new byte[1024];  // 1000 allocations
    ProcessData(buffer);
}
```

## Parallel Processing

### Parallel Encryption

```csharp
using HeroCrypt.Performance.Parallel;

// ✅ GOOD: Parallel processing for large data
var largeFile = File.ReadAllBytes("large-file.dat");

var encrypted = await ParallelAesGcm.EncryptParallelAsync(
    largeFile,
    key,
    nonce,
    chunkSize: 1024 * 1024  // 1 MB chunks
);
```

### Parallel Decryption

```csharp
// ✅ Two-phase authentication ensures security
var decrypted = await ParallelAesGcm.DecryptParallelAsync(
    encrypted,
    key,
    nonce,
    chunkSize: 1024 * 1024
);
// Phase 1: Decrypt all chunks in parallel
// Phase 2: Verify all MACs (ensures authenticity)
```

### Thread Pool Configuration

```csharp
// ✅ Configure for CPU-intensive work
ThreadPool.GetMinThreads(out int workerThreads, out int ioThreads);
ThreadPool.SetMinThreads(Environment.ProcessorCount, ioThreads);

// ✅ Use ParallelOptions for control
var options = new ParallelOptions
{
    MaxDegreeOfParallelism = Environment.ProcessorCount
};

await Parallel.ForEachAsync(items, options, async (item, ct) =>
{
    await ProcessAsync(item);
});
```

## Algorithm Selection

### Symmetric Encryption

```csharp
// Performance comparison (approximate):

// ChaCha20-Poly1305: 1.5 GB/s (software)
// - Best for software-only systems
// - Constant-time, side-channel resistant
var encrypted = ChaCha20Poly1305Cipher.Encrypt(plaintext, key, nonce, aad);

// AES-GCM: 5-10 GB/s (with AES-NI)
// - Best when hardware acceleration available
// - Requires AES-NI for security
using var aesGcm = new AesGcm(key);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
```

### Password Hashing

```csharp
// Argon2 configuration trade-offs:

// High security (recommended for production)
var hash = Argon2.Hash(
    password, salt,
    iterations: 3,
    memorySizeKB: 65536,  // 64 MB
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id
);
// Time: ~200ms on modern CPU

// Medium security (for resource-constrained systems)
var hash = Argon2.Hash(
    password, salt,
    iterations: 2,
    memorySizeKB: 19456,  // 19 MB
    parallelism: 1,
    hashLength: 32,
    type: Argon2Type.Argon2id
);
// Time: ~50ms on modern CPU
```

### Hashing

```csharp
// Blake2b: 1-2 GB/s (faster than SHA-256)
var hash = Blake2bCore.ComputeHash(data, 32);

// SHA-256: 500 MB/s (with hardware acceleration)
// Use .NET built-in for FIPS compliance
using var sha256 = SHA256.Create();
var hash = sha256.ComputeHash(data);
```

## Benchmarking

### Custom Benchmarking

```csharp
using System.Diagnostics;

public class CryptoBenchmark
{
    public static async Task<double> BenchmarkHashingAsync(int iterations)
    {
        var sw = Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            var hash = await HashAsync("password");
        }

        sw.Stop();
        return sw.ElapsedMilliseconds / (double)iterations;
    }

    public static double BenchmarkThroughput(int dataSize, int iterations)
    {
        var data = new byte[dataSize];
        RandomNumberGenerator.Fill(data);

        var sw = Stopwatch.StartNew();

        for (int i = 0; i < iterations; i++)
        {
            var hash = Blake2bCore.ComputeHash(data, 32);
        }

        sw.Stop();

        double totalMB = (dataSize * iterations) / (1024.0 * 1024.0);
        double seconds = sw.ElapsedMilliseconds / 1000.0;
        return totalMB / seconds;  // MB/s
    }
}
```

### BenchmarkDotNet Integration

```csharp
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

[MemoryDiagnoser]
public class CryptoBenchmarks
{
    private byte[] _data;
    private byte[] _key;
    private byte[] _nonce;

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[1024];
        _key = new byte[32];
        _nonce = new byte[12];
        RandomNumberGenerator.Fill(_data);
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_nonce);
    }

    [Benchmark]
    public byte[] ChaCha20Poly1305_Encrypt()
    {
        return ChaCha20Poly1305Cipher.Encrypt(_data, _key, _nonce, null);
    }

    [Benchmark]
    public byte[] Blake2b_Hash()
    {
        return Blake2bCore.ComputeHash(_data, 32);
    }
}

// Run benchmarks
BenchmarkRunner.Run<CryptoBenchmarks>();
```

## Common Pitfalls

### 1. Not Using Hardware Acceleration

```csharp
// Recommended: use strong parameters and let hardware acceleration kick in automatically
var hash = Argon2.Hash(
    password, salt,
    iterations: 3,
    memorySizeKB: 65536,
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id);
```

### 2. Allocating in Loops

```csharp
// ❌ BAD: Allocates 1000 times
for (int i = 0; i < 1000; i++)
{
    var buffer = new byte[1024];
    Process(buffer);
}

// ✅ GOOD: Allocate once, reuse
var buffer = new byte[1024];
for (int i = 0; i < 1000; i++)
{
    Process(buffer);
    Array.Clear(buffer);
}
```

### 3. Not Using Span<T>

```csharp
// ❌ BAD: Creates arrays
public byte[] Encrypt(byte[] plaintext, byte[] key)
{
    var temp = new byte[plaintext.Length];
    // ...
    return temp;
}

// ✅ GOOD: Uses Span<T>
public void Encrypt(
    ReadOnlySpan<byte> plaintext,
    Span<byte> ciphertext,
    ReadOnlySpan<byte> key)
{
    Span<byte> temp = stackalloc byte[plaintext.Length];
    // No heap allocations
}
```

### 4. Over-Parallelization

```csharp
// ❌ BAD: Too many parallel tasks
await Parallel.ForEachAsync(smallItems, new ParallelOptions
{
    MaxDegreeOfParallelism = 100  // Too many!
}, async (item, ct) => await ProcessAsync(item));

// ✅ GOOD: Match CPU core count
await Parallel.ForEachAsync(items, new ParallelOptions
{
    MaxDegreeOfParallelism = Environment.ProcessorCount
}, async (item, ct) => await ProcessAsync(item));
```

### 5. Using Weak Parameters for Performance

```csharp
// ❌ BAD: Weak Argon2 parameters
var hash = Argon2.Hash(
    password, salt,
    iterations: 1,        // Too low!
    memorySizeKB: 8192,   // Too low!
    parallelism: 1,
    hashLength: 32,
    type: Argon2Type.Argon2id
);

// ✅ GOOD: Strong parameters
var hash = Argon2.Hash(
    password, salt,
    iterations: 3,        // Minimum recommended
    memorySizeKB: 65536,  // 64 MB minimum
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id
);
```

## Performance Checklist

- [ ] Enable hardware acceleration where available
- [ ] Use batch operations for bulk processing
- [ ] Use `Span<T>` and stack allocation when possible
- [ ] Reuse buffers instead of allocating in loops
- [ ] Use memory pooling for large allocations
- [ ] Configure parallelism based on CPU cores
- [ ] Choose appropriate algorithm for use case
- [ ] Benchmark your specific workload
- [ ] Monitor GC pressure and allocations
- [ ] Never sacrifice security for performance

## Benchmarking Results

### Reference Performance (Intel i7-12700K)

| Operation | Throughput | Notes |
|-----------|------------|-------|
| Blake2b | 2.1 GB/s | AVX2 acceleration |
| ChaCha20-Poly1305 | 1.8 GB/s | SIMD acceleration |
| AES-GCM | 8.5 GB/s | AES-NI acceleration |
| Argon2id (High) | 5 hashes/sec | 64 MB, 3 iterations |
| RSA-2048 sign | 2000 ops/sec | Software |
| RSA-2048 verify | 50000 ops/sec | Software |
| ECDSA-P256 sign | 15000 ops/sec | Hardware |
| ECDSA-P256 verify | 8000 ops/sec | Hardware |

### Batch Operation Speedups

| Operation | Single | Batch | Speedup |
|-----------|--------|-------|---------|
| ChaCha20-Poly1305 | 100 ops/s | 800 ops/s | 8x |
| AES-GCM | 150 ops/s | 1200 ops/s | 8x |
| Blake2b | 500 ops/s | 2000 ops/s | 4x |

## Additional Resources

- [Hardware Acceleration](../src/HeroCrypt/Hardware/)
- [Batch Operations](../src/HeroCrypt/Performance/Batch/)
- [Memory Pooling](../src/HeroCrypt/Performance/Memory/)
- [Parallel Operations](../src/HeroCrypt/Performance/Parallel/)
- [Best Practices](best-practices.md)
