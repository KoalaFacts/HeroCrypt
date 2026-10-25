# Performance and allocation guide

This guide describes **measured HeroCrypt behaviour** and shows public API patterns that exist in the repository. It replaces examples that referenced non-existent batch, parallel, memory-pool and hardware-detection APIs, along with unsourced benchmark multipliers. Do not infer throughput, hardware acceleration or security certification from a feature name.

## Evidence and limits

| Change | What was measured | Scope |
| --- | --- | --- |
| [BLAKE2b span input](performance/blake2b-span-allocation.md) | Unkeyed BLAKE2b-256, 1 KiB input: **2,008 to 960 managed bytes/call**; 1 MiB input: **1,050,017.5–1,050,663.5 to 960 managed bytes/call** | Ubuntu x64, .NET 10.0.13 Release, SDK 10.0.402; three samples of 32 calls, with warmups. Inputs/builders were constructed outside the measurement. |
| [netstandard2.0 secure clearing](performance/netstandard-secureclear-gc.md) | A `netstandard2.0` library assembly running under a modern .NET 10 Linux host showed **0/0/0 per-generation GC deltas** on each measured 1 KiB and 16 KiB BLAKE2b invocation after removing forced collections | Three samples per size, two warmups. The earlier 16/16/16 and 256/256/256 counts are historical observations, not a new paired throughput benchmark. |

The linked reports contain the source commits, assembly fingerprints, runtime/OS details, input patterns, raw samples, and reproduction instructions. **These results measure managed allocation and garbage-collection counts, not elapsed time, throughput, power use, memory lifetime or resistance to side-channel attacks.** The Gen0/Gen1/Gen2 collection counts overlap; do not sum them. Do not extrapolate the `netstandard2.0` result to .NET Framework or Mono.

Claims such as “3–10× faster batches”, “8.5 GB/s AES”, and “4–8× AVX-512” were previously shown without reproducible source measurements. They are intentionally not repeated here. Detecting an instruction set does not prove that a particular HeroCrypt code path uses it.

## ChaCha variant metadata is not a security or speed guarantee

`ChaChaVariants.GetSecurityBits(...)` returns historical **64/96/128** labels and
`ChaChaVariants.GetPerformanceMultiplier(...)` returns historical **2.5/1.7/1.0**
ratios. Both methods are retained with their existing numeric values for public
API compatibility; **neither provides an audited cryptanalytic security bound or
measured HeroCrypt throughput**. In particular, reduced-round ChaCha8/12 does not
acquire a defensible bit-security estimate merely from its round count. Do not
use those values to select cryptography, claim compliance, or size production
capacity. RFC 8439 specifies the 20-round variant; prefer its ChaCha20-Poly1305
authenticated construction when integrity and authenticity are required. Measure
runtime behavior with the reproducible methodology below and independently
review any reduced-round deployment.

## Work with existing public APIs

### BLAKE2b hashing

```csharp
using HeroCrypt;

// data is a caller-owned byte[] (or another buffer).
using var hasher = HeroCryptBuilder.Blake2b()
    .WithOutputLength(32);

byte[] digest = hasher.ComputeHash(data.AsSpan());
```

This calls the public span overload and avoids a full-input copy in the builder. It **does not** mean that all internal BLAKE2b work is allocation-free. Compare the result with an independent RFC 7693 implementation for your chosen output size, key, salt and personalization settings.

### ChaCha20-Poly1305 authenticated encryption

```csharp
using HeroCrypt;

// key is 32 bytes, plaintext/aad are caller-owned byte[] values.
using var encryptor = HeroCryptBuilder.ChaCha20Poly1305()
    .WithKey(key)
    .WithRandomNonce()
    .WithAssociatedData(aad);

byte[] ciphertextAndTag = encryptor.Encrypt(plaintext);
byte[] nonce = encryptor.GetNonce(); // Store with this ciphertext.

// In the receiving path, recover the original nonce, AAD and key.
using var decryptor = HeroCryptBuilder.ChaCha20Poly1305()
    .WithKey(key)
    .WithNonce(nonce)
    .WithAssociatedData(aad);
byte[] recovered = decryptor.Decrypt(ciphertextAndTag);
```

**Never encrypt two distinct messages with the same ChaCha20-Poly1305 key and nonce.** A builder's nonce does not automatically rotate between `Encrypt` calls; create a new random nonce for each encryption and preserve it with the ciphertext. Authentication failure must abort processing—do not consume unverified plaintext.

## Span, allocation, and secret handling

A `ReadOnlySpan<byte>` input can reduce copies across an API boundary, but internal buffers, returned results, cryptographic provider state and the runtime may still allocate. `stackalloc` is not an automatic secure-wipe mechanism: explicitly erase sensitive spans in `finally` after their last use. Avoid storing secret keys or recovery phrases as immutable strings where callers require reliable memory erasure.

Use the APIs and security guidance appropriate to the targeted runtime. On modern .NET, `CryptographicOperations.ZeroMemory` expresses an intent to wipe the supplied buffer. HeroCrypt's `netstandard2.0` fallback uses best-effort volatile writes and a memory barrier. Neither method can guarantee that copies in registers, JIT spills, dumps, unmanaged providers or previous allocations have been erased. See [the security policy and limitations](../SECURITY.md) and [production readiness](../PRODUCTION_READINESS.md).

Use `IDisposable` builders for key-bearing operations and dispose them promptly. Clear caller-owned sensitive arrays separately after the operation; disposing a builder does not clear every independent copy the caller might hold. Avoid logging keys, nonces with private context, passphrases, or secret-derived buffers.

## Reproducible benchmarking checklist

1. **Choose a fixed workload:** exact public API, key/AAD configuration, message sizes, data-generation pattern, number of iterations, expected output, and encryption nonce policy.
2. **Identify both builds:** record source commits and SHA-256 of the actual assemblies under test. Keep before and after builds in separate directories, using the same SDK, runtime and configuration.
3. **Verify correctness independently:** check BLAKE2b against `hashlib.blake2b` or RFC 7693 test vectors; use RFC 8439 and an independent AEAD implementation for ChaCha20-Poly1305. Test wrong keys, truncated data and tag/AAD tampering for the affected paths.
4. **Keep setup outside the measured region:** prepare payloads and keys first, warm up each path, and retain raw per-sample results. Never put `GC.Collect` inside a normal timed workload merely to make it look stable.
5. **Separate metrics:** `GC.GetAllocatedBytesForCurrentThread()` measures managed allocations on the calling thread for synchronous code; `GC.CollectionCount(generation)` counts overlapping collections by generation. Use an appropriate timed harness (such as BenchmarkDotNet) for elapsed time and throughput, and report uncertainty and hardware conditions.
6. **Run compatibility gates:** verify the intended TFM assembly actually loads on the target host; run the repository's xUnit/Microsoft.Testing.Platform tests across required frameworks and platforms. Recheck public wire formats and failure semantics after any optimization.

Existing reproducible harnesses and raw measurements:

- [BLAKE2b builder allocation](performance/blake2b-span-allocation.md)
- [netstandard2.0 secure clearing GC](performance/netstandard-secureclear-gc.md)

Do not advertise benchmark numbers from a different machine, TFM or operation as measured HeroCrypt performance. Treat any unmeasured speedups as hypotheses until reproducible evidence is captured.
