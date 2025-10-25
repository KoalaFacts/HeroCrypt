# HC-128 Stream Cipher Implementation

## Overview

This document describes the HC-128 stream cipher implementation added to HeroCrypt as part of Phase 3C.

## What is HC-128?

HC-128 is a **high-performance stream cipher** designed by Hongjun Wu. It was selected for the **eSTREAM portfolio** (Profile 1: Software) after extensive cryptanalysis and performance evaluation.

### Key Features

- **eSTREAM Portfolio**: Selected for software profile (high performance)
- **High Performance**: Exceptionally fast - one of the fastest software stream ciphers
- **Strong Security**: 128-bit security level, extensive cryptanalysis resistance
- **Large Internal State**: 4096 bytes (two 512-word tables)
- **Simple Design**:
  - 128-bit key (16 bytes)
  - 128-bit IV (16 bytes)
  - Two S-box tables (P and Q)
  - Efficient 32-bit operations
- **Patent-Free**: Free to use without licensing restrictions

## Design Principles

HC-128 is based on:
1. **Dual Tables**: Two 512-word tables (P and Q) that are updated and used alternately
2. **Feedback Functions**: G1 and G2 provide non-linear feedback
3. **Output Filters**: H1 and H2 use S-box lookups for output generation
4. **Key Expansion**: SHA-256-like functions (F1, F2) for initialization

### Security Properties

- **128-bit Security**: Designed to resist all known attacks up to 2^128 operations
- **No Distinguishers**: No practical distinguishers from random found
- **Resistant to**:
  - Differential attacks
  - Linear attacks
  - Algebraic attacks
  - Guess-and-determine attacks
  - Time-memory-data tradeoffs
- **eSTREAM Approval**: Passed extensive Phase 3 evaluation

## Files Added

```
src/HeroCrypt/Cryptography/Symmetric/Hc128/
└── Hc128Core.cs                    # Core HC-128 stream cipher implementation

tests/HeroCrypt.Tests/
└── Hc128Tests.cs                   # Comprehensive tests
```

## Usage Examples

### Basic Encryption/Decryption

```csharp
using HeroCrypt.Cryptography.Symmetric.Hc128;
using System.Text;

// Prepare data
var plaintext = Encoding.UTF8.GetBytes("Hello, HC-128!");
var key = new byte[16];  // 128-bit key
var iv = new byte[16];   // 128-bit IV

// Generate random key and IV (in practice, use SecureRandom)
using (var rng = RandomNumberGenerator.Create())
{
    rng.GetBytes(key);
    rng.GetBytes(iv);
}

// Encrypt
var ciphertext = new byte[plaintext.Length];
Hc128Core.Transform(ciphertext, plaintext, key, iv);

// Decrypt (same operation - stream cipher is symmetric)
var decrypted = new byte[plaintext.Length];
Hc128Core.Transform(decrypted, ciphertext, key, iv);

// Verify
Console.WriteLine(Encoding.UTF8.GetString(decrypted)); // "Hello, HC-128!"
```

### High-Speed Bulk Encryption

```csharp
// HC-128 excels at high-speed bulk encryption
var largeData = new byte[100 * 1024 * 1024]; // 100 MB
new Random(42).NextBytes(largeData);

var key = new byte[16];
var iv = new byte[16];
RandomNumberGenerator.Fill(key);
RandomNumberGenerator.Fill(iv);

// Encrypt (very fast!)
var encrypted = new byte[largeData.Length];
var stopwatch = Stopwatch.StartNew();
Hc128Core.Transform(encrypted, largeData, key, iv);
stopwatch.Stop();

Console.WriteLine($"Encrypted {largeData.Length} bytes in {stopwatch.ElapsedMilliseconds}ms");
Console.WriteLine($"Throughput: {(largeData.Length / 1024.0 / 1024.0) / stopwatch.Elapsed.TotalSeconds:F2} MB/s");

// Decrypt
var decrypted = new byte[largeData.Length];
Hc128Core.Transform(decrypted, encrypted, key, iv);

// Verify
Assert.Equal(largeData, decrypted);
```

### Streaming Applications

```csharp
// HC-128 is ideal for real-time streaming
async Task EncryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv)
{
    // Initialize HC-128 state once
    var buffer = new byte[4096];
    int bytesRead;

    while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
    {
        var encrypted = new byte[bytesRead];
        Hc128Core.Transform(encrypted, buffer.AsSpan(0, bytesRead), key, iv);
        await output.WriteAsync(encrypted, 0, encrypted.Length);
    }
}
```

### Integration with HMAC for Authentication

```csharp
// HC-128 is a stream cipher - combine with HMAC for authenticated encryption
byte[] EncryptAndAuthenticate(byte[] plaintext, byte[] encKey, byte[] authKey, byte[] iv)
{
    // Encrypt with HC-128
    var ciphertext = new byte[plaintext.Length];
    Hc128Core.Transform(ciphertext, plaintext, encKey, iv);

    // Authenticate with HMAC
    using var hmac = new HMACSHA256(authKey);
    var combined = new byte[iv.Length + ciphertext.Length];
    iv.CopyTo(combined, 0);
    ciphertext.CopyTo(combined, iv.Length);
    var tag = hmac.ComputeHash(combined);

    // Return IV || Ciphertext || Tag
    var result = new byte[iv.Length + ciphertext.Length + tag.Length];
    iv.CopyTo(result, 0);
    ciphertext.CopyTo(result, iv.Length);
    tag.CopyTo(result, iv.Length + ciphertext.Length);

    return result;
}
```

## Performance Characteristics

### Strengths

- **Extremely Fast**: Among the fastest software stream ciphers
- **Consistent Performance**: No performance variations across different data sizes
- **Low Per-Byte Cost**: ~1-2 CPU cycles per byte on modern processors
- **Efficient Initialization**: Reasonable setup time (1024 rounds)
- **Good Cache Behavior**: Tables fit in L1/L2 cache

### Benchmarks (Approximate)

| Platform | Performance | Notes |
|----------|-------------|-------|
| Modern CPU (3 GHz) | ~1500-2000 MB/s | Single-threaded |
| ARM Cortex-A53 | ~250-300 MB/s | Embedded/IoT |
| Comparison to Rabbit | Similar | Both very fast |
| Comparison to ChaCha20 | Slightly faster | In long streams |
| Comparison to AES-128 (software) | 3-4x faster | No AES-NI |

### Trade-offs

- **Large State**: 4KB of state (larger than most stream ciphers)
- **Initialization Cost**: 1024 rounds (more than ChaCha20's 20 rounds)
- **Memory Usage**: Not ideal for extremely constrained devices
- **No Hardware Support**: No dedicated CPU instructions
- **No Authentication**: Must be combined with MAC for AEAD

## Security Considerations

### IV Requirements

⚠️ **CRITICAL**: Never reuse an IV with the same key!

```csharp
// GOOD: Generate new IV for each message
var iv = new byte[16];
RandomNumberGenerator.Fill(iv);

// BAD: Reusing the same IV compromises security
// DO NOT DO THIS!
var sameIv = new byte[16]; // Always zero - INSECURE!
```

**Why?** IV reuse creates keystream reuse:
- `C1 = P1 XOR K` and `C2 = P2 XOR K`
- Attacker can compute `C1 XOR C2 = P1 XOR P2` (leaks plaintext relationship)

### IV Management Strategies

| Strategy | Security | Complexity | Use Case |
|----------|----------|------------|----------|
| **Random IV** | ✅ High | Low | General purpose (recommended) |
| **Counter IV** | ✅ High | Medium | Stateful protocols (careful!) |
| **Timestamp-based** | ⚠️ Medium | Low | Ensure high-resolution clock |

### Key Management

- **Key Size**: 128-bit (16 bytes) - adequate for most applications
- **Key Lifetime**: Limit to ~2^64 messages per key (IV exhaustion)
- **Key Derivation**: Use HKDF or similar for deriving session keys

### State Size Considerations

HC-128's 4KB state means:
- **Pro**: Large state provides security margin
- **Con**: More memory than ChaCha20 (~64 bytes) or Rabbit (~256 bytes)
- **Mitigation**: Still very small for modern systems

## Comparison with Other Stream Ciphers

| Feature | HC-128 | Rabbit | ChaCha20 | Salsa20 | AES-CTR |
|---------|--------|--------|----------|---------|---------|
| **Key Size** | 128-bit | 128-bit | 256-bit | 256-bit | 128/256-bit |
| **IV Size** | 128-bit | 64-bit | 96-bit | 64-bit | 128-bit |
| **State Size** | 4096 bytes | 256 bytes | 64 bytes | 64 bytes | 16 bytes |
| **Speed** | Fastest | Very Fast | Very Fast | Very Fast | Fast |
| **eSTREAM** | ✅ Portfolio | ✅ Portfolio | ❌ No | ✅ Portfolio | ❌ No |
| **Security Level** | 128-bit | 128-bit | 256-bit | 256-bit | 128/256-bit |
| **Memory** | High | Low | Low | Low | Very Low |
| **Initialization** | Medium | Fast | Very Fast | Very Fast | Instant |

## When to Use HC-128

### ✅ Best For:

- **Maximum Throughput**: Scenarios requiring absolute maximum encryption speed
- **Large File Encryption**: Encrypting large files or databases
- **Bulk Data Processing**: Log encryption, backup encryption
- **Long-Running Streams**: Video streaming, large file transfers
- **Software-Only Deployment**: Systems without hardware acceleration
- **Research/Academic**: Studying eSTREAM portfolio ciphers

### ❌ Consider Alternatives When:

- **Memory Constrained**: Use ChaCha20 or Rabbit (smaller state)
- **Authenticated Encryption Needed**: Use ChaCha20-Poly1305 or AES-GCM
- **256-bit Security Required**: Use ChaCha20 or Salsa20
- **Tiny Embedded Systems**: Use Rabbit or lightweight ciphers
- **TLS/DTLS**: Use ChaCha20-Poly1305 (standardized)
- **Hardware Acceleration Available**: Use AES-GCM with AES-NI

## Testing

Run the HC-128 tests:

```bash
# Run all HC-128 tests
dotnet test --filter "FullyQualifiedName~Hc128Tests"

# Run consistency tests
dotnet test --filter "Category=Consistency&FullyQualifiedName~Hc128Tests"

# Run edge case tests
dotnet test --filter "Category=EdgeCase&FullyQualifiedName~Hc128Tests"
```

## Implementation Details

### Internal State

```
P Table: 512 × 32-bit words (2048 bytes)
Q Table: 512 × 32-bit words (2048 bytes)
Counter: 10-bit (0-1023, alternates between P and Q)
Total:   ~4096 bytes
```

### Algorithm Flow

**Initialization:**
1. Expand key and IV into 1280-word array using F1/F2 functions
2. Load first 512 words into P table
3. Load next 512 words into Q table
4. Run 1024 iterations to mix state (discard output)
5. Reset counter to 0

**Keystream Generation:**
```
for each step i from 0 to 1023:
  j = i mod 512

  if i < 512:
    P[j] = P[j] + G1(P[j-3], P[j-10], P[j-511])
    output = H1(P[j-12]) XOR P[j]
  else:
    Q[j] = Q[j] + G2(Q[j-3], Q[j-10], Q[j-511])
    output = H2(Q[j-12]) XOR Q[j]
```

**Key Functions:**

- **G1(x, y, z)**: `(ROR(x,10) XOR ROR(z,23)) + ROR(y,8)` - Feedback for P
- **G2(x, y, z)**: `(ROL(x,10) XOR ROL(z,23)) + ROL(y,8)` - Feedback for Q
- **H1(x)**: `Q[x[0..7]] + Q[256 + x[16..23]]` - S-box output for P
- **H2(x)**: `P[x[0..7]] + P[256 + x[16..23]]` - S-box output for Q
- **F1(x)**: `ROR(x,7) XOR ROR(x,18) XOR (x >> 3)` - Key expansion
- **F2(x)**: `ROR(x,17) XOR ROR(x,19) XOR (x >> 10)` - Key expansion

### Security Analysis

- **State Size**: 4096 bytes >> 128-bit key (excellent margin)
- **Mixing**: G1/G2 provide non-linear feedback
- **S-boxes**: H1/H2 use large S-box tables for confusion
- **Initialization**: 1024 rounds ensure thorough mixing
- **Period**: Extremely long (no short cycles)

## Known Limitations

1. **No Authentication**: Must be combined with MAC
2. **Large State**: 4KB may be excessive for tiny embedded systems
3. **Initialization Cost**: 1024 rounds takes more time than ChaCha20
4. **128-bit Security Only**: Cannot provide 256-bit security level

## References

- **eSTREAM**: [ECRYPT Stream Cipher Project](https://www.ecrypt.eu.org/stream/)
- **Original Paper**: "The Stream Cipher HC-128" by Hongjun Wu
- **eSTREAM Phase 3 Report**: Security and performance evaluation
- **NIST Report**: Analysis of eSTREAM candidates

## Next Steps

Phase 3C is now complete with:

1. ✅ **AES-CCM** - Counter with CBC-MAC (RFC 3610)
2. ✅ **AES-SIV** - Nonce-misuse resistant AEAD (RFC 5297)
3. ✅ **Rabbit** - High-speed stream cipher (RFC 4503)
4. ✅ **HC-128** - eSTREAM portfolio stream cipher

Consider next:
- Phase 4: Key derivation functions (HKDF, Argon2, scrypt)
- Phase 5: Digital signatures (Ed25519, ECDSA)
- Integration with authentication (Poly1305, HMAC)

---

**Implementation Date**: October 2025
**eSTREAM**: Portfolio Cipher (Profile 1: Software)
**Status**: ✅ Complete and Tested
