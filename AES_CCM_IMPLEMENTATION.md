# AES-CCM Implementation

## Overview

This document describes the AES-CCM (Counter with CBC-MAC) implementation added to HeroCrypt as part of Phase 3C.

## What is AES-CCM?

AES-CCM is an AEAD (Authenticated Encryption with Associated Data) mode defined in **RFC 3610**. It combines:
- **CTR mode** for encryption (confidentiality)
- **CBC-MAC** for authentication (integrity)

### Key Features

- **RFC 3610 Compliant**: Fully compliant with the official specification
- **IoT Optimized**: Widely used in Bluetooth LE, Zigbee, Thread, and 802.15.4
- **Flexible Parameters**:
  - Key sizes: 128, 192, or 256 bits
  - Nonce sizes: 7-13 bytes (default: 13 bytes)
  - Tag sizes: 4-16 bytes in 2-byte increments (default: 16 bytes)
- **Secure by Design**: Constant-time operations, secure memory handling

## Files Added

```
src/HeroCrypt/Cryptography/Symmetric/AesCcm/
└── AesCcmCore.cs                    # Core AES-CCM implementation

tests/HeroCrypt.Tests/
└── AesCcmTests.cs                   # Comprehensive tests with RFC 3610 test vectors
```

## Files Modified

```
src/HeroCrypt/Abstractions/
└── IAeadService.cs                  # Added Aes128Ccm and Aes256Ccm to enum

src/HeroCrypt/Services/
└── AeadService.cs                   # Integrated AES-CCM support
```

## Usage Examples

### Basic Encryption/Decryption

```csharp
using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using System.Text;

// Create the service
var aeadService = new AeadService();

// Prepare data
var plaintext = Encoding.UTF8.GetBytes("Hello, AES-CCM!");
var associatedData = Encoding.UTF8.GetBytes("metadata");

// Generate key and nonce
var key = aeadService.GenerateKey(AeadAlgorithm.Aes128Ccm);     // 16 bytes
var nonce = aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm); // 13 bytes

// Encrypt
var ciphertext = await aeadService.EncryptAsync(
    plaintext,
    key,
    nonce,
    associatedData,
    AeadAlgorithm.Aes128Ccm
);

// Decrypt
var decrypted = await aeadService.DecryptAsync(
    ciphertext,
    key,
    nonce,
    associatedData,
    AeadAlgorithm.Aes128Ccm
);

// Verify
Console.WriteLine(Encoding.UTF8.GetString(decrypted)); // "Hello, AES-CCM!"
```

### AES-256-CCM (Higher Security)

```csharp
// Use AES-256 for higher security
var key = aeadService.GenerateKey(AeadAlgorithm.Aes256Ccm);     // 32 bytes
var nonce = aeadService.GenerateNonce(AeadAlgorithm.Aes256Ccm); // 13 bytes

var ciphertext = await aeadService.EncryptAsync(
    plaintext,
    key,
    nonce,
    algorithm: AeadAlgorithm.Aes256Ccm
);
```

### IoT Use Case (Bluetooth LE)

```csharp
// Bluetooth LE typically uses 13-byte nonces and 4-8 byte tags
using HeroCrypt.Cryptography.Symmetric.AesCcm;

var key = new byte[16];  // AES-128 for IoT
var nonce = new byte[13]; // 13-byte nonce
var plaintext = Encoding.UTF8.GetBytes("Sensor data: 25.3°C");
var associatedData = new byte[] { 0x01, 0x02, 0x03 }; // Device ID

// Encrypt with 8-byte tag (common for IoT to save bandwidth)
var ciphertext = new byte[plaintext.Length + 8];
AesCcmCore.Encrypt(
    ciphertext,
    plaintext,
    key,
    nonce,
    associatedData,
    tagSize: 8  // Smaller tag for constrained devices
);
```

### Without Associated Data

```csharp
// AAD is optional
var ciphertext = await aeadService.EncryptAsync(
    plaintext,
    key,
    nonce,
    algorithm: AeadAlgorithm.Aes128Ccm
);
```

## RFC 3610 Compliance

The implementation has been tested against official RFC 3610 test vectors:

- **Test Vector #1**: 8-byte tag, 13-byte nonce ✅
- **Test Vector #2**: Different nonce configuration ✅
- **Test Vector #3**: Longer associated data ✅

All test vectors pass, confirming RFC compliance.

## Performance Characteristics

### Strengths

- **Sequential Processing**: Suitable for constrained devices (no parallel requirement)
- **Deterministic**: Two-pass algorithm provides strong guarantees
- **Hardware Support**: Leverages AES-NI when available
- **Memory Efficient**: Minimal memory overhead

### Trade-offs

- **Two Passes**: Requires two passes over the data (one for MAC, one for encryption)
- **Not Parallelizable**: Unlike AES-GCM, cannot encrypt blocks in parallel
- **Performance**: ~30-40% slower than AES-GCM on modern CPUs with AES-NI

## Security Considerations

### Nonce Requirements

⚠️ **CRITICAL**: Never reuse a nonce with the same key!

```csharp
// GOOD: Generate new nonce for each message
var nonce = aeadService.GenerateNonce(AeadAlgorithm.Aes128Ccm);

// BAD: Reusing the same nonce compromises security
// DO NOT DO THIS!
```

### Tag Size Selection

| Tag Size | Security Level | Use Case |
|----------|---------------|----------|
| 4 bytes | Low | Constrained IoT devices (accept higher risk) |
| 8 bytes | Medium | Bluetooth LE, Zigbee (good balance) |
| 16 bytes | High | General purpose (recommended) |

### Associated Data

- AAD is authenticated but not encrypted
- Useful for headers, metadata, protocol information
- Changes to AAD will cause authentication failure

## Comparison with Other AEAD Modes

| Feature | AES-CCM | AES-GCM | ChaCha20-Poly1305 |
|---------|---------|---------|-------------------|
| **Speed (software)** | Moderate | Fast | Very Fast |
| **Speed (hardware)** | Fast | Very Fast | Fast |
| **Parallelizable** | No | Yes | No |
| **Patent-Free** | Yes | Yes | Yes |
| **IoT Adoption** | Very High | Medium | Growing |
| **Nonce Size** | 7-13 bytes | 12 bytes | 12/24 bytes |
| **Tag Size** | 4-16 bytes | 16 bytes | 16 bytes |

## When to Use AES-CCM

### ✅ Best For:

- **IoT and Embedded Systems**: Bluetooth LE, Zigbee, Thread, 802.15.4
- **Constrained Devices**: Low memory, sequential processing
- **Standards Compliance**: When protocols mandate AES-CCM
- **Variable Tag Sizes**: When you need smaller tags for bandwidth

### ❌ Consider Alternatives When:

- **High Throughput Needed**: Use AES-GCM with AES-NI
- **Software-Only Performance**: Use ChaCha20-Poly1305
- **Parallel Processing**: Use AES-GCM

## Testing

Run the AES-CCM tests:

```bash
# Run all AES-CCM tests
dotnet test --filter "FullyQualifiedName~AesCcmTests"

# Run only RFC compliance tests
dotnet test --filter "Category=Compliance&FullyQualifiedName~AesCcmTests"

# Run fast tests only
dotnet test --filter "Category=Fast&FullyQualifiedName~AesCcmTests"
```

## Implementation Details

### Architecture

```
AesCcmCore (internal static class)
├── Encrypt()         - Main encryption method
├── Decrypt()         - Main decryption method
├── ComputeTag()      - CBC-MAC authentication
├── EncryptCtr()      - CTR mode encryption
└── DecryptCtr()      - CTR mode decryption
```

### Algorithm Flow

**Encryption:**
1. Build formatting block B_0 (flags | nonce | message length)
2. Compute CBC-MAC over AAD and plaintext → Tag T
3. Encrypt plaintext using CTR mode → Ciphertext C
4. Encrypt tag T using CTR mode with counter=0 → Encrypted Tag T'
5. Return C || T'

**Decryption:**
1. Decrypt encrypted tag using CTR mode with counter=0 → Tag T
2. Decrypt ciphertext using CTR mode → Plaintext P
3. Compute CBC-MAC over AAD and P → Expected Tag T'
4. Constant-time compare T with T'
5. Return P if tags match, otherwise fail

## References

- **RFC 3610**: [Counter with CBC-MAC (CCM)](https://www.rfc-editor.org/rfc/rfc3610.html)
- **NIST SP 800-38C**: Recommendation for Block Cipher Modes of Operation: The CCM Mode
- **IEEE 802.15.4**: Uses AES-CCM for MAC layer security
- **Bluetooth Core Spec**: Uses AES-CCM for LE Secure Connections

## Next Steps

Continue with Phase 3C implementation:

1. **AES-SIV** - Nonce-misuse resistant AEAD (RFC 5297)
2. **Rabbit** - High-speed stream cipher (RFC 4503)
3. **AES-OCB** - High-performance AEAD (RFC 7253)
4. **HC-128** - eSTREAM portfolio stream cipher

---

**Implementation Date**: October 2025
**RFC Compliance**: RFC 3610
**Status**: ✅ Complete and Tested
