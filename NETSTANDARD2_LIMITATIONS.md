# .NET Standard 2.0 Compatibility Limitations

## Overview

HeroCrypt supports multiple target frameworks including .NET Standard 2.0 for broad compatibility. However, some advanced features require APIs only available in .NET Core 3.0+ (.NET 5+, .NET 6+, etc.).

## Core Features (✅ .NET Standard 2.0 Compatible)

The following core cryptographic features are fully compatible with .NET Standard 2.0:

- **Symmetric Encryption**: AES, ChaCha20, Salsa20, Rabbit, HC-128, HC-256, RC4
- **AEAD Ciphers**: AES-GCM, AES-CCM, AES-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-OCB
- **Hashing**: Blake2b, SHA-256, SHA-512, SHA-3
- **Password Hashing**: Argon2, PBKDF2, Scrypt
- **Key Derivation**: HKDF
- **Digital Signatures**: RSA, ECDSA, EdDSA
- **PGP**: Full PGP encryption/decryption support
- **Basic Security**: Secure memory management, constant-time operations

## Advanced Features (⚠️ Requires .NET Core 3.0+)

The following advanced features use APIs not available in .NET Standard 2.0 and require .NET Core 3.0 or later:

### Enterprise Features
- **Certificate Authority (CA)**: X.509 certificate generation and management
  - Reason: `CertificateRequest` class not available in .NET Standard 2.0
  - Alternative: Use BouncyCastle library or upgrade to .NET Core 3.0+

- **Key Management Service (KMS)**: Enterprise key lifecycle management
  - Reason: Uses `CryptographicOperations`, `Span<T>` APIs extensively

- **Compliance Framework**: Regulatory compliance tracking
  - Reason: Uses LINQ methods not available in .NET Standard 2.0

### Cryptographic Protocols
- **Signal Protocol**: End-to-end encrypted messaging
- **Noise Protocol**: Secure channel establishment
- **OPAQUE**: Password-authenticated key exchange
- **OTR Protocol**: Off-the-Record messaging

*Reason: Extensive use of `RandomNumberGenerator.Fill()`, `SHA256.HashData()`, and other .NET Core 3.0+ APIs*

### Zero-Knowledge & Advanced Cryptography
- **zk-SNARKs (Groth16)**: Zero-knowledge proofs
- **Ring Signatures**: Anonymous signatures
- **Threshold Signatures**: Multi-party signing
- **Secure MPC**: Multi-party computation

*Reason: Complex cryptographic operations using modern .NET APIs and C# 8.0 features (Index/Range)*

### HD Wallets & Blockchain
- **BIP-32**: Hierarchical Deterministic Wallets
- **BIP-39**: Mnemonic seed phrases
- **Shamir Secret Sharing**: Secret splitting/reconstruction

*Reason: Uses `HMACSHA512.TryComputeHash()` and other span-based APIs*

### Hardware Security
- **SIMD Acceleration**: Hardware-accelerated cryptography
  - Limited functionality in .NET Standard 2.0 (scalar fallbacks used)
  - Full acceleration requires .NET Core 3.0+ for `System.Runtime.Intrinsics`

## Migration Guide

### For Library Users

**If you need .NET Standard 2.0 compatibility:**
- Stick to core features listed above
- Avoid advanced enterprise and protocol features
- SIMD operations will use slower scalar fallbacks

**If you can target .NET Core 3.0+ or .NET 5+:**
- All features are available
- Better performance with hardware acceleration
- Access to modern cryptographic protocols

### For Contributors

When adding new features:

1. **Check API Availability**: Verify all APIs used are available in .NET Standard 2.0
   - ✅ Available: `RandomNumberGenerator.GetBytes()`, `SHA256.ComputeHash()`
   - ❌ Not Available: `RandomNumberGenerator.Fill()`, `SHA256.HashData()`

2. **Use Polyfills**: Import `HeroCrypt.Polyfills` namespace for compatibility helpers
   ```csharp
   #if NETSTANDARD2_0
   using HeroCrypt.Polyfills;
   #endif
   ```

3. **Conditional Compilation**: Wrap modern API usage
   ```csharp
   #if NETSTANDARD2_0
       using (var rng = RandomNumberGenerator.Create())
       {
           rng.GetBytes(buffer);
       }
   #else
       RandomNumberGenerator.Fill(buffer);
   #endif
   ```

4. **Document Limitations**: Update this file if adding .NET Core 3.0+ only features

## API Compatibility Matrix

| API | .NET Standard 2.0 | .NET Core 3.0+ | Polyfill Available |
|-----|-------------------|----------------|-------------------|
| `RandomNumberGenerator.Fill()` | ❌ | ✅ | ✅ Extension method |
| `SHA256.HashData()` | ❌ | ✅ | ✅ Static class |
| `CryptographicOperations.FixedTimeEquals()` | ❌ | ✅ | ✅ Static class |
| `System.Runtime.Intrinsics` | ❌ | ✅ | ❌ Scalar fallback |
| `CertificateRequest` | ❌ | ✅ | ❌ |
| `HMACSHA512.TryComputeHash()` | ❌ | ✅ | ✅ Extension method |
| `Index` / `Range` operators | ❌ | ✅ | ❌ Use array slicing |
| `BitConverter.TryWriteBytes()` | ❌ | ✅ | ✅ Extension method |

## Performance Considerations

### .NET Standard 2.0
- **SIMD Operations**: Fall back to scalar implementations (2-8x slower)
- **Span<T> Operations**: May require array allocations
- **Memory Pooling**: Limited compared to modern .NET

### .NET Core 3.0+
- **Hardware Acceleration**: Full SIMD support (AVX2, AVX-512, ARM NEON)
- **Zero-Copy Operations**: Extensive use of `Span<T>` and `Memory<T>`
- **Improved GC**: Better memory management for crypto operations

## Recommendations

- **New Projects**: Target .NET 6.0 or later for best performance and full feature set
- **Library Consumers**: Use .NET Standard 2.0 target only if you must support .NET Framework 4.6.1+
- **Production Deployments**: Prefer .NET 8.0 for latest security updates and performance

## Future Work

The following improvements are planned for .NET Standard 2.0 compatibility:

- [ ] Add conditional compilation to exclude advanced features from .NET Standard 2.0 builds
- [ ] Create more comprehensive polyfills for common operations
- [ ] Performance benchmarks comparing .NET Standard 2.0 vs .NET 8.0
- [ ] Documentation on migrating from .NET Standard 2.0 to modern .NET

## Questions?

For questions about .NET Standard 2.0 compatibility, please open an issue on GitHub with the "compatibility" label.
