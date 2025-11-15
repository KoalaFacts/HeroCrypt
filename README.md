# HeroCrypt

[![NuGet Version](https://img.shields.io/nuget/v/HeroCrypt.svg)](https://www.nuget.org/packages/HeroCrypt/)
[![Build Status](https://github.com/BeingCiteable/HeroCrypt/workflows/Build%20Pipeline/badge.svg)](https://github.com/BeingCiteable/HeroCrypt/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET%20Standard-2.0-blue)](https://dotnet.microsoft.com/download)
[![.NET](https://img.shields.io/badge/.NET-6.0%20|%207.0%20|%208.0%20|%209.0%20|%2010.0-blue)](https://dotnet.microsoft.com/download)

A fully RFC-compliant cryptographic library for .NET featuring high-performance, secure implementations of modern cryptographic algorithms with multi-framework support.

## ✨ Features

- **🔐 Argon2 Password Hashing** - Full RFC 9106 compliance
  - Argon2d, Argon2i, and Argon2id variants
  - Configurable memory, iterations, and parallelism
  - Secure salt generation and constant-time comparison

- **#️⃣ Blake2b Hashing** - Full RFC 7693 compliance
  - Variable output sizes (1-64 bytes)
  - Keyed hashing (MAC) support
  - Blake2b-Long for outputs > 64 bytes

- **🔑 RSA Encryption** - PKCS#1 v2.2 support
  - Key generation (512-4096 bits)
  - PKCS#1 v1.5 and OAEP padding
  - Digital signatures

- **📧 PGP Encryption** - OpenPGP-compatible
  - Hybrid encryption with AES session keys
  - RSA key pair support
  - Passphrase protection for private keys

- **🔒 Modern Symmetric Encryption (AEAD)**
  - ChaCha20-Poly1305 (RFC 8439) with SIMD optimizations
  - XChaCha20-Poly1305 (extended 24-byte nonce)
  - AES-GCM with hardware acceleration
  - AES-CCM (RFC 3610)
  - AES-SIV (RFC 5297) - nonce-misuse resistant
  - AES-OCB (RFC 7253) - high-performance AEAD

- **🌊 Stream Ciphers**
  - ChaCha8/ChaCha12/ChaCha20 variants
  - XSalsa20
  - Rabbit cipher (RFC 4503)
  - HC-128 and HC-256 (eSTREAM portfolio)
  - RC4 (legacy compatibility with security warnings)

- **📐 Elliptic Curve Cryptography**
  - Curve25519 (X25519 key exchange)
  - Ed25519 (digital signatures)
  - Secp256k1 (Bitcoin-compatible)
  - Hardware-accelerated field arithmetic

- **🔑 Key Derivation & Management**
  - PBKDF2 (with SHA256/SHA384/SHA512)
  - HKDF (RFC 5869)
  - Scrypt (memory-hard KDF)
  - Balloon Hashing (cache-timing resistant)
  - BIP32 Hierarchical Deterministic Wallets
  - BIP39 Mnemonic Codes (12/15/18/21/24 words)
  - Shamir's Secret Sharing (SSS)
  - Key rotation and hierarchical key management

- **🔮 Post-Quantum Cryptography**
  - **ML-KEM (FIPS 203)** - Key encapsulation mechanism (formerly CRYSTALS-Kyber)
    - ✅ Production-ready on .NET 10+ (native BCL implementation)
    - ML-KEM-512, ML-KEM-768, ML-KEM-1024 parameter sets
    - Protection against "harvest now, decrypt later" attacks
  - **ML-DSA (FIPS 204)** - Digital signatures (formerly CRYSTALS-Dilithium)
    - ✅ Production-ready on .NET 10+ (native BCL implementation)
    - ML-DSA-44, ML-DSA-65, ML-DSA-87 parameter sets
    - Lattice-based quantum-resistant signatures
  - **SLH-DSA (FIPS 205)** - Stateless hash-based signatures (formerly SPHINCS+)
    - ✅ Production-ready on .NET 10+ (native BCL implementation)
    - "Small" and "Fast" variants at 128/192/256-bit security levels
    - Conservative security based on hash functions only
  - ⚠️ Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+

- **🎭 Zero-Knowledge & Advanced Protocols (Reference Implementations)**
  - zk-SNARKs (Groth16-style) - Zero-knowledge succinct proofs
  - Ring Signatures - Anonymous group signatures (basic, linkable, traceable)
  - Threshold Signatures - Distributed multi-party signing (Schnorr, ECDSA, EdDSA, BLS)
  - Multi-Party Computation - Secure computation without revealing inputs
  - Private Set Intersection - Find common elements privately
  - Beaver Triples - Preprocessing for secure multiplication
  - ⚠️ Educational implementations demonstrating API design and workflow

- **🔒 Hardware Security Integration (Abstraction Layer)**
  - PKCS#11 HSM integration - Industry-standard hardware security module API
  - Azure Key Vault connector - Cloud HSM integration with Azure
  - TPM 2.0 support - Trusted Platform Module for platform integrity
  - TEE abstractions - Intel SGX and ARM TrustZone trusted execution
  - Hardware RNG - Intel RDRAND/RDSEED optimizations with automatic fallback
  - Sealed storage, remote attestation, and secure key management
  - ⚠️ Abstraction layers requiring vendor SDK and hardware/cloud access

- **⚡ Performance & Optimization**
  - SIMD acceleration - AVX-512, AVX2, SSE2, and ARM NEON optimizations
  - Memory pool management - Efficient buffer reuse with automatic security zeroing
  - Parallel cryptography - Multi-threaded operations with automatic load balancing
  - Batch operations - 3-10x throughput improvement for bulk operations
  - Zero-copy operations - Span<T> and stackalloc for minimal allocations
  - Cache-line alignment - Optimized memory layout for better cache performance
  - Hardware capability detection - Automatic fallback for maximum compatibility

- **🔗 Cryptographic Protocols**
  - Noise Protocol Framework - Modern secure transport with multiple handshake patterns
  - Signal Protocol - End-to-end encryption with Double Ratchet and X3DH
  - OTR Messaging - Off-the-Record messaging with deniable authentication
  - OPAQUE PAKE - RFC 9497 password-authenticated key exchange
  - TLS 1.3 - Custom cipher suites, 0-RTT resumption, certificate pinning

- **🏢 Enterprise Features**
  - Certificate Authority - X.509 certificate generation, CRL, OCSP responder
  - Compliance Framework - FIPS 140-2, Common Criteria, SOC 2, PCI-DSS validation
  - Key Management Service - Centralized KMS with lifecycle management and RBAC
  - Audit Logging - Comprehensive security event tracking and compliance reporting

## 📦 Installation

```bash
dotnet add package HeroCrypt
```

## 🚀 Quick Start

### Argon2 Password Hashing

```csharp
using HeroCrypt.Services;

// Configure Argon2 options
var options = new Argon2Options
{
    Type = Argon2Type.Argon2id,
    Iterations = 3,
    MemorySize = 65536,  // 64 MB
    Parallelism = 4,
    HashLength = 32
};

var hashingService = new Argon2HashingService(options);

// Hash a password
string hash = await hashingService.HashAsync("mySecurePassword");

// Verify a password
bool isValid = await hashingService.VerifyAsync("mySecurePassword", hash);
```

### Blake2b Hashing

```csharp
using HeroCrypt.Cryptography.Blake2b;

// Simple hash
byte[] data = Encoding.UTF8.GetBytes("Hello, World!");
byte[] hash = Blake2bCore.ComputeHash(data, 32);  // 32-byte hash

// Keyed hash (MAC)
byte[] key = Encoding.UTF8.GetBytes("secret-key");
byte[] mac = Blake2bCore.ComputeHash(data, 32, key);
```

### RSA Encryption

```csharp
using HeroCrypt.Cryptography.RSA;

// Generate key pair
var keyPair = RsaCore.GenerateKeyPair(2048);

// Encrypt with OAEP padding
byte[] encrypted = RsaCore.Encrypt(
    data, 
    keyPair.PublicKey, 
    RsaPaddingMode.Oaep, 
    HashAlgorithmName.SHA256
);

// Decrypt
byte[] decrypted = RsaCore.Decrypt(
    encrypted, 
    keyPair.PrivateKey, 
    RsaPaddingMode.Oaep, 
    HashAlgorithmName.SHA256
);
```

### Post-Quantum Cryptography (.NET 10+)

```csharp
using HeroCrypt.Cryptography.PostQuantum.Kyber;
using HeroCrypt.Cryptography.PostQuantum.Dilithium;

// Option 1: Using fluent builder pattern (recommended)
// ML-KEM: Quantum-resistant key encapsulation
using var keyPair = MLKem.Create()
    .WithSecurityBits(192)  // or .WithSecurityLevel(MLKemWrapper.SecurityLevel.MLKem768)
    .GenerateKeyPair();

// Sender: Encapsulate a shared secret
var (ciphertext, sharedSecret) = MLKem.Create()
    .WithPublicKey(keyPair.PublicKeyPem)
    .Encapsulate();

// Receiver: Decapsulate to recover the shared secret
var recoveredSecret = MLKem.Create()
    .WithKeyPair(keyPair)
    .Decapsulate(ciphertext);

// ML-DSA: Quantum-resistant digital signatures
using var signingKey = MLDsa.Create()
    .WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa65)
    .GenerateKeyPair();

// Sign with optional context
var signature = MLDsa.Create()
    .WithKeyPair(signingKey)
    .WithData("Important message")
    .WithContext("application-v1")
    .Sign();

// Verify signature
bool isValid = MLDsa.Create()
    .WithPublicKey(signingKey.PublicKeyPem)
    .WithData("Important message")
    .WithContext("application-v1")
    .Verify(signature);

// Option 2: Using wrapper classes directly
using var keyPair2 = MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);
using var result = MLKemWrapper.Encapsulate(keyPair2.PublicKeyPem);
byte[] recovered = keyPair2.Decapsulate(result.Ciphertext);
```

## 🏗️ Architecture

HeroCrypt is built with a modular architecture:

- **Core Implementations** - Low-level cryptographic primitives
- **Service Layer** - High-level, easy-to-use APIs
- **Abstractions** - Interfaces for dependency injection

## 📊 RFC Compliance

| Algorithm | Standard | Status |
|-----------|----------|--------|
| Argon2d   | RFC 9106 | ✅ Fully Compliant |
| Argon2i   | RFC 9106 | ✅ Fully Compliant |
| Argon2id  | RFC 9106 | ✅ Fully Compliant |
| Blake2b   | RFC 7693 | ✅ Fully Compliant |
| RSA       | RFC 8017 | ✅ Basic Support |

## 🎯 Target Frameworks

- .NET Standard 2.0
- .NET 6.0
- .NET 7.0
- .NET 8.0
- .NET 9.0
- .NET 10.0 (with native Post-Quantum Cryptography support)

## 🔒 Security

- Core algorithms (Argon2, Blake2b) implemented from scratch following RFC specifications
- Leverages .NET's proven cryptographic primitives for AES, SHA-256, and secure random generation
- Constant-time comparisons for sensitive operations
- Secure memory management

## 📖 Documentation

### Getting Started

- **[Getting Started Guide](docs/getting-started.md)** - Quick start guide with examples
- **[API Patterns](docs/api-patterns.md)** - API design patterns and conventions
- **[Examples](examples/)** - Practical code examples for common use cases

### Production Use

- **[Production Readiness](PRODUCTION_READINESS.md)** - Feature status and production guidelines
- **[Best Practices](docs/best-practices.md)** - Security best practices
- **[Performance Guide](docs/performance-guide.md)** - Optimization strategies

### Support

- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions
- **[Migration Guide](docs/migration-guide.md)** - Migrating between versions

### Technical Details

- **[Standards Compliance](STANDARDS_COMPLIANCE.md)** - RFC compliance and test vectors
- **[Development Roadmap](DEVELOPMENT_ROADMAP.md)** - Future features and roadmap
- **[Test Status](TEST_STATUS.md)** - Test coverage and platform compatibility

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- RFC 9106 (Argon2) specification authors
- RFC 7693 (Blake2) specification authors
- .NET cryptographic community