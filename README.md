# HeroCrypt

[![NuGet Version](https://img.shields.io/nuget/v/HeroCrypt.svg)](https://www.nuget.org/packages/HeroCrypt/)
[![Build Status](https://github.com/KoalaFacts/HeroCrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/KoalaFacts/HeroCrypt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/KoalaFacts/HeroCrypt/branch/main/graph/badge.svg)](https://codecov.io/gh/KoalaFacts/HeroCrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET%20Standard-2.0-purple)](https://dotnet.microsoft.com/download)
[![.NET](https://img.shields.io/badge/.NET-8.0%20|%209.0%20|%2010.0-purple)](https://dotnet.microsoft.com/download)

A fully RFC-compliant cryptographic library for .NET featuring high-performance, secure implementations of modern cryptographic algorithms with multi-framework support.

## Table of Contents

- [Features](#-features)
- [Framework Support](#-framework-support)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Architecture](#%EF%B8%8F-architecture)
- [RFC Compliance](#-rfc-compliance)
- [Security](#-security)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

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
  - Rabbit cipher (RFC 4503) - Fully RFC-compliant with correct endianness
  - HC-128 and HC-256 (eSTREAM portfolio)

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
  - BIP32 Hierarchical Deterministic Wallets - Production-ready with secp256k1 support
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

## 🎯 Framework Support

HeroCrypt supports a wide range of .NET platforms for maximum compatibility:

| Framework | Version | Status | Notes |
|-----------|---------|--------|-------|
| .NET Standard | 2.0 | ✅ Full Support | Compatible with .NET Framework 4.6.1+, Unity, Xamarin |
| .NET | 8.0 | ✅ Full Support | Long-term support (LTS) |
| .NET | 9.0 | ✅ Full Support | Standard term support |
| .NET | 10.0 | ✅ Full Support | Includes native post-quantum cryptography |

### Feature Availability by Framework

#### Core Cryptography (All Frameworks)
- ✅ Argon2, Blake2b, PBKDF2, HKDF, Scrypt
- ✅ ChaCha20-Poly1305, XChaCha20-Poly1305
- ✅ RSA, ECDSA, Ed25519
- ✅ Stream ciphers (Rabbit, ChaCha, HC-128/256, etc.)
- ✅ Hash functions (SHA-2, SHA-3, BLAKE2, etc.)

#### .NET 8.0+ Enhanced Features
- ✅ AES-GCM with custom tag sizes (hardware-accelerated AEAD)
- ✅ AES-CCM (authenticated encryption)
- ✅ Ed25519 (built-in BCL implementation)
- 📝 Note: AES-GCM is available on all frameworks, but .NET 8+ adds support for custom tag sizes

#### .NET 10.0+ Only
- ✅ **ML-KEM (FIPS 203)** - Post-quantum key encapsulation
- ✅ **ML-DSA (FIPS 204)** - Post-quantum digital signatures
- ✅ **SLH-DSA (FIPS 205)** - Stateless hash-based signatures
- ⚠️ Requires Windows CNG with PQC support or OpenSSL 3.5+

### .NET Standard 2.0 Compatibility

When targeting .NET Standard 2.0, HeroCrypt automatically uses polyfills and fallback implementations:
- Uses `RandomNumberGenerator.Create().GetBytes()` instead of `RandomNumberGenerator.Fill()`
- AES-GCM/CCM operations throw `NotSupportedException` with clear upgrade guidance
- Post-quantum cryptography is not available (compile-time excluded)
- All other features work identically across all frameworks

## 📦 Installation

```bash
dotnet add package HeroCrypt
```

## 🚀 Quick Start

HeroCrypt provides three levels of API access:
1. **Primitives** - Direct access to algorithms: `HeroCryptBuilder.ChaCha20Poly1305()`
2. **Operations** - Algorithm-agnostic facades: `HeroCryptBuilder.Encrypt.WithChaCha20Poly1305()`
3. **Protocols** - Complex constructions: `HeroCryptBuilder.Pgp()`, `HeroCryptBuilder.Bip32()`

### Encryption with ChaCha20-Poly1305

```csharp
using HeroCrypt;

// Generate a random key
var key = new byte[32];
RandomNumberGenerator.Fill(key);

// Encrypt data
using var cipher = HeroCryptBuilder.ChaCha20Poly1305()
    .WithKey(key)
    .WithRandomNonce();

var ciphertext = cipher.Encrypt(Encoding.UTF8.GetBytes("Hello, World!"));

// Decrypt data
var plaintext = cipher.Decrypt(ciphertext);
```

### Hashing with Blake2b

```csharp
using HeroCrypt;

// Compute a 32-byte hash
using var hasher = HeroCryptBuilder.Blake2b()
    .WithOutputLength(32);

var hash = hasher.ComputeHash(Encoding.UTF8.GetBytes("Hello, World!"));

// Keyed hash (MAC)
using var mac = HeroCryptBuilder.Blake2b()
    .WithOutputLength(32)
    .WithKey(key);

var authenticatedHash = mac.ComputeHash(data);
```

### Digital Signatures with Ed25519

```csharp
using HeroCrypt;

// Generate a key pair
using var signer = HeroCryptBuilder.Ed25519();
var (privateKey, publicKey) = signer.GenerateKeyPair();

// Sign a message
var signature = signer
    .WithPrivateKey(privateKey)
    .WithMessage(data)
    .Sign();

// Verify a signature
bool isValid = signer
    .WithPublicKey(publicKey)
    .WithMessage(data)
    .Verify(signature);
```

### Key Derivation with Argon2

```csharp
using HeroCrypt;

// Derive a key from a password
using var kdf = HeroCryptBuilder.Argon2()
    .WithPassword(Encoding.UTF8.GetBytes("mySecurePassword"))
    .WithRandomSalt()
    .WithInteractivePreset();  // Balanced security/performance

var derivedKey = kdf.DeriveKey();
```

### PGP Hybrid Encryption

```csharp
using HeroCrypt;

// Generate RSA key pair
var pgp = HeroCryptBuilder.Pgp();
var keyPair = pgp.GenerateRsaKeyPair();

// Encrypt a message
var envelope = pgp.Encrypt("Secret message", keyPair.PublicKey);

// Decrypt the message
var plaintext = pgp.DecryptToString(envelope, keyPair.PrivateKey);
```

### Working with Text Formats (Hex, Base64, Base64Url)

All builders support convenient text format methods for storing and transmitting cryptographic data:

```csharp
using HeroCrypt;

// ENCRYPTION: Get key and result as text formats
using var encryptBuilder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey();

var keyHex = encryptBuilder.GetKeyAsHex();  // or GetKeyAsBase64(), GetKeyAsBase64Url()
var result = encryptBuilder.Encrypt("Hello, World!");

// Access result as text - perfect for JSON, databases, URLs
var encryptedData = new {
    key = keyHex,
    ciphertext = result.CiphertextAsBase64Url,  // URL-safe encoding
    nonce = result.NonceAsBase64Url
};

// DECRYPTION: Use text format inputs directly
var decrypted = HeroCryptBuilder.Decrypt()
    .WithAesGcm()
    .WithKeyFromHex(encryptedData.key)
    .WithNonceFromBase64Url(encryptedData.nonce)
    .DecryptFromBase64UrlToString(encryptedData.ciphertext);
```

### Password Hashing with Text Storage

```csharp
using HeroCrypt;

// Hash a password and get values as text for storage
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword("mySecurePassword")
    .WithRandomSalt(16);

var saltHex = kdf.GetSaltAsHex();
var keyHex = kdf.DeriveKeyToHex();
// Store saltHex and keyHex in your database

// Later: Verify password using stored text values
var derivedKey = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(enteredPassword)
    .WithSaltFromHex(storedSaltHex)
    .DeriveKeyToHex();

bool isValid = derivedKey == storedKeyHex;
```

### Hybrid Encryption with Text Formats (X25519)

```csharp
using HeroCrypt;

// Encrypt with X25519 hybrid encryption
var result = HeroCryptBuilder.Encrypt()
    .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
    .WithKey(recipientPublicKey)
    .Encrypt("Confidential message");

// All components as URL-safe text for API transmission
var apiPayload = new {
    c = result.CiphertextAsBase64Url,
    n = result.NonceAsBase64Url,
    k = result.EncapsulatedKeyAsBase64Url
};

// Decrypt using text inputs
var plaintext = HeroCryptBuilder.Decrypt()
    .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
    .WithKey(recipientPrivateKey)
    .WithNonceFromBase64Url(apiPayload.n)
    .WithEncapsulatedKeyFromBase64Url(apiPayload.k)
    .DecryptFromBase64UrlToString(apiPayload.c);
```

### Text Encoding Quick Reference

| Pattern | When to Use | Example |
|---------|-------------|---------|
| `*AsHex` | Properties on result structs | `result.CiphertextAsHex` |
| `*AsBase64` | Properties on result structs | `result.NonceAsBase64` |
| `*AsBase64Url` | URL-safe output for APIs | `result.CiphertextAsBase64Url` |
| `*ToHex()` | Action methods returning hex | `kdf.DeriveKeyToHex()` |
| `*ToBase64()` | Action methods returning Base64 | `signer.SignToBase64(data)` |
| `Get*AsHex()` | Retrieve builder state as hex | `builder.GetKeyAsHex()` |
| `With*FromHex()` | Set value from hex string | `.WithKeyFromHex(hexKey)` |
| `With*FromBase64Url()` | Set value from URL-safe Base64 | `.WithNonceFromBase64Url(nonce)` |
| `*FromHexToString()` | Decode, process, return string | `.DecryptFromHexToString(hex)` |

> **Tip:** Use `Base64Url` for URLs, APIs, and JWTs. Use `Hex` for logs and debugging. See [API Patterns](docs/api-patterns.md#text-encoding-conventions) for full details.

### Post-Quantum Cryptography (.NET 10+)

```csharp
using HeroCrypt;

// ML-KEM: Quantum-resistant key encapsulation
using var mlKem = HeroCryptBuilder.MlKem()
    .WithParameterSet(MlKemParameterSet.MlKem768);

var (publicKey, privateKey) = mlKem.GenerateKeyPair();
var (ciphertext, sharedSecret) = mlKem.Encapsulate(publicKey);
var decapsulated = mlKem.Decapsulate(ciphertext, privateKey);

// ML-DSA: Quantum-resistant digital signatures
using var mlDsa = HeroCryptBuilder.MlDsa()
    .WithParameterSet(MlDsaParameterSet.MlDsa65);

var (signingKey, verifyKey) = mlDsa.GenerateKeyPair();
var signature = mlDsa.Sign(data, signingKey);
bool isValid = mlDsa.Verify(data, signature, verifyKey);
```

## 🏗️ Architecture

HeroCrypt is built with a small, layered architecture:

- **Fluent Builders** - High-level, easy-to-use APIs (`HeroCryptBuilder`)
- **Core Implementations** - Low-level cryptographic primitives

## 📊 RFC Compliance

| Algorithm | Standard | Status |
|-----------|----------|--------|
| Argon2d   | RFC 9106 | ✅ Fully Compliant |
| Argon2i   | RFC 9106 | ✅ Fully Compliant |
| Argon2id  | RFC 9106 | ✅ Fully Compliant |
| Blake2b   | RFC 7693 | ✅ Fully Compliant |
| ChaCha20-Poly1305 | RFC 8439 | ✅ Fully Compliant |
| Curve25519 (X25519) | RFC 7748 | ✅ Fully Compliant |
| Rabbit Stream Cipher | RFC 4503 | ✅ Fully Compliant |
| HKDF | RFC 5869 | ✅ Fully Compliant |
| ML-KEM (FIPS 203) | FIPS 203 | ✅ Production-ready (.NET 10+) |
| ML-DSA (FIPS 204) | FIPS 204 | ✅ Production-ready (.NET 10+) |
| SLH-DSA (FIPS 205) | FIPS 205 | ✅ Production-ready (.NET 10+) |
| RSA       | RFC 8017 | ✅ Basic Support |

## 🔒 Security

- Core algorithms (Argon2, Blake2b, ChaCha20, Rabbit) implemented from scratch following RFC specifications
- Elliptic curve operations (secp256k1, Curve25519) leverage .NET's ECDsa and proven field arithmetic
- Post-quantum cryptography uses .NET 10+ native BCL implementations (FIPS 203/204/205)
- Constant-time comparisons for sensitive operations
- Secure memory management with automatic zeroing
- Comprehensive test coverage with RFC test vectors and real-world scenarios

## 📖 Documentation

### Getting Started

- **[Getting Started Guide](docs/getting-started.md)** - Quick start guide with examples
- **[Algorithm Selection Guide](docs/algorithm-selection.md)** - Choosing the right algorithm for your use case
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
