# HeroCrypt

[![NuGet Version](https://img.shields.io/nuget/v/HeroCrypt.svg)](https://www.nuget.org/packages/HeroCrypt/)
[![Build Status](https://github.com/BeingCiteable/HeroCrypt/workflows/Build%20Pipeline/badge.svg)](https://github.com/BeingCiteable/HeroCrypt/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET%20Standard-2.0-blue)](https://dotnet.microsoft.com/download)
[![.NET](https://img.shields.io/badge/.NET-6.0%20|%207.0%20|%208.0%20|%209.0-blue)](https://dotnet.microsoft.com/download)

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

- **🔮 Post-Quantum Cryptography (Reference Implementations)**
  - CRYSTALS-Kyber (ML-KEM, FIPS 203) - Key encapsulation
  - CRYSTALS-Dilithium (ML-DSA, FIPS 204) - Digital signatures
  - SPHINCS+ (SLH-DSA, FIPS 205) - Stateless signatures
  - Security levels: 128-bit, 192-bit, 256-bit post-quantum
  - ⚠️ Simplified reference implementations for API design

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

## 🔒 Security

- Core algorithms (Argon2, Blake2b) implemented from scratch following RFC specifications
- Leverages .NET's proven cryptographic primitives for AES, SHA-256, and secure random generation
- Constant-time comparisons for sensitive operations
- Secure memory management

## 📖 Documentation

- [STANDARDS_COMPLIANCE.md](STANDARDS_COMPLIANCE.md) - Detailed compliance information and test vectors
- [DEVELOPMENT_ROADMAP.md](DEVELOPMENT_ROADMAP.md) - Complete development roadmap and planned features

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- RFC 9106 (Argon2) specification authors
- RFC 7693 (Blake2) specification authors
- .NET cryptographic community