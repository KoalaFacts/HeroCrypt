# HeroCrypt

[![NuGet Version](https://img.shields.io/nuget/v/HeroCrypt.svg)](https://www.nuget.org/packages/HeroCrypt/)
[![Build Status](https://github.com/KoalaFacts/HeroCrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/KoalaFacts/HeroCrypt/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![.NET](https://img.shields.io/badge/.NET%20Standard-2.0-purple)](https://dotnet.microsoft.com/download)
[![.NET](https://img.shields.io/badge/.NET-8.0%20|%209.0%20|%2010.0-purple)](https://dotnet.microsoft.com/download)

A cryptographic library for .NET with standards-based primitives, OpenPGP support and multi-framework APIs. Supported production profiles and limitations are documented below.

> **Production scope:** Qualify the exact API, runtime and protocol profile used by your application. The release includes tested primitives, platform-dependent features and educational protocols; it is not a blanket cryptographic security certification. See [production readiness](PRODUCTION_READINESS.md), [security limits](SECURITY.md) and [migration guidance](docs/migration-guide.md). No completed independent professional security audit is claimed.

## Table of Contents

- [Features](#-features)
- [Framework Support](#-framework-support)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Architecture](#%EF%B8%8F-architecture)
- [RFC Compliance](#-rfc-compliance)
- [Security](#-security)
- [Documentation](#-documentation)
- [Development](#development)
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
  - BIP32 master and private-parent key derivation with secp256k1 and HASH160 fingerprints;
    public-parent derivation and xprv/xpub import/export are unsupported
  - BIP39 official English mnemonics (12/15/18/21/24 words), checksum-validated wallet entry and NFKD seed conversion; review migration guidance for older placeholder phrases
  - Shamir's Secret Sharing (SSS)
  - Key rotation and hierarchical key management

- **🔮 Post-Quantum Cryptography**
  - **ML-KEM (FIPS 203)** - Key encapsulation mechanism (formerly CRYSTALS-Kyber)
    - Platform-dependent .NET 10+ BCL implementation; validate availability and integration
    - ML-KEM-512, ML-KEM-768, ML-KEM-1024 parameter sets
    - Protection against "harvest now, decrypt later" attacks
  - **ML-DSA (FIPS 204)** - Digital signatures (formerly CRYSTALS-Dilithium)
    - Platform-dependent .NET 10+ BCL implementation; validate availability and integration
    - ML-DSA-44, ML-DSA-65, ML-DSA-87 parameter sets
    - Lattice-based quantum-resistant signatures
  - **SLH-DSA (FIPS 205)** - Stateless hash-based signatures (formerly SPHINCS+)
    - Platform-dependent .NET 10+ BCL implementation; validate availability and integration
    - "Small" and "Fast" variants at 128/192/256-bit security levels
    - Conservative security based on hash functions only
  - ⚠️ Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+

- **🎭 Advanced Protocol Availability**
  - Ring signatures and zk-SNARKs are not implemented. Their insecure prototypes were removed before the first release; see the [verification audit](SECURITY.md#ring-signature-and-zk-snark-verification-audit---2026-09-30).
  - Threshold signature operations are disabled: the former simulation did not authenticate signatures
  - MPC, private set intersection, and Beaver triple operations are disabled in 1.0.2: the former local simulation did not provide distributed privacy or authenticated computation; see the [migration guide](docs/migration-guide.md#mpc-security-change-in-v102).

- **🔒 Integration boundaries**
  - The repository includes hardware capability detection helpers, not integrated PKCS#11 HSM, Azure Key Vault, TPM/TEE, sealed storage or remote-attestation providers.
  - External HSM/cloud-key integrations require separate implementations and security review.

- **⚡ Performance & allocation**
  - Synchronous `ReadOnlySpan<byte>` entry points avoid some caller-side copying; individual implementations can still allocate internally
  - BLAKE2b-256 builder span-input change removes one full-input copy; see [paired allocation samples](docs/performance/blake2b-span-allocation.md)
  - The `netstandard2.0` secure-clear fallback no longer forces two garbage collections per call; see [the scoped consumer and GC evidence](docs/performance/netstandard-secureclear-gc.md)
  - No universal SIMD acceleration, zero-allocation, batch throughput multiplier or cryptographic side-channel guarantee is implied; [benchmark and validation guidance](docs/performance-guide.md)

- **🔗 Cryptographic Protocols**
  - Noise Protocol Framework - Educational/reference implementation; not a qualified production protocol
  - [Double Ratchet](docs/double-ratchet.md) - Classical X25519 DH and symmetric ratchets for HeroCrypt endpoints, with authenticated messages, bounded out-of-order delivery and replay rejection. Accepts authenticated bootstrap inputs, including the separate X3DH profile.
  - [X3DH Identity Handshake](docs/x3dh.md) - X25519/SHA-256 and normalized XEdDSA signed prekeys, optional one-time prekeys, explicit expected-peer identity checks and transactional first-message acceptance. Requires independently verified identities; no Signal wire interoperability or persistence.
  - OTR Messaging - Educational/reference implementation; not a qualified production protocol
  - OPAQUE PAKE - Educational/reference implementation; not a qualified production protocol
  - TLS 1.3 transport, CA/OCSP responder, hosted KMS/RBAC, and compliance certification are not provided by this library.

## 🎯 Framework Support

The library targets the following frameworks. Target compatibility does not mean every API is available on every runtime; see [Production Readiness](PRODUCTION_READINESS.md).

| Framework | Version | Status | Notes |
|-----------|---------|--------|-------|
| .NET Standard | 2.0 | Library target | AES-GCM operations unsupported; post-quantum primitives excluded; consumer/runtime compatibility requires validation |
| .NET | 8.0 | Library and test target | Runtime/provider limits apply |
| .NET | 9.0 | Library and test target | Runtime/provider limits apply |
| .NET | 10.0 | Library and test target | Native post-quantum APIs require platform support |

### Feature Availability by Framework

#### Core Cryptography (All Frameworks)
- ✅ Argon2, Blake2b, PBKDF2, HKDF, Scrypt
- ✅ ChaCha20-Poly1305, XChaCha20-Poly1305
- ✅ RSA, ECDSA, Ed25519
- ✅ AES-CCM: HeroCrypt's CBC-MAC/CTR construction over the platform AES primitive
- ✅ Stream ciphers (Rabbit, ChaCha, HC-128/256, etc.)
- ✅ Hash functions (SHA-2, SHA-3, BLAKE2, etc.)

#### .NET 8.0+ Enhanced Features
- ✅ Platform AES-GCM with a fixed 16-byte authentication tag; runtime/provider limits apply
- 📝 Ed25519 uses HeroCrypt's managed implementation across supported target frameworks, not a built-in BCL implementation.
- 📝 AES-GCM is unavailable when targeting .NET Standard 2.0; its operations throw `PlatformNotSupportedException`.

#### .NET 10.0+ Only
- ✅ **ML-KEM (FIPS 203)** - Post-quantum key encapsulation
- ✅ **ML-DSA (FIPS 204)** - Post-quantum digital signatures
- ✅ **SLH-DSA (FIPS 205)** - Stateless hash-based signatures
- ⚠️ Requires Windows CNG with PQC support or OpenSSL 3.5+

### .NET Standard 2.0 Compatibility

When targeting .NET Standard 2.0, HeroCrypt automatically uses polyfills and fallback implementations:
- Uses `RandomNumberGenerator.Create().GetBytes()` instead of `RandomNumberGenerator.Fill()`
- AES-GCM operations throw `PlatformNotSupportedException`; use ChaCha20-Poly1305 or XChaCha20-Poly1305 as an alternative
- AES-CCM uses HeroCrypt's CBC-MAC/CTR construction over the platform AES primitive
- Post-quantum cryptography is not available (compile-time excluded)
- Feature availability still depends on the selected API and runtime; see [Production Readiness](PRODUCTION_READINESS.md)

## 📦 Installation

```bash
dotnet add package HeroCrypt
```

## 🚀 Quick Start

HeroCrypt provides three levels of API access:
1. **Primitives** - Direct access to algorithms: `HeroCryptBuilder.ChaCha20Poly1305()`
2. **Operations** - Algorithm-agnostic facades: `HeroCryptBuilder.Encrypt().WithChaCha20Poly1305()`
3. **Protocols** - Complex constructions: `HeroCryptBuilder.HdWallet()` for supported BIP32/BIP39 operations; OpenPGP message/packet APIs are separate from these fluent factories

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
    .WithSignature(signature)
    .Verify();
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

### RSA Hybrid Encryption

```csharp
using HeroCrypt;
using HeroCrypt.Protocols.MessageExchange;

// Generate RSA key pair
var hybrid = HeroCryptBuilder.HybridEncryption();
var keyPair = hybrid.GenerateRsaKeyPair();

// Encrypt a message
var envelope = hybrid.Encrypt("Secret message", keyPair.PublicKey);

// Decrypt the message
var plaintext = HybridEncryptionBuilder.DecryptToString(envelope, keyPair.PrivateKey);
```

This custom RSA-OAEP-SHA256 + AEAD envelope requires RSA keys of at least 2048 bits.
It is distinct from OpenPGP (`HeroCryptBuilder.Pgp()`) and HPKE. Encryption does not
authenticate a sender or prevent replay. Check associated data against your expected
application context; `IsText` is an unauthenticated hint. See the
[hybrid encryption security model](SECURITY.md#hybrid-encryption-security-model).

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

Store the KDF algorithm, its parameters, salt and derived verifier together. Restore **the same parameters** when verifying. Compare verifier **bytes**, not hex strings, using a fixed-time comparison:

```csharp
using HeroCrypt;
using System;
using System.Security.Cryptography;

using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword("mySecurePassword")
    .WithRandomSalt(16);

string saltHex = kdf.GetSaltAsHex();
byte[] keyBytes = kdf.DeriveKey();
string keyHex = Convert.ToHexString(keyBytes);
CryptographicOperations.ZeroMemory(keyBytes);
// Store saltHex and keyHex, with the Argon2id parameters.

using var verifier = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(enteredPassword)
    .WithSaltFromHex(storedSaltHex);

byte[] candidate = verifier.DeriveKey();
byte[] stored = Convert.FromHexString(storedKeyHex);
bool isValid;
try
{
    isValid = CryptographicOperations.FixedTimeEquals(candidate, stored);
}
finally
{
    CryptographicOperations.ZeroMemory(candidate);
    CryptographicOperations.ZeroMemory(stored);
}
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
| `ComputeHashTo*()` | Compute hash with text output | `hasher.ComputeHashToHex(data)` |
| `Get*AsHex()` | Retrieve builder state as hex | `builder.GetKeyAsHex()` |
| `With*FromHex()` | Set value from hex string | `.WithKeyFromHex(hexKey)` |
| `With*FromBase64Url()` | Set value from URL-safe Base64 | `.WithNonceFromBase64Url(nonce)` |
| `*FromHexToString()` | Decode, process, return string | `.DecryptFromHexToString(hex)` |

> **Tip:** Use `Base64Url` for URLs, APIs, and JWTs. Use `Hex` for logs and debugging. See [API Patterns](docs/api-patterns.md#text-encoding-conventions) for full details.

### Post-Quantum Cryptography (.NET 10+)

The .NET 10 source exposes `HeroCryptBuilder.MLKem()` and `HeroCryptBuilder.MLDsa()` when a compatible provider is available. Configure `WithSecurityLevel(...)` and the appropriate key pair, public key or data before invoking the parameterless `Encapsulate()` or `Sign()` methods. Earlier examples using `MlKem()` / `MlDsa()`, `WithParameterSet(...)`, and positional sign/encapsulation arguments did not match these APIs and were removed.

A published-package PQC example still requires an actual consumer compilation before it is labelled runnable; repository CI does not prove that separate package-consumer example.

## 🏗️ Architecture

HeroCrypt is built with a small, layered architecture:

- **Fluent Builders** - High-level, easy-to-use APIs (`HeroCryptBuilder`)
- **Core Implementations** - Low-level cryptographic primitives

## 📊 RFC Compliance

| Algorithm | Standard | Status |
|-----------|----------|--------|
| Argon2d   | RFC 9106 | Test-vector coverage |
| Argon2i   | RFC 9106 | Test-vector coverage |
| Argon2id  | RFC 9106 | Test-vector coverage |
| Blake2b   | RFC 7693 | Test-vector coverage |
| ChaCha20-Poly1305 | RFC 8439 | Test-vector coverage |
| Curve25519 (X25519) | RFC 7748 | Test-vector coverage |
| Rabbit Stream Cipher | RFC 4503 | Test-vector coverage |
| HKDF | RFC 5869 | Test-vector coverage |
| ML-KEM (FIPS 203) | FIPS 203 | Platform-dependent BCL (.NET 10+) |
| ML-DSA (FIPS 204) | FIPS 204 | Platform-dependent BCL (.NET 10+) |
| SLH-DSA (FIPS 205) | FIPS 205 | Platform-dependent BCL (.NET 10+) |
| RSA       | RFC 8017 | ✅ Basic Support |

## 🔒 Security

- Core algorithms (Argon2, Blake2b, ChaCha20, Rabbit) implemented from scratch following RFC specifications
- secp256k1 key operations, RFC 6979 ECDSA signatures and BIP32 RIPEMD-160 fingerprints use HeroCrypt's managed implementations. Bouncy Castle is used only for independent comparison tests and is not a runtime dependency.
- Managed secp256k1 uses variable-time `BigInteger` arithmetic; timing/cache side-channel resistance and complete secret zeroization are not established.
- Post-quantum cryptography uses .NET 10+ native BCL implementations (FIPS 203/204/205)
- Constant-time comparisons for sensitive operations
- Secure memory management with automatic zeroing
- Comprehensive test coverage with RFC test vectors and real-world scenarios

## 📖 Documentation

### Getting Started

- **[Getting Started Guide](docs/getting-started.md)** - Quick start guide with examples
- **[Algorithm Selection Guide](docs/algorithm-selection.md)** - Choosing the right algorithm for your use case
- **[API Patterns](docs/api-patterns.md)** - API design patterns and conventions
- **[Common Patterns](docs/common-patterns.md)** - Builder disposal, error handling, and workflows
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

## Development

Repository builds use the exact .NET SDK pinned in `global.json` (currently 10.0.402, with roll-forward disabled). Install the .NET 8 and 9 runtimes as well when running their test targets. CI uses locked dependency restore and Microsoft.Testing.Platform.

For the .NET 10 target:

```bash
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore --framework net10.0
dotnet test --project tests/HeroCrypt.Tests/HeroCrypt.Tests.csproj --configuration Release --no-build --framework net10.0 --no-restore
```

For `net8.0` or `net9.0`, replace `net10.0` in both the build and test commands with the desired target. To compile the library's .NET Standard target (there is no .NET Standard test runtime):

```bash
dotnet build src/HeroCrypt/HeroCrypt.csproj --configuration Release --no-restore --framework netstandard2.0
```

The test matrix runs `net8.0`, `net9.0`, and `net10.0`. Passing tests does not establish independent security certification or support for every platform-dependent feature.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- RFC 9106 (Argon2) specification authors
- RFC 7693 (Blake2) specification authors
- .NET cryptographic community
