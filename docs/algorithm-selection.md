# Algorithm Selection Guide

This guide helps you choose the right cryptographic algorithm for your use case.

## Table of Contents

1. [Quick Decision Tree](#quick-decision-tree)
2. [Encryption Algorithms](#encryption-algorithms)
3. [Hashing Algorithms](#hashing-algorithms)
4. [Key Derivation Functions](#key-derivation-functions)
5. [Digital Signatures](#digital-signatures)
6. [Post-Quantum Algorithms](#post-quantum-algorithms)

## Quick Decision Tree

### What do you need to do?

**Encrypt data?**
- Small messages (< 256 KB) → [ChaCha20-Poly1305](#chacha20-poly1305) or [AES-GCM](#aes-gcm)
- Nonce might be reused → [AES-SIV](#aes-siv)
- High-performance bulk data → [AES-OCB](#aes-ocb)
- Browser/cloud interop → [AES-GCM](#aes-gcm)

**Hash passwords?**
- New applications → [Argon2id](#argon2id) (recommended)
- Legacy compatibility → [PBKDF2](#pbkdf2)
- Memory-constrained → [Scrypt](#scrypt)

**Derive keys from master key?**
- Key expansion → [HKDF](#hkdf) (fast, not for passwords)

**Sign data?**
- General purpose → [Ed25519](#ed25519) (recommended)
- Blockchain/cryptocurrency → [Secp256k1](#secp256k1)
- Enterprise/certificates → [RSA-PSS](#rsa-signatures) or [ECDSA](#ecdsa)
- FIPS compliance → [ECDSA P-256](#ecdsa) or [RSA-PSS](#rsa-signatures)
- Future quantum resistance → [ML-DSA](#ml-dsa-post-quantum)

**Hash data?**
- General purpose → [SHA-256](#sha-256) or [Blake2b](#blake2b)
- High performance → [Blake2b](#blake2b)
- FIPS compliance → [SHA-256](#sha-256)

---

## Encryption Algorithms

### ChaCha20-Poly1305

**When to use:**
- Mobile/embedded devices (no AES hardware)
- High-security applications
- Cross-platform compatibility
- Default choice when unsure

**Characteristics:**
- 256-bit key, 96-bit nonce
- Software-efficient (no special CPU instructions needed)
- RFC 8439 compliant
- Widely deployed (TLS 1.3, WireGuard, SSH)

```csharp
using var builder = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithRandomKey();
```

### AES-GCM

**When to use:**
- Hardware with AES-NI (Intel/AMD, modern ARM)
- Browser/cloud interop (Web Crypto API)
- FIPS compliance required

**Characteristics:**
- 128/192/256-bit keys, 96-bit nonce
- Hardware-accelerated on modern CPUs
- Widely supported in browsers and cloud services

```csharp
using var builder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey();
```

### AES-SIV

**When to use:**
- Nonce might accidentally be reused
- Deterministic encryption needed
- Maximum safety margin

**Characteristics:**
- Nonce-misuse resistant
- Slightly slower than GCM
- Requires double key size (256-bit for AES-128 security)

```csharp
using var builder = HeroCryptBuilder.Encrypt()
    .WithAesSiv()
    .WithRandomKey();
```

### AES-OCB

**When to use:**
- Maximum encryption throughput
- Large file encryption
- Single-pass authenticated encryption

**Characteristics:**
- Fastest AEAD mode
- Patent-free since 2021
- Single-pass operation

### Comparison Table

| Algorithm | Speed | Hardware Accel | Nonce-Misuse Resistant | FIPS |
|-----------|-------|----------------|----------------------|------|
| ChaCha20-Poly1305 | Fast | No | No | No |
| AES-GCM | Very Fast* | Yes | No | Yes |
| AES-SIV | Medium | Yes | **Yes** | No |
| AES-OCB | Very Fast | Yes | No | No |

*With AES-NI hardware acceleration

---

## Hashing Algorithms

### SHA-256

**When to use:**
- FIPS compliance required
- Interoperability with external systems
- Standard compliance

```csharp
using var builder = HeroCryptBuilder.Hash()
    .WithSha256();
var hash = builder.ComputeHashToHex(data);
```

### Blake2b

**When to use:**
- Maximum performance
- Variable output length needed
- Keyed hashing (MAC)

**Characteristics:**
- Faster than SHA-256
- Variable output (1-64 bytes)
- Built-in keying support

```csharp
using var builder = HeroCryptBuilder.Hash()
    .WithBlake2b()
    .WithOutputLength(32);
```

### Comparison Table

| Algorithm | Speed | Output Size | Keyed Mode | FIPS |
|-----------|-------|-------------|------------|------|
| SHA-256 | Medium | 32 bytes | No (use HMAC) | Yes |
| SHA-384 | Medium | 48 bytes | No (use HMAC) | Yes |
| SHA-512 | Fast (64-bit) | 64 bytes | No (use HMAC) | Yes |
| Blake2b | Fast | 1-64 bytes | **Yes** | No |

---

## Key Derivation Functions

### Argon2id

**When to use:**
- Password hashing (new applications)
- Storing user credentials
- Maximum protection against GPU/ASIC attacks

**Characteristics:**
- Memory-hard (expensive to parallelize)
- Side-channel resistant (hybrid of Argon2i and Argon2d)
- Winner of Password Hashing Competition

```csharp
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(password)
    .WithRandomSalt();
```

### Scrypt

**When to use:**
- Cryptocurrency wallets (historical compatibility)
- When Argon2 is unavailable

### PBKDF2

**When to use:**
- Legacy system compatibility
- FIPS compliance required
- Resource-constrained environments

**Characteristics:**
- Widely supported
- Not memory-hard (GPU attacks possible)
- Use high iteration count (100,000+)

### HKDF

**When to use:**
- Deriving multiple keys from one master key
- Key expansion (NOT password hashing)
- Protocol key derivation

**Warning:** HKDF is NOT suitable for password hashing. It's fast by design.

```csharp
// Derive encryption and MAC keys from master
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithHkdfSha256()
    .WithPassword(masterKey)  // High-entropy input, NOT user password
    .WithSalt(context)
    .WithInfo("encryption-key");
```

### Comparison Table

| Algorithm | Memory-Hard | GPU Resistant | FIPS | Use Case |
|-----------|-------------|---------------|------|----------|
| Argon2id | **Yes** | **Yes** | No | Password hashing |
| Scrypt | Yes | Yes | No | Password hashing |
| PBKDF2 | No | No | Yes | Legacy/FIPS |
| HKDF | No | No | Yes | Key expansion only |

---

## Digital Signatures

### Ed25519

**When to use:**
- General purpose signing
- Maximum security/speed ratio
- Modern applications

**Characteristics:**
- 256-bit security
- Fast signing and verification
- Small signatures (64 bytes)
- Deterministic (no RNG needed for signing)

```csharp
using var signer = HeroCryptBuilder.Sign()
    .WithEd25519()
    .WithPrivateKey(privateKey);
var signature = signer.Sign(message);
```

### Secp256k1

**When to use:**
- Bitcoin/Ethereum compatibility
- Blockchain applications

### ECDSA (NIST curves)

**When to use:**
- FIPS compliance required
- Enterprise PKI
- X.509 certificates

**Curves:**
- P-256 (128-bit security) - Most common
- P-384 (192-bit security) - Higher security
- P-521 (256-bit security) - Maximum security

### RSA Signatures

**When to use:**
- Legacy system compatibility
- Enterprise PKI
- When ECDSA is not supported

**Modes:**
- RSA-PSS (recommended) - Probabilistic, more secure
- RSA-PKCS#1 v1.5 - Legacy, use only for compatibility

```csharp
using var signer = HeroCryptBuilder.Sign()
    .WithRsaPssSha256()
    .WithPrivateKey(privateKey);
```

### Comparison Table

| Algorithm | Key Size | Signature Size | Speed | FIPS | Post-Quantum |
|-----------|----------|----------------|-------|------|--------------|
| Ed25519 | 32 bytes | 64 bytes | Very Fast | No | No |
| ECDSA P-256 | 32 bytes | 64 bytes | Fast | Yes | No |
| RSA-2048 | 256 bytes | 256 bytes | Slow | Yes | No |
| RSA-3072 | 384 bytes | 384 bytes | Slower | Yes | No |
| ML-DSA-65 | ~2 KB | ~3 KB | Medium | Yes* | **Yes** |

*FIPS 204 approved

---

## Post-Quantum Algorithms

### ML-KEM (Key Encapsulation)

**When to use:**
- Protecting data that must stay secret for 10+ years
- "Harvest now, decrypt later" threat model
- Hybrid encryption with classical algorithms

**Parameter Sets:**
- ML-KEM-512: 128-bit security
- ML-KEM-768: 192-bit security (recommended)
- ML-KEM-1024: 256-bit security

```csharp
// Requires .NET 10+
using var mlKem = HeroCryptBuilder.MlKem()
    .WithParameterSet(MlKemParameterSet.MlKem768);
```

### ML-DSA (Digital Signatures)

**When to use:**
- Long-term document signing
- Critical infrastructure
- Government/defense applications

**Parameter Sets:**
- ML-DSA-44: 128-bit security
- ML-DSA-65: 192-bit security (recommended)
- ML-DSA-87: 256-bit security

### SLH-DSA (Hash-Based Signatures)

**When to use:**
- Maximum conservatism (relies only on hash functions)
- When lattice-based security is questioned

**Characteristics:**
- Larger signatures than ML-DSA
- Based solely on hash function security

### Comparison Table

| Algorithm | Type | Key Size | Sig/CT Size | Security Basis |
|-----------|------|----------|-------------|----------------|
| ML-KEM-768 | KEM | ~2.4 KB | ~1 KB | Lattice (MLWE) |
| ML-DSA-65 | Signature | ~4 KB | ~3.3 KB | Lattice (MLDSA) |
| SLH-DSA-128s | Signature | ~64 B | ~7.8 KB | Hash functions |

---

## Summary Recommendations

| Use Case | Recommended Algorithm |
|----------|----------------------|
| Encrypt data | ChaCha20-Poly1305 or AES-GCM |
| Hash passwords | Argon2id |
| Derive keys from master | HKDF-SHA256 |
| Sign data | Ed25519 |
| Blockchain signatures | Secp256k1 |
| FIPS-compliant encryption | AES-GCM |
| FIPS-compliant signatures | ECDSA P-256 or RSA-PSS |
| Post-quantum encryption | ML-KEM-768 (hybrid) |
| Post-quantum signatures | ML-DSA-65 |

## Additional Resources

- [API Patterns](api-patterns.md) - API conventions and encoding patterns
- [Best Practices](best-practices.md) - Security best practices
- [Performance Guide](performance-guide.md) - Optimization strategies
