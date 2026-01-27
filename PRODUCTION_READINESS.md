# Production Readiness Guide

This document provides a clear overview of which HeroCrypt features are production-ready and which are educational/reference implementations.

## Quick Summary

| Status | Description |
|--------|-------------|
| **Production-Ready** | Fully tested, RFC-compliant, suitable for production use |
| **Beta** | Functional and tested, but API may change |
| **Educational** | Reference implementations for learning, not for production |
| **Abstraction** | Requires external dependencies (hardware/cloud) |

## Production-Ready Features

These features are fully tested, RFC-compliant, and recommended for production use.

### Hashing Algorithms

| Algorithm | Status | Standard | Notes |
|-----------|--------|----------|-------|
| SHA-256/384/512 | Production-Ready | FIPS 180-4 | BCL implementation |
| SHA3-256/384/512 | Production-Ready | FIPS 202 | .NET 8+ only |
| Blake2b | Production-Ready | RFC 7693 | Variable output 1-64 bytes |
| Blake2b-Long | Production-Ready | RFC 7693 | Outputs > 64 bytes |

### Password Hashing & Key Derivation

| Algorithm | Status | Standard | Notes |
|-----------|--------|----------|-------|
| Argon2d | Production-Ready | RFC 9106 | Data-dependent |
| Argon2i | Production-Ready | RFC 9106 | Data-independent |
| Argon2id | Production-Ready | RFC 9106 | Hybrid (recommended) |
| PBKDF2 | Production-Ready | RFC 8018 | SHA-256/384/512 |
| HKDF | Production-Ready | RFC 5869 | Key derivation |
| Scrypt | Production-Ready | RFC 7914 | Memory-hard |

### Authenticated Encryption (AEAD)

| Algorithm | Status | Standard | Notes |
|-----------|--------|----------|-------|
| ChaCha20-Poly1305 | Production-Ready | RFC 8439 | SIMD optimized |
| XChaCha20-Poly1305 | Production-Ready | RFC 8439 | Extended nonce |
| AES-GCM | Production-Ready | NIST SP 800-38D | Hardware accelerated |
| AES-CCM | Production-Ready | RFC 3610 | .NET 8+ |
| AES-SIV | Production-Ready | RFC 5297 | Nonce-misuse resistant |
| AES-OCB | Production-Ready | RFC 7253 | High performance |

### Stream Ciphers

| Algorithm | Status | Standard | Notes |
|-----------|--------|----------|-------|
| ChaCha20 | Production-Ready | RFC 8439 | 8/12/20 round variants |
| XChaCha20 | Production-Ready | Draft | Extended nonce |
| XSalsa20 | Production-Ready | - | NaCl compatible |
| Rabbit | Production-Ready | RFC 4503 | Fully compliant |
| HC-128 | Production-Ready | eSTREAM | Portfolio cipher |
| HC-256 | Production-Ready | eSTREAM | Portfolio cipher |

### Asymmetric Cryptography

| Algorithm | Status | Standard | Notes |
|-----------|--------|----------|-------|
| RSA (OAEP) | Production-Ready | RFC 8017 | 2048+ bit keys |
| RSA (PSS) | Production-Ready | RFC 8017 | Signatures |
| ECDSA (P-256/384/521) | Production-Ready | FIPS 186-4 | BCL implementation |
| Ed25519 | Production-Ready | RFC 8032 | .NET 8+ native |
| X25519 | Production-Ready | RFC 7748 | Key exchange |
| secp256k1 | Production-Ready | SEC 2 | Bitcoin compatible |

### Wallet & Key Management

| Feature | Status | Standard | Notes |
|---------|--------|----------|-------|
| BIP39 Mnemonics | Production-Ready | BIP-0039 | 12-24 word phrases |
| BIP32 HD Wallets | Production-Ready | BIP-0032 | Hierarchical derivation |
| Shamir's Secret Sharing | Production-Ready | - | Threshold schemes |

## Beta Features

These features are functional but may have API changes in future versions.

### Post-Quantum Cryptography (.NET 10+ Only)

| Algorithm | Status | Standard | Notes |
|-----------|--------|----------|-------|
| ML-KEM | Beta | FIPS 203 | Key encapsulation |
| ML-DSA | Beta | FIPS 204 | Digital signatures |
| SLH-DSA | Beta | FIPS 205 | Hash-based signatures |

**Requirements:**
- .NET 10.0 or later
- Windows: Windows 11 24H2+ or Windows Server 2025+
- Linux: OpenSSL 3.5+ with PQC provider

**Note:** These use native .NET BCL implementations and are production-quality, but are marked Beta due to the relatively new FIPS standards.

## Educational / Reference Implementations

These implementations demonstrate cryptographic concepts and API design patterns. They are **NOT suitable for production use** without extensive review and hardening.

### Zero-Knowledge Proofs

| Feature | Status | Notes |
|---------|--------|-------|
| zk-SNARKs (Groth16) | Educational | Demonstrates ZKP concepts |
| Commitment Schemes | Educational | Pedersen, hash-based |

### Advanced Signature Schemes

| Feature | Status | Notes |
|---------|--------|-------|
| Ring Signatures | Educational | Anonymous group signing |
| Threshold Signatures | Educational | Distributed signing |
| Blind Signatures | Educational | Unlinkable signatures |

### Multi-Party Computation

| Feature | Status | Notes |
|---------|--------|-------|
| Secure MPC | Educational | Basic protocols |
| Private Set Intersection | Educational | PSI protocols |
| Beaver Triples | Educational | Preprocessing |

### Cryptographic Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| Noise Framework | Educational | Multiple patterns |
| Signal Protocol | Educational | Double Ratchet, X3DH |
| OTR Messaging | Educational | Deniable messaging |
| OPAQUE PAKE | Educational | RFC 9497 |

## Abstraction Layers

These features provide interfaces to external systems and require vendor SDKs or hardware access.

### Hardware Security

| Feature | Status | Requirements |
|---------|--------|--------------|
| PKCS#11 HSM | Abstraction | HSM device + vendor SDK |
| Azure Key Vault | Abstraction | Azure subscription |
| TPM 2.0 | Abstraction | TPM hardware |
| TEE (SGX/TrustZone) | Abstraction | Compatible hardware |

### Enterprise Features

| Feature | Status | Requirements |
|---------|--------|--------------|
| Certificate Authority | Abstraction | PKI infrastructure |
| Key Management Service | Abstraction | KMS backend |
| Compliance Framework | Abstraction | Audit infrastructure |

## Using This Guide

### Before Production Deployment

1. **Verify Status**: Confirm the feature is marked "Production-Ready"
2. **Check Requirements**: Ensure your target framework supports the feature
3. **Review Best Practices**: See [docs/best-practices.md](docs/best-practices.md)
4. **Test Thoroughly**: Run integration tests with your specific use case
5. **Security Review**: Consider a security audit for sensitive applications

### For Educational Features

Educational implementations are valuable for:
- Learning cryptographic concepts
- Prototyping and experimentation
- Understanding API design patterns
- Academic research

**Do NOT use educational features for:**
- Production systems
- Protecting real user data
- Financial or healthcare applications
- Any security-critical application

### Upgrading from Educational to Production

If you need production-quality versions of educational features:

1. **Evaluate alternatives**: Look for established libraries
2. **Request prioritization**: Open a GitHub issue for production support
3. **Contribute**: Help implement production-quality versions
4. **Consult experts**: Engage cryptographic consultants

## Framework Compatibility Matrix

| Feature Category | .NET Standard 2.0 | .NET 8.0 | .NET 9.0 | .NET 10.0 |
|-----------------|-------------------|----------|----------|-----------|
| Core Hashing | Yes | Yes | Yes | Yes |
| Password Hashing | Yes | Yes | Yes | Yes |
| Stream Ciphers | Yes | Yes | Yes | Yes |
| ChaCha20-Poly1305 | Yes | Yes | Yes | Yes |
| AES-GCM | Limited | Yes | Yes | Yes |
| AES-CCM | No | Yes | Yes | Yes |
| Ed25519 (native) | No | Yes | Yes | Yes |
| SHA-3 | No | Yes | Yes | Yes |
| Post-Quantum | No | No | No | Yes |

## Security Considerations

### Production-Ready Features

- Implemented following RFC specifications
- Include comprehensive test vectors
- Use constant-time operations where applicable
- Implement secure memory clearing
- Undergo regular code review

### Educational Features

- May not implement all security countermeasures
- May be vulnerable to side-channel attacks
- May not handle all edge cases
- Should not be trusted with real secrets

## Getting Help

- **Questions**: [GitHub Discussions](https://github.com/KoalaFacts/HeroCrypt/discussions)
- **Bug Reports**: [GitHub Issues](https://github.com/KoalaFacts/HeroCrypt/issues)
- **Security Issues**: See [SECURITY.md](SECURITY.md)
- **Feature Requests**: [GitHub Issues](https://github.com/KoalaFacts/HeroCrypt/issues) with `enhancement` label

## Version History

This document applies to HeroCrypt v1.0.0 and later.

See [CHANGELOG.md](CHANGELOG.md) for version-specific changes to production readiness.
