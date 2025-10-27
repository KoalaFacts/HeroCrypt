# Changelog

All notable changes to HeroCrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Zero-Knowledge & Advanced Protocols (Phase 3F) - Reference implementations
  - zk-SNARKs (Groth16-style) with trusted setup, proof generation, and verification
  - Ring Signatures with basic, linkable, and traceable variants
  - Threshold Signatures supporting Schnorr, ECDSA, EdDSA, and BLS schemes
  - Multi-Party Computation with secure sum, multiplication, and private set intersection
  - Comprehensive test suite with 35+ test cases for advanced protocols
- Post-Quantum Cryptography (Phase 3E) - Reference implementations
  - CRYSTALS-Kyber (ML-KEM, FIPS 203) key encapsulation mechanism
  - CRYSTALS-Dilithium (ML-DSA, FIPS 204) digital signatures
  - SPHINCS+ (SLH-DSA, FIPS 205) stateless hash-based signatures
  - Multiple security levels (128-bit, 192-bit, 256-bit post-quantum)
- Key Derivation & Management (Phase 3D)
  - Shamir's Secret Sharing with GF(256) finite field arithmetic
  - BIP32 Hierarchical Deterministic Wallets
  - BIP39 Mnemonic Codes for seed generation (12/15/18/21/24 words)
  - Balloon Hashing for memory-hard password hashing
- Advanced Symmetric Algorithms (Phase 3C)
  - AES-OCB (Offset Codebook Mode) - RFC 7253 AEAD
  - HC-256 stream cipher (eSTREAM portfolio, 256-bit security)
  - RC4 stream cipher (legacy compatibility with security warnings)
- Project infrastructure and community guidelines
  - SECURITY.md with vulnerability reporting policy
  - CONTRIBUTING.md with comprehensive contribution guidelines
  - CHANGELOG.md for version tracking
  - EditorConfig for consistent code style
  - GitHub issue and pull request templates
  - Dependabot configuration for automated dependency updates
  - CodeQL security scanning workflow

### Changed
- Updated DEVELOPMENT_ROADMAP.md marking Phases 3C, 3D, 3E, and 3F as completed
- Enhanced README.md with all new cryptographic features
- Improved documentation with production requirement warnings for reference implementations

### Security
- Added comprehensive security policy and vulnerability reporting process
- Documented security best practices for HeroCrypt usage
- Identified and clearly marked reference implementations requiring full production implementations

## [0.9.0] - 2024-12-XX (Phase 3B Complete)

### Added
- Modern Symmetric Cryptography (Phase 3B)
  - ChaCha20-Poly1305 (RFC 8439) with SIMD optimizations
  - XChaCha20-Poly1305 (extended 24-byte nonce)
  - AES-GCM with hardware acceleration
  - AES-CCM (RFC 3610)
  - AES-SIV (RFC 5297) - nonce-misuse resistant
  - Streaming encryption support
- Performance benchmarking framework structure

### Changed
- Optimized ChaCha20 with AVX2 SIMD instructions
- Enhanced AEAD framework for authenticated encryption

## [0.8.0] - 2024-11-XX (Phase 3A Complete)

### Added
- Elliptic Curve Cryptography (Phase 3A)
  - Curve25519 (X25519 key exchange)
  - Ed25519 (digital signatures)
  - Secp256k1 (Bitcoin-compatible)
  - Hardware-accelerated field arithmetic
  - Comprehensive ECC service interface

### Changed
- Improved ECC performance with optimized field operations

## [0.7.0] - 2024-10-XX (Phase 2 Complete)

### Added
- Infrastructure & Security Hardening (Phase 2)
  - Hardware acceleration detection (AVX2, AES-NI)
  - Secure memory management with automatic zeroing
  - Constant-time comparison operations
  - Fluent API builders for common scenarios
  - Comprehensive testing framework
  - Security policies and configuration system
  - Observability and telemetry infrastructure

### Changed
- Refactored core algorithms for better performance
- Enhanced error handling and validation

### Security
- Implemented constant-time operations for sensitive comparisons
- Added secure memory management for key material
- Improved side-channel attack resistance

## [0.6.0] - 2024-09-XX (Phase 1 Complete)

### Added
- Foundation & Core Algorithms (Phase 1)
  - Argon2 Password Hashing (Argon2d, Argon2i, Argon2id)
    - Full RFC 9106 compliance
    - Configurable memory, iterations, and parallelism
    - Secure salt generation
  - Blake2b Hashing
    - Full RFC 7693 compliance
    - Variable output sizes (1-64 bytes)
    - Keyed hashing (MAC) support
    - Blake2b-Long for outputs > 64 bytes
  - RSA Encryption & Digital Signatures
    - PKCS#1 v2.2 support
    - Key generation (512-4096 bits)
    - PKCS#1 v1.5 and OAEP padding
  - PGP-compatible Encryption
    - Hybrid encryption with AES session keys
    - RSA key pair support
    - Passphrase protection for private keys
  - Multi-framework targeting (.NET Standard 2.0, .NET 6-9)
  - Dependency injection support

### Changed
- Initial release architecture and project structure

## [0.1.0] - 2024-08-XX (Initial Release)

### Added
- Project initialization
- Basic project structure
- NuGet package configuration
- CI/CD pipeline setup
- Initial documentation

---

## Release Types

### Major Releases (x.0.0)
- Breaking API changes
- Major architectural changes
- Removal of deprecated features

### Minor Releases (0.x.0)
- New features (backward compatible)
- New algorithm implementations
- Performance improvements
- Deprecated features (with migration path)

### Patch Releases (0.0.x)
- Bug fixes
- Security patches
- Documentation improvements
- Minor performance optimizations

## Deprecation Policy

- Features marked as deprecated will be supported for at least 2 minor versions
- Deprecation warnings will be added via `[Obsolete]` attributes
- Migration guides will be provided in release notes
- Security-critical deprecations may be expedited

## Security Updates

Security vulnerabilities will be addressed with highest priority:
- **Critical**: Immediate patch release within 24-48 hours
- **High**: Patch release within 7 days
- **Medium**: Included in next scheduled release
- **Low**: Included in next minor release

## Links

- [Homepage](https://github.com/YourOrg/HeroCrypt)
- [Documentation](https://github.com/YourOrg/HeroCrypt/tree/main/docs)
- [Issue Tracker](https://github.com/YourOrg/HeroCrypt/issues)
- [NuGet Package](https://www.nuget.org/packages/HeroCrypt)

---

*This changelog is maintained by the HeroCrypt development team.*
*For security advisories, see [SECURITY.md](SECURITY.md).*
