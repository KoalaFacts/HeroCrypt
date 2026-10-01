# Changelog

## [Unreleased]

### Security

- Resolve OpenPGP primary-key expiration from the newest authenticated current
  self-signature for the signed object. Reject missing, conflicting or unsupported
  policy evidence instead of treating it as an unlimited lifetime. Generate V6
  Direct Key self-signatures and authenticate the policy used by expiration updates.
  See [migration notes](docs/migration-guide.md#openpgp-expiration-policy-changes-after-v104).
- Require authenticated bindings for every subkey when OpenPGP binding validation
  is requested. Authenticate primary-key and subkey revocations, reject unsupported
  revocation evidence and scope each subkey status to its signed target. Correct
  version-prefixed issuer fingerprint matching in structural checks.
- Preserve parsed OpenPGP signature-subpacket length encodings so verification
  authenticates received bytes. Reject length-form changes without re-signing and
  accept independently signed legal five-octet encodings. Newly created subpackets
  continue to use minimal length encodings.
- Bind OpenPGP verification results to the actual verification key, validate issuer
  hints and signature/key versions and algorithms, and reject weak hashes,
  unsupported critical semantics and malformed RSA signature encodings.
- Reject ambiguous single-signature message streams and mismatched one-pass
  metadata. Return false for truncated packet framing in signed-message `TryRead`.
- Reuse the V6 signature salt in its one-pass packet and select V6 signatures for
  V6 keys. Explicit V6 mode requires a V6 key in either configuration order.
- Correct V6 signature salt sizes to RFC 9580 Table 23 and reject unsupported
  hash identifiers instead of assigning a default salt length.
- Scope OpenPGP verification to cryptographic checks under supplied keys.
- Correct V4/V6 signature header/trailer lengths and key-material prefixes; bind V6
  salts in certification, binding, revocation, expiration and rotation signatures.
  Historical nonstandard signatures require trusted re-signing/certification;
  no legacy verification fallback is provided. See
  [migration notes](docs/migration-guide.md#openpgp-signature-hash-correction-after-v104).
- Normalize canonical document line endings in both signing and verification while
  preserving authenticated trailing spaces and tabs.

## [1.0.4] - 2026-09-30

### Migration required

- Review stored hybrid envelopes and imported keys before upgrading. RSA envelopes
  require canonical algorithm metadata, a 32-byte payload key, RSA keys of at least
  2048 bits and strict single PEM/DER encoding. Low-order X25519 inputs are rejected;
  nonstandard historical high-bit decoding may change decryption results.
- Explicit X25519/ML-KEM nonces are now honored and deterministic mode is rejected.
  Ensure callers provide unique nonces and remove deterministic-mode configuration.
  See [hybrid migration](docs/migration-guide.md#hybrid-encryption-hardening-in-v104).

### Security

- Harden RSA hybrid envelopes with canonical AEAD selection, imported RSA key
  minimums, a 32-byte payload-key requirement, strict single PEM/DER validation
  and deterministic disposal/clearing of owned secret buffers.
- Reject all-zero X25519 agreement output, including low-order input aliases.
  Correct RFC 7748 high-bit input decoding and cover known-key hybrid ciphertexts.
- Restore accidentally excluded .NET 10 ML-KEM encryption suites and enforce
  selected key parameter sets on encapsulation, decapsulation and public-key import.
- Honor explicit AEAD nonces in X25519/ML-KEM hybrid operations, validate nonce
  lengths and reject deterministic mode instead of silently ignoring these options.
- Clarify custom hybrid encryption's sender, replay, context and metadata limits.
  See [migration notes](docs/migration-guide.md#hybrid-encryption-hardening-in-v104).

### Testing

- Replace the random ChaCha20 single-byte inequality assertion with an RFC 8439
  known vector. A zero keystream byte legitimately leaves a plaintext byte unchanged.

## [1.0.3] - 2026-09-30

### Migration required

- **Review existing wallets before upgrading.** Earlier BIP39 placeholder phrases
  are nonstandard, and regenerating phrases from the same entropy can change the
  wallet. Unicode/text normalization corrections can also change existing seeds.
  Preserve trusted seeds/private keys and verify wallet identity before changing
  recovery material. See [BIP39 migration](docs/migration-guide.md#bip39-wallet-entry-changes-in-v103).
- Recompute BIP32 fingerprint metadata from trusted parents and configure the
  original Shamir reconstruction threshold explicitly. See the
  [migration guide](docs/migration-guide.md).

### Security

- Validate Shamir share indices, lengths, initialization and count before
  interpolation. Add explicit reconstruction/verification thresholds and enforce
  the builder's configured threshold. Raw shares do not authenticate their origin,
  sharing session or original threshold; the legacy overload only requires two.
- Replace the demonstration BIP39 placeholder wordlist with the official 2048-word
  English list. Apply NFKD to raw seed password/salt, validate mnemonic checksums
  during entropy decoding and wallet construction, canonicalize accepted English
  wallet inputs, guard entropy-size overflow, and clear owned temporary buffers.
  Existing placeholder phrases and historical Unicode/text derivation require
  explicit recovery review; see the migration guide before updating stored wallets.
- Correct BIP32 parent fingerprints to HASH160, enforce wallet algorithm policy,
  validate key material and root metadata, reject depth overflow and ambiguous paths,
  and isolate caller buffers from key/result cleanup. Reuse portable secp256k1 private
  derivation and run HD wallet regressions on macOS as well as Windows/Linux.
- Reject null wallet sources and blank configured paths; honor the last builder
  source selection so seed configuration cannot override a later mnemonic selection.
- Clarify unsupported public-parent derivation and xprv/xpub import/export, fingerprint
  authentication limits, and the standard non-hardened private-key exposure boundary.

### Fixed

- Use fixed distributions for key-validation acceptance and sample-entropy tests,
  eliminating random rejection by the repeated-pair heuristic. Retain separate
  random generator tests and verify the existing repeated-pair rejection boundary.

## [1.0.2] - 2026-09-30

### Security

- Disable the MPC simulation: sum, multiplication, private set intersection, and
  Beaver triple generation now throw `NotSupportedException`. The former local
  implementation ignored security models and did not provide distributed privacy
  or authenticated computation. Remove the simulated arithmetic and hash matching.
- Add rejection regressions for security model and policy bypasses, silent sum
  truncation, invalid multiplication thresholds, and corrupted Beaver triples.
  Document migration and update protocol availability claims.

## [1.0.1] - 2026-09-30

### Security

- Disable the forgeable threshold signature simulation. Threshold key generation,
  partial signing, combination, and verification now throw `NotSupportedException`.
  Remove the corporate approval example and document migration of existing approvals.
- Correct unsigned constant-time equality and modular reduction over the full
  32-bit range; retain a fixed 32-round reduction algorithm.

## [1.0.0] - 2026-09-29

See [GitHub Release](https://github.com/KoalaFacts/HeroCrypt/releases/tag/v1.0.0) for details.


## [0.3.0] - 2026-01-28

See [GitHub Release](https://github.com/KoalaFacts/HeroCrypt/releases/tag/v0.3.0) for details.


## [0.2.0] - 2026-01-22

See [GitHub Release](https://github.com/KoalaFacts/HeroCrypt/releases/tag/v0.2.0) for details.


## [0.1.2] - 2026-01-14

See [GitHub Release](https://github.com/KoalaFacts/HeroCrypt/releases/tag/v0.1.2) for details.


## [0.1.1] - 2026-01-14

See [GitHub Release](https://github.com/KoalaFacts/HeroCrypt/releases/tag/v0.1.1) for details.


## [0.1.0] - 2026-01-14

See [GitHub Release](https://github.com/KoalaFacts/HeroCrypt/releases/tag/v0.1.0) for details.


All notable changes to HeroCrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
- Correct ring signature and zk-SNARK availability claims: their insecure prototypes
  were removed before the first release. Record the historical forgery reproductions
  and inspection of all 24 library assemblies in the six public NuGet versions.
- Mark threshold signature operations as disabled in readiness and onboarding guides.

### Added
- Text encoding convenience methods on operation builders (EncryptionBuilder, DecryptionBuilder, HashBuilder, SignatureBuilder, VerificationBuilder, KeyDerivationBuilder)
  - Hex encoding: `*AsHex`, `*ToHex()`, `Get*AsHex()`, `With*FromHex()`
  - Base64 encoding: `*AsBase64`, `*ToBase64()`, `Get*AsBase64()`, `With*FromBase64()`
  - Base64Url encoding: `*AsBase64Url`, `*ToBase64Url()`, `Get*AsBase64Url()`, `With*FromBase64Url()`
- Post-Quantum Cryptography - .NET 10+ Native Support ✅ **Production Ready**
  - ML-KEM (FIPS 203) - Key encapsulation mechanism with ML-KEM-512/768/1024
  - ML-DSA (FIPS 204) - Digital signatures with ML-DSA-44/65/87
  - SLH-DSA (FIPS 205) - Stateless hash-based signatures (Small/Fast variants)
  - Unified HeroCryptBuilder with fluent API for PQC operations
  - Algorithm-specific builders (MLKemBuilder, MLDsaBuilder, SlhDsaBuilder)
  - Comprehensive test suite with 45+ tests including integration and real-world examples
  - Security hardening: PEM validation, secure memory operations, disposal safety
  - Platform support: Windows CNG with PQC or OpenSSL 3.5+
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
- Project infrastructure and community guidelines
  - SECURITY.md with vulnerability reporting policy
  - CONTRIBUTING.md with comprehensive contribution guidelines
  - CHANGELOG.md for version tracking
  - EditorConfig for consistent code style
  - GitHub issue and pull request templates
  - Dependabot configuration for automated dependency updates
  - CodeQL security scanning workflow

### Documentation
- Added comprehensive algorithm selection guide (docs/algorithm-selection.md)
- Added text encoding conventions section to API patterns guide
- Added text encoding issues section to troubleshooting guide
- Added text encoding performance section to performance guide
- Added working with text formats section to getting started guide
- Enhanced XML documentation on operation builders with encoding examples
- Added `<seealso>` tags to all encoding methods for IntelliSense discoverability
- Added cross-references between all documentation pages for encoding topics
- Added FluentApiDemo.cs example showcasing all text encoding convenience methods
- Enhanced migration guide with text encoding migration patterns

### Changed
- **BREAKING**: Dropped .NET 6.0 and .NET 7.0 support - Now requires .NET 8.0+ or .NET Standard 2.0
- Updated DEVELOPMENT_ROADMAP.md marking Phases 3C, 3D, 3E, and 3F as completed
- Enhanced README.md with all new cryptographic features
- Improved documentation with production requirement warnings for reference implementations
- Updated all documentation to reflect .NET 8.0/9.0/10.0 as supported modern frameworks
- Updated GitHub workflows to build and test on .NET 8.0/9.0/10.0 only

### Fixed
- BIP32 Hierarchical Deterministic Wallets
  - Fixed secp256k1 public key derivation using .NET's ECDsa implementation
  - Corrected chain code generation for hardened and non-hardened child key derivation
  - All 37 BIP32 test vectors now passing on all platforms
- ML-KEM (Post-Quantum KEM) on .NET 10
  - Fixed buffer size requirements - now uses exact ciphertext sizes per algorithm variant
  - ML-KEM-512: 768 bytes, ML-KEM-768: 1088 bytes, ML-KEM-1024: 1568 bytes
  - Resolved ArgumentException on .NET 10 native implementation
- Rabbit Stream Cipher (RFC 4503)
  - Fixed key and IV endianness to match RFC specification (little-endian)
  - Corrected g-function implementation and block counter byte ordering
  - Updated test vectors to match RFC 4503 reference implementation
- Curve25519 (RFC 7748)
  - Fixed iterated test implementation to correctly update u and k values
  - Now correctly implements RFC 7748 Section 5.2 iteration algorithm
- ChainOfTrust Post-Quantum test
  - Fixed ML-DSA verification to include context parameter using fluent API
- Build warnings
  - Reduced build warnings from ~11,200 to ~2,242 (80% reduction)
  - Fixed SYSLIB0053 obsolete API warnings with conditional compilation
  - Updated Polyfill package to 9.0.3 for .NET Standard 2.0 compatibility
  - Fixed CS0168 unused variable warnings across the codebase

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
  - Multi-framework targeting (.NET Standard 2.0, .NET 8-10)
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

- [Homepage](https://github.com/KoalaFacts/HeroCrypt)
- [Documentation](https://github.com/KoalaFacts/HeroCrypt/tree/main/docs)
- [Issue Tracker](https://github.com/KoalaFacts/HeroCrypt/issues)
- [NuGet Package](https://www.nuget.org/packages/HeroCrypt)

---

*This changelog is maintained by the HeroCrypt development team.*
*For security advisories, see [SECURITY.md](SECURITY.md).*
