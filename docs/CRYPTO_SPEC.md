# HeroCrypt Cryptographic Specification

**Document Version**: 1.0
**Date**: 2026-01-21
**Classification**: Public

---

## 1. Overview

This document specifies the cryptographic algorithms, parameters, and security properties implemented in HeroCrypt. It serves as a reference for security auditors, developers, and compliance assessments.

---

## 2. Symmetric Encryption

### 2.1 AEAD Ciphers (Recommended)

#### ChaCha20-Poly1305 (RFC 8439)

| Property | Value |
|----------|-------|
| Key Size | 256 bits (32 bytes) |
| Nonce Size | 96 bits (12 bytes) |
| Tag Size | 128 bits (16 bytes) |
| Block Size | 512 bits (64 bytes) |
| Security Level | 256-bit |
| Status | **Production Ready** |

**Implementation Notes**:
- SIMD optimizations (AVX2, SSE2) available
- Constant-time core operations
- RFC 8439 compliant

**Usage**:
```csharp
HeroCryptBuilder.Encrypt()
    .UseChaCha20Poly1305()
    .WithKey(key)
    .WithNonce(nonce)
    .WithPlaintext(data)
    .Build();
```

#### XChaCha20-Poly1305 (Extended Nonce)

| Property | Value |
|----------|-------|
| Key Size | 256 bits (32 bytes) |
| Nonce Size | 192 bits (24 bytes) |
| Tag Size | 128 bits (16 bytes) |
| Security Level | 256-bit |
| Status | **Production Ready** |

**Benefits**: Extended 24-byte nonce allows random nonce generation without collision concerns.

#### AES-GCM (NIST SP 800-38D)

| Property | Value |
|----------|-------|
| Key Sizes | 128, 192, 256 bits |
| Nonce Size | 96 bits (12 bytes) recommended |
| Tag Sizes | 96, 104, 112, 120, 128 bits |
| Block Size | 128 bits (16 bytes) |
| Status | **Production Ready** |

**Implementation Notes**:
- Hardware acceleration via AES-NI
- Custom tag sizes supported on .NET 8+
- GHASH implemented with carry-less multiplication where available

#### AES-CCM (RFC 3610)

| Property | Value |
|----------|-------|
| Key Sizes | 128, 192, 256 bits |
| Nonce Size | 56-104 bits (7-13 bytes) |
| Tag Sizes | 32, 48, 64, 80, 96, 112, 128 bits |
| Status | **Production Ready** (.NET 8+) |

#### AES-SIV (RFC 5297)

| Property | Value |
|----------|-------|
| Key Size | 256, 384, 512 bits (split key) |
| IV Size | Synthetic (derived) |
| Status | **Production Ready** |

**Benefits**: Nonce-misuse resistant - provides security even if nonces are reused (deterministic encryption).

#### AES-OCB (RFC 7253)

| Property | Value |
|----------|-------|
| Key Sizes | 128, 192, 256 bits |
| Nonce Size | Up to 120 bits |
| Tag Size | Up to 128 bits |
| Status | **Production Ready** |

**Warning**: Patent restrictions may apply for commercial use.

---

### 2.2 Stream Ciphers

#### ChaCha Variants

| Variant | Rounds | Key Size | Nonce Size | Status |
|---------|--------|----------|------------|--------|
| ChaCha20 | 20 | 256 bits | 96 bits | Production Ready |
| ChaCha12 | 12 | 256 bits | 96 bits | Production Ready |
| ChaCha8 | 8 | 256 bits | 96 bits | Production Ready |

**Note**: ChaCha20 recommended for security-critical applications.

#### XSalsa20

| Property | Value |
|----------|-------|
| Key Size | 256 bits |
| Nonce Size | 192 bits (24 bytes) |
| Status | **Production Ready** |

#### Rabbit (RFC 4503)

| Property | Value |
|----------|-------|
| Key Size | 128 bits (16 bytes) |
| IV Size | 64 bits (8 bytes) optional |
| Status | **Production Ready** |

**Implementation Notes**: Fully RFC 4503 compliant with correct endianness handling.

#### HC-128 / HC-256 (eSTREAM)

| Cipher | Key Size | IV Size | Status |
|--------|----------|---------|--------|
| HC-128 | 128 bits | 128 bits | Production Ready |
| HC-256 | 256 bits | 256 bits | Production Ready |

---

## 3. Asymmetric Encryption

### 3.1 RSA (RFC 8017)

| Property | Supported Values |
|----------|-----------------|
| Key Sizes | 2048, 3072, 4096 bits |
| Padding Modes | PKCS#1 v1.5, OAEP |
| OAEP Hash | SHA-256, SHA-384, SHA-512 |
| Status | **Production Ready** |

**Recommendations**:
- Minimum 2048 bits for security
- Prefer 3072+ bits for long-term security
- Use OAEP padding (not PKCS#1 v1.5 for new applications)

**Key Generation**:
```csharp
var keyPair = RsaCore.GenerateKeyPair(3072);
```

### 3.2 Elliptic Curve Cryptography

#### Curve25519 / X25519 (RFC 7748)

| Property | Value |
|----------|-------|
| Key Size | 256 bits (32 bytes) |
| Shared Secret | 256 bits |
| Security Level | ~128 bits |
| Status | **Production Ready** |

**Use Case**: Diffie-Hellman key exchange.

#### Ed25519 (RFC 8032)

| Property | Value |
|----------|-------|
| Key Size | 256 bits (32 bytes public, 64 bytes private) |
| Signature Size | 512 bits (64 bytes) |
| Security Level | ~128 bits |
| Status | **Production Ready** |

**Use Case**: Digital signatures.

#### secp256k1 (SEC 2)

| Property | Value |
|----------|-------|
| Key Size | 256 bits |
| Security Level | ~128 bits |
| Status | **Production Ready** |

**Use Case**: Bitcoin-compatible signatures, BIP32 wallets.

---

## 4. Hash Functions

### 4.1 Cryptographic Hashes

| Algorithm | Output Sizes | Status | Standard |
|-----------|--------------|--------|----------|
| SHA-256 | 256 bits | Production Ready | FIPS 180-4 |
| SHA-384 | 384 bits | Production Ready | FIPS 180-4 |
| SHA-512 | 512 bits | Production Ready | FIPS 180-4 |
| Blake2b | 1-512 bits | Production Ready | RFC 7693 |
| Blake2b-Long | >512 bits | Production Ready | RFC 7693 |

### 4.2 Blake2b Details (RFC 7693)

| Property | Value |
|----------|-------|
| Output Size | 1-64 bytes (configurable) |
| Key Size | 0-64 bytes (optional keyed mode) |
| Block Size | 128 bytes |
| Status | **Production Ready** |

**Features**:
- Keyed hashing (MAC) support
- Personalization and salt parameters
- SIMD optimization (AVX2)

```csharp
// Simple hash
byte[] hash = Blake2bCore.ComputeHash(data, outputLength: 32);

// Keyed hash (MAC)
byte[] mac = Blake2bCore.ComputeHash(data, outputLength: 32, key: secretKey);
```

---

## 5. Key Derivation Functions

### 5.1 Argon2 (RFC 9106)

| Variant | Use Case | Memory-Hardness | Timing-Hardness |
|---------|----------|-----------------|-----------------|
| Argon2d | Cryptocurrency | Maximum | Vulnerable to side-channel |
| Argon2i | Password hashing | Good | Resistant |
| Argon2id | **Recommended** | Good | Resistant (hybrid) |

**Parameters**:

| Parameter | Range | Recommended (OWASP) |
|-----------|-------|---------------------|
| Memory (m) | 8 KB - 4 GB | 19456 KB (19 MB) for Argon2id |
| Iterations (t) | 1+ | 2 for Argon2id with 19 MB |
| Parallelism (p) | 1-255 | 1 |
| Output Length | 4-2^32 bytes | 32 bytes |
| Salt Length | 8+ bytes | 16 bytes |

**Implementation**: Full RFC 9106 compliance with constant-time operations.

### 5.2 PBKDF2 (RFC 8018)

| Property | Supported Values |
|----------|-----------------|
| Hash Functions | SHA-256, SHA-384, SHA-512 |
| Iterations | 1+ (recommend 600,000+ for SHA-256) |
| Output Length | Configurable |
| Status | **Production Ready** |

**Note**: Prefer Argon2id for new applications.

### 5.3 HKDF (RFC 5869)

| Property | Value |
|----------|-------|
| Hash Functions | SHA-256, SHA-384, SHA-512 |
| Status | **Production Ready** |

**Use Case**: Key expansion, deriving multiple keys from shared secret.

### 5.4 Scrypt

| Property | Supported Values |
|----------|-----------------|
| N (CPU/memory cost) | Power of 2, typically 2^14 to 2^20 |
| r (block size) | Typically 8 |
| p (parallelism) | Typically 1 |
| Status | **Production Ready** |

### 5.5 Balloon Hashing

| Property | Value |
|----------|-------|
| Type | Memory-hard, cache-timing resistant |
| Status | **Production Ready** |

---

## 6. Digital Signatures

### 6.1 Supported Algorithms

| Algorithm | Key Size | Signature Size | Security Level | Status |
|-----------|----------|----------------|----------------|--------|
| Ed25519 | 256 bits | 512 bits | ~128 bits | Production Ready |
| ECDSA (P-256) | 256 bits | 512 bits | ~128 bits | Production Ready |
| ECDSA (secp256k1) | 256 bits | 512 bits | ~128 bits | Production Ready |
| RSA-PSS | 2048-4096 bits | Key size | 112-128+ bits | Production Ready |
| RSA PKCS#1 v1.5 | 2048-4096 bits | Key size | 112-128+ bits | Production Ready |

**Recommendation**: Use Ed25519 for new applications.

---

## 7. Post-Quantum Cryptography

**Availability**: .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+

### 7.1 ML-KEM (FIPS 203)

| Parameter Set | Public Key | Ciphertext | Shared Secret | Security Level |
|--------------|------------|------------|---------------|----------------|
| ML-KEM-512 | 800 bytes | 768 bytes | 32 bytes | NIST Level 1 |
| ML-KEM-768 | 1184 bytes | 1088 bytes | 32 bytes | NIST Level 3 |
| ML-KEM-1024 | 1568 bytes | 1568 bytes | 32 bytes | NIST Level 5 |

**Use Case**: Key encapsulation mechanism for hybrid encryption.

### 7.2 ML-DSA (FIPS 204)

| Parameter Set | Public Key | Signature | Security Level |
|--------------|------------|-----------|----------------|
| ML-DSA-44 | 1312 bytes | 2420 bytes | NIST Level 2 |
| ML-DSA-65 | 1952 bytes | 3293 bytes | NIST Level 3 |
| ML-DSA-87 | 2592 bytes | 4595 bytes | NIST Level 5 |

**Use Case**: Digital signatures resistant to quantum attacks.

### 7.3 SLH-DSA (FIPS 205)

| Variant | Security | Public Key | Signature |
|---------|----------|------------|-----------|
| SLH-DSA-128s | 128-bit | 32 bytes | 7856 bytes |
| SLH-DSA-128f | 128-bit | 32 bytes | 17088 bytes |
| SLH-DSA-192s | 192-bit | 48 bytes | 16224 bytes |
| SLH-DSA-192f | 192-bit | 48 bytes | 35664 bytes |
| SLH-DSA-256s | 256-bit | 64 bytes | 29792 bytes |
| SLH-DSA-256f | 256-bit | 64 bytes | 49856 bytes |

**Use Case**: Stateless hash-based signatures (conservative choice).

---

## 8. Protocols

### 8.1 BIP32 HD Wallets

| Property | Value |
|----------|-------|
| Curve | secp256k1 |
| Master Key | 32-byte private scalar plus 32-byte chain code from HMAC-SHA512 |
| Child Key Derivation | HMAC-SHA512 |
| Parent Fingerprint | First four bytes of RIPEMD160(SHA256(compressed public key)) |
| Supported Operations | Master generation; normal/hardened private-parent derivation |
| Unsupported Operations | Public-parent child derivation; xprv/xpub import/export |
| Platforms | .NET 8/9/10 on Windows, Linux and macOS; portable secp256k1 core |
| Status | **Scoped key derivation primitive** |

The default master domain is `Bitcoin seed`; a custom `keyType` produces a different
derivation. Seeds must be 16-64 bytes. Extended keys validate private scalars in
`1..n-1`, compressed public points, four-byte fingerprints, and zero root metadata.
Depth cannot exceed 255. Text paths use numeric components in `0..2147483647` and
an explicit apostrophe, `h` or `H` suffix for hardened indices; `DeriveChild` accepts
the full raw `uint` index range. Invalid child scalars reject at the requested index;
callers must retry the next index and record the index actually used.

Constructor inputs are copied. Result arrays remain mutable: protect them, avoid
concurrent mutation, and clear `ExtendedKey` and builder result seeds when finished.
`DerivePath(key, "m")` returns the same key object. Path derivation preserves the
caller-owned root and clears owned intermediates on success or failure. The builder
clears its unreturned master key and owned temporary seed on failure.
The last builder source selection replaces the previous source;
null seed/mnemonic inputs and blank configured paths reject instead of falling back.
Buffer cleanup is ownership hygiene, not a guarantee that managed runtimes or crypto
dependencies erase every secret copy or execute in constant time. Compliance policy rejects BIP32's
secp256k1 construction; algorithm policy does not provide module certification.

Fingerprints can collide and do not authenticate ancestry. A parent's extended public
material (public key and chain code) combined with a non-hardened descendant private
key can expose the parent's private key. Use hardened boundaries where isolation is
required, and protect seeds, private keys and chain codes. These are construction
limits described in the [BIP32 standard](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

### 8.2 BIP39 Mnemonics

| Property | Supported Values |
|----------|-----------------|
| Word Counts | 12, 15, 18, 21, 24 |
| Entropy | 128-256 bits |
| Wordlist | Official ordered 2048-word English list |
| Seed | 64 bytes, PBKDF2-HMAC-SHA512, 2048 iterations |
| Passphrase | Optional; NFKD, no trimming or case folding |
| Status | **Scoped wallet seed primitive** |

Generation and checksum/entropy validation use the official English wordlist.
`MnemonicToEntropy` checks the checksum before returning entropy.
`HdWalletBuilder` validates and canonicalizes accepted English case/spacing before
seed derivation and returns the phrase actually used.

Raw `MnemonicToSeed` is independent of the wordlist parser: it applies NFKD to the
mnemonic and salt without changing mnemonic case or collapsing spaces. Callers
must validate inputs separately when a standard recovery phrase is required. Raw
Unicode text conversion does not imply non-English generation/checksum support.
Every passphrase yields a seed; this API cannot detect a wrong passphrase.

Instance policy is passed to PBKDF2 and SHA-256 checksum validation. The fixed 2048
iterations are required by BIP39, below general password-KDF recommendations; policy
acceptance does not certify the module or wallet. Owned temporary entropy/bit/hash
and UTF-8 buffers are cleared, and callers must clear returned seed/entropy arrays.
Managed strings and dependency/runtime copies cannot be guaranteed erased; no
constant-time or runtime-wide zeroization claim is made.

Earlier placeholder wordlists and text derivation can yield different wallets.
Review the [migration guidance](migration-guide.md#bip39-wallet-entry-changes-in-v103)
before changing stored recovery material. Wordlist provenance and the MIT notice
are in [third-party notices](../THIRD-PARTY-NOTICES.md).

### 8.3 Shamir's Secret Sharing

| Property | Value |
|----------|-------|
| Field | GF(256) |
| Threshold | 2 <= k <= n <= 255; caller supplies the trusted reconstruction threshold |
| Security model | Trusted dealer; confidentiality only, no share authentication or VSS |
| Status | **Scoped confidentiality primitive** |

```csharp
var shamir = new ShamirSecretSharing();
var shares = shamir.Split(secret, threshold: 3, shareCount: 5);
var recovered = shamir.Reconstruct(shares.AsSpan(0, 3), threshold: 3);
var matches = shamir.Verify(shares.AsSpan(0, 3), secret, threshold: 3);
```

Store the original threshold in trusted application metadata. Shares contain only
`Index` and `Data`; the overloads without an explicit threshold require two shares
and cannot infer the threshold used at splitting. The builder enforces `WithThreshold`
for splitting, reconstruction and verification, with a default of 2.

`Verify` is an expected-value comparison, not proof of share origin, session membership,
dealer honesty or participant honesty. Authenticate each share and bind its index,
threshold and sharing-session identity outside this API. `SecurityPolicyOptions` does
not introduce authentication, algorithm restrictions or compliance certification here.
No managed-runtime constant-time guarantee is made.

The confidentiality model requires independent uniform coefficients over the whole
field, including zero; equal share payloads can legitimately occur. Fewer than k
shares reveal no information about secret bytes in that model, but secret length is
visible and guessing the original value can still succeed by chance. This is a
mathematical model, not a claim that passing a roundtrip test proves secrecy.
See [Shamir's original paper record](https://dspace.mit.edu/entities/publication/91c51bfc-5678-409c-80c5-44ce8fcdbadf)
and [NIST FIPS 197, section 4.2](https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf)
for the secret-sharing construction and GF(256) arithmetic respectively.

---

### 8.4 Hybrid encryption compositions

| API | Construction | Validation |
|-----|--------------|------------|
| `HybridEncryptionBuilder` | RSA-OAEP-SHA256 wraps a fresh 32-byte key; AES-GCM / ChaCha20-Poly1305 / XChaCha20-Poly1305 encrypts payload | RSA >= 2048 bits, exact algorithm name, single SPKI/PKCS8 PEM, full DER consumption |
| X25519 operation suites | Ephemeral X25519, HKDF-SHA256 (empty salt, fixed `X25519-Hybrid-Encryption` info), AEAD | RFC 7748 top-bit decoding; reject all-zero agreement output |
| .NET 10 ML-KEM operation suites | Native ML-KEM-768/1024 shared secret used as 32-byte AEAD key | Native support; public/private key parameter set must match suite |

These custom constructions are not HPKE or OpenPGP and provide no sender
authentication or replay protection. X25519 public keys/suite identifiers are not
included in its KDF; no public-key identity binding is claimed. ML-KEM + AEAD is
not a classical-plus-post-quantum KEM combiner. Applications must validate expected
associated-data context. The RSA envelope's `IsText` field is unauthenticated.
See the [security model](../SECURITY.md#hybrid-encryption-security-model) and
[migration notes](migration-guide.md#hybrid-encryption-hardening-after-v103).

## 9. Random Number Generation

### 9.1 Source

| Platform | RNG Source |
|----------|------------|
| All | `System.Security.Cryptography.RandomNumberGenerator` |
| Hardware | Intel RDRAND/RDSEED (with fallback) |

### 9.2 Security Properties

- Cryptographically secure
- Properly seeded from OS entropy
- No use of `System.Random` for any cryptographic operation

---

## 10. Memory Security

### 10.1 Secure Memory Operations

| Operation | Implementation |
|-----------|----------------|
| Memory Zeroing | `SecureMemoryOperations.SecureClear()` |
| Constant-Time Compare | `ConstantTimeOperations.ConstantTimeArrayEquals()` |
| SIMD Acceleration | AVX2/SSE2 constant-time operations |

### 10.2 IDisposable Pattern

All key-holding objects implement `IDisposable` for deterministic cleanup:

```csharp
using var keyPair = MLKem.Create().GenerateKeyPair();
// Key material zeroed on dispose
```

---

## 11. Compliance Matrix

### 11.1 FIPS 140-2 Compatible Algorithms

| Category | Algorithms |
|----------|------------|
| Symmetric | AES (128/192/256) |
| Hash | SHA-256, SHA-384, SHA-512 |
| Signature | RSA (2048+), ECDSA |
| KDF | PBKDF2, HKDF |
| RNG | CSPRNG via OS |

### 11.2 Non-FIPS Algorithms (Secure but not FIPS approved)

| Category | Algorithms |
|----------|------------|
| Symmetric | ChaCha20-Poly1305, XChaCha20 |
| Hash | Blake2b |
| Signature | Ed25519 |
| KDF | Argon2, Scrypt |

---

## 12. Algorithm Selection Guide

### 12.1 Recommended Algorithms by Use Case

| Use Case | Recommended | Alternative |
|----------|-------------|-------------|
| Password Hashing | Argon2id | Scrypt, PBKDF2 |
| Symmetric Encryption | ChaCha20-Poly1305 | AES-256-GCM |
| Key Exchange | X25519 | ECDH (P-256) |
| Digital Signatures | Ed25519 | ECDSA (P-256), RSA-PSS |
| General Hashing | Blake2b | SHA-256/512 |
| Key Derivation | HKDF | - |
| Post-Quantum KEM | ML-KEM-768 | ML-KEM-1024 |
| Post-Quantum Sig | ML-DSA-65 | SLH-DSA |

### 12.2 Algorithms to Avoid

| Algorithm | Reason |
|-----------|--------|
| RC4 | Broken - removed from library |
| DES/3DES | Weak, deprecated |
| MD5 | Collision attacks |
| SHA-1 | Collision attacks |
| RSA < 2048 | Insufficient key size |
| ECB mode | No semantic security |

---

*Last Updated: 2026-01-21*
