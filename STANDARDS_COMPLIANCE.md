# Standards Compliance

This document details HeroCrypt's compliance with cryptographic standards, RFCs, and NIST specifications.

## Compliance Summary

| Standard | Algorithm | Status | Verification Method |
|----------|-----------|--------|---------------------|
| RFC 9106 | Argon2 | Fully Compliant | Official test vectors |
| RFC 7693 | Blake2b | Fully Compliant | Official test vectors |
| RFC 8439 | ChaCha20-Poly1305 | Fully Compliant | Official test vectors |
| RFC 7748 | X25519 | Fully Compliant | Official test vectors |
| RFC 8032 | Ed25519 | Fully Compliant | BCL implementation |
| RFC 5869 | HKDF | Fully Compliant | Official test vectors |
| RFC 4503 | Rabbit | Fully Compliant | Appendix A test vectors |
| RFC 8017 | RSA (PKCS#1 v2.2) | Compliant | BCL implementation |
| FIPS 203 | ML-KEM | Compliant | BCL implementation (.NET 10+) |
| FIPS 204 | ML-DSA | Compliant | BCL implementation (.NET 10+) |
| FIPS 205 | SLH-DSA | Compliant | BCL implementation (.NET 10+) |

## Detailed Compliance Information

### RFC 9106 - Argon2

**Status:** Fully Compliant

HeroCrypt implements all three Argon2 variants as specified in RFC 9106:

| Variant | Description | Test Vectors |
|---------|-------------|--------------|
| Argon2d | Data-dependent | RFC 9106 Section 5 |
| Argon2i | Data-independent | RFC 9106 Section 5 |
| Argon2id | Hybrid | RFC 9106 Section 5 |

**Verified Features:**
- Memory-hardness with configurable memory cost
- Configurable iteration count (time cost)
- Parallelism support with lane mixing
- Variable-length output (tag)
- Associated data support
- Secret key support

**Test Vector Source:** RFC 9106 Appendix A

```csharp
// RFC 9106 compliant usage
var hash = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword("password")
    .WithSalt(salt)
    .WithIterations(3)
    .WithMemorySize(65536)  // 64 MB
    .WithParallelism(4)
    .DeriveKey(32);
```

### RFC 7693 - Blake2b

**Status:** Fully Compliant

| Feature | Support | Notes |
|---------|---------|-------|
| Variable output (1-64 bytes) | Yes | Full range supported |
| Keyed hashing (MAC) | Yes | Keys up to 64 bytes |
| Personalization | Yes | Up to 16 bytes |
| Salt | Yes | Up to 16 bytes |
| Blake2b-Long | Yes | Outputs > 64 bytes |

**Test Vector Source:** RFC 7693 Appendix A and official Blake2 test vectors

```csharp
// RFC 7693 compliant usage
var hash = HeroCryptBuilder.Hash()
    .WithBlake2b256()
    .ComputeHash(data);

// Keyed hash (MAC)
var mac = HeroCryptBuilder.Hash()
    .WithBlake2b256()
    .WithKey(key)
    .ComputeHash(data);
```

### RFC 8439 - ChaCha20 and Poly1305

**Status:** Fully Compliant

| Component | Status | Notes |
|-----------|--------|-------|
| ChaCha20 cipher | Compliant | 256-bit key, 96-bit nonce |
| Poly1305 MAC | Compliant | 128-bit tag |
| AEAD construction | Compliant | Combined encryption + auth |

**Test Vector Source:** RFC 8439 Section 2.8.2 (AEAD test vectors)

**Additional Variants:**
- ChaCha8/ChaCha12 (reduced rounds)
- XChaCha20 (extended 192-bit nonce)

```csharp
// RFC 8439 compliant AEAD
var result = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithKey(key)
    .WithNonce(nonce)
    .Encrypt(plaintext);
```

### RFC 7748 - Curve25519 (X25519)

**Status:** Fully Compliant

| Operation | Status | Notes |
|-----------|--------|-------|
| Scalar multiplication | Compliant | Constant-time |
| Key exchange | Compliant | ECDH |
| Key validation | Compliant | Low-order point rejection |

**Test Vector Source:** RFC 7748 Section 6.1

```csharp
// RFC 7748 compliant key exchange
var keyPair = HeroCryptBuilder.X25519().GenerateKeyPair();
var sharedSecret = HeroCryptBuilder.X25519()
    .WithPrivateKey(myPrivateKey)
    .ComputeSharedSecret(theirPublicKey);
```

### RFC 8032 - Ed25519

**Status:** Fully Compliant (via .NET BCL)

| Feature | Status | Notes |
|---------|--------|-------|
| Key generation | Compliant | 32-byte seeds |
| Signing | Compliant | 64-byte signatures |
| Verification | Compliant | Constant-time |
| Batch verification | Supported | Performance optimization |

**Implementation:** Uses .NET's native Ed25519 implementation (.NET 8+)

```csharp
// RFC 8032 compliant signatures
var (privateKey, publicKey) = HeroCryptBuilder.Sign()
    .WithEd25519()
    .GenerateKeyPair();

var signature = HeroCryptBuilder.Sign()
    .WithEd25519()
    .WithKey(privateKey)
    .Sign(message);
```

### RFC 5869 - HKDF

**Status:** Fully Compliant

| Phase | Status | Notes |
|-------|--------|-------|
| Extract | Compliant | PRK derivation |
| Expand | Compliant | OKM generation |
| Combined | Compliant | Extract-then-Expand |

**Hash Functions:** SHA-256, SHA-384, SHA-512

**Test Vector Source:** RFC 5869 Appendix A

```csharp
// RFC 5869 compliant key derivation
var derivedKey = HeroCryptBuilder.DeriveKey()
    .WithHkdfSha256()
    .WithInputKeyMaterial(ikm)
    .WithSalt(salt)
    .WithInfo(info)
    .DeriveKey(32);
```

### RFC 4503 - Rabbit Stream Cipher

**Status:** Fully Compliant

| Feature | Status | Notes |
|---------|--------|-------|
| Key setup | Compliant | 128-bit keys |
| IV setup | Compliant | 64-bit IV (optional) |
| Keystream generation | Compliant | Correct endianness |
| Counter mode | Compliant | Next-state function |

**Test Vector Source:** RFC 4503 Appendix A (all 6 test vectors pass)

**Note:** HeroCrypt correctly implements little-endian byte ordering as specified in RFC 4503, which differs from some other implementations.

```csharp
// RFC 4503 compliant encryption
var ciphertext = HeroCryptBuilder.Encrypt()
    .WithRabbit()
    .WithKey(key)
    .WithIv(iv)
    .Encrypt(plaintext);
```

### FIPS 203/204/205 - Post-Quantum Cryptography

**Status:** Compliant (via .NET 10 BCL)

| Standard | Algorithm | Status | Notes |
|----------|-----------|--------|-------|
| FIPS 203 | ML-KEM | Compliant | 512/768/1024 parameter sets |
| FIPS 204 | ML-DSA | Compliant | 44/65/87 parameter sets |
| FIPS 205 | SLH-DSA | Compliant | Small/Fast variants |

**Requirements:**
- .NET 10.0+
- Windows CNG with PQC support, or
- OpenSSL 3.5+ with PQC provider

**Implementation:** Native .NET BCL implementations (not HeroCrypt code)

```csharp
// FIPS 203 compliant key encapsulation
var keyPair = HeroCryptBuilder.MlKem()
    .WithParameterSet(MlKemParameterSet.MlKem768)
    .GenerateKeyPair();

var (ciphertext, sharedSecret) = keyPair.Encapsulate();
```

## NIST Standards

### NIST SP 800-38D - AES-GCM

**Status:** Compliant (via .NET BCL)

| Feature | Status | Notes |
|---------|--------|-------|
| 128/192/256-bit keys | Supported | All key sizes |
| 96-bit nonce | Recommended | Default configuration |
| Tag sizes | 96-128 bits | Configurable (.NET 8+) |
| Hardware acceleration | Supported | AES-NI |

### NIST SP 800-38C - AES-CCM

**Status:** Compliant (.NET 8+)

### FIPS 180-4 - SHA-2

**Status:** Compliant (via .NET BCL)

SHA-256, SHA-384, SHA-512 implementations use .NET's FIPS-validated BCL.

### FIPS 202 - SHA-3

**Status:** Compliant (.NET 8+)

SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256

## eSTREAM Portfolio

### HC-128 and HC-256

**Status:** Compliant with eSTREAM specification

| Cipher | Key Size | IV Size | Status |
|--------|----------|---------|--------|
| HC-128 | 128 bits | 128 bits | Compliant |
| HC-256 | 256 bits | 256 bits | Compliant |

## Industry Standards

### BIP-0032 - Hierarchical Deterministic Wallets

**Status:** Fully Compliant

| Feature | Status | Notes |
|---------|--------|-------|
| Master key generation | Compliant | From seed |
| Child key derivation | Compliant | Normal and hardened |
| Path notation | Supported | m/44'/0'/0'/0/0 |
| secp256k1 curve | Compliant | Bitcoin compatible |

### BIP-0039 - Mnemonic Codes

**Status:** Fully Compliant

| Feature | Status | Notes |
|---------|--------|-------|
| 12-24 word phrases | Supported | All standard lengths |
| English wordlist | Included | 2048 words |
| Checksum validation | Compliant | Entropy verification |
| Seed derivation | Compliant | PBKDF2-HMAC-SHA512 |

### SEC 2 - secp256k1

**Status:** Fully Compliant

Used for Bitcoin-compatible operations and BIP-32 wallets.

## Verification Process

### Test Vector Validation

All RFC-compliant implementations are verified against official test vectors:

1. **Unit Tests**: Individual function tests with RFC examples
2. **Integration Tests**: Full workflow tests
3. **Compliance Tests**: Dedicated test category for standards

### Running Compliance Tests

```bash
# Run all compliance tests
dotnet test --filter "Category=Compliance"

# Run specific standard tests
dotnet test --filter "FullyQualifiedName~Argon2"
dotnet test --filter "FullyQualifiedName~Blake2b"
dotnet test --filter "FullyQualifiedName~ChaCha20"
```

### Continuous Verification

- All test vectors are verified on every build
- CI/CD pipeline includes compliance test suite
- Regular updates when new test vectors are published

## Known Limitations

### .NET Standard 2.0

- AES-GCM: Limited (no custom tag sizes)
- AES-CCM: Not available
- SHA-3: Not available
- Ed25519 native: Not available
- Post-quantum: Not available

### Platform-Specific

- Post-quantum cryptography requires specific OS support
- Hardware acceleration varies by platform
- Some algorithms may use software fallbacks

## Reporting Compliance Issues

If you discover a compliance issue:

1. **Check existing issues**: [GitHub Issues](https://github.com/KoalaFacts/HeroCrypt/issues)
2. **Report with details**: Include RFC section, expected vs. actual output
3. **Provide test case**: Minimal reproducible example preferred

## References

### RFCs
- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [RFC 7693 - Blake2](https://www.rfc-editor.org/rfc/rfc7693)
- [RFC 8439 - ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 7748 - Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 5869 - HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 4503 - Rabbit Stream Cipher](https://www.rfc-editor.org/rfc/rfc4503)
- [RFC 8017 - PKCS #1](https://www.rfc-editor.org/rfc/rfc8017)

### NIST Publications
- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 180-4 - SHA-2](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [FIPS 202 - SHA-3](https://csrc.nist.gov/publications/detail/fips/202/final)
- [SP 800-38D - AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

### Bitcoin Improvement Proposals
- [BIP-0032 - HD Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-0039 - Mnemonic Codes](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
