# HeroCrypt Standards Compliance

## Overview

HeroCrypt implements cryptographic algorithms from scratch following official standards and specifications. This document details the standards followed and how to verify compliance.

## Implemented Standards

### 1. Argon2 Password Hashing
**Standard:** RFC 9106 (September 2021)  
**Reference:** https://datatracker.ietf.org/doc/html/rfc9106

**Implementation Details:**
- Full support for Argon2d, Argon2i, and Argon2id variants
- Blake2b compression function as specified in RFC 7693
- Compliant memory access patterns for each variant
- Support for secret keys and associated data

**Verification:**
- Run `dotnet test --filter "ClassName=StandardsComplianceTests"` to verify against RFC 9106 test vectors
- Test vectors from RFC 9106 Appendix A are included
- Each variant (Argon2d, Argon2i, Argon2id) is tested with official vectors

### 2. RSA Encryption
**Standard:** PKCS#1 v2.2 (RFC 8017)  
**Reference:** https://datatracker.ietf.org/doc/html/rfc8017

**Implementation Details:**
- RSA key generation with configurable key sizes (512-4096 bits)
- PKCS#1 v1.5 padding for signatures
- Miller-Rabin primality testing for prime generation
- Custom BigInteger implementation for arbitrary precision arithmetic

### 3. Blake2b Hash Function
**Standard:** RFC 7693  
**Reference:** https://datatracker.ietf.org/doc/html/rfc7693

**Implementation Details:**
- Used internally by Argon2
- 64-bit variant (Blake2b)
- Supports variable output length

## How to Verify Compliance

### 1. Run Compliance Tests

```bash
# Run all compliance tests
dotnet test --filter "ClassName=StandardsComplianceTests"

# Run specific standard tests
dotnet test --filter "FullyQualifiedName~Argon2d_RFC9106"
dotnet test --filter "FullyQualifiedName~Argon2i_RFC9106"
dotnet test --filter "FullyQualifiedName~Argon2id_RFC9106"
```

### 2. Test Vector Sources

All test vectors are taken directly from the official RFC documents:

- **Argon2 Test Vectors:** RFC 9106, Appendix A
  - A.1: Argon2d Test Vectors
  - A.2: Argon2i Test Vectors
  - A.3: Argon2id Test Vectors

### 3. Verification Methods

The compliance tests verify:
1. **Exact Output Match:** Generated hashes match byte-for-byte with RFC test vectors
2. **Parameter Validation:** Proper rejection of invalid parameters as per specification
3. **Deterministic Output:** Same inputs always produce same outputs
4. **Salt Independence:** Different salts produce different outputs

### 4. Test Vector Example

```csharp
// RFC 9106 Test Vector for Argon2d
Password: 32 bytes of 0x01
Salt: 16 bytes of 0x02
Secret: 8 bytes of 0x03
Associated Data: 12 bytes of 0x04
Iterations: 3
Memory: 32 KB
Parallelism: 4
Output Length: 32 bytes

Expected Output: 
512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb
```

## Security Considerations

1. **Core Algorithms:** Argon2 and Blake2b are implemented from scratch following RFC specifications
2. **Supporting Primitives:** Uses .NET's built-in cryptographic primitives (AES, SHA256, RandomNumberGenerator) for proven security
3. **Constant-Time Operations:** Critical operations use constant-time comparisons
4. **Secure Random Generation:** Uses platform's cryptographically secure RNG
5. **Memory Management:** Proper cleanup of sensitive data

## Compliance Status

| Algorithm | Standard | Test Vectors | Status |
|-----------|----------|--------------|--------|
| Argon2d   | RFC 9106 | ✅ Pass      | ✅ Fully Compliant |
| Argon2i   | RFC 9106 | ✅ Pass      | ✅ Fully Compliant |
| Argon2id  | RFC 9106 | ✅ Pass      | ✅ Fully Compliant |
| Blake2b   | RFC 7693 | ✅ Pass      | ✅ Fully Compliant |
| RSA       | RFC 8017 | Partial      | 🔄 Basic implementation |
| AES       | FIPS 197 | N/A          | 📦 Uses .NET implementation |
| SHA-256   | FIPS 180-4 | N/A        | 📦 Uses .NET implementation |

## Future Compliance Work

- Add NIST CAVP test vectors for RSA
- Add OpenPGP (RFC 4880) compliance tests
- Add FIPS 140-2 validation tests where applicable

## References

1. RFC 9106 - Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
2. RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2
3. RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
4. RFC 4880 - OpenPGP Message Format