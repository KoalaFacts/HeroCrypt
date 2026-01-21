# Threat Model: HeroCrypt

**Document Version**: 1.0
**Date**: 2026-01-21
**Classification**: Public

---

## 1. Overview

### 1.1 System Description

HeroCrypt is a comprehensive cryptographic library for .NET providing:
- Password hashing (Argon2d/i/id)
- Symmetric encryption (ChaCha20-Poly1305, AES-GCM/CCM/SIV/OCB)
- Asymmetric encryption (RSA, ECC)
- Digital signatures (Ed25519, ECDSA, RSA)
- Key derivation (PBKDF2, HKDF, Scrypt, Balloon)
- Stream ciphers (ChaCha, Rabbit, HC-128/256, XSalsa20)
- Post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA on .NET 10+)
- HD wallets (BIP32/BIP39)
- Secret sharing (Shamir's)

### 1.2 Scope

This threat model covers:
- Core cryptographic primitives
- Key management operations
- Memory handling of sensitive data
- API surface attack vectors

Out of scope:
- Applications built using HeroCrypt
- Network transport layer
- Operating system security
- Hardware attacks (beyond basic side-channel consideration)

---

## 2. Assets

### 2.1 Critical Assets

| Asset | Description | Impact if Compromised |
|-------|-------------|----------------------|
| Private Keys | RSA, ECC, Ed25519 private keys | Complete loss of confidentiality and authentication |
| Encryption Keys | AES, ChaCha20 symmetric keys | Decryption of all protected data |
| Passwords/Secrets | User passwords, API keys | Account compromise, data breach |
| HD Wallet Seeds | BIP39 mnemonics, master keys | Complete cryptocurrency theft |
| Session Keys | Ephemeral encryption keys | Session compromise |

### 2.2 Important Assets

| Asset | Description | Impact if Compromised |
|-------|-------------|----------------------|
| Nonces/IVs | Initialization vectors | Potential plaintext recovery (nonce reuse) |
| MACs/Signatures | Authentication tags | Message forgery, integrity loss |
| Salt Values | Argon2/PBKDF2 salts | Rainbow table attacks possible |
| Key Shares | Shamir's secret shares | Reduced threshold security |

---

## 3. Trust Boundaries

```
+------------------------------------------------------------------+
|                        Application Layer                          |
|  +------------------------------------------------------------+  |
|  |                    HeroCrypt API                            |  |
|  |  +------------------+  +------------------+  +------------+ |  |
|  |  | Fluent Builders  |  | Core Primitives  |  | Protocols  | |  |
|  |  +------------------+  +------------------+  +------------+ |  |
|  |            |                   |                   |        |  |
|  |  +---------------------------------------------------------+|  |
|  |  |              Security Layer                              ||  |
|  |  | - Constant-time ops  - Memory zeroing  - Input validation||  |
|  |  +---------------------------------------------------------+|  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
              +---------------+---------------+
              |                               |
    +---------v---------+          +----------v----------+
    |   .NET Runtime    |          |  BouncyCastle (PGP) |
    | RandomNumberGen   |          |                     |
    | System.Crypto     |          |                     |
    +-------------------+          +---------------------+
              |
    +---------v---------+
    |   Operating System |
    |   Entropy Sources  |
    +-------------------+
```

### 3.1 Trust Boundary Descriptions

1. **Application <-> HeroCrypt**: Application provides inputs; HeroCrypt must validate
2. **HeroCrypt <-> .NET Runtime**: HeroCrypt trusts .NET's RNG and built-in crypto
3. **HeroCrypt <-> OS**: Relies on OS for entropy and memory protection
4. **User <-> Application**: User-provided data is untrusted

---

## 4. Data Flow Diagram

### 4.1 Encryption Flow

```
+----------+    plaintext    +-----------+    ciphertext    +----------+
|   User   | --------------> | HeroCrypt | ---------------> |  Output  |
| (Caller) |                 | Encrypt() |                  | (Caller) |
+----------+                 +-----------+                  +----------+
     |                            |
     | key, nonce                 | key in memory
     v                            v
+----------+                 +-----------+
| Key      |                 | Secure    |
| Material |                 | Memory    |
+----------+                 | Zeroing   |
                             +-----------+
```

### 4.2 Password Hashing Flow

```
+----------+    password     +-----------+     hash        +----------+
|   User   | --------------> |  Argon2   | --------------> |  Output  |
| (Caller) |                 |  Hasher   |                 | (Caller) |
+----------+                 +-----------+                 +----------+
     |                            |
     | config params              | internal state
     | (iterations, memory)       | (zeroed after use)
     v                            v
+----------+                 +-----------+
|  Salt    |                 |  Memory   |
| (random) |                 |  Blocks   |
+----------+                 +-----------+
```

---

## 5. Threats (STRIDE Analysis)

### 5.1 Spoofing

| ID | Threat | Attack Vector | Impact | Mitigation | Status |
|----|--------|--------------|--------|------------|--------|
| S-1 | Key impersonation | Attacker provides fake public key | Man-in-the-middle | Out of scope (application responsibility) | N/A |
| S-2 | Algorithm spoofing | Attacker tricks system into using weak algorithm | Weakened security | Strong defaults, algorithm validation | Mitigated |

### 5.2 Tampering

| ID | Threat | Attack Vector | Impact | Mitigation | Status |
|----|--------|--------------|--------|------------|--------|
| T-1 | Ciphertext modification | Attacker modifies encrypted data | Data corruption/forgery | AEAD modes (GCM, Poly1305) verify integrity | Mitigated |
| T-2 | Parameter tampering | Attacker modifies crypto parameters | Weakened security | Input validation, parameter bounds checking | Mitigated |
| T-3 | Library tampering | Modified HeroCrypt DLL | Complete compromise | Strong naming, NuGet signed packages | Mitigated |

### 5.3 Repudiation

| ID | Threat | Attack Vector | Impact | Mitigation | Status |
|----|--------|--------------|--------|------------|--------|
| R-1 | Signature denial | Signer claims they didn't sign | Legal/accountability issues | Digital signatures (Ed25519, RSA) provide non-repudiation | Mitigated |
| R-2 | Operation denial | Deny performing crypto operation | Audit trail gaps | Out of scope (application logging) | N/A |

### 5.4 Information Disclosure

| ID | Threat | Attack Vector | Impact | Mitigation | Status |
|----|--------|--------------|--------|------------|--------|
| I-1 | Timing attacks | Measure operation timing | Key/plaintext recovery | Constant-time operations | Mitigated |
| I-2 | Memory disclosure | Read process memory | Key exposure | Secure memory zeroing, GC considerations | Partially Mitigated |
| I-3 | Error message leakage | Detailed exceptions | Information leakage | Generic error messages | Mitigated |
| I-4 | Padding oracle | Observe decryption errors | Plaintext recovery | AEAD modes, constant-time validation | Mitigated |
| I-5 | Side-channel (cache) | Cache timing analysis | Key recovery | SIMD constant-time ops | Partially Mitigated |
| I-6 | Nonce reuse | Same nonce with same key | Plaintext XOR recovery | Random nonce generation, warnings | Mitigated |

### 5.5 Denial of Service

| ID | Threat | Attack Vector | Impact | Mitigation | Status |
|----|--------|--------------|--------|------------|--------|
| D-1 | Resource exhaustion | Large Argon2 memory parameter | Memory exhaustion | Parameter validation, max limits | Mitigated |
| D-2 | CPU exhaustion | Expensive operations | Service unavailability | Reasonable defaults, documentation | Partially Mitigated |
| D-3 | Memory leak | Repeated operations | Memory exhaustion | IDisposable, using patterns | Mitigated |

### 5.6 Elevation of Privilege

| ID | Threat | Attack Vector | Impact | Mitigation | Status |
|----|--------|--------------|--------|------------|--------|
| E-1 | Buffer overflow | Malformed input | Code execution | Managed code, bounds checking | Mitigated |
| E-2 | Unsafe code exploitation | Bugs in unsafe blocks | Memory corruption | Limited unsafe usage, careful review | Mitigated |

---

## 6. Risk Assessment Matrix

| Threat ID | Likelihood | Impact | Risk Level | Priority |
|-----------|------------|--------|------------|----------|
| I-1 (Timing) | Medium | High | **High** | 1 |
| I-2 (Memory) | Low | Critical | **High** | 2 |
| I-4 (Padding Oracle) | Medium | High | **High** | 3 |
| T-1 (Tampering) | Medium | High | **High** | 4 |
| I-5 (Cache) | Low | High | Medium | 5 |
| D-1 (Resource) | Medium | Medium | Medium | 6 |
| I-6 (Nonce reuse) | Low | High | Medium | 7 |
| E-2 (Unsafe) | Very Low | Critical | Medium | 8 |
| D-2 (CPU) | Low | Medium | Low | 9 |
| S-2 (Algo spoof) | Very Low | Medium | Low | 10 |

---

## 7. Security Controls

### 7.1 Implemented Controls

#### Constant-Time Operations
- Location: `Security/ConstantTimeOperations.cs`, `Security/SimdConstantTimeOperations.cs`
- Purpose: Prevent timing attacks on sensitive comparisons
- Methods: `ConstantTimeEquals`, `ConditionalSelect`, `ConstantTimeArrayEquals`
- SIMD optimization: AVX2/SSE2 accelerated while maintaining constant-time

#### Secure Memory Management
- Location: `Security/SecureMemoryOperations.cs`
- Purpose: Prevent key material leakage
- Methods: `SecureClear`, automatic zeroing in Dispose patterns
- Limitation: .NET GC may copy data; consider pinned memory for extreme security

#### Input Validation
- Location: `Security/InputValidator.cs`
- Purpose: Reject malformed or dangerous inputs
- Validates: Key sizes, parameter ranges, buffer lengths

#### AEAD by Default
- Recommended modes: ChaCha20-Poly1305, AES-GCM
- Purpose: Provide authentication with encryption
- Prevents: Ciphertext tampering, padding oracles

### 7.2 Security Best Practices Enforced

| Practice | Implementation |
|----------|----------------|
| Secure RNG | `RandomNumberGenerator.Fill()` exclusively |
| No weak algorithms | RC4 removed; MD5/SHA1 warnings |
| Minimum key sizes | RSA >= 2048, AES >= 128 |
| Safe defaults | Argon2id, AES-256-GCM as defaults |

---

## 8. Residual Risks

### 8.1 Accepted Risks

| Risk | Reason | Mitigation |
|------|--------|------------|
| GC memory copies | .NET runtime behavior | Document limitation, use secure buffers where critical |
| JIT timing variations | Runtime optimization | Use `NoInlining`, `NoOptimization` attributes |
| Hardware attacks | Out of scope for software library | Document as out of scope |

### 8.2 Known Limitations

1. **Post-Quantum on older .NET**: ML-KEM/ML-DSA only available on .NET 10+
2. **Reference implementations**: Some advanced protocols are educational only
3. **AES-OCB patents**: Commercial use may require licensing
4. **No HSM integration**: Hardware security module support is abstraction only

---

## 9. Recommendations

### 9.1 For Library Users

1. **Always use AEAD modes** for encryption (ChaCha20-Poly1305 or AES-GCM)
2. **Never reuse nonces** with the same key
3. **Use Argon2id** for password hashing with OWASP-recommended parameters
4. **Validate all inputs** before passing to HeroCrypt
5. **Keep library updated** for security patches
6. **Use strong key sizes**: RSA-3072+, AES-256

### 9.2 For Library Maintainers

1. **Regular security audits** of cryptographic code
2. **Monitor CVEs** in dependencies
3. **Constant-time review** for any new comparison operations
4. **Memory handling review** for new key/secret processing
5. **Test vector validation** for all algorithm implementations

---

## 10. Appendix

### A. Attack Surface Summary

| Component | Entry Points | Trust Level Required |
|-----------|--------------|---------------------|
| Fluent Builders | Public API | None (untrusted input) |
| Core Primitives | Internal/Public | None |
| Security Layer | Internal | Library code only |

### B. Security Testing Recommendations

- [ ] Fuzz testing on all public APIs
- [ ] Timing analysis on comparison operations
- [ ] Memory inspection after operations
- [ ] Negative testing with invalid parameters
- [ ] Test vector validation against RFCs

### C. References

- OWASP Cryptographic Storage Cheat Sheet
- NIST SP 800-57 (Key Management)
- RFC 9106 (Argon2)
- RFC 8439 (ChaCha20-Poly1305)
- FIPS 203/204/205 (Post-Quantum)

---

*Last Updated: 2026-01-21*
