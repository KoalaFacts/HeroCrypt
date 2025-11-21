# Security Policy

## 🔒 Security Commitment

HeroCrypt is a cryptographic library where security is paramount. We take all security vulnerabilities seriously and appreciate the efforts of security researchers and the community in responsibly disclosing issues.

## 📢 Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by email to:

**security@herocrypt.dev** (or repository maintainer's email)

Please include the following information in your report:

- **Type of vulnerability** (e.g., buffer overflow, timing attack, incorrect implementation)
- **Full path of source file(s)** related to the vulnerability
- **Location of the affected source code** (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit it
- **Your assessment** of the severity (Critical, High, Medium, Low)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
- **Updates**: We will provide regular updates on the progress of addressing the vulnerability.
- **Timeline**: We aim to release a fix within 90 days of disclosure, though critical issues will be prioritized.
- **Credit**: With your permission, we will publicly credit you for the discovery once the fix is released.

## 🛡️ Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.x   | :white_check_mark: | Active support |
| < 1.0   | :x:                | Not supported |

**Note**: Security fixes will be backported to the latest minor version of supported major versions.

## 🔐 Security Best Practices

When using HeroCrypt, please follow these security best practices:

### 1. **Use Recommended Algorithms**
- **Password Hashing**: Use Argon2id (default) for password hashing
- **Encryption**: Use ChaCha20-Poly1305 or AES-GCM for AEAD
- **Signatures**: Use Ed25519 for digital signatures
- **Key Exchange**: Use X25519 for Diffie-Hellman key exchange
- **Hashing**: Use Blake2b or SHA-256/SHA-512 for general hashing

### 2. **Avoid Deprecated/Weak Algorithms**
- ❌ **Never use RC4** – removed from the library due to insecurity
- ⚠️ **Use caution with RSA** - Ensure key sizes ≥ 2048 bits, prefer 3072 or 4096 bits
- ⚠️ **Post-Quantum algorithms** - Current implementations are reference/educational only

### 3. **Key Management**
- **Never hardcode keys** in source code
- **Use secure key storage** (OS key stores, HSM, or encrypted at rest)
- **Rotate keys regularly** according to your security policy
- **Use appropriate key sizes**:
  - AES: 256-bit keys
  - RSA: ≥ 2048 bits (prefer 3072+)
  - ECC: 256-bit curves (Curve25519, secp256k1)
  - Argon2: Follow OWASP recommendations

### 4. **Random Number Generation**
- HeroCrypt uses `System.Security.Cryptography.RandomNumberGenerator`
- **Never** use `System.Random` for cryptographic operations
- Ensure your system has sufficient entropy

### 5. **Memory Security**
- HeroCrypt uses secure memory management for sensitive data
- Keys and secrets are zeroed after use
- Consider using `SecureString` for user-entered secrets where appropriate

### 6. **Side-Channel Attacks**
- HeroCrypt implements constant-time operations for critical paths
- Be aware of timing attacks when implementing custom logic
- Avoid branching on secret data

### 7. **Input Validation**
- Always validate and sanitize inputs before cryptographic operations
- Check key lengths and parameter ranges
- Validate ciphertext authenticity before decryption (use AEAD)

### 8. **Configuration**
- Use secure defaults (don't lower security parameters without good reason)
- For Argon2: Use at least the minimum recommended parameters
- For AES-GCM: Never reuse nonces with the same key
- For ChaCha20-Poly1305: Use random or counter-based nonces

## 🚨 Known Limitations & Warnings

### Reference Implementations
The following components are **simplified reference implementations** for educational and API design purposes only:

- **Post-Quantum Cryptography** (Phase 3E)
  - CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+
  - ⚠️ **DO NOT use in production** without complete implementation

- **Zero-Knowledge & Advanced Protocols** (Phase 3F)
  - zk-SNARKs, Ring Signatures, Threshold Signatures, MPC
  - ⚠️ **Educational purposes only** - requires full cryptographic implementation

Production use of these features requires:
- Complete mathematical implementations
- Security audits
- Constant-time operations
- Formal verification
- NIST test vector validation

### Algorithm-Specific Warnings

- **RC4**: Removed; known vulnerabilities make it unsafe
- **AES-OCB**: Patent restrictions may apply for commercial use
- **Shamir's Secret Sharing**: Implemented over GF(256), ensure sufficient threshold
- **BIP39 Mnemonics**: Using simplified wordlist (production needs full BIP39 wordlist)

## 🔍 Security Audits

### Completed Audits

**Internal Security Audit - October 2025**
- **Date**: 2025-10-26
- **Type**: Comprehensive internal code audit
- **Scope**: All source files (~11,000 lines of code)
- **Grade**: B+ (Production-Ready Core, Educational Advanced Features)

**Findings**:
- **CRITICAL-001**: Non-cryptographic Random in SecureBuffer (Line 271) - ✅ **FIXED**
- **CRITICAL-003**: Hardware RNG placeholder using Environment.TickCount - ✅ **FIXED** (secure fallback enforced)
- **HIGH-002**: NotImplementedException in 5 production code paths - ✅ **FIXED** (proper error handling)

**Actions Taken**:
- Replaced `new Random()` with `RandomNumberGenerator.Fill()` in SecureBuffer.cs
- Hardware RNG now safely falls back to cryptographic RNG (documented as reference)
- Removed NotImplementedException, added clear error messages for unsupported features
- Created PRODUCTION_READINESS.md to document feature status
- Updated security documentation

**Conclusion**: Core cryptographic features (Argon2, Blake2b, ChaCha20-Poly1305, AES-GCM, RSA, ECC) are production-ready after fixes. Advanced features (PQC, ZK, Protocols, Hardware) are educational implementations only.

### Planned Audits
- Professional third-party security audit planned for Q2 2026
- Specific focus on core cryptographic implementations
- Formal verification exploration for critical components

## 📋 Security Checklist for Contributors

Before submitting code that touches cryptographic implementations:

- [ ] Implementation follows published standards (RFC, NIST FIPS, etc.)
- [ ] Test vectors from official specifications are included
- [ ] Constant-time operations used where necessary
- [ ] Memory is securely cleared after use
- [ ] No timing or side-channel vulnerabilities introduced
- [ ] Input validation is comprehensive
- [ ] Error handling doesn't leak sensitive information
- [ ] Documentation includes security warnings where appropriate
- [ ] Code has been reviewed by another developer
- [ ] All existing tests pass
- [ ] New tests added for new functionality

## 🎓 Security Research

We welcome security research on HeroCrypt. If you're conducting academic research:

- Please let us know about your research
- We're happy to provide clarification or assist with questions
- We appreciate advance notice before publishing findings
- Please follow responsible disclosure practices

## 📚 Resources

### Cryptographic Standards
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [IETF RFCs](https://www.ietf.org/standards/rfcs/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

### Security Tools
- [CodeQL](https://codeql.github.com/) - Semantic code analysis
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Snyk](https://snyk.io/) - Vulnerability scanning

### Learning Resources
- [Cryptography I (Coursera)](https://www.coursera.org/learn/crypto)
- [Serious Cryptography](https://nostarch.com/seriouscrypto) by Jean-Philippe Aumasson
- [Real-World Cryptography](https://www.manning.com/books/real-world-cryptography) by David Wong

## 🔔 Security Advisories

Security advisories will be published via:
- GitHub Security Advisories
- NuGet package warnings
- Release notes with CVE identifiers (if applicable)
- Security mailing list (planned)

## 💬 Contact

For non-security questions:
- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions and discussions

For security concerns:
- **Email**: security@herocrypt.dev

---

**Thank you for helping keep HeroCrypt and the .NET cryptography community secure!**

*Last Updated: 2025-10-26*
