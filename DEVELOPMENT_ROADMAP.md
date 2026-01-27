# Development Roadmap

This document outlines the planned development direction for HeroCrypt, including upcoming features, improvements, and long-term goals.

## Current Status: v1.0.0

HeroCrypt v1.0.0 provides a comprehensive cryptographic library with:
- Production-ready core algorithms (Argon2, Blake2b, ChaCha20-Poly1305, AES-GCM, etc.)
- Multi-framework support (.NET Standard 2.0, .NET 8/9/10)
- Post-quantum cryptography support (.NET 10+)
- Fluent builder APIs for ease of use
- Extensive documentation and examples

## Release Phases

### Phase 1: Foundation (Completed)

**Status:** Released in v1.0.0

- [x] Core hashing algorithms (SHA-2, SHA-3, Blake2b)
- [x] Password hashing (Argon2id, PBKDF2, Scrypt)
- [x] Symmetric encryption (AES-GCM, ChaCha20-Poly1305)
- [x] Stream ciphers (Rabbit, HC-128/256, XSalsa20)
- [x] Asymmetric cryptography (RSA, ECDSA, Ed25519, X25519)
- [x] Key derivation (HKDF, PBKDF2, Scrypt)
- [x] HD wallets (BIP-32, BIP-39)
- [x] Secret sharing (Shamir's)
- [x] Multi-framework support

### Phase 2: Post-Quantum & Protocols (Current)

**Status:** In Progress

- [x] ML-KEM (FIPS 203) - Key encapsulation
- [x] ML-DSA (FIPS 204) - Digital signatures
- [x] SLH-DSA (FIPS 205) - Hash-based signatures
- [ ] Hybrid classical/PQC encryption schemes
- [ ] PQC key exchange protocols
- [ ] TLS 1.3 integration improvements

### Phase 3: Enterprise Features (Planned)

**Status:** Planning

- [ ] Enhanced HSM integration
  - [ ] AWS CloudHSM connector
  - [ ] Google Cloud HSM connector
  - [ ] Improved PKCS#11 support
- [ ] Certificate management improvements
  - [ ] ACME protocol support
  - [ ] Certificate transparency logging
  - [ ] OCSP stapling
- [ ] Compliance enhancements
  - [ ] FIPS 140-3 validation preparation
  - [ ] Common Criteria documentation
  - [ ] SOC 2 audit support

### Phase 4: Advanced Protocols (Future)

**Status:** Research

- [ ] Messaging protocols
  - [ ] Matrix protocol support
  - [ ] MLS (Messaging Layer Security)
- [ ] Zero-knowledge improvements
  - [ ] Production-grade zk-SNARKs
  - [ ] Bulletproofs
  - [ ] zk-STARKs exploration
- [ ] Secure computation
  - [ ] Fully homomorphic encryption (FHE)
  - [ ] Trusted execution environment (TEE) improvements

## Feature Backlog

### High Priority

| Feature | Description | Status |
|---------|-------------|--------|
| Hybrid PQC Encryption | Combine classical + PQC for defense in depth | Planning |
| Key Rotation API | Automated key lifecycle management | Design |
| Streaming Encryption | Large file encryption with minimal memory | Design |
| Batch Operations | High-throughput bulk cryptography | In Progress |

### Medium Priority

| Feature | Description | Status |
|---------|-------------|--------|
| WebAssembly Support | Browser-based cryptography | Research |
| .NET MAUI Optimization | Mobile platform improvements | Research |
| Performance Profiling | Built-in performance diagnostics | Planning |
| Key Escrow | Enterprise key recovery | Design |

### Low Priority

| Feature | Description | Status |
|---------|-------------|--------|
| GUI Key Manager | Desktop key management tool | Backlog |
| Plugin Architecture | Extensible algorithm support | Backlog |
| Hardware Wallet Support | Ledger/Trezor integration | Backlog |

## Framework Support Timeline

### Current Support

| Framework | Status | End of Support |
|-----------|--------|----------------|
| .NET Standard 2.0 | Supported | Indefinite |
| .NET 8.0 LTS | Full Support | November 2026 |
| .NET 9.0 | Full Support | May 2026 |
| .NET 10.0 | Full Support | November 2028 |

### Planned Support

| Framework | Expected | Notes |
|-----------|----------|-------|
| .NET 11.0 | Q4 2026 | Upon release |
| .NET 12.0 LTS | Q4 2027 | Upon release |

### Deprecation Schedule

| Framework | Deprecation | Removal |
|-----------|-------------|---------|
| .NET 6.0 | Deprecated | v2.0.0 |
| .NET 7.0 | Deprecated | v2.0.0 |

## Algorithm Roadmap

### Under Consideration

| Algorithm | Category | Status | Notes |
|-----------|----------|--------|-------|
| BIKE | Post-Quantum KEM | Research | NIST alternate |
| Classic McEliece | Post-Quantum KEM | Research | NIST alternate |
| SPHINCS+ pure | Post-Quantum Sig | Evaluation | Alternative to SLH-DSA |
| Ascon | AEAD | Research | Lightweight crypto |
| AEGIS | AEAD | Research | High-speed AEAD |

### Not Planned

| Algorithm | Reason |
|-----------|--------|
| DES/3DES | Deprecated, insecure |
| MD5 (new code) | Insecure for cryptographic use |
| RC4 | Known vulnerabilities |
| Blowfish | Superseded by modern ciphers |

## Breaking Changes Policy

### Semantic Versioning

HeroCrypt follows semantic versioning:
- **Major (x.0.0)**: Breaking API changes
- **Minor (0.x.0)**: New features, backward compatible
- **Patch (0.0.x)**: Bug fixes, backward compatible

### Deprecation Policy

1. Features deprecated with `[Obsolete]` attribute
2. Warning messages for at least one minor version
3. Removal in next major version
4. Migration guide provided

### Upcoming Breaking Changes (v2.0.0)

| Change | Migration Path |
|--------|----------------|
| Remove .NET 6.0/7.0 support | Upgrade to .NET 8.0+ |
| Streamlined builder API | Update method chains |
| Unified exception types | Update catch blocks |

## Performance Goals

### Current Performance

| Operation | Current | Target |
|-----------|---------|--------|
| Blake2b (1KB) | 0.8 μs | 0.5 μs |
| ChaCha20-Poly1305 (1KB) | 1.2 μs | 0.8 μs |
| AES-GCM (1KB) | 0.6 μs | 0.4 μs |
| Argon2id (64MB, 3 iter) | 350 ms | 300 ms |

### Optimization Priorities

1. **SIMD improvements**: Wider vector operations (AVX-512)
2. **Memory allocation**: Reduce GC pressure
3. **Parallelization**: Better multi-core utilization
4. **Hardware acceleration**: Expand AES-NI, SHA-NI usage

## Documentation Roadmap

### Planned Documentation

| Document | Status | Target |
|----------|--------|--------|
| API Reference (auto-generated) | Planning | v1.1.0 |
| Architecture Diagrams | Planning | v1.1.0 |
| Video Tutorials | Backlog | v1.2.0 |
| Interactive Examples | Research | v2.0.0 |

### Translation Plans

| Language | Status | Target |
|----------|--------|--------|
| English | Complete | v1.0.0 |
| Chinese (Simplified) | Planning | v1.2.0 |
| Japanese | Backlog | v1.3.0 |
| German | Backlog | v1.3.0 |

## Community & Governance

### Contribution Areas

We welcome contributions in:
- Algorithm implementations
- Performance optimizations
- Documentation improvements
- Test coverage expansion
- Platform compatibility testing

### Review Process

1. **Design review**: For new features
2. **Security review**: For cryptographic changes
3. **Code review**: For all changes
4. **Documentation review**: For public API changes

### Security Audit Schedule

| Audit Type | Frequency | Last Completed |
|------------|-----------|----------------|
| Internal review | Continuous | Ongoing |
| External audit | Major releases | Planned |
| Penetration testing | Annual | Planned |

## How to Influence the Roadmap

### Feature Requests

1. Check [existing issues](https://github.com/KoalaFacts/HeroCrypt/issues)
2. Open a new issue with the `enhancement` label
3. Provide use case and rationale
4. Engage in discussion

### Prioritization Factors

- Security impact
- User demand (issue upvotes)
- Standards compliance
- Implementation complexity
- Maintenance burden

### Sponsorship

Priority support and feature requests available for sponsors. Contact us for enterprise support options.

## Version History

| Version | Release Date | Major Features |
|---------|--------------|----------------|
| v1.0.0 | 2025 | Initial release, core cryptography |
| v1.1.0 | Planned | Performance improvements, hybrid PQC |
| v2.0.0 | Planned | API refinements, .NET 12 support |

## Feedback

We value community input on our roadmap:

- **GitHub Discussions**: [Share ideas](https://github.com/KoalaFacts/HeroCrypt/discussions)
- **GitHub Issues**: [Request features](https://github.com/KoalaFacts/HeroCrypt/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting

---

*This roadmap is subject to change based on community feedback, security requirements, and ecosystem developments.*
