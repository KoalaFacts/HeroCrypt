# HeroCrypt Documentation

Welcome to the HeroCrypt documentation! This directory contains comprehensive guides to help you use HeroCrypt effectively and securely.

## Quick Links

- **[Getting Started](getting-started.md)** - New to HeroCrypt? Start here!
- **[Best Practices](best-practices.md)** - Security best practices for production use
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions
- **[Examples](../examples/)** - Code examples for common use cases

## Documentation Overview

### For New Users

1. **[Getting Started](getting-started.md)**
   - Installation instructions
   - Quick start examples
   - Core concepts
   - Common use cases

2. **[API Patterns](api-patterns.md)**
   - API design principles
   - Builder-first usage
   - Fluent API examples

### For Production Deployment

3. **[Best Practices](best-practices.md)**
   - Security principles
   - Password hashing guidelines
   - Encryption best practices
   - Key management strategies
   - Memory management
   - Error handling
   - Logging and monitoring

4. **[Production Readiness](../PRODUCTION_READINESS.md)**
   - Feature status (production vs. educational)
   - Compliance requirements
   - Security audit results

### Performance Optimization

5. **[Performance Guide](performance-guide.md)**
   - Hardware acceleration
   - Batch operations
   - Memory optimization
   - Parallel processing
   - Algorithm selection
   - Benchmarking

### Troubleshooting and Support

6. **[Troubleshooting](troubleshooting.md)**
   - Installation issues
   - Runtime errors
   - Performance problems
   - Platform-specific issues
   - Memory issues
   - Encryption/decryption failures

### Migration

7. **[Migration Guide](migration-guide.md)**
   - Migrating between HeroCrypt versions
   - Migrating from other libraries
   - Breaking changes
   - Deprecated features

## Examples

The [examples](../examples/) directory contains practical examples:

- **[FluentApiDemo.cs](../examples/HeroCrypt.Examples/FluentApiDemo.cs)** - Fluent builder demonstration
- **[Program.cs](../examples/HeroCrypt.Examples/Program.cs)** - Legacy API examples (for comparison)
- **[UseCases/](../examples/HeroCrypt.Examples/UseCases/)**
  - Password storage example
  - Data encryption example
  - Digital signatures example
  - And more...

## Additional Resources

### Core Documentation Files

- **[README.md](../README.md)** - Project overview and features
- **[SECURITY.md](../SECURITY.md)** - Security policy and vulnerability reporting
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contribution guidelines
- **[CHANGELOG.md](../CHANGELOG.md)** - Version history and changes
- **[LICENSE](../LICENSE)** - MIT License

### Technical Documentation

- **[DEVELOPMENT_ROADMAP.md](../DEVELOPMENT_ROADMAP.md)** - Future features and roadmap
- **[TEST_STATUS.md](../TEST_STATUS.md)** - Test coverage and platform status
- **[STANDARDS_COMPLIANCE.md](../STANDARDS_COMPLIANCE.md)** - RFC compliance information

## Feature Status

HeroCrypt contains both **production-ready** and **educational/reference** implementations:

### ✅ Production-Ready Core

- Argon2id password hashing (RFC 9106)
- Blake2b hashing (RFC 7693)
- ChaCha20-Poly1305 AEAD (RFC 8439)
- AES-GCM
- RSA (OAEP, PSS)
- ECC (P-256, P-384, P-521)
- Key derivation (HKDF, PBKDF2, Scrypt)
- BIP39 mnemonic codes

### 📚 Educational/Reference Only

- Post-quantum cryptography
- Zero-knowledge proofs
- Advanced protocols
- Hardware security integration (abstractions only)

**Always check [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) before using a feature in production.**

## Getting Help

### Community Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/KoalaFacts/HeroCrypt/issues)
- **GitHub Discussions**: Ask questions and share knowledge
- **Stack Overflow**: Tag questions with `herocrypt`

### Security Issues

For security vulnerabilities, please follow our [security policy](../SECURITY.md) and report privately.

### Contributing

We welcome contributions! Please read our [contributing guide](../CONTRIBUTING.md) for:
- Code of conduct
- Development workflow
- Coding standards
- Pull request process

## Documentation Conventions

Throughout this documentation, we use the following conventions:

- ✅ **Recommended** or **Safe** practice
- ❌ **Not recommended** or **Unsafe** practice
- ⚠️ **Warning** or **Caution**
- 📚 **Reference** or **Educational** implementation
- 🔒 **Security-critical** information

### Code Examples

`csharp
// GOOD: Recommended pattern
var hash = Argon2.Hash(
    password: "password"u8.ToArray(),
    salt: RandomNumberGenerator.GetBytes(16),
    iterations: 3,
    memorySizeKB: 65536,
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id);

// BAD: Anti-pattern to avoid
var hash = WeakHash(password);  // Don't do this!
`

## Quick Reference

### Common Operations

| Operation | Guide | Example |
|-----------|-------|---------|
| Hash passwords | [Best Practices](best-practices.md#password-hashing) | Argon2id |
| Encrypt data | [Getting Started](getting-started.md#quick-start) | ChaCha20-Poly1305 |
| Digital signatures | [Examples](../examples/) | RSA PSS, ECDSA |
| Key derivation | [Best Practices](best-practices.md#key-management) | HKDF, PBKDF2 |

### Algorithm Selection

| Use Case | Recommended Algorithm | Guide |
|----------|----------------------|-------|
| Password hashing | Argon2id | [Best Practices](best-practices.md#password-hashing) |
| Authenticated encryption | ChaCha20-Poly1305 or AES-GCM | [Getting Started](getting-started.md#authenticated-encryption) |
| Hashing | Blake2b or SHA-256 | [Performance Guide](performance-guide.md#algorithm-selection) |
| Digital signatures | ECDSA P-256 or RSA-3072 | [Examples](../examples/) |
| Key derivation | HKDF | [Best Practices](best-practices.md#key-derivation) |

### Security Levels

| Level | Use Case | Parameters |
|-------|----------|------------|
| Low | Testing only | Fast, weak |
| Medium | Resource-constrained | Balanced |
| High | Production (recommended) | Strong security |
| VeryHigh | High-value data | Very strong |
| Military | Maximum security | Very slow |

## Documentation Structure

```
docs/
├── README.md                 # This file
├── getting-started.md        # Quick start guide
├── best-practices.md         # Security best practices
├── api-patterns.md           # API design patterns
├── performance-guide.md      # Performance optimization
├── troubleshooting.md        # Common issues
└── migration-guide.md        # Version migration
```

## Version

This documentation is for **HeroCrypt v1.0.0**.

For older versions, please refer to the documentation in the corresponding git tag.

## Feedback

Found an issue with the documentation? Please:

1. Check if it's already reported in [GitHub Issues](https://github.com/KoalaFacts/HeroCrypt/issues)
2. If not, create a new issue with the `documentation` label
3. Provide suggestions for improvement

## License

HeroCrypt is released under the [MIT License](../LICENSE).

Documentation is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

**Happy coding with HeroCrypt! 🔐**
