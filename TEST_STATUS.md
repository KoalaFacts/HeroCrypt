# Test Status

This document provides an overview of HeroCrypt's test coverage, platform compatibility, and testing methodology.

## Test Summary

| Metric | Value |
|--------|-------|
| Total Test Files | 78+ |
| Test Categories | 10 |
| Target Frameworks | .NET 8.0, 9.0, 10.0 |
| CI/CD Integration | GitHub Actions |

## Test Categories

Tests are organized into categories for efficient execution and filtering:

| Category | Description | Typical Duration |
|----------|-------------|------------------|
| `Fast` | Quick tests without key generation | < 100ms |
| `Slow` | Tests with RSA key generation or intensive computation | 1-15 seconds |
| `Compliance` | RFC and standards verification | < 200ms |
| `Integration` | Multi-component workflow tests | Variable |
| `Unit` | Individual component isolation tests | < 50ms |
| `Security` | Cryptographic security property tests | < 500ms |
| `Memory` | Memory hygiene and disposal tests | < 100ms |
| `EdgeCase` | Boundary condition tests | < 100ms |
| `KnownAnswer` | Official test vector verification | < 100ms |
| `ThreadSafety` | Concurrent access tests | < 500ms |
| `InputValidation` | Malformed input handling | < 100ms |

## Running Tests

### All Tests
```bash
dotnet test
```

### By Category
```bash
# Fast tests only (CI recommended)
dotnet test --filter "Category=Fast"

# Compliance tests
dotnet test --filter "Category=Compliance"

# Exclude slow tests
dotnet test --filter "Category!=Slow"

# Multiple categories
dotnet test --filter "Category=Fast|Category=Compliance"
```

### By Framework
```bash
# .NET 8.0 only
dotnet test -f net8.0

# .NET 10.0 only (includes post-quantum tests)
dotnet test -f net10.0
```

### By Component
```bash
# Specific algorithm
dotnet test --filter "FullyQualifiedName~Blake2b"
dotnet test --filter "FullyQualifiedName~ChaCha20"
dotnet test --filter "FullyQualifiedName~Argon2"

# Operations layer
dotnet test --filter "FullyQualifiedName~EncryptionBuilder"
dotnet test --filter "FullyQualifiedName~HashBuilder"
```

## Test Coverage by Component

### Core Primitives

| Component | Test File | Categories | Status |
|-----------|-----------|------------|--------|
| Argon2 | `Argon2CoreTests.cs` | Fast, Compliance | Comprehensive |
| Blake2b | `Blake2bCoreTests.cs` | Fast, Compliance | Comprehensive |
| ChaCha20 | `ChaCha20CoreTests.cs` | Fast, Compliance | Comprehensive |
| ChaCha Variants | `ChaChaVariantsCoreTests.cs` | Fast | Complete |
| ChaCha20-Poly1305 | `ChaCha20Poly1305CoreTests.cs` | Fast, Compliance | Comprehensive |
| XChaCha20-Poly1305 | `XChaCha20Poly1305CoreTests.cs` | Fast | Complete |
| Poly1305 | `Poly1305CoreTests.cs` | Fast, Compliance | Complete |
| AES-GCM | `AesGcmCoreTests.cs` | Fast | Complete |
| AES-CCM | `AesCcmCoreTests.cs` | Fast | Complete |
| AES-SIV | `AesSivCoreTests.cs` | Fast | Complete |
| AES-OCB | `AesOcbCoreTests.cs` | Fast | Complete |
| AES-CMAC | `AesCmacCoreTests.cs` | Fast | Complete |
| Rabbit | `RabbitCoreTests.cs` | Fast, Compliance | Comprehensive |
| HC-128 | `Hc128CoreTests.cs` | Fast | Complete |
| HC-256 | `Hc256CoreTests.cs` | Fast | Complete |
| XSalsa20 | `XSalsa20CoreTests.cs` | Fast | Complete |
| PBKDF2 | `Pbkdf2CoreTests.cs` | Fast | Complete |
| HKDF | `HkdfCoreTests.cs` | Fast, Compliance | Complete |
| Scrypt | `ScryptCoreTests.cs` | Slow | Complete |
| Balloon Hashing | `BalloonHashingCoreTests.cs` | Slow | Complete |

### Asymmetric Cryptography

| Component | Test File | Categories | Status |
|-----------|-----------|------------|--------|
| RSA | `RsaCoreTests.cs` | Slow | Complete |
| Ed25519 | `Ed25519CoreTests.cs` | Fast | Complete |
| Curve25519 | `Curve25519CoreTests.cs` | Fast | Complete |
| secp256k1 | `Secp256k1CoreTests.cs` | Fast | Complete |
| ECDSA | `EcdsaCoreTests.cs` | Fast | Complete |

### Post-Quantum (.NET 10+)

| Component | Test File | Categories | Status |
|-----------|-----------|------------|--------|
| ML-KEM | `PostQuantumNet10Tests.cs` | Fast | Complete |
| ML-DSA | `PostQuantumNet10Tests.cs` | Fast | Complete |
| SLH-DSA | `PostQuantumNet10Tests.cs` | Fast | Complete |
| PQC Integration | `PostQuantumIntegrationTests.cs` | Integration | Complete |

### Operations Layer

| Builder | Test File | Categories | Status |
|---------|-----------|------------|--------|
| EncryptionBuilder | `EncryptionBuilderTests.cs` | Fast, Unit | Comprehensive |
| DecryptionBuilder | `DecryptionBuilderTests.cs` | Fast, Unit | Comprehensive |
| HashBuilder | `HashBuilderTests.cs` | Fast, Unit | Comprehensive |
| SignatureBuilder | `SignatureBuilderTests.cs` | Fast, Unit | Comprehensive |
| VerificationBuilder | `VerificationBuilderTests.cs` | Fast, Unit | Comprehensive |
| KeyDerivationBuilder | `KeyDerivationBuilderTests.cs` | Fast, Unit | Comprehensive |

### Protocols

| Protocol | Test File | Categories | Status |
|----------|-----------|------------|--------|
| BIP-39 Mnemonics | `Bip39MnemonicTests.cs` | Fast, Compliance | Complete |
| BIP-32 HD Wallets | `Bip32HdWalletTests.cs` | Fast, Compliance | Complete |
| HD Wallet Builder | `HdWalletBuilderTests.cs` | Fast | Complete |
| Shamir's Secret Sharing | `ShamirSecretSharingTests.cs` | Fast | Complete |
| Secret Sharing Builder | `SecretSharingBuilderTests.cs` | Fast | Complete |
| Threshold Signatures | `ThresholdSignaturesTests.cs` | Slow | Complete |
| MPC | `SecureMpcTests.cs` | Slow | Complete |
| Hybrid Encryption | `HybridEncryptionBuilderTests.cs` | Fast | Complete |
| Key Manager | `KeyManagerTests.cs` | Fast | Complete |

### OpenPGP

| Component | Test File | Status |
|-----------|-----------|--------|
| Packet Headers | `PgpPacketHeaderTests.cs` | Complete |
| Key Packets | `PgpKeyPacketTests.cs` | Complete |
| Signature Packets | `PgpSignaturePacketTests.cs` | Complete |
| Encryption Packets | `PgpSymmetricallyEncryptedDataPacketTests.cs` | Complete |
| AEAD Packets | `PgpAeadEncryptedDataPacketTests.cs` | Complete |
| Key Generation | `PgpKeyGeneratorTests.cs` | Complete |
| Key Rings | `PgpKeyRingTests.cs` | Complete |
| Message Encryption | `PgpMessageEncryptorTests.cs` | Complete |
| Message Decryption | `PgpMessageDecryptionTests.cs` | Complete |
| End-to-End | `PgpEndToEndAlgorithmTests.cs` | Complete |
| MPI Handling | `MpiTests.cs` | Complete |
| Armor Encoding | `ArmorCoreTests.cs` | Complete |
| CRC-24 | `Crc24CoreTests.cs` | Complete |
| S2K | `S2KCoreTests.cs` | Complete |

### Security Tests

| Component | Test File | Categories | Status |
|-----------|-----------|------------|--------|
| SIMD Constant-Time | `SimdConstantTimeOperationsTests.cs` | Security | Complete |
| Security Hardening | `SecurityHardeningTests.cs` | Security | Complete |
| Thread Safety | `ThreadSafetyTests.cs` | ThreadSafety | Complete |

## Platform Compatibility

### Tested Platforms

| Platform | .NET 8.0 | .NET 9.0 | .NET 10.0 | Notes |
|----------|----------|----------|-----------|-------|
| Windows x64 | Pass | Pass | Pass | Full support |
| Windows ARM64 | Pass | Pass | Pass | Full support |
| Linux x64 | Pass | Pass | Pass | Full support |
| Linux ARM64 | Pass | Pass | Pass | Full support |
| macOS x64 | Pass | Pass | Pass | SHA-3 may skip |
| macOS ARM64 | Pass | Pass | Pass | SHA-3 may skip |

### Platform-Specific Notes

- **Post-Quantum**: .NET 10+ only, requires Windows CNG or OpenSSL 3.5+
- **SHA-3**: .NET 8+ only, may be unavailable on older macOS
- **SHAKE XOF**: .NET 9+ only
- **AES-CCM**: .NET 8+ only
- **Hardware acceleration**: Automatically detected and used when available

## CI/CD Integration

### GitHub Actions Workflow

```yaml
# Recommended CI configuration
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        framework: [net8.0, net9.0, net10.0]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: |
            8.0.x
            9.0.x
            10.0.x
      - name: Test
        run: dotnet test -f ${{ matrix.framework }} --logger trx
```

### Recommended Test Strategy

| Stage | Filter | Purpose |
|-------|--------|---------|
| PR Checks | `Category=Fast` | Quick feedback |
| Merge Checks | `Category=Fast\|Category=Compliance` | Standards verification |
| Nightly | All tests | Full coverage |
| Release | All tests + manual review | Release validation |

## Test Vector Sources

### RFC Test Vectors

| Algorithm | Source |
|-----------|--------|
| Argon2 | RFC 9106 Appendix A |
| Blake2b | RFC 7693 Appendix A |
| ChaCha20-Poly1305 | RFC 8439 Section 2.8.2 |
| HKDF | RFC 5869 Appendix A |
| Rabbit | RFC 4503 Appendix A |
| X25519 | RFC 7748 Section 6.1 |

### NIST Test Vectors

| Algorithm | Source |
|-----------|--------|
| AES-GCM | NIST CAVP |
| SHA-2 | NIST CAVP |
| SHA-3 | NIST CAVP |

### Industry Test Vectors

| Standard | Source |
|----------|--------|
| BIP-39 | Official BIP-0039 test vectors |
| BIP-32 | Official BIP-0032 test vectors |
| secp256k1 | Bitcoin Core test vectors |

## Performance Benchmarks

### Typical Test Durations

| Test Category | Typical Duration | Notes |
|---------------|------------------|-------|
| Fast tests (all) | 5-15 seconds | Recommended for CI |
| Compliance tests | 1-3 seconds | Standards verification |
| Slow tests | 30-120 seconds | Includes RSA keygen |
| All tests | 2-5 minutes | Full suite |

### Algorithm-Specific Performance

| Operation | Typical Duration | Notes |
|-----------|------------------|-------|
| Blake2b hash (1KB) | < 1ms | Very fast |
| Argon2id (test params) | 10-50ms | 2 iterations, 8MB |
| ChaCha20-Poly1305 (1KB) | < 1ms | SIMD accelerated |
| RSA 2048-bit keygen | 5-15 seconds | Varies by platform |
| Ed25519 sign/verify | < 1ms | BCL implementation |

## Known Issues

### Platform-Specific

| Issue | Affected Platforms | Workaround |
|-------|-------------------|------------|
| SHA-3 unavailable | macOS < 13 | Tests skip gracefully |
| PQC unavailable | .NET < 10, older Windows | Tests skip gracefully |
| Slower RSA keygen | ARM platforms | Increase timeout |

### Test Flakiness

| Issue | Cause | Resolution |
|-------|-------|------------|
| Timing tests | System load | Use statistical thresholds |
| Thread safety | Race conditions | Fixed in test design |

## Contributing to Tests

### Adding New Tests

1. Follow naming conventions: `*Tests.cs` for test classes
2. Use appropriate categories via `[Trait]` attributes
3. Include edge cases and error conditions
4. Add RFC test vectors where applicable

### Test Organization

```
tests/HeroCrypt.Tests/
├── Infrastructure/          # Test helpers and utilities
├── Operations/              # Operations layer tests
├── Primitives/              # Algorithm implementation tests
│   ├── Argon2/
│   ├── Blake2b/
│   ├── ChaCha20/
│   └── ...
├── Protocols/               # Protocol tests
│   ├── HdWallet/
│   ├── SecretSharing/
│   └── ...
└── Security/                # Security-specific tests
```

### Test Categories

```csharp
[Trait("Category", TestCategories.FAST)]
[Trait("Category", TestCategories.UNIT)]
public class MyAlgorithmTests
{
    [Fact]
    public void Should_hash_correctly()
    {
        // Test implementation
    }
}
```

## Reporting Test Issues

1. **Check existing issues**: [GitHub Issues](https://github.com/KoalaFacts/HeroCrypt/issues)
2. **Include environment**: OS, .NET version, hardware
3. **Provide reproduction**: Minimal failing test case
4. **Include logs**: Full test output with stack traces

## Version History

This document applies to HeroCrypt v1.0.0 and later.

See [CHANGELOG.md](CHANGELOG.md) for test-related changes.
