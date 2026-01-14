# HeroCrypt Test Framework Conventions

## Overview

This document defines the comprehensive testing framework, patterns, and conventions for the HeroCrypt cryptographic library. All tests MUST follow these guidelines to ensure consistency, maintainability, and thorough coverage.

## Test Organization

### File Structure
```
tests/HeroCrypt.Tests/
├── Cryptography/
│   └── Primitives/
│       ├── Cipher/
│       │   ├── Aead/           # AEAD cipher tests
│       │   └── Stream/         # Stream cipher tests
│       ├── Hash/               # Hash function tests
│       ├── Kdf/                # Key derivation tests
│       ├── Mac/                # MAC tests
│       ├── PostQuantum/        # Post-quantum tests
│       └── Signature/          # Digital signature tests
├── Security/                   # Security utility tests
├── Infrastructure/             # Base classes and utilities
└── TestData/                   # Test vectors and fixtures
```

### Naming Conventions
- Test files: `{ClassName}Tests.cs`
- Test classes: `{ClassName}Tests` (e.g., `ChaCha20CoreTests`)
- Nested classes: Category name (e.g., `BasicFunctionality`, `EdgeCases`, `Security`)
- Test methods: `{MethodName}_{Scenario}_{ExpectedResult}` (e.g., `Transform_WithValidInput_ReturnsEncryptedData`)

## Test Categories

All tests MUST be tagged with appropriate category traits:

### Execution Speed
- `TestCategories.FAST` - Completes in < 100ms
- `TestCategories.SLOW` - May take seconds (key generation, large data)

### Test Type
- `TestCategories.UNIT` - Tests single component in isolation
- `TestCategories.INTEGRATION` - Tests multiple components together
- `TestCategories.COMPLIANCE` - Verifies RFC/standard compliance

### Coverage Type
- `TestCategories.SECURITY` - Security property verification
- `TestCategories.MEMORY` - Memory hygiene verification
- `TestCategories.EDGE_CASE` - Boundary condition testing
- `TestCategories.KNOWN_ANSWER` - Official test vector verification

## Nested Class Structure

Every test class MUST use nested classes for organization:

```csharp
public class AlgorithmCoreTests
{
    // Shared constants at top
    private const int KEY_SIZE = 32;
    
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality { }
    
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases { }
    
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security { }
    
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation { }
    
    [Trait("Category", TestCategories.SLOW)]
    public class Performance { }
    
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests { }
    
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class MemoryHygiene { }
}
```

## Required Test Coverage by Algorithm Type

### Stream Ciphers (ChaCha20, Salsa20, XSalsa20, HC-128)

**BasicFunctionality:**
- Transform with valid parameters
- Round-trip (encrypt/decrypt)
- Determinism (same key/nonce = same output)
- Different key/nonce produces different output

**EdgeCases:**
- Empty input
- Single byte
- Partial blocks (not multiple of block size)
- Exact block boundary
- Zero key/nonce (weak but valid)
- Maximum counter value

**Security:**
- Counter overflow detection
- Nonce reuse detection (keystream leakage)
- All-zero plaintext produces keystream

**ParameterValidation:**
- Invalid key size
- Invalid nonce size
- Output buffer too small

**Performance:**
- Large data (1MB+)
- Chunk processing consistency

**KnownAnswerTests:**
- Official RFC test vectors

### AEAD Ciphers (AES-GCM, AES-CCM, AES-OCB, ChaCha20-Poly1305)

**BasicFunctionality:**
- Encrypt/decrypt round-trip
- With associated data
- Without associated data

**EdgeCases:**
- Empty plaintext (tag only)
- Empty associated data
- Large associated data
- Partial blocks

**Security:**
- Modified ciphertext detection
- Modified tag detection
- Modified associated data detection
- Wrong key detection

**ParameterValidation:**
- Invalid key sizes
- Invalid nonce sizes
- Invalid tag sizes
- Buffer size validation

### Digital Signatures (Ed25519, ECDSA, RSA)

**BasicFunctionality:**
- Key generation
- Public key derivation
- Sign and verify
- Deterministic signatures (if applicable)

**EdgeCases:**
- Empty message
- Single byte message
- Large message (1MB+)

**Security:**
- Modified message detection
- Modified signature detection
- Wrong public key detection
- Random signature rejection

**KnownAnswerTests:**
- RFC test vectors

### Key Derivation Functions (Argon2, Scrypt, PBKDF2, HKDF)

**BasicFunctionality:**
- Determinism with same parameters
- Different salt produces different output
- Different password produces different output

**EdgeCases:**
- Minimum parameter values
- Empty salt (where allowed)
- Empty info (HKDF)

**ParameterValidation:**
- Invalid iteration count
- Invalid memory size
- Invalid parallelism
- Invalid output length

**KnownAnswerTests:**
- RFC test vectors

### Hash Functions (Blake2b, SHA-3)

**BasicFunctionality:**
- Correct output length
- Determinism
- Keyed hashing (if applicable)

**EdgeCases:**
- Empty input
- Single byte
- Large input

**KnownAnswerTests:**
- Official test vectors

## Test Method Structure

All test methods MUST follow this structure:

```csharp
[Fact]
public void MethodName_Scenario_ExpectedResult()
{
    // Arrange - Setup test data and dependencies
    var key = new byte[KEY_SIZE];
    RandomNumberGenerator.Fill(key);
    
    // Act - Execute the method under test
    var result = Algorithm.Method(key);
    
    // Assert - Verify the result
    Assert.Equal(expected, result);
}
```

## Assertions Best Practices

1. **Use specific assertions:**
   - `Assert.Equal()` for value comparison
   - `Assert.NotEqual()` for inequality
   - `Assert.True()` / `Assert.False()` for booleans
   - `Assert.Throws<T>()` for expected exceptions
   - `Assert.Contains()` for substring checks

2. **Check exception messages:**
   ```csharp
   var ex = Assert.Throws<ArgumentException>(() => Method(invalid));
   Assert.Contains("expected text", ex.Message);
   ```

3. **Use constant-time comparison for security tests:**
   ```csharp
   Assert.True(SecureMemoryOperations.ConstantTimeEquals(a, b));
   ```

## Test Data Generation

1. **Use cryptographically secure random:**
   ```csharp
   RandomNumberGenerator.Fill(buffer);
   // or
   var bytes = RandomNumberGenerator.GetBytes(length);
   ```

2. **Use deterministic seeds for reproducibility in performance tests:**
   ```csharp
   new Random(42).NextBytes(buffer);
   ```

3. **Store test vectors in KnownAnswerTests class or separate files**

## Running Tests

```bash
# Run all tests
dotnet test

# Run fast tests only
dotnet test --filter "Category=Fast"

# Run security tests
dotnet test --filter "Category=Security"

# Run compliance tests
dotnet test --filter "Category=Compliance"

# Exclude slow tests
dotnet test --filter "Category!=Slow"
```
