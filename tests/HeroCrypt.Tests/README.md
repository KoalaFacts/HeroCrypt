# HeroCrypt Tests

## Test Categories

Tests are organized into categories for efficient execution:

- **Fast**: Tests that complete in milliseconds (no key generation, minimal iterations)
- **Slow**: Tests involving RSA key generation or intensive computations
- **Compliance**: RFC compliance tests that verify standard compliance
- **Integration**: Tests that verify multiple components working together
- **Unit**: Tests for individual components in isolation

## Running Tests

### Run All Tests
```bash
dotnet test
```

### Run Only Fast Tests (Recommended for CI)
```bash
dotnet test --filter "Category=Fast"
```

### Run Compliance Tests
```bash
dotnet test --filter "Category=Compliance"
```

### Run Unit Tests Only
```bash
dotnet test --filter "Category=Unit"
```

### Exclude Slow Tests
```bash
dotnet test --filter "Category!=Slow"
```

### Run Multiple Categories
```bash
dotnet test --filter "Category=Fast|Category=Compliance"
```

### Run Specific Test Class
```bash
dotnet test --filter "FullyQualifiedName~Blake2bTests"
dotnet test --filter "FullyQualifiedName~StandardsComplianceTests"
```

## Test Organization

| Test Class | Categories | Description | Typical Duration |
|------------|------------|-------------|------------------|
| `Argon2HashingServiceTests` | Fast, Unit | Argon2 hashing (core) with minimal parameters | < 100ms |
| `Blake2bTests` | Fast, Unit | Blake2b hash function tests | < 50ms |
| `StandardsComplianceTests` | Fast, Compliance | RFC compliance verification | < 200ms |

## CI/CD Recommendations

For continuous integration, use:
```bash
# Quick feedback - run fast tests only
dotnet test --filter "Category=Fast" --logger "trx"

# Nightly or scheduled - run all tests
dotnet test --logger "trx"
```

## Performance Notes

- RSA key generation (1024-bit) takes ~1-5 seconds per key
- RSA key generation (2048-bit) takes ~5-15 seconds per key
- Argon2 with test parameters (2 iterations, 8MB) takes ~10-50ms
- Blake2b hashing is very fast (~1ms for most inputs)
