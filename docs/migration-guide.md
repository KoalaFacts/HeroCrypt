# Migration Guide

This guide helps you migrate between HeroCrypt versions and from other cryptographic libraries.

## Table of Contents

1. [Migrating to v1.0](#migrating-to-v10)
2. [New Text Encoding Methods](#new-text-encoding-methods)
3. [Fluent Builders Replace Services](#fluent-builders-replace-services)
4. [Deprecated and Removed](#deprecated-and-removed)
5. [Migrating from Other Libraries](#migrating-from-other-libraries)

---

## Migrating to v1.0

### Breaking Changes

- **Dropped .NET 6.0 and .NET 7.0 support** - Now requires .NET 8.0+ or .NET Standard 2.0
- Service layer removed - use fluent builders directly
- Interface abstractions removed - builders are the public surface

### Updated Method Names

Some builder methods have been renamed for consistency:

| Old Method | New Method |
|------------|------------|
| `UseArgon2()` | `WithArgon2id()` |
| `WithKeyLength(n)` | `WithOutputLength(n)` |
| `Build()` | `DeriveKey()` |

---

## New Text Encoding Methods

HeroCrypt now includes convenient text encoding methods on all operation builders. This eliminates manual `Convert.ToBase64String()` and `Convert.FromBase64String()` calls.

### Before (Manual Conversion)

```csharp
// Old approach - manual encoding
var hash = kdf.DeriveKey();
var hashBase64 = Convert.ToBase64String(hash);  // Manual

var storedSalt = Convert.FromBase64String(saltBase64);  // Manual
kdf.WithSalt(storedSalt);
```

### After (Built-in Encoding)

```csharp
// New approach - fluent encoding methods
var hashBase64 = kdf.DeriveKeyToBase64();  // Direct

kdf.WithSaltFromBase64(saltBase64);  // Direct
```

### Available Encoding Methods

| Builder | Output Methods | Input Methods |
|---------|----------------|---------------|
| EncryptionBuilder | `GetKeyAsHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()` |
| DecryptionBuilder | `DecryptFromHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()`, `WithNonceFromHex/Base64/Base64Url()` |
| HashBuilder | `ComputeHashToHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()` |
| SignatureBuilder | `SignToHex/Base64/Base64Url()` | `WithKeyFromHex/Base64/Base64Url()` |
| VerificationBuilder | - | `WithKeyFromHex/Base64/Base64Url()`, `WithSignatureFromHex/Base64/Base64Url()` |
| KeyDerivationBuilder | `DeriveKeyToHex/Base64/Base64Url()`, `GetSaltAsHex/Base64/Base64Url()` | `WithSaltFromHex/Base64/Base64Url()` |

### Result Struct Properties

Encryption results have text encoding properties:

```csharp
var result = encryptor.Encrypt(plaintext);

// Text properties (no method call needed)
string ciphertextHex = result.CiphertextAsHex;
string nonceBase64 = result.NonceAsBase64;
string nonceBase64Url = result.NonceAsBase64Url;
```

### Choosing the Right Format

| Format | Use When |
|--------|----------|
| **Hex** | Logging, debugging, config files, human readability |
| **Base64** | Database storage, JSON payloads, file storage |
| **Base64Url** | URLs, query parameters, JWTs, HTTP headers, APIs |

---

## Fluent Builders Replace Services

The service layer has been removed. Use the fluent builders directly:

### Password Hashing (Argon2id)

```csharp
// New approach with fluent builders
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword("password")
    .WithRandomSalt()
    .WithOutputLength(32);

var hashHex = kdf.DeriveKeyToHex();
var saltHex = kdf.GetSaltAsHex();
```

### Encryption (ChaCha20-Poly1305)

```csharp
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithRandomKey();

var result = encryptor.Encrypt("secret data");
var keyBase64 = encryptor.GetKeyAsBase64();
var ciphertextBase64 = result.CiphertextAsBase64;
var nonceBase64 = result.NonceAsBase64;
```

### Hashing (SHA-256)

```csharp
using var hasher = HeroCryptBuilder.Hash()
    .WithSha256();

var hashHex = hasher.ComputeHashToHex("data to hash");
```

---

## Deprecated and Removed

### Removed Classes

- All `*Service` classes: `AeadService`, `Argon2HashingService`, `KeyDerivationService`, `RsaService`, `PgpService`, etc.
- Interface abstractions: `IAeadService`, `IHashingService`, etc.

### Replacement Mapping

| Removed | Replacement |
|---------|-------------|
| `Argon2HashingService.Hash()` | `HeroCryptBuilder.DeriveKey().WithArgon2id()` |
| `AeadService.Encrypt()` | `HeroCryptBuilder.Encrypt().WithAesGcm()` |
| `KeyDerivationService.DeriveKey()` | `HeroCryptBuilder.DeriveKey().WithHkdfSha256()` |
| `RsaService.Sign()` | `HeroCryptBuilder.Sign().WithRsaPssSha256()` |

---

## Migrating from Other Libraries

### From System.Security.Cryptography

```csharp
// Before: Manual HMAC-SHA256
using var hmac = new HMACSHA256(key);
var hash = hmac.ComputeHash(data);
var hashBase64 = Convert.ToBase64String(hash);

// After: HeroCrypt fluent API
using var hasher = HeroCryptBuilder.Hash()
    .WithSha256()
    .WithKey(key);
var hashBase64 = hasher.ComputeHashToBase64(data);
```

### From Libsodium / NaCl

```csharp
// HeroCrypt ChaCha20-Poly1305 is compatible with libsodium
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithKey(key);
var result = encryptor.Encrypt(plaintext);
```

### From BouncyCastle

```csharp
// Argon2 with same parameters as BouncyCastle
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(password)
    .WithSalt(salt)
    .WithOutputLength(32);
// Note: Default parameters are 3 iterations, 64MB memory, 4 parallelism
```

---

## Dependency Injection

There are no service types to register. If you need DI, wrap the builders in your own service classes:

```csharp
public interface ICryptoService
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash, string salt);
}

public class CryptoService : ICryptoService
{
    public string HashPassword(string password)
    {
        using var kdf = HeroCryptBuilder.DeriveKey()
            .WithArgon2id()
            .WithPassword(password)
            .WithRandomSalt()
            .WithOutputLength(32);
        return $"{kdf.GetSaltAsHex()}:{kdf.DeriveKeyToHex()}";
    }

    public bool VerifyPassword(string password, string hash, string salt)
    {
        using var kdf = HeroCryptBuilder.DeriveKey()
            .WithArgon2id()
            .WithPassword(password)
            .WithSaltFromHex(salt)
            .WithOutputLength(32);
        return kdf.DeriveKeyToHex() == hash;
    }
}
```

---

## Additional Resources

- [Getting Started](getting-started.md) - Quick start guide
- [API Patterns](api-patterns.md#text-encoding-conventions) - Text encoding naming conventions
- [Best Practices](best-practices.md) - Security recommendations
- [Troubleshooting](troubleshooting.md#text-encoding-issues) - Common encoding issues
