# Migration Guide

This guide helps you migrate between HeroCrypt versions and from other cryptographic libraries.

## MPC security change in v1.0.2

`SecureMpc.SecureSum`, `SecureMultiply`, `PrivateSetIntersection`, and
`GenerateBeaverTriples` now throw `NotSupportedException`. The corresponding
configured `MpcBuilder` operations are also unsupported. No reviewed MPC or private
set intersection protocol is currently implemented. Security policies and models,
including `Malicious` and `Covert`, cannot enable these operations.

The former implementation gathered all parties' plaintext inputs or shares in one
process and did not authenticate participants or preprocessing material. Selecting
a security model did not enforce it. PSI was a local hash-based set comparison,
and multiplication accepted invalid thresholds and corrupted Beaver triples.
Unequal sum input lengths could silently discard trailing bytes.

Review applications that relied on these APIs for privacy or tamper detection.
Previously computed results do not prove that inputs remained private or that
participants and triples were authenticated. Independently revalidate results from
trusted inputs, and reassess any disclosure of party inputs to the executing process.
Use a reviewed distributed protocol with explicit participant and trust boundaries
before resuming MPC or PSI. Catching `NotSupportedException` and continuing with a
plaintext calculation does not restore those security guarantees.

## Threshold signature security change in v1.0.1

The threshold signature simulation has been removed. `ThresholdSignatures` and
configured `ThresholdSignatureBuilder` operations now throw `NotSupportedException`.
No secure threshold signing protocol is currently implemented.

Previously accepted threshold signatures were public hash values that anyone could
forge using only the public key and message. Do not use them as proof of approval
or authenticity. Re-establish approvals from an authoritative source and use a
reviewed signing protocol before accepting new signatures. Existing threshold
signature values cannot be converted into authentic signatures.

## Table of Contents

1. [Migrating to v1.0](#migrating-to-v10)
2. [New Text Encoding Methods](#new-text-encoding-methods)
3. [Fluent Builders Replace Services](#fluent-builders-replace-services)
4. [Deprecated and Removed](#deprecated-and-removed)
5. [Migrating from Other Libraries](#migrating-from-other-libraries)

---

## Migrating to v1.0

### Security: replace secp256k1 signatures from v0.1.0 through v0.3.0

HeroCrypt v0.1.0 through v0.3.0 produced a 64-byte value using a MAC key derived
from the public key instead of an ECDSA signature. Anyone with the public key
could forge that value. **Do not use signatures created by those versions as
proof of authenticity**, even if an older HeroCrypt verifier accepts them.

Version 1.0.0 signs with secp256k1 ECDSA and emits a 64-byte `r || s` signature
with a normalized low-S value. The unified builder hashes input data with
SHA-256 before signing or verifying it. The algorithm-specific
`Secp256k1Builder` accepts an already computed 32-byte message hash.

To migrate stored signatures:

1. Upgrade every signer and verifier to 1.0.0 before accepting new signatures.
2. Identify records signed with v0.1.0 through v0.3.0 using trusted version or
   creation metadata. Both formats are 64 bytes, so length cannot identify the
   old values.
3. Re-establish each original message from an authoritative source and sign it
   again with the private key. Do not automatically re-sign a message merely
   because its old signature verifies.
4. Replace the stored signature and record the new signature format or version.
   If the message cannot be authenticated independently, invalidate the old
   signature and request a new signed record.
5. Review any authorization decisions that relied solely on old signatures.

There is no safe conversion from an old signature to ECDSA. This flaw did not
expose the private key, so a key change alone cannot repair previously trusted
records.

```csharp
using var signer = HeroCryptBuilder.Sign()
    .WithSecp256k1()
    .WithPrivateKey(privateKey);
byte[] signature = signer.Sign(authenticatedMessage);

using var verifier = HeroCryptBuilder.Verify()
    .WithSecp256k1()
    .WithPublicKey(publicKey)
    .WithSignature(signature);
bool isValid = verifier.Verify(authenticatedMessage);
```

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
