# Migration Guide

This guide helps you migrate between HeroCrypt versions and from other cryptographic libraries.

## Table of Contents

1. [Version Migration](#version-migration)
2. [Migrating from Other Libraries](#migrating-from-other-libraries)
3. [API Changes](#api-changes)
4. [Breaking Changes](#breaking-changes)
5. [Deprecated Features](#deprecated-features)

## Version Migration

### From 0.x to 1.0

Version 1.0 is the first stable release with several breaking changes from pre-release versions.

#### Major Changes

1. **Removed Reference Implementations**
   - Post-quantum cryptography (Kyber, Dilithium, SPHINCS+)
   - Zero-knowledge proofs (zk-SNARKs, Ring Signatures)
   - Advanced protocols (Signal, Noise, TLS enhancements)
   - Hardware security stubs (TPM, SGX, HSM abstraction layers without real implementations)

**Migration**:
```csharp
// ❌ OLD: Reference implementations (removed)
// var ciphertext = KyberKem.Encapsulate(...);
// var proof = ZkSnark.GenerateProof(...);

// ✅ NEW: Use external libraries for these features
// For PQC: Use liboqs, Bouncy Castle
// For ZK: Use libsnark, bellman, bulletproofs
```

2. **Fluent API Introduction**

**Migration**:
```csharp
// ❌ OLD: Direct service usage
var service = new Argon2HashingService(new Argon2Options
{
    Type = Argon2Type.Argon2id,
    Iterations = 3,
    MemorySize = 65536,
    Parallelism = 4
});
var hash = await service.HashAsync("password");

// ✅ NEW: Fluent API (recommended)
var hash = await heroCrypt.Argon2
    .WithPassword("password")
    .WithSecurityLevel(SecurityLevel.High)
    .HashAsync();

// ✅ OLD API: Still supported
var service = new Argon2HashingService(new Argon2Options
{
    Type = Argon2Type.Argon2id,
    Iterations = 3,
    MemorySize = 65536,
    Parallelism = 4
});
var hash = await service.HashAsync("password");
```

3. **Dependency Injection Support**

**Migration**:
```csharp
// ❌ OLD: Manual instantiation
var service = new Argon2HashingService(options);

// ✅ NEW: Dependency injection
services.AddHeroCrypt(SecurityLevel.High);

// In your class
public class UserService
{
    private readonly IHeroCrypt _heroCrypt;

    public UserService(IHeroCrypt heroCrypt)
    {
        _heroCrypt = heroCrypt;
    }
}
```

4. **Security Level Enum**

**Migration**:
```csharp
// ❌ OLD: Manual parameters
var options = new Argon2Options
{
    Iterations = 3,
    MemorySize = 65536,
    Parallelism = 4
};

// ✅ NEW: Security levels
var hash = await heroCrypt.Argon2
    .WithPassword("password")
    .WithSecurityLevel(SecurityLevel.High)  // Automatically sets parameters
    .HashAsync();
```

5. **Hardware Acceleration API**

**Migration**:
```csharp
// ❌ OLD: Manual detection
if (Avx2.IsSupported)
{
    // Use AVX2 version
}
else
{
    // Use portable version
}

// ✅ NEW: Automatic detection
var hash = await heroCrypt.Argon2
    .WithPassword("password")
    .WithHardwareAcceleration()  // Automatically detects and uses best available
    .HashAsync();
```

### Configuration Changes

#### Argon2Options

```csharp
// OLD (0.x)
var options = new Argon2Options
{
    HashSize = 32,
    SaltSize = 16
};

// NEW (1.0)
var options = new Argon2Options
{
    HashLength = 32,  // Renamed from HashSize
    SaltLength = 16   // Renamed from SaltSize
};
```

#### HeroCryptOptions

```csharp
// NEW (1.0): Centralized options
services.AddHeroCrypt(options =>
{
    options.DefaultSecurityLevel = SecurityLevel.High;
    options.EnableHardwareAcceleration = true;
    options.EnableDetailedLogging = false;
    options.MaxMemoryUsageKb = 512 * 1024;
    options.DefaultRsaKeySize = 3072;
});
```

## Migrating from Other Libraries

### From Bouncy Castle

#### Password Hashing

```csharp
// OLD: Bouncy Castle
using Org.BouncyCastle.Crypto.Generators;

var generator = new Argon2BytesGenerator();
generator.Init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
    .WithVersion(Argon2Parameters.ARGON2_VERSION_13)
    .WithIterations(3)
    .WithMemoryAsKB(65536)
    .WithParallelism(4)
    .WithSalt(salt)
    .Build());

var hash = new byte[32];
generator.GenerateBytes(password, hash);

// NEW: HeroCrypt
using HeroCrypt.Cryptography.KeyDerivation;

var hash = Argon2.Hash(
    password,
    salt,
    iterations: 3,
    memorySizeKB: 65536,
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id
);
```

#### AES-GCM Encryption

```csharp
// OLD: Bouncy Castle
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

var cipher = new GcmBlockCipher(new AesEngine());
cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
var ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
cipher.DoFinal(ciphertext, len);

// NEW: HeroCrypt (use .NET built-in)
using System.Security.Cryptography;

using var aesGcm = new AesGcm(key);
var ciphertext = new byte[plaintext.Length];
var tag = new byte[16];
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
```

### From libsodium (via Sodium.Core)

#### Authenticated Encryption

```csharp
// OLD: Sodium.Core
using Sodium;

var ciphertext = SecretAead.Encrypt(plaintext, nonce, key, aad);

// NEW: HeroCrypt
using HeroCrypt.Cryptography.Symmetric;

var ciphertext = ChaCha20Poly1305Cipher.Encrypt(plaintext, key, nonce, aad);
```

#### Password Hashing

```csharp
// OLD: Sodium.Core
using Sodium;

var hash = PasswordHash.ArgonHashString(password, PasswordHash.StrengthArgon.Interactive);
var isValid = PasswordHash.ArgonHashStringVerify(hash, password);

// NEW: HeroCrypt
using HeroCrypt.Cryptography.KeyDerivation;

var salt = new byte[16];
RandomNumberGenerator.Fill(salt);

var hash = Argon2.Hash(password, salt, 3, 65536, 4, 32, Argon2Type.Argon2id);
var isValid = Argon2.Verify(hash, password);
```

### From Microsoft.AspNetCore.Cryptography

#### Key Derivation

```csharp
// OLD: ASP.NET Core
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

var hash = KeyDerivation.Pbkdf2(
    password: password,
    salt: salt,
    prf: KeyDerivationPrf.HMACSHA256,
    iterationCount: 100000,
    numBytesRequested: 32
);

// NEW: HeroCrypt
using HeroCrypt.Cryptography.KeyDerivation;

var hash = Pbkdf2Core.DeriveKey(
    password,
    salt,
    iterations: 100000,
    keyLength: 32,
    algorithm: HashAlgorithmName.SHA256
);
```

### From System.Security.Cryptography (Built-in .NET)

HeroCrypt complements .NET's built-in cryptography, not replaces it.

#### When to Use HeroCrypt

- ✅ Argon2 password hashing (not in .NET)
- ✅ Blake2b hashing (not in .NET)
- ✅ ChaCha20-Poly1305 (available in .NET 8+)
- ✅ PGP encryption (not in .NET)
- ✅ Advanced key derivation (Scrypt, Balloon, HKDF)
- ✅ High-level service APIs with DI

#### When to Use .NET Built-in

- ✅ AES-GCM (hardware-accelerated)
- ✅ SHA-256, SHA-384, SHA-512 (FIPS-compliant)
- ✅ RSA (FIPS-compliant)
- ✅ ECDSA with NIST curves (FIPS-compliant)
- ✅ HMAC operations

#### Hybrid Approach

```csharp
// Use .NET for FIPS-compliant operations
using var sha256 = SHA256.Create();
var hash = sha256.ComputeHash(data);

// Use HeroCrypt for modern algorithms
using HeroCrypt.Cryptography.KeyDerivation;
var passwordHash = Argon2.Hash(password, salt, 3, 65536, 4, 32, Argon2Type.Argon2id);

// Use HeroCrypt for high-level APIs
var encrypted = await heroCrypt.PGP
    .WithData(plaintext)
    .WithPublicKey(publicKey)
    .EncryptAsync();
```

## API Changes

### Renamed Classes

| Old Name (0.x) | New Name (1.0) | Notes |
|----------------|----------------|-------|
| `HashingService` | `Argon2HashingService` | More specific |
| `AesGcmService` | `AeadService` | More generic |
| `Argon2Options.HashSize` | `Argon2Options.HashLength` | Consistent naming |
| `Argon2Options.SaltSize` | `Argon2Options.SaltLength` | Consistent naming |

### Removed Classes

| Removed Class | Alternative |
|---------------|-------------|
| `KyberKem` | Use liboqs or Bouncy Castle |
| `DilithiumDsa` | Use liboqs or Bouncy Castle |
| `ZkSnark` | Use libsnark or bellman (Rust) |
| `RingSignature` | Use specialized ZK libraries |
| `SignalProtocol` | Use libsignal |
| `NoiseProtocol` | Use Noise.NET |

### New Classes

| New Class | Purpose |
|-----------|---------|
| `IHeroCrypt` | Main service interface |
| `IArgon2FluentBuilder` | Fluent API for Argon2 |
| `IPgpFluentBuilder` | Fluent API for PGP |
| `HeroCryptOptions` | Centralized configuration |
| `SecurityLevel` | Predefined security parameters |
| `HardwareAccelerationDetector` | Hardware capability detection |

## Breaking Changes

### v1.0.0

1. **Removed reference implementations** (see above)

2. **Namespace changes**:
   - `HeroCrypt.Cryptography.PostQuantum` → Removed
   - `HeroCrypt.Cryptography.ZeroKnowledge` → Removed
   - `HeroCrypt.Protocols` → Removed
   - `HeroCrypt.HardwareSecurity` → Partial (only abstractions remain)

3. **Method signature changes**:

```csharp
// OLD
public static byte[] Hash(byte[] password, byte[] salt, Argon2Options options)

// NEW
public static byte[] Hash(
    byte[] password,
    byte[] salt,
    int iterations,
    int memorySizeKB,
    int parallelism,
    int hashLength,
    Argon2Type type)
```

4. **Configuration changes**:

```csharp
// OLD
services.AddArgon2Hashing(options => { ... });
services.AddBlake2bHashing(options => { ... });
services.AddRsaEncryption(options => { ... });

// NEW (unified)
services.AddHeroCrypt(options =>
{
    options.DefaultSecurityLevel = SecurityLevel.High;
    options.EnableHardwareAcceleration = true;
});
```

## Deprecated Features

### Currently Deprecated (will be removed in v2.0)

None. Version 1.0 is a clean slate.

### Planned Deprecations (v2.0)

The following may be deprecated in future versions:

1. **Direct Core API usage** (prefer Service layer or Fluent API)
2. **Manual options configuration** (prefer SecurityLevel)

## Data Migration

### Password Hashes

Password hashes are **compatible** between versions. No migration needed.

```csharp
// Hashes created in 0.x work in 1.0
var isValid = Argon2.Verify(oldHash, password);  // Still works
```

### Encrypted Data

Encrypted data is **compatible** if you use the same algorithms.

```csharp
// Data encrypted with ChaCha20-Poly1305 in 0.x
// Can be decrypted in 1.0 with same key/nonce
var decrypted = ChaCha20Poly1305Cipher.Decrypt(oldCiphertext, key, nonce, aad);
```

### PGP Keys

PGP keys are **compatible** across versions.

```csharp
// Keys generated in 0.x work in 1.0
var decrypted = await pgpService.DecryptTextAsync(ciphertext, oldPrivateKey);
```

### RSA Keys

RSA keys in PKCS#8/X.509 format are **compatible**.

```csharp
// Keys in standard formats work across versions
var privateKey = rsaService.ImportPkcs8PrivateKey(keyBytes);
```

## Migration Checklist

- [ ] Review [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) for feature status
- [ ] Update NuGet package: `dotnet add package HeroCrypt --version 1.0.0`
- [ ] Remove references to deleted namespaces
- [ ] Update service registration to use `AddHeroCrypt()`
- [ ] Consider migrating to Fluent API for simpler code
- [ ] Update tests to use new APIs
- [ ] Review security levels and adjust if needed
- [ ] Enable hardware acceleration where appropriate
- [ ] Test password verification with existing hashes
- [ ] Test decryption of existing encrypted data
- [ ] Update documentation and examples

## Getting Help

If you encounter issues during migration:

1. Check [Troubleshooting Guide](troubleshooting.md)
2. Review [API Patterns](api-patterns.md)
3. See [Examples](../examples/)
4. Open a [GitHub Issue](https://github.com/KoalaFacts/HeroCrypt/issues)

## Version History

| Version | Release Date | Status |
|---------|--------------|--------|
| 1.0.0 | 2025-10-29 | Current stable |
| 0.x | 2025-01-15 - 2025-10-28 | Pre-release (deprecated) |
