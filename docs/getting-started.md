# Getting Started with HeroCrypt

Welcome to HeroCrypt! This guide will help you get started with the library quickly.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [Common Use Cases](#common-use-cases)
5. [Next Steps](#next-steps)

## Installation

### NuGet Package

```bash
dotnet add package HeroCrypt
```

### Requirements

- **.NET Standard 2.0+** or **.NET 6.0+**
- Supported platforms: Windows, Linux, macOS
- Optional: Hardware acceleration (AVX2, AVX-512, NEON)

## Quick Start

### 1. Password Hashing with Argon2

```csharp
using HeroCrypt.Cryptography.KeyDerivation;
using System.Security.Cryptography;

// Generate a random salt
var salt = new byte[16];
RandomNumberGenerator.Fill(salt);

// Hash a password with Argon2id (production-ready)
var password = "MySecurePassword123!"u8.ToArray();
var hash = Argon2.Hash(
    password,
    salt,
    iterations: 3,
    memorySizeKB: 65536,  // 64 MB
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id
);

// Verify the password
bool isValid = Argon2.Verify(hash, password);
Console.WriteLine($"Password valid: {isValid}");
```

### 2. Authenticated Encryption with ChaCha20-Poly1305

```csharp
using HeroCrypt.Cryptography.Symmetric;
using System.Security.Cryptography;

// Generate a random key and nonce
var key = new byte[32];
var nonce = new byte[12];
RandomNumberGenerator.Fill(key);
RandomNumberGenerator.Fill(nonce);

// Encrypt data
var plaintext = "Sensitive data to encrypt"u8.ToArray();
var associatedData = "metadata"u8.ToArray();

var ciphertext = ChaCha20Poly1305Cipher.Encrypt(
    plaintext,
    key,
    nonce,
    associatedData
);

// Decrypt and verify
var decrypted = ChaCha20Poly1305Cipher.Decrypt(
    ciphertext,
    key,
    nonce,
    associatedData
);

Console.WriteLine($"Decrypted: {System.Text.Encoding.UTF8.GetString(decrypted)}");
```

### 3. Using the Fluent API with Dependency Injection

```csharp
using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Extensions;
using Microsoft.Extensions.DependencyInjection;

// Setup DI container
var services = new ServiceCollection();

// Add HeroCrypt with High security level
services.AddHeroCrypt(SecurityLevel.High);

var serviceProvider = services.BuildServiceProvider();

// Get the main HeroCrypt service
var heroCrypt = serviceProvider.GetRequiredService<IHeroCrypt>();

// Hash a password using fluent API
var hash = await heroCrypt.Argon2
    .WithPassword("MySecurePassword")
    .WithSecurityLevel(SecurityLevel.High)
    .WithHardwareAcceleration()
    .HashAsync();

Console.WriteLine($"Password hash: {hash}");
```

## Core Concepts

### Security Levels

HeroCrypt provides predefined security levels for easy configuration:

- **SecurityLevel.Low** - Fast, minimal security (testing only)
- **SecurityLevel.Medium** - Balanced security and performance
- **SecurityLevel.High** - Strong security (recommended)
- **SecurityLevel.VeryHigh** - Maximum security
- **SecurityLevel.Military** - Extreme security (very slow)

### Production-Ready Features

Not all features in HeroCrypt are production-ready. Always refer to [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) for the latest status.

**Production-Ready Core:**
- ✅ Argon2id password hashing
- ✅ Blake2b hashing
- ✅ ChaCha20-Poly1305 AEAD
- ✅ AES-GCM
- ✅ RSA (OAEP, PSS)
- ✅ ECC (P-256, P-384, P-521)
- ✅ Key derivation (HKDF, PBKDF2, Scrypt)
- ✅ BIP39 mnemonic codes

**Educational/Reference Only:**
- 📚 Post-quantum cryptography
- 📚 Zero-knowledge proofs
- 📚 Advanced protocols

### Memory Management

HeroCrypt provides secure memory management:

```csharp
using HeroCrypt.Memory;

// Use SecureBuffer for sensitive data
using var secureBuffer = new SecureBuffer(32);

// Memory is automatically zeroed when disposed
// Memory is locked to prevent swapping to disk
```

### Hardware Acceleration

HeroCrypt automatically detects and uses hardware acceleration:

```csharp
using HeroCrypt.Hardware;

var capabilities = HardwareAccelerationDetector.DetectCapabilities();
Console.WriteLine($"AVX2: {capabilities.HasAvx2}");
Console.WriteLine($"AVX-512: {capabilities.HasAvx512}");
Console.WriteLine($"AES-NI: {capabilities.HasAesNi}");
```

## Common Use Cases

### Secure Password Storage

```csharp
// Registration: Hash the user's password
var passwordHash = await heroCrypt.Argon2
    .WithPassword(userPassword)
    .WithSecurityLevel(SecurityLevel.High)
    .HashAsync();

// Store passwordHash in database
await SaveToDatabase(userId, passwordHash);

// Login: Verify the password
var storedHash = await GetFromDatabase(userId);
var isValid = await heroCrypt.Argon2
    .WithPassword(userPassword)
    .VerifyAsync(storedHash);

if (isValid)
{
    // Login successful
}
```

### Encrypting User Data

```csharp
using HeroCrypt.Cryptography.Symmetric;

// Generate a data encryption key (DEK)
var dek = new byte[32];
RandomNumberGenerator.Fill(dek);

// Encrypt user data
var userData = System.Text.Encoding.UTF8.GetBytes(userJson);
var nonce = new byte[12];
RandomNumberGenerator.Fill(nonce);

var encryptedData = ChaCha20Poly1305Cipher.Encrypt(
    userData,
    dek,
    nonce,
    associatedData: System.Text.Encoding.UTF8.GetBytes(userId)
);

// Store encryptedData, nonce, and encrypt DEK with master key
```

### Digital Signatures

```csharp
using HeroCrypt.Cryptography.Asymmetric;
using System.Security.Cryptography;

// Generate ECC key pair
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var privateKey = ecdsa.ExportECPrivateKey();
var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

// Sign a message
var message = "Document to sign"u8.ToArray();
var signature = EccOperations.Sign(
    message,
    privateKey,
    EccCurve.NistP256
);

// Verify signature
bool isValid = EccOperations.Verify(
    message,
    signature,
    publicKey,
    EccCurve.NistP256
);
```

### Key Derivation

```csharp
using HeroCrypt.Cryptography.KeyDerivation;

// Derive a key from a master key
var masterKey = new byte[32];
RandomNumberGenerator.Fill(masterKey);

var derivedKey = HkdfCore.DeriveKey(
    masterKey,
    keyLength: 32,
    info: "application-specific-context"u8.ToArray(),
    salt: null
);
```

## Next Steps

1. **Read [Best Practices](best-practices.md)** - Learn security best practices
2. **Review [API Patterns](api-patterns.md)** - Understand API design patterns
3. **Check [Performance Guide](performance-guide.md)** - Optimize for your use case
4. **Explore [Examples](../examples/)** - See more complete examples
5. **Read [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md)** - Understand feature status

## Getting Help

- **Documentation**: Check the `/docs` folder
- **Examples**: See the `/examples` folder
- **Issues**: [GitHub Issues](https://github.com/KoalaFacts/HeroCrypt/issues)
- **Security**: See [SECURITY.md](../SECURITY.md) for vulnerability reporting

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
