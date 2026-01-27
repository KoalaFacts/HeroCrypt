# Getting Started with HeroCrypt

Welcome to HeroCrypt! This guide will help you get started with the library quickly.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [Common Use Cases](#common-use-cases)
5. [Working with Text Formats](#working-with-text-formats-hex-base64-base64url)
6. [Next Steps](#next-steps)

## Installation

### NuGet Package

```bash
dotnet add package HeroCrypt
```

### Requirements

- **.NET Standard 2.0+** or **.NET 8.0+**
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

### 3. Using the Fluent Builders (no DI required)

```csharp
using HeroCrypt;
using HeroCrypt.Encryption;
using System.Security.Cryptography;

// Encrypt
var key = RandomNumberGenerator.GetBytes(32);
var plaintext = "Hello, HeroCrypt!"u8.ToArray();

var encrypted = HeroCryptBuilder.Encrypt()
    .WithAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305)
    .WithKey(key)
    .Build(plaintext);

// Decrypt
var decrypted = HeroCryptBuilder.Decrypt()
    .WithAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305)
    .WithKey(key)
    .WithNonce(encrypted.Nonce)
    .Build(encrypted.Ciphertext);

Console.WriteLine($"Round-trip OK: {plaintext.SequenceEqual(decrypted)}");
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
using HeroCrypt.Cryptography.KeyDerivation;

// Registration: Hash the user's password
var passwordHash = Argon2.Hash(
    password: userPassword,
    salt: RandomNumberGenerator.GetBytes(16),
    iterations: 3,
    memorySizeKB: 65536,
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id);

await SaveToDatabase(userId, passwordHash);

// Login: Verify the password
var storedHash = await GetFromDatabase(userId);
var isValid = Argon2.Verify(storedHash, userPassword);
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

### Working with Text Formats (Hex, Base64, Base64Url)

Cryptographic data is binary, but you often need to store or transmit it as text. HeroCrypt provides consistent encoding methods across all builders.

#### Encryption with Text Storage

```csharp
using HeroCrypt;

// ENCRYPT: Get everything as text for storage
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey();

var result = encryptor.Encrypt("Sensitive data");

// Save as text (choose format based on your needs)
var record = new {
    KeyHex = encryptor.GetKeyAsHex(),           // For logs, debugging
    CiphertextBase64 = result.CiphertextAsBase64,   // For databases, JSON
    NonceBase64Url = result.NonceAsBase64Url        // For URLs, APIs
};

// DECRYPT: Load from text
var plaintext = HeroCryptBuilder.Decrypt()
    .WithAesGcm()
    .WithKeyFromHex(record.KeyHex)
    .WithNonceFromBase64Url(record.NonceBase64Url)
    .DecryptFromBase64ToString(record.CiphertextBase64);
```

#### Password Hashing with Text Storage

```csharp
using HeroCrypt;

// HASH: Store salt and hash as text
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(userPassword)
    .WithRandomSalt(16);

var hashHex = kdf.DeriveKeyToHex();
var saltHex = kdf.GetSaltAsHex();

// Store hashHex and saltHex in your database
await db.SaveUserCredentials(userId, hashHex, saltHex);

// VERIFY: Load from text and compare
var storedSaltHex = await db.GetSalt(userId);
var storedHashHex = await db.GetHash(userId);

var computedHash = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(enteredPassword)
    .WithSaltFromHex(storedSaltHex)
    .DeriveKeyToHex();

bool isValid = computedHash == storedHashHex;
```

#### HMAC Signatures for APIs

```csharp
using HeroCrypt;

// Sign API request
using var signer = HeroCryptBuilder.Sign()
    .WithHmacSha256()
    .WithKey(sharedSecret);

var signatureBase64Url = signer.SignToBase64Url($"{timestamp}:{requestBody}");

// Add to HTTP header (URL-safe, no padding issues)
request.Headers.Add("X-Signature", signatureBase64Url);

// Verify on server
using var verifier = HeroCryptBuilder.Verify()
    .WithHmacSha256()
    .WithKey(sharedSecret)
    .WithSignatureFromBase64Url(signatureBase64Url);

bool isValid = verifier.Verify($"{timestamp}:{requestBody}");
```

#### Quick Reference: When to Use Each Format

| Format | Best For | Example Methods |
|--------|----------|-----------------|
| **Hex** | Logs, debugging, config files | `GetKeyAsHex()`, `WithKeyFromHex()` |
| **Base64** | Databases, JSON, general storage | `CiphertextAsBase64`, `WithNonceFromBase64()` |
| **Base64Url** | URLs, APIs, JWTs, query strings | `SignToBase64Url()`, `DecryptFromBase64UrlToString()` |

> **Tip:** Use `Base64Url` for web APIs and `Hex` for debugging. See [API Patterns](api-patterns.md#text-encoding-conventions) and [Troubleshooting](troubleshooting.md#text-encoding-issues) for more details.

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
