# HeroCrypt

[![NuGet Version](https://img.shields.io/nuget/v/HeroCrypt.svg)](https://www.nuget.org/packages/HeroCrypt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fully RFC-compliant cryptographic library for .NET featuring high-performance, secure implementations of modern cryptographic algorithms.

## ✨ Features

- **🔐 Argon2 Password Hashing** - Full RFC 9106 compliance
  - Argon2d, Argon2i, and Argon2id variants
  - Configurable memory, iterations, and parallelism
  - Secure salt generation and constant-time comparison
  
- **#️⃣ Blake2b Hashing** - Full RFC 7693 compliance
  - Variable output sizes (1-64 bytes)
  - Keyed hashing (MAC) support
  - Blake2b-Long for outputs > 64 bytes

- **🔑 RSA Encryption** - PKCS#1 v2.2 support
  - Key generation (512-4096 bits)
  - PKCS#1 v1.5 and OAEP padding
  - Digital signatures

- **📧 PGP Encryption** - OpenPGP-compatible
  - Hybrid encryption with AES session keys
  - RSA key pair support
  - Passphrase protection for private keys

## 📦 Installation

```bash
dotnet add package HeroCrypt
```

## 🚀 Quick Start

### Argon2 Password Hashing

```csharp
using HeroCrypt.Services;

// Configure Argon2 options
var options = new Argon2Options
{
    Type = Argon2Type.Argon2id,
    Iterations = 3,
    MemorySize = 65536,  // 64 MB
    Parallelism = 4,
    HashLength = 32
};

var hashingService = new Argon2HashingService(options);

// Hash a password
string hash = await hashingService.HashAsync("mySecurePassword");

// Verify a password
bool isValid = await hashingService.VerifyAsync("mySecurePassword", hash);
```

### Blake2b Hashing

```csharp
using HeroCrypt.Cryptography.Blake2b;

// Simple hash
byte[] data = Encoding.UTF8.GetBytes("Hello, World!");
byte[] hash = Blake2bCore.ComputeHash(data, 32);  // 32-byte hash

// Keyed hash (MAC)
byte[] key = Encoding.UTF8.GetBytes("secret-key");
byte[] mac = Blake2bCore.ComputeHash(data, 32, key);
```

### RSA Encryption

```csharp
using HeroCrypt.Cryptography.RSA;

// Generate key pair
var keyPair = RsaCore.GenerateKeyPair(2048);

// Encrypt with OAEP padding
byte[] encrypted = RsaCore.Encrypt(
    data, 
    keyPair.PublicKey, 
    RsaPaddingMode.Oaep, 
    HashAlgorithmName.SHA256
);

// Decrypt
byte[] decrypted = RsaCore.Decrypt(
    encrypted, 
    keyPair.PrivateKey, 
    RsaPaddingMode.Oaep, 
    HashAlgorithmName.SHA256
);
```

## 🏗️ Architecture

HeroCrypt is built with a modular architecture:

- **Core Implementations** - Low-level cryptographic primitives
- **Service Layer** - High-level, easy-to-use APIs
- **Abstractions** - Interfaces for dependency injection

## 📊 RFC Compliance

| Algorithm | Standard | Status |
|-----------|----------|--------|
| Argon2d   | RFC 9106 | ✅ Fully Compliant |
| Argon2i   | RFC 9106 | ✅ Fully Compliant |
| Argon2id  | RFC 9106 | ✅ Fully Compliant |
| Blake2b   | RFC 7693 | ✅ Fully Compliant |
| RSA       | RFC 8017 | ✅ Basic Support |

## 🎯 Target Frameworks

- .NET Standard 2.0
- .NET 6.0
- .NET 7.0
- .NET 8.0
- .NET 9.0

## 🔒 Security

- Core algorithms (Argon2, Blake2b) implemented from scratch following RFC specifications
- Leverages .NET's proven cryptographic primitives for AES, SHA-256, and secure random generation
- Constant-time comparisons for sensitive operations
- Secure memory management

## 📖 Documentation

See [STANDARDS_COMPLIANCE.md](STANDARDS_COMPLIANCE.md) for detailed compliance information and test vectors.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- RFC 9106 (Argon2) specification authors
- RFC 7693 (Blake2) specification authors
- .NET cryptographic community