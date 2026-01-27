# HeroCrypt Examples

This directory contains practical, runnable examples demonstrating HeroCrypt's cryptographic capabilities.

## Quick Start

```bash
# Run the interactive example menu
cd examples/HeroCrypt.Examples
dotnet run
```

This launches an interactive console menu where you can select and run individual examples.

## Available Examples

### Core Examples

| Example | File | Description |
|---------|------|-------------|
| Fluent API Demo | [FluentApiDemo.cs](HeroCrypt.Examples/FluentApiDemo.cs) | Text encoding convenience methods (Hex, Base64, Base64Url) |

### Use Case Examples

Located in [UseCases/](HeroCrypt.Examples/UseCases/):

| Example | File | Description |
|---------|------|-------------|
| Password Storage | [PasswordStorageExample.cs](HeroCrypt.Examples/UseCases/PasswordStorageExample.cs) | Secure password hashing with Argon2id |
| Data Encryption | [DataEncryptionExample.cs](HeroCrypt.Examples/UseCases/DataEncryptionExample.cs) | Symmetric encryption with AES-GCM |
| Digital Signatures | [DigitalSignaturesExample.cs](HeroCrypt.Examples/UseCases/DigitalSignaturesExample.cs) | RSA and ECDSA signing workflows |
| Secret Sharing | [SecretSharingExample.cs](HeroCrypt.Examples/UseCases/SecretSharingExample.cs) | Shamir's Secret Sharing for key backup |
| Cryptographic Wallet | [CryptographicWalletExample.cs](HeroCrypt.Examples/UseCases/CryptographicWalletExample.cs) | BIP-39/BIP-32 HD wallet creation |
| Secure Messaging | [SecureMessagingExample.cs](HeroCrypt.Examples/UseCases/SecureMessagingExample.cs) | Hybrid encryption for secure communication |
| Corporate Approval | [CorporateApprovalExample.cs](HeroCrypt.Examples/UseCases/CorporateApprovalExample.cs) | Threshold signatures for multi-party approval |

### Post-Quantum Examples (.NET 10+)

Located in [PostQuantum/](HeroCrypt.Examples/PostQuantum/):

| Example | File | Description |
|---------|------|-------------|
| Digital Signatures | [DigitalSignatureExample.cs](HeroCrypt.Examples/PostQuantum/DigitalSignatureExample.cs) | ML-DSA quantum-resistant signatures |
| Hybrid Encryption | [HybridEncryptionExample.cs](HeroCrypt.Examples/PostQuantum/HybridEncryptionExample.cs) | ML-KEM key encapsulation |
| PQC Overview | [PostQuantumExamples.cs](HeroCrypt.Examples/PostQuantum/PostQuantumExamples.cs) | Combined post-quantum demos |

## Example Details

### 1. Fluent API Demo

Demonstrates HeroCrypt's text encoding convenience methods for working with cryptographic data:

```csharp
// Encryption with text format output
var result = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey()
    .Encrypt("Hello, World!");

// Access results as text - perfect for APIs and databases
var ciphertext = result.CiphertextAsBase64Url;
var nonce = result.NonceAsBase64Url;
var key = encryptBuilder.GetKeyAsHex();
```

**Topics covered:**
- Encryption with Hex, Base64, and Base64Url output
- Decryption from text-encoded input
- Password hashing with text storage
- API request signing with Base64Url
- Key management in text formats
- Data hashing with text output
- HMAC for message authentication

### 2. Password Storage

Demonstrates secure password hashing for database storage:

```csharp
// Hash a password with Argon2id
var hash = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(password)
    .WithRandomSalt(16)
    .DeriveKeyToHex();

// Store hash and salt in database
```

**Best practices shown:**
- Using Argon2id (recommended for passwords)
- Proper salt generation
- Secure storage format
- Password verification workflow

### 3. Data Encryption

Demonstrates symmetric encryption for protecting sensitive data:

```csharp
// Encrypt with AES-GCM
var result = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey()
    .Encrypt(sensitiveData);

// Decrypt
var plaintext = HeroCryptBuilder.Decrypt()
    .WithAesGcm()
    .FromEncryptionResult(result)
    .Decrypt();
```

**Topics covered:**
- AES-GCM authenticated encryption
- Proper key and nonce handling
- Secure data storage patterns

### 4. Digital Signatures

Demonstrates creating and verifying digital signatures:

```csharp
// Sign with Ed25519
var signature = HeroCryptBuilder.Sign()
    .WithEd25519()
    .WithKey(privateKey)
    .Sign(document);

// Verify
var isValid = HeroCryptBuilder.Verify()
    .WithEd25519()
    .WithKey(publicKey)
    .WithSignature(signature)
    .Verify(document);
```

**Algorithms demonstrated:**
- Ed25519 (recommended for new applications)
- ECDSA (P-256, secp256k1)
- RSA-PSS

### 5. Secret Sharing

Demonstrates Shamir's Secret Sharing for distributed key backup:

```csharp
// Split a secret into 5 shares, requiring 3 to reconstruct
var shares = HeroCryptBuilder.SecretSharing()
    .WithShamirScheme()
    .WithThreshold(3)
    .WithTotalShares(5)
    .Split(secretKey);

// Reconstruct with any 3 shares
var reconstructed = HeroCryptBuilder.SecretSharing()
    .WithShamirScheme()
    .Combine(threeShares);
```

**Use cases:**
- Key escrow and backup
- Distributed secret management
- Multi-party key recovery

### 6. Cryptographic Wallet

Demonstrates BIP-39/BIP-32 HD wallet creation:

```csharp
// Generate mnemonic phrase
var mnemonic = HeroCryptBuilder.HdWallet()
    .GenerateMnemonic(24);

// Derive wallet keys
var wallet = HeroCryptBuilder.HdWallet()
    .FromMnemonic(mnemonic)
    .DerivePath("m/44'/0'/0'/0/0");
```

**Topics covered:**
- BIP-39 mnemonic generation (12-24 words)
- BIP-32 key derivation paths
- Hardened vs. normal derivation
- Bitcoin-compatible addresses

### 7. Post-Quantum Cryptography

Demonstrates quantum-resistant algorithms (.NET 10+ only):

```csharp
// ML-KEM key encapsulation
var keyPair = HeroCryptBuilder.MlKem()
    .WithParameterSet(MlKemParameterSet.MlKem768)
    .GenerateKeyPair();

var (ciphertext, sharedSecret) = keyPair.Encapsulate();

// ML-DSA signatures
var signature = HeroCryptBuilder.MlDsa()
    .WithParameterSet(MlDsaParameterSet.MlDsa65)
    .Sign(document, signingKey);
```

**Requirements:**
- .NET 10.0 or later
- Windows 11 24H2+ or OpenSSL 3.5+

## Running Individual Examples

### From Command Line

```bash
# Run interactively
dotnet run

# Or run a specific example programmatically
dotnet run -- --example "Password Storage"
```

### In Your IDE

1. Open the solution in Visual Studio or VS Code
2. Set `HeroCrypt.Examples` as the startup project
3. Run (F5 or Ctrl+F5)

## Framework Compatibility

| Example | .NET Standard 2.0 | .NET 8.0 | .NET 9.0 | .NET 10.0 |
|---------|-------------------|----------|----------|-----------|
| Core Examples | Yes | Yes | Yes | Yes |
| Use Case Examples | Yes | Yes | Yes | Yes |
| Post-Quantum | No | No | No | Yes |

## Related Documentation

- [Getting Started Guide](../docs/getting-started.md) - Quick start and installation
- [API Patterns](../docs/api-patterns.md) - Text encoding conventions and API design
- [Best Practices](../docs/best-practices.md) - Security recommendations
- [Algorithm Selection](../docs/algorithm-selection.md) - Choosing the right algorithm

## Contributing Examples

We welcome new examples! When contributing:

1. Follow the existing example structure
2. Include clear comments explaining each step
3. Demonstrate security best practices
4. Add your example to this README
5. Update the interactive menu in `Program.cs`

## License

Examples are licensed under MIT, same as the main HeroCrypt library.
