# FIPS Compliance Guide

This guide provides comprehensive information for using HeroCrypt in FIPS 140-2/140-3 compliant environments.

## Table of Contents

1. [Overview](#overview)
2. [FIPS-Approved Algorithms](#fips-approved-algorithms)
3. [Non-FIPS Algorithms](#non-fips-algorithms)
4. [FIPS Mode Configuration](#fips-mode-configuration)
5. [Algorithm Selection by Use Case](#algorithm-selection-by-use-case)
6. [Key Size Requirements](#key-size-requirements)
7. [OpenPGP Interoperability](#openpgp-interoperability)
8. [NIST SP 800-57 Key Management](#nist-sp-800-57-key-management)
9. [CMVP Validation Process](#cmvp-validation-process)
10. [Compliance Checklist](#compliance-checklist)

## Overview

FIPS 140-2 and FIPS 140-3 are U.S. government security standards for cryptographic modules. Organizations subject to federal regulations (FISMA, FedRAMP, HIPAA, etc.) or those in regulated industries often require FIPS-compliant cryptography.

### When FIPS Compliance Is Required

- U.S. Federal government agencies
- Government contractors handling sensitive data
- Healthcare organizations (HIPAA)
- Financial institutions (PCI-DSS in some contexts)
- Organizations seeking FedRAMP authorization

### HeroCrypt FIPS Status

HeroCrypt provides FIPS-approved algorithms through .NET's built-in cryptographic primitives. However, HeroCrypt itself is **not CMVP validated**. For formal FIPS compliance:

1. Use only FIPS-approved algorithms listed below
2. Ensure the underlying .NET runtime uses a FIPS-validated cryptographic module
3. Consider formal CMVP validation if required (see [CMVP Validation Process](#cmvp-validation-process))

## FIPS-Approved Algorithms

The following algorithms in HeroCrypt are FIPS-approved and suitable for use in FIPS-compliant environments:

### Symmetric Encryption

| Algorithm | Standard | Key Sizes | Notes |
|-----------|----------|-----------|-------|
| **AES-GCM** | FIPS 197, SP 800-38D | 128, 192, 256 bits | Recommended AEAD mode |
| **AES-CCM** | FIPS 197, SP 800-38C | 128, 192, 256 bits | Alternative AEAD mode |
| **AES-CBC** | FIPS 197, SP 800-38A | 128, 192, 256 bits | Use with HMAC for integrity |

```csharp
// FIPS-compliant encryption
using var builder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()           // FIPS-approved
    .WithKeySize(256)       // 256-bit key
    .WithRandomKey();

var ciphertext = builder.Encrypt(plaintext);
```

### Hash Functions

| Algorithm | Standard | Output Size | Notes |
|-----------|----------|-------------|-------|
| **SHA-256** | FIPS 180-4 | 256 bits | Recommended for most uses |
| **SHA-384** | FIPS 180-4 | 384 bits | Higher security margin |
| **SHA-512** | FIPS 180-4 | 512 bits | Maximum security |
| **SHA3-256** | FIPS 202 | 256 bits | .NET 8+ only |
| **SHA3-384** | FIPS 202 | 384 bits | .NET 8+ only |
| **SHA3-512** | FIPS 202 | 512 bits | .NET 8+ only |

```csharp
// FIPS-compliant hashing
using var builder = HeroCryptBuilder.Hash()
    .WithSha256();          // FIPS-approved

var hash = builder.ComputeHash(data);
```

### Message Authentication Codes (MAC)

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| **HMAC-SHA256** | FIPS 198-1 | Recommended |
| **HMAC-SHA384** | FIPS 198-1 | Higher security |
| **HMAC-SHA512** | FIPS 198-1 | Maximum security |
| **AES-CMAC** | SP 800-38B | Block cipher-based MAC |

```csharp
// FIPS-compliant MAC
using var builder = HeroCryptBuilder.Mac()
    .WithHmacSha256()       // FIPS-approved
    .WithKey(key);

var mac = builder.ComputeMac(data);
```

### Digital Signatures

| Algorithm | Standard | Key Sizes | Notes |
|-----------|----------|-----------|-------|
| **RSA-PSS** | FIPS 186-4 | 2048, 3072, 4096 bits | Recommended RSA mode |
| **RSA-PKCS#1 v1.5** | FIPS 186-4 | 2048, 3072, 4096 bits | Legacy compatibility |
| **ECDSA P-256** | FIPS 186-4 | 256 bits | Recommended ECC |
| **ECDSA P-384** | FIPS 186-4 | 384 bits | Higher security |
| **ECDSA P-521** | FIPS 186-4 | 521 bits | Maximum security |

```csharp
// FIPS-compliant signatures
using var builder = HeroCryptBuilder.Sign()
    .WithEcdsaP256()        // FIPS-approved NIST curve
    .WithPrivateKey(privateKey);

var signature = builder.Sign(data);
```

### Key Derivation Functions

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| **PBKDF2-SHA256** | SP 800-132 | Password-based (100,000+ iterations) |
| **HKDF-SHA256** | SP 800-56C | Key expansion (not for passwords) |

```csharp
// FIPS-compliant password hashing
using var builder = HeroCryptBuilder.DeriveKey()
    .WithPbkdf2Sha256()     // FIPS-approved
    .WithIterations(600000) // High iteration count
    .WithPassword(password)
    .WithRandomSalt();

var key = builder.DeriveKey(32);
```

### Key Agreement

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| **ECDH P-256** | SP 800-56A | Recommended |
| **ECDH P-384** | SP 800-56A | Higher security |
| **ECDH P-521** | SP 800-56A | Maximum security |

### Random Number Generation

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| **CTR_DRBG** | SP 800-90A | Via .NET BCL |
| **HASH_DRBG** | SP 800-90A | Via .NET BCL |

HeroCrypt uses `System.Security.Cryptography.RandomNumberGenerator`, which delegates to the operating system's FIPS-validated CSPRNG when running in FIPS mode.

### Post-Quantum Cryptography (.NET 10+)

| Algorithm | Standard | Notes |
|-----------|----------|-------|
| **ML-KEM** | FIPS 203 | Key encapsulation |
| **ML-DSA** | FIPS 204 | Digital signatures |
| **SLH-DSA** | FIPS 205 | Hash-based signatures |

## Non-FIPS Algorithms

The following algorithms are **NOT FIPS-approved** and must not be used in FIPS-compliant environments:

### Encryption (Not FIPS)

| Algorithm | Alternative |
|-----------|-------------|
| ChaCha20-Poly1305 | Use AES-GCM |
| XChaCha20-Poly1305 | Use AES-GCM |
| AES-OCB | Use AES-GCM or AES-CCM |
| AES-SIV | Use AES-GCM with unique nonces |

### Hash Functions (Not FIPS)

| Algorithm | Alternative |
|-----------|-------------|
| Blake2b | Use SHA-256 or SHA-512 |
| Blake2s | Use SHA-256 |
| MD5 | Use SHA-256 (MD5 is also broken) |
| SHA-1 | Use SHA-256 (SHA-1 is deprecated) |

### Key Derivation (Not FIPS)

| Algorithm | Alternative |
|-----------|-------------|
| Argon2id | Use PBKDF2-SHA256 (high iterations) |
| Argon2i | Use PBKDF2-SHA256 |
| Argon2d | Use PBKDF2-SHA256 |
| Scrypt | Use PBKDF2-SHA256 |
| Balloon | Use PBKDF2-SHA256 |

### Signatures (Not FIPS)

| Algorithm | Alternative |
|-----------|-------------|
| Ed25519 | Use ECDSA P-256 or RSA-PSS |
| Ed448 | Use ECDSA P-384 or RSA-PSS |
| Secp256k1 | Use ECDSA P-256 |

### Key Agreement (Not FIPS)

| Algorithm | Alternative |
|-----------|-------------|
| X25519 | Use ECDH P-256 |
| X448 | Use ECDH P-384 |

## FIPS Mode Configuration

### Enabling FIPS Mode in .NET

#### Windows

```powershell
# Enable system-wide FIPS mode via Group Policy or registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -Value 1
```

#### Linux

```bash
# Enable FIPS mode (varies by distribution)
# RHEL/CentOS:
fips-mode-setup --enable

# Ubuntu:
sudo ua enable fips
```

### Runtime Verification

```csharp
using System.Security.Cryptography;

// Check if FIPS mode is enabled
bool isFipsEnabled = CryptoConfig.AllowOnlyFipsAlgorithms;

if (isFipsEnabled)
{
    Console.WriteLine("FIPS mode is enabled");
}
```

### HeroCrypt FIPS-Only Pattern

```csharp
/// <summary>
/// FIPS-compliant cryptography helper.
/// Only exposes FIPS-approved algorithms.
/// </summary>
public static class FipsCrypto
{
    /// <summary>
    /// Creates a FIPS-compliant encryption builder.
    /// </summary>
    public static IEncryptionBuilder CreateEncryptor()
    {
        return HeroCryptBuilder.Encrypt()
            .WithAesGcm()
            .WithKeySize(256);
    }

    /// <summary>
    /// Creates a FIPS-compliant hash builder.
    /// </summary>
    public static IHashBuilder CreateHasher()
    {
        return HeroCryptBuilder.Hash()
            .WithSha256();
    }

    /// <summary>
    /// Creates a FIPS-compliant signature builder.
    /// </summary>
    public static ISignatureBuilder CreateSigner()
    {
        return HeroCryptBuilder.Sign()
            .WithEcdsaP256();
    }

    /// <summary>
    /// Creates a FIPS-compliant password hasher.
    /// Uses PBKDF2-SHA256 with high iteration count.
    /// </summary>
    public static IKeyDerivationBuilder CreatePasswordHasher()
    {
        return HeroCryptBuilder.DeriveKey()
            .WithPbkdf2Sha256()
            .WithIterations(600000);  // OWASP recommendation for PBKDF2-SHA256
    }
}
```

## Algorithm Selection by Use Case

### Symmetric Encryption

| Use Case | FIPS Algorithm | Configuration |
|----------|----------------|---------------|
| General encryption | AES-256-GCM | 96-bit nonce, 128-bit tag |
| High-throughput | AES-128-GCM | If 128-bit security acceptable |
| IoT/Constrained | AES-128-CCM | Smaller tag options |

### Password Storage

| Use Case | FIPS Algorithm | Configuration |
|----------|----------------|---------------|
| User passwords | PBKDF2-SHA256 | 600,000+ iterations |
| High-security | PBKDF2-SHA512 | 210,000+ iterations |

> **Note:** PBKDF2 is not memory-hard and is less resistant to GPU attacks than Argon2. Use maximum practical iteration counts.

### Digital Signatures

| Use Case | FIPS Algorithm | Key Size |
|----------|----------------|----------|
| General purpose | ECDSA P-256 | 256 bits |
| Long-term (10+ years) | ECDSA P-384 | 384 bits |
| Maximum security | RSA-PSS | 4096 bits |
| Certificates | ECDSA P-256/P-384 | 256/384 bits |

### Key Exchange

| Use Case | FIPS Algorithm | Notes |
|----------|----------------|-------|
| TLS-style | ECDH P-256 | Ephemeral keys |
| Long-term keys | ECDH P-384 | Higher security |

## Key Size Requirements

Per NIST SP 800-57 Rev. 5 and SP 800-131A Rev. 2:

### Minimum Key Sizes (Through 2030)

| Algorithm | Minimum Key Size | Recommended |
|-----------|------------------|-------------|
| AES | 128 bits | 256 bits |
| RSA (signing) | 2048 bits | 3072 bits |
| RSA (encryption) | 2048 bits | 3072 bits |
| ECDSA/ECDH | P-256 (256 bits) | P-384 |
| HMAC | 128 bits | 256 bits |

### Security Strength Equivalence

| Security Bits | AES | RSA/DH | ECC |
|---------------|-----|--------|-----|
| 112 | - | 2048 | P-224 |
| 128 | 128 | 3072 | P-256 |
| 192 | 192 | 7680 | P-384 |
| 256 | 256 | 15360 | P-521 |

## OpenPGP Interoperability

When using HeroCrypt's OpenPGP features in FIPS environments, additional restrictions apply:

### FIPS-Compliant OpenPGP Algorithms

| Category | Allowed | Not Allowed |
|----------|---------|-------------|
| Symmetric | AES-128, AES-192, AES-256 | 3DES, CAST5, Blowfish, IDEA, Twofish |
| Hash | SHA-256, SHA-384, SHA-512 | SHA-1 (except verification), MD5 |
| Public Key | RSA (2048+), ECDSA (NIST curves) | Ed25519, Curve25519, DSA |

### Legacy Algorithm Warnings

HeroCrypt marks non-FIPS OpenPGP algorithms with `[Obsolete]` attributes:

```csharp
// These will generate compiler warnings:
// CS0618: '...' is obsolete

SymmetricCipherAlgorithm.TripleDes    // 64-bit block, deprecated
SymmetricCipherAlgorithm.Blowfish     // 64-bit block, deprecated
SymmetricCipherAlgorithm.Cast5        // 64-bit block, deprecated
SymmetricCipherAlgorithm.Idea         // 64-bit block, deprecated
```

### FIPS-Compliant OpenPGP Key Generation

```csharp
// Generate FIPS-compliant OpenPGP keys
var keyPair = PgpKeyGenerator.Create()
    .WithUserId("user@example.com")
    .WithPrimaryKey(PgpPublicKeyAlgorithm.RsaEncryptOrSign, 4096)  // RSA 4096
    .WithSubKey(PgpPublicKeyAlgorithm.RsaEncryptOrSign, 4096)      // RSA 4096
    .WithHashAlgorithm(PgpHashAlgorithmId.Sha256)                   // SHA-256
    .WithSymmetricAlgorithm(SymmetricCipherAlgorithm.Aes256)       // AES-256
    .Generate();
```

## NIST SP 800-57 Key Management

### Key States and Transitions

```
Pre-activation → Active → Deactivated → Compromised/Destroyed
```

### Cryptoperiods (Recommended Maximums)

| Key Type | Originator Usage | Recipient Usage |
|----------|------------------|-----------------|
| Symmetric encryption | 2 years | 5 years |
| Asymmetric key pair | 2 years | 5 years (public key) |
| Symmetric authentication | 2 years | 2 years |
| Digital signature | 3 years | Indefinite (verification) |

### Key Management Implementation

```csharp
public class FipsKeyManager
{
    public record KeyMetadata(
        string KeyId,
        DateTimeOffset CreatedAt,
        DateTimeOffset ActivatedAt,
        DateTimeOffset? DeactivatedAt,
        KeyState State);

    public enum KeyState { PreActivation, Active, Deactivated, Compromised, Destroyed }

    /// <summary>
    /// Checks if a key is within its valid cryptoperiod.
    /// </summary>
    public bool IsKeyValid(KeyMetadata key, TimeSpan maxCryptoperiod)
    {
        if (key.State != KeyState.Active)
            return false;

        var age = DateTimeOffset.UtcNow - key.ActivatedAt;
        return age <= maxCryptoperiod;
    }

    /// <summary>
    /// Rotates encryption keys per NIST guidelines.
    /// </summary>
    public async Task RotateEncryptionKey(string currentKeyId)
    {
        // 1. Generate new key
        var newKey = GenerateFipsKey();

        // 2. Mark current key as deactivated (originator usage ends)
        await DeactivateKey(currentKeyId);

        // 3. Activate new key
        await ActivateKey(newKey.KeyId);

        // 4. Re-encrypt data with new key (optional, depends on policy)
        // Old key remains valid for decryption until recipient usage ends
    }
}
```

## CMVP Validation Process

If your organization requires formal FIPS 140-2/140-3 validation, the Cryptographic Module Validation Program (CMVP) process involves:

### 1. Determine Validation Requirements

- **Security Level:** 1-4 (most commercial applications need Level 1 or 2)
- **Module Type:** Software, firmware, or hardware
- **Module Boundary:** Define what's included in the cryptographic module

### 2. Engage an Accredited Laboratory

CMVP validation requires testing by a NVLAP-accredited Cryptographic and Security Testing (CST) laboratory:

- [List of Accredited Labs](https://csrc.nist.gov/projects/cryptographic-module-validation-program/testing-labs)
- Typical cost: $50,000 - $200,000+
- Timeline: 12-24 months

### 3. Documentation Requirements

- Security Policy
- Finite State Model
- Cryptographic Algorithm Validation (CAVP) certificates
- Source code and design documentation
- Test documentation

### 4. Testing Process

1. **Design Review:** Laboratory reviews security policy and design
2. **CAVP Testing:** Algorithm implementations tested for correctness
3. **CMVP Testing:** Module tested against FIPS 140 requirements
4. **Report Submission:** Test report submitted to CMVP
5. **Validation:** NIST/CSEC issues validation certificate

### 5. Maintenance

- Algorithm transitions require revalidation
- Significant changes require revalidation
- Annual reviews recommended

### Alternative: Use Pre-Validated Modules

Instead of validating HeroCrypt, consider:

1. **Use .NET's FIPS-Validated Provider:** Windows CNG, OpenSSL (on Linux) are FIPS-validated
2. **Use Cloud HSM:** AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM
3. **Use Hardware Security Modules:** Thales, Entrust, etc.

```csharp
// Using .NET's FIPS-validated cryptography (via BCL)
using System.Security.Cryptography;

using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
```

## Compliance Checklist

### Algorithm Selection

- [ ] Only FIPS-approved algorithms are used in production
- [ ] ChaCha20, Blake2b, Argon2, Ed25519 are NOT used
- [ ] Key sizes meet NIST SP 800-57 minimums
- [ ] RSA keys are at least 2048 bits (3072 recommended)
- [ ] ECC uses NIST curves (P-256, P-384, P-521)

### Key Management

- [ ] Keys are generated using FIPS-approved DRBG
- [ ] Key storage uses hardware protection where possible
- [ ] Key rotation follows NIST SP 800-57 cryptoperiods
- [ ] Key destruction is performed securely

### Implementation

- [ ] FIPS mode is enabled in the operating system
- [ ] Runtime FIPS mode is verified at startup
- [ ] Non-FIPS algorithms throw exceptions in FIPS mode
- [ ] All cryptographic operations use FIPS-validated modules

### Documentation

- [ ] Security policy documents FIPS algorithm usage
- [ ] Key management procedures are documented
- [ ] Incident response includes key compromise procedures
- [ ] Audit trails capture cryptographic operations

### Testing

- [ ] Algorithm implementations verified against CAVP vectors
- [ ] Boundary conditions and error handling tested
- [ ] FIPS mode enforcement tested

## Algorithm Deprecation Timeline

HeroCrypt follows a structured deprecation timeline for weak and legacy algorithms. This ensures users have adequate time to migrate while maintaining security.

### Deprecation Stages

| Stage | Description | Behavior |
|-------|-------------|----------|
| **Active** | Fully supported | No warnings |
| **Deprecated** | Marked obsolete | Compiler warnings (`[Obsolete]`) |
| **Legacy-Only** | Disabled by default | Runtime warnings, requires opt-in |
| **Removed** | No longer available | Throws `NotSupportedException` |

### Current Deprecation Schedule

#### Symmetric Algorithms

| Algorithm | Current Status | Legacy-Only | Removal | Reason |
|-----------|----------------|-------------|---------|--------|
| 3DES (Triple DES) | Deprecated | Q1 2026 | Q1 2028 | 64-bit block, NIST disallowed after 2023 |
| Blowfish | Deprecated | Q1 2026 | Q1 2028 | 64-bit block, weak key schedule |
| CAST5 | Deprecated | Q1 2026 | Q1 2028 | 64-bit block |
| IDEA | Deprecated | Q1 2026 | Q1 2028 | 64-bit block, patent concerns |
| RC4 | Removed | - | Removed | Multiple practical attacks |

#### Hash Functions

| Algorithm | Current Status | Legacy-Only | Removal | Reason |
|-----------|----------------|-------------|---------|--------|
| MD5 | Deprecated | Q1 2025 | Q1 2027 | Collision attacks trivial |
| SHA-1 | Deprecated | Q1 2025 | Q1 2027 | SHAttered collision attack (2017) |

#### Key Derivation

| Algorithm | Current Status | Legacy-Only | Removal | Reason |
|-----------|----------------|-------------|---------|--------|
| PBKDF2-SHA1 | Deprecated | Q1 2026 | Q1 2028 | SHA-1 weakness |

#### Public Key Algorithms

| Algorithm | Current Status | Legacy-Only | Removal | Reason |
|-----------|----------------|-------------|---------|--------|
| RSA < 2048 bits | Blocked | - | Blocked | NIST minimum key size |
| DSA | Deprecated | Q1 2026 | Q1 2028 | ECDSA preferred |

### Migration Guides

#### From 3DES to AES-256

```csharp
// Before (deprecated)
// var cipher = TripleDes.Create();

// After (recommended)
using var builder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithKeySize(256);
```

#### From SHA-1 to SHA-256

```csharp
// Before (deprecated)
// var hash = SHA1.HashData(data);

// After (recommended)
using var builder = HeroCryptBuilder.Hash()
    .WithSha256();
var hash = builder.ComputeHash(data);
```

#### From MD5 to SHA-256

```csharp
// Before (deprecated)
// var hash = MD5.HashData(data);

// After (recommended)
using var builder = HeroCryptBuilder.Hash()
    .WithSha256();
var hash = builder.ComputeHash(data);
```

### Deprecation Notifications

To receive deprecation warnings at runtime, enable the warning listener:

```csharp
using HeroCrypt.Security;

// Subscribe to deprecation warnings
CryptoAudit.OnDeprecationWarning += (sender, e) =>
{
    Console.WriteLine($"Warning: {e.Algorithm} is deprecated. Use {e.Alternative} instead.");
};
```

### Opt-In for Legacy Algorithms

For legitimate legacy compatibility requirements:

```csharp
// Builder-level opt-in (preferred)
using var builder = HeroCryptBuilder.Hash()
    .AllowLegacyAlgorithms()  // Explicitly opt-in
    .WithSha1();               // Now permitted

// Scope-based opt-in
using (SecurityPolicy.LegacyScope())
{
    // Legacy algorithms permitted within this scope
}
```

## Additional Resources

- [NIST FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [CMVP Validated Modules List](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
- [Algorithm Selection Guide](algorithm-selection.md)
- [Best Practices](best-practices.md)
