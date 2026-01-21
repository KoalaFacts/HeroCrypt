# HeroCrypt API Security Guide

**Document Version**: 1.0
**Date**: 2026-01-21

This guide provides security best practices for developers using the HeroCrypt library.

---

## 1. Secure Usage Examples

### 1.1 Password Hashing with Argon2id

**DO: Use Argon2id with appropriate parameters**

```csharp
using HeroCrypt;
using System.Security.Cryptography;
using System.Text;

// Generate a cryptographically secure salt
var salt = RandomNumberGenerator.GetBytes(16);

// Hash password with OWASP-recommended parameters
var hash = HeroCryptBuilder.DeriveKey()
    .UseArgon2()
    .WithVariant(Argon2Type.Argon2id)  // Recommended variant
    .WithPassword(Encoding.UTF8.GetBytes(password))
    .WithSalt(salt)
    .WithMemorySize(19456)  // 19 MB (OWASP recommendation)
    .WithIterations(2)       // With 19 MB memory
    .WithParallelism(1)
    .WithKeyLength(32)
    .Build();

// Store both salt and hash (e.g., as Base64)
var storedHash = $"{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
```

**DON'T: Use weak parameters**

```csharp
// WRONG: Parameters too weak
var weakHash = HeroCryptBuilder.DeriveKey()
    .UseArgon2()
    .WithMemorySize(1024)   // Too low - easily brute-forced
    .WithIterations(1)      // Too low
    .Build();
```

### 1.2 Symmetric Encryption with ChaCha20-Poly1305

**DO: Use random nonces and proper error handling**

```csharp
using HeroCrypt;
using System.Security.Cryptography;

public byte[] EncryptSecurely(byte[] plaintext, byte[] key)
{
    // Generate a random nonce for EACH encryption
    var nonce = RandomNumberGenerator.GetBytes(12);

    var ciphertext = HeroCryptBuilder.Encrypt()
        .UseChaCha20Poly1305()
        .WithKey(key)
        .WithNonce(nonce)
        .WithPlaintext(plaintext)
        .Build();

    // Prepend nonce to ciphertext for storage/transmission
    var result = new byte[nonce.Length + ciphertext.Length];
    nonce.CopyTo(result, 0);
    ciphertext.CopyTo(result, nonce.Length);

    return result;
}

public byte[] DecryptSecurely(byte[] encryptedData, byte[] key)
{
    // Extract nonce and ciphertext
    var nonce = encryptedData[..12];
    var ciphertext = encryptedData[12..];

    try
    {
        return HeroCryptBuilder.Decrypt()
            .UseChaCha20Poly1305()
            .WithKey(key)
            .WithNonce(nonce)
            .WithCiphertext(ciphertext)
            .Build();
    }
    catch (CryptographicException)
    {
        // Don't leak information about why decryption failed
        throw new InvalidOperationException("Decryption failed");
    }
}
```

**DON'T: Reuse nonces or use predictable values**

```csharp
// WRONG: Never use a fixed nonce!
var fixedNonce = new byte[12]; // All zeros - CATASTROPHIC
var ciphertext = HeroCryptBuilder.Encrypt()
    .UseChaCha20Poly1305()
    .WithKey(key)
    .WithNonce(fixedNonce)  // NEVER DO THIS
    .WithPlaintext(plaintext)
    .Build();

// WRONG: Never use a counter that could repeat
static int counter = 0;
var badNonce = BitConverter.GetBytes(counter++); // Could repeat after restart!
```

### 1.3 RSA Encryption

**DO: Use OAEP padding and appropriate key sizes**

```csharp
using HeroCrypt.Cryptography.RSA;

// Generate a strong key pair
var keyPair = RsaCore.GenerateKeyPair(3072); // 3072 bits minimum recommended

// Encrypt with OAEP padding
var encrypted = RsaCore.Encrypt(
    data,
    keyPair.PublicKey,
    RsaPaddingMode.Oaep,          // Use OAEP, not PKCS#1 v1.5
    HashAlgorithmName.SHA256
);

// Decrypt
var decrypted = RsaCore.Decrypt(
    encrypted,
    keyPair.PrivateKey,
    RsaPaddingMode.Oaep,
    HashAlgorithmName.SHA256
);
```

**DON'T: Use weak key sizes or PKCS#1 v1.5 for new applications**

```csharp
// WRONG: Key size too small
var weakKey = RsaCore.GenerateKeyPair(1024); // Insecure!

// AVOID: PKCS#1 v1.5 padding (vulnerable to padding oracle attacks)
var vulnerable = RsaCore.Encrypt(
    data,
    publicKey,
    RsaPaddingMode.Pkcs1,  // Prefer OAEP for new applications
    HashAlgorithmName.SHA1 // SHA-1 also deprecated
);
```

### 1.4 Digital Signatures with Ed25519

**DO: Verify signatures before trusting data**

```csharp
using HeroCrypt.Cryptography.Ed25519;

// Sign data
var keyPair = Ed25519Core.GenerateKeyPair();
var signature = Ed25519Core.Sign(message, keyPair.PrivateKey);

// Always verify before processing
bool isValid = Ed25519Core.Verify(message, signature, keyPair.PublicKey);

if (!isValid)
{
    throw new CryptographicException("Invalid signature");
}

// Only process message if signature is valid
ProcessMessage(message);
```

**DON'T: Process data before verification**

```csharp
// WRONG: Processing before verification
ProcessMessage(message);  // Attacker could have modified message!
bool isValid = Ed25519Core.Verify(message, signature, publicKey);
```

### 1.5 Key Derivation with HKDF

**DO: Use HKDF for deriving multiple keys from a shared secret**

```csharp
using HeroCrypt;

// After key exchange, derive separate keys for encryption and MAC
var sharedSecret = PerformKeyExchange();

var encryptionKey = HeroCryptBuilder.DeriveKey()
    .UseHkdf()
    .WithHashAlgorithm(HashAlgorithmName.SHA256)
    .WithInputKeyMaterial(sharedSecret)
    .WithSalt(salt)
    .WithInfo(Encoding.UTF8.GetBytes("encryption"))
    .WithKeyLength(32)
    .Build();

var macKey = HeroCryptBuilder.DeriveKey()
    .UseHkdf()
    .WithHashAlgorithm(HashAlgorithmName.SHA256)
    .WithInputKeyMaterial(sharedSecret)
    .WithSalt(salt)
    .WithInfo(Encoding.UTF8.GetBytes("authentication"))
    .WithKeyLength(32)
    .Build();
```

---

## 2. Common Mistakes to Avoid

### 2.1 Nonce Reuse

**Problem**: Reusing a nonce with the same key in stream ciphers or AEAD modes.

```csharp
// CATASTROPHIC: Same nonce used twice
var nonce = RandomNumberGenerator.GetBytes(12);
var ct1 = Encrypt(key, nonce, message1);
var ct2 = Encrypt(key, nonce, message2); // XOR of messages recoverable!
```

**Solution**: Always generate a fresh random nonce, or use XChaCha20-Poly1305 with 24-byte nonces.

### 2.2 Using System.Random for Cryptography

**Problem**: `System.Random` is not cryptographically secure.

```csharp
// WRONG: Predictable random values
var random = new Random();
var key = new byte[32];
random.NextBytes(key);  // INSECURE - predictable!
```

**Solution**: Always use `RandomNumberGenerator`.

```csharp
// CORRECT: Cryptographically secure
var key = RandomNumberGenerator.GetBytes(32);
```

### 2.3 Comparing MACs/Signatures with ==

**Problem**: Regular comparison leaks timing information.

```csharp
// WRONG: Timing attack vulnerable
if (computedMac == providedMac)  // Variable-time comparison
{
    // Process message
}
```

**Solution**: Use constant-time comparison.

```csharp
using HeroCrypt.Security;

// CORRECT: Constant-time comparison
if (SecureMemoryOperations.ConstantTimeEquals(computedMac, providedMac))
{
    // Process message
}
```

### 2.4 Not Clearing Sensitive Data

**Problem**: Keys remain in memory after use.

```csharp
// WRONG: Key remains in memory
var key = DeriveKey(password);
var encrypted = Encrypt(key, data);
// key is still in memory!
```

**Solution**: Clear sensitive data when done.

```csharp
// CORRECT: Clear key after use
var key = DeriveKey(password);
try
{
    return Encrypt(key, data);
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}

// Or use IDisposable patterns
using var keyPair = GenerateKeyPair();
// Automatically cleared on dispose
```

### 2.5 Leaking Information in Errors

**Problem**: Detailed error messages help attackers.

```csharp
// WRONG: Leaks information
catch (Exception ex)
{
    if (ex.Message.Contains("padding"))
        return "Invalid padding";  // Padding oracle!
    if (ex.Message.Contains("MAC"))
        return "Invalid MAC";      // Helps attacker
}
```

**Solution**: Generic error messages for crypto failures.

```csharp
// CORRECT: Generic error
catch (CryptographicException)
{
    return "Decryption failed";  // No details
}
```

---

## 3. Security Checklist

### Before Encryption

- [ ] Key is cryptographically random and appropriate size
- [ ] Nonce/IV is randomly generated for each encryption
- [ ] Using AEAD mode (ChaCha20-Poly1305 or AES-GCM)
- [ ] Associated data included if applicable

### Before Decryption

- [ ] Ciphertext length is validated
- [ ] Using constant-time operations for any comparisons
- [ ] Error handling doesn't leak information

### Key Management

- [ ] Keys are never hardcoded
- [ ] Keys are stored securely (key vault, HSM, or encrypted)
- [ ] Keys are cleared from memory after use
- [ ] Key rotation mechanism in place

### Password Hashing

- [ ] Using Argon2id (not MD5, SHA-1, or plain SHA-256)
- [ ] Salt is random and unique per password
- [ ] Parameters follow OWASP recommendations
- [ ] Verification uses constant-time comparison

### Signatures

- [ ] Always verify before processing data
- [ ] Public keys are from trusted sources
- [ ] Using secure algorithms (Ed25519, ECDSA P-256+, RSA 3072+)

---

## 4. API Security Reference

### 4.1 Constant-Time Operations

```csharp
using HeroCrypt.Security;

// Compare byte arrays
bool equal = SecureMemoryOperations.ConstantTimeEquals(a, b);

// SIMD-accelerated comparison (large arrays)
bool equal = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

// Conditional operations
byte result = ConstantTimeOperations.ConditionalSelect(condition, trueVal, falseVal);
```

### 4.2 Secure Memory Operations

```csharp
using HeroCrypt.Security;

// Clear sensitive data
SecureMemoryOperations.SecureClear(sensitiveData);

// SIMD-accelerated clearing
SimdConstantTimeOperations.SecureClear(largeBuffer);
```

### 4.3 Input Validation

```csharp
using HeroCrypt.Security;

// Validate key sizes
InputValidator.ValidateKeySize(key, expectedSize: 32);

// Validate buffer lengths
InputValidator.ValidateBufferLength(buffer, minLength: 16);
```

---

## 5. Framework-Specific Considerations

### 5.1 .NET Standard 2.0

```csharp
// AES-GCM not available - use ChaCha20-Poly1305 instead
#if NETSTANDARD2_0
    var ciphertext = HeroCryptBuilder.Encrypt()
        .UseChaCha20Poly1305()  // Works on all frameworks
        .WithKey(key)
        .Build();
#else
    var ciphertext = HeroCryptBuilder.Encrypt()
        .UseAesGcm()  // Available on .NET 8+
        .WithKey(key)
        .Build();
#endif
```

### 5.2 .NET 10+ Post-Quantum

```csharp
#if NET10_0_OR_GREATER
// Post-quantum key exchange
using var keyPair = HeroCrypt.Create()
    .PostQuantum()
    .MLKem()
    .WithSecurityBits(192)
    .GenerateKeyPair();

var (ciphertext, sharedSecret) = HeroCrypt.Create()
    .PostQuantum()
    .MLKem()
    .WithPublicKey(recipientPublicKey)
    .Encapsulate();
#endif
```

---

## 6. Threat Mitigation Quick Reference

| Threat | Mitigation | HeroCrypt API |
|--------|------------|---------------|
| Timing attacks | Constant-time comparison | `ConstantTimeOperations` |
| Memory disclosure | Secure clearing | `SecureMemoryOperations.SecureClear()` |
| Nonce reuse | Random nonce generation | `RandomNumberGenerator.GetBytes()` |
| Weak passwords | Memory-hard hashing | Argon2id builder |
| Padding oracle | AEAD modes | ChaCha20-Poly1305, AES-GCM |
| Key exposure | IDisposable pattern | `using var key = ...` |

---

*Last Updated: 2026-01-21*
