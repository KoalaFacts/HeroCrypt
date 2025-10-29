# Security Best Practices

This guide covers security best practices when using HeroCrypt in production systems.

## Table of Contents

1. [General Security Principles](#general-security-principles)
2. [Password Hashing](#password-hashing)
3. [Encryption](#encryption)
4. [Key Management](#key-management)
5. [Memory Management](#memory-management)
6. [Error Handling](#error-handling)
7. [Logging and Monitoring](#logging-and-monitoring)
8. [Compliance and Auditing](#compliance-and-auditing)

## General Security Principles

### 1. Use Only Production-Ready Features

Always check [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) before using any feature.

```csharp
// ✅ GOOD: Production-ready
var hash = Argon2.Hash(password, salt, 3, 65536, 4, 32, Argon2Type.Argon2id);

// ❌ BAD: Reference implementation (educational only)
// Don't use post-quantum, zero-knowledge, or protocol implementations
```

### 2. Validate All Inputs

```csharp
using HeroCrypt.Security;

// ✅ GOOD: Validate inputs
if (!InputValidator.IsValidKeySize(keySize))
{
    throw new ArgumentException("Invalid key size");
}

if (!InputValidator.IsValidNonceSize(nonceSize, algorithm))
{
    throw new ArgumentException("Invalid nonce size");
}

// Validate before cryptographic operations
var plaintext = ValidateAndSanitize(userInput);
```

### 3. Use Constant-Time Operations

```csharp
using HeroCrypt.Security;

// ✅ GOOD: Constant-time comparison
bool isValid = ConstantTimeOperations.Equals(hash1, hash2);

// ❌ BAD: Timing-vulnerable comparison
// if (hash1.SequenceEqual(hash2)) { ... }
```

### 4. Generate Secure Random Values

```csharp
using System.Security.Cryptography;

// ✅ GOOD: Cryptographically secure random
var key = new byte[32];
RandomNumberGenerator.Fill(key);

// ❌ BAD: Not cryptographically secure
// var random = new Random();
// random.NextBytes(key);
```

## Password Hashing

### Argon2id Configuration

```csharp
// ✅ RECOMMENDED: High security (production)
var hash = Argon2.Hash(
    password,
    salt,
    iterations: 3,           // Minimum recommended
    memorySizeKB: 65536,     // 64 MB (adjust based on hardware)
    parallelism: 4,          // Number of threads
    hashLength: 32,          // 256-bit output
    type: Argon2Type.Argon2id  // Hybrid mode (best for most cases)
);

// ⚠️ MINIMUM: Medium security (resource-constrained)
var hash = Argon2.Hash(
    password,
    salt,
    iterations: 2,
    memorySizeKB: 19456,     // 19 MB
    parallelism: 1,
    hashLength: 32,
    type: Argon2Type.Argon2id
);
```

### Password Verification

```csharp
// ✅ GOOD: Use built-in verify method
bool isValid = Argon2.Verify(storedHash, userPassword);

// Always use constant-time comparison internally
```

### Salt Generation

```csharp
// ✅ GOOD: Random salt for each password
var salt = new byte[16];  // 128-bit salt
RandomNumberGenerator.Fill(salt);

// ❌ BAD: Reusing salts
// const byte[] salt = { ... };
```

### Password Storage

```csharp
// ✅ GOOD: Store hash, salt, and parameters
public class PasswordRecord
{
    public string UserId { get; set; }
    public byte[] Hash { get; set; }
    public byte[] Salt { get; set; }
    public int Iterations { get; set; }
    public int MemorySizeKB { get; set; }
    public int Parallelism { get; set; }
    public Argon2Type Type { get; set; }
}
```

## Encryption

### Use Authenticated Encryption (AEAD)

```csharp
// ✅ GOOD: ChaCha20-Poly1305 AEAD
var ciphertext = ChaCha20Poly1305Cipher.Encrypt(
    plaintext,
    key,
    nonce,
    associatedData
);

// ✅ GOOD: AES-GCM AEAD
using var aesGcm = new AesGcm(key);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

// ❌ BAD: Encryption without authentication
// var ciphertext = AesCore.Encrypt(plaintext, key);  // No integrity check
```

### Nonce Management

```csharp
// ✅ GOOD: Random nonce (if not reusing key)
var nonce = new byte[12];
RandomNumberGenerator.Fill(nonce);

// ✅ GOOD: Counter-based nonce (if single key, multiple messages)
ulong counter = 0;
var nonce = new byte[12];
BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), counter++);

// ❌ BAD: Reusing nonce with same key
// var nonce = new byte[12];  // Never reuse!
```

### Key Size Requirements

```csharp
// ✅ GOOD: Proper key sizes
var chaChaKey = new byte[32];    // 256-bit for ChaCha20
var aesKey = new byte[32];        // 256-bit for AES-256
var rsaKeySize = 3072;            // 3072-bit RSA (2048 minimum)

// ❌ BAD: Weak key sizes
// var aesKey = new byte[16];     // 128-bit (too weak for high security)
// var rsaKeySize = 1024;         // 1024-bit RSA (broken)
```

### Associated Data

```csharp
// ✅ GOOD: Include context in authenticated data
var associatedData = System.Text.Encoding.UTF8.GetBytes($"{userId}|{timestamp}|{version}");

var ciphertext = ChaCha20Poly1305Cipher.Encrypt(
    plaintext,
    key,
    nonce,
    associatedData
);

// This prevents ciphertext from being valid in different contexts
```

## Key Management

### Key Generation

```csharp
// ✅ GOOD: Generate strong random keys
var masterKey = new byte[32];
RandomNumberGenerator.Fill(masterKey);

// Store in secure location (HSM, Azure Key Vault, AWS KMS, etc.)
await keyVault.SetSecretAsync("master-key", Convert.ToBase64String(masterKey));
```

### Key Derivation

```csharp
// ✅ GOOD: Derive keys from master key
using HeroCrypt.Cryptography.KeyDerivation;

var masterKey = await GetMasterKeyFromSecureStorage();

var encryptionKey = HkdfCore.DeriveKey(
    masterKey,
    keyLength: 32,
    info: "encryption-key-v1"u8.ToArray(),
    salt: null
);

var authenticationKey = HkdfCore.DeriveKey(
    masterKey,
    keyLength: 32,
    info: "authentication-key-v1"u8.ToArray(),
    salt: null
);
```

### Key Rotation

```csharp
// ✅ GOOD: Implement key rotation
public class KeyRotationService
{
    private readonly Dictionary<int, byte[]> _keyVersions = new();
    private int _currentVersion = 1;

    public byte[] GetCurrentKey() => _keyVersions[_currentVersion];

    public byte[] GetKey(int version) => _keyVersions[version];

    public void RotateKey()
    {
        _currentVersion++;
        var newKey = new byte[32];
        RandomNumberGenerator.Fill(newKey);
        _keyVersions[_currentVersion] = newKey;
    }

    public async Task ReencryptWithNewKey(byte[] ciphertext, int oldVersion)
    {
        var oldKey = GetKey(oldVersion);
        var newKey = GetCurrentKey();

        // Decrypt with old key
        var plaintext = Decrypt(ciphertext, oldKey);

        // Encrypt with new key
        var newCiphertext = Encrypt(plaintext, newKey);

        return newCiphertext;
    }
}
```

### Key Storage

```csharp
// ✅ GOOD: Use secure key storage
// Option 1: Hardware Security Module (HSM)
// Option 2: Cloud KMS (Azure Key Vault, AWS KMS, Google Cloud KMS)
// Option 3: Operating System Key Store

// Example: Azure Key Vault
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var client = new SecretClient(
    new Uri("https://your-vault.vault.azure.net/"),
    new DefaultAzureCredential()
);

await client.SetSecretAsync("encryption-key", Convert.ToBase64String(key));

// ❌ BAD: Hardcoded keys
// const string key = "hardcoded-key-123";

// ❌ BAD: Keys in source code or config files
// var key = Configuration["EncryptionKey"];
```

## Memory Management

### Secure Memory Cleanup

```csharp
// ✅ GOOD: Use SecureBuffer for sensitive data
using HeroCrypt.Memory;

using (var buffer = new SecureBuffer(32))
{
    // Use buffer for sensitive operations
    var key = buffer.GetSpan();
    // ... crypto operations ...
}
// Memory is automatically zeroed and unlocked

// ✅ GOOD: Manual secure cleanup
var sensitiveData = new byte[32];
try
{
    // Use data
}
finally
{
    SecureMemoryOperations.SecureClear(sensitiveData);
}
```

### Prevent Memory Leaks

```csharp
// ✅ GOOD: Use Span<T> for stack allocation
public void ProcessSensitiveData(ReadOnlySpan<byte> data)
{
    Span<byte> buffer = stackalloc byte[32];
    // Process data
    // Buffer is automatically cleared when method returns
}

// ✅ GOOD: Dispose cryptographic objects
using (var rsa = RSA.Create(2048))
{
    // Use RSA
}
// Keys are automatically cleared
```

### Memory Locking

```csharp
// ✅ GOOD: Lock sensitive memory (prevents swapping to disk)
using HeroCrypt.Memory;

using var secureBuffer = new SecureBuffer(32);
// Memory is locked to prevent swapping
// Memory is zeroed on disposal
```

## Error Handling

### Don't Leak Information in Errors

```csharp
// ✅ GOOD: Generic error messages
try
{
    var decrypted = Decrypt(ciphertext, key);
}
catch (CryptographicException)
{
    // Log detailed error for debugging
    _logger.LogError("Decryption failed for user {UserId}", userId);

    // Return generic error to user
    throw new InvalidOperationException("Authentication failed");
}

// ❌ BAD: Specific error messages
// throw new Exception("MAC verification failed - possible tampering");
// throw new Exception("Invalid key length: expected 32, got 16");
```

### Constant-Time Error Handling

```csharp
// ✅ GOOD: Same execution time for all paths
public bool VerifyPassword(string password, byte[] storedHash)
{
    try
    {
        return Argon2.Verify(storedHash, password);
    }
    catch
    {
        // Still return false, don't leak timing information
        return false;
    }
}

// ❌ BAD: Early return on error
// if (storedHash == null) return false;  // Faster path leaks info
```

## Logging and Monitoring

### Log Security Events

```csharp
// ✅ GOOD: Log security-relevant events
_logger.LogInformation("User {UserId} authenticated successfully", userId);
_logger.LogWarning("Failed authentication attempt for user {UserId}", userId);
_logger.LogError("Encryption operation failed for user {UserId}", userId);

// ❌ BAD: Log sensitive data
// _logger.LogInformation("User password: {Password}", password);
// _logger.LogInformation("Encryption key: {Key}", Convert.ToBase64String(key));
```

### Monitor for Anomalies

```csharp
// ✅ GOOD: Track and alert on suspicious patterns
public class SecurityMonitor
{
    private readonly Dictionary<string, int> _failedAttempts = new();

    public bool CheckFailedAttempts(string userId)
    {
        if (_failedAttempts.TryGetValue(userId, out int count))
        {
            if (count >= 5)
            {
                _logger.LogWarning("Account {UserId} locked due to failed attempts", userId);
                return false;  // Account locked
            }
        }
        return true;
    }

    public void RecordFailedAttempt(string userId)
    {
        _failedAttempts[userId] = _failedAttempts.GetValueOrDefault(userId) + 1;
    }
}
```

## Compliance and Auditing

### FIPS 140-2 Compliance

```csharp
// ✅ For FIPS compliance, use only NIST-approved algorithms
using System.Security.Cryptography;

// FIPS-approved:
// - AES-GCM (use .NET's built-in)
// - SHA-256, SHA-384, SHA-512
// - RSA with OAEP or PSS
// - ECDSA with NIST curves (P-256, P-384, P-521)
// - HMAC-SHA256

// NOT FIPS-approved:
// - ChaCha20-Poly1305
// - Blake2b
// - Argon2
```

### Audit Trails

```csharp
// ✅ GOOD: Comprehensive audit logging
public class CryptoAuditLogger
{
    public async Task LogCryptoOperation(
        string operation,
        string userId,
        bool success,
        Dictionary<string, object> metadata)
    {
        var auditEvent = new AuditEvent
        {
            Timestamp = DateTime.UtcNow,
            Operation = operation,
            UserId = userId,
            Success = success,
            Metadata = metadata,
            IpAddress = GetClientIp(),
            UserAgent = GetUserAgent()
        };

        await _auditLog.WriteAsync(auditEvent);
    }
}

// Usage:
await _auditLogger.LogCryptoOperation(
    "password-hash",
    userId,
    success: true,
    new Dictionary<string, object>
    {
        { "algorithm", "Argon2id" },
        { "iterations", 3 },
        { "memory", "64MB" }
    }
);
```

## Summary Checklist

- [ ] Only use production-ready features
- [ ] Validate all inputs before cryptographic operations
- [ ] Use constant-time operations for sensitive comparisons
- [ ] Generate cryptographically secure random values
- [ ] Use Argon2id with strong parameters for passwords
- [ ] Use AEAD ciphers (ChaCha20-Poly1305, AES-GCM) for encryption
- [ ] Never reuse nonces with the same key
- [ ] Use proper key sizes (256-bit for symmetric, 3072-bit for RSA)
- [ ] Store keys in secure storage (HSM, KMS)
- [ ] Implement key rotation
- [ ] Use SecureBuffer for sensitive data
- [ ] Clear sensitive data from memory after use
- [ ] Don't leak information in error messages
- [ ] Log security events (without sensitive data)
- [ ] Monitor for anomalies and suspicious patterns
- [ ] Maintain audit trails for compliance
- [ ] Regularly update the library to get security fixes

## Additional Resources

- [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) - Feature status
- [SECURITY.md](../SECURITY.md) - Security policy and reporting
- [API Patterns](api-patterns.md) - API design patterns
- [Performance Guide](performance-guide.md) - Optimization best practices
