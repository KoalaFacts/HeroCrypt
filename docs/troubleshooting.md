# Troubleshooting Guide

Common issues and solutions when using HeroCrypt.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Runtime Errors](#runtime-errors)
3. [Performance Issues](#performance-issues)
4. [Platform-Specific Issues](#platform-specific-issues)
5. [Memory Issues](#memory-issues)
6. [Encryption/Decryption Failures](#encryptiondecryption-failures)
7. [Key Management Issues](#key-management-issues)
8. [Getting Help](#getting-help)

## Installation Issues

### NuGet Package Not Found

**Problem**: `dotnet add package HeroCrypt` fails with "Unable to find package"

**Solution**:
```bash
# Clear NuGet cache
dotnet nuget locals all --clear

# Restore packages
dotnet restore

# Try again
dotnet add package HeroCrypt
```

### Version Conflicts

**Problem**: "Version conflict detected for HeroCrypt"

**Solution**:
```xml
<!-- Explicitly specify version in .csproj -->
<ItemGroup>
  <PackageReference Include="HeroCrypt" Version="1.0.0" />
</ItemGroup>
```

### Missing .NET SDK

**Problem**: "The current .NET SDK does not support targeting .NET X.0"

**Solution**:
```bash
# Install required .NET SDK
# For .NET 8.0:
wget https://dot.net/v1/dotnet-install.sh
bash dotnet-install.sh --channel 8.0

# Or download from: https://dotnet.microsoft.com/download
```

## Runtime Errors

### ArgumentException: Invalid key size

**Problem**:
```
ArgumentException: Invalid key size: expected 32, got 16
```

**Solution**:
```csharp
// ❌ Wrong key size
var key = new byte[16];  // Too small!

// ✅ Correct key size
var key = new byte[32];  // 256-bit key
RandomNumberGenerator.Fill(key);
```

### ArgumentException: Invalid nonce size

**Problem**:
```
ArgumentException: Invalid nonce size: expected 12, got 24
```

**Solution**:
```csharp
// ❌ Wrong nonce size for ChaCha20-Poly1305
var nonce = new byte[24];  // XChaCha20 uses 24, ChaCha20 uses 12

// ✅ Correct nonce size
var nonce = new byte[12];  // ChaCha20-Poly1305
RandomNumberGenerator.Fill(nonce);

// ✅ Or use XChaCha20-Poly1305 for 24-byte nonces
var nonce = new byte[24];  // XChaCha20-Poly1305
```

### CryptographicException: MAC verification failed

**Problem**:
```
CryptographicException: MAC verification failed
```

**Causes**:
1. Wrong key
2. Corrupted ciphertext
3. Wrong associated data
4. Wrong nonce

**Solution**:
```csharp
// Ensure all parameters match encryption:
var plaintext = ChaCha20Poly1305Cipher.Decrypt(
    ciphertext,
    key,           // Must be same key
    nonce,         // Must be same nonce
    associatedData // Must be same associated data (or null)
);
```

### InvalidOperationException: Password not set

**Problem**:
```
InvalidOperationException: Password not set. Call WithPassword() first.
```

**Solution**:
```csharp
// ❌ Missing WithPassword()
var hash = await heroCrypt.Argon2
    .WithSecurityLevel(SecurityLevel.High)
    .HashAsync();  // Error!

// ✅ Correct usage
var hash = await heroCrypt.Argon2
    .WithPassword("mypassword")  // Required!
    .WithSecurityLevel(SecurityLevel.High)
    .HashAsync();
```

### OutOfMemoryException during Argon2 hashing

**Problem**:
```
OutOfMemoryException: Insufficient memory to allocate Argon2 buffer
```

**Solution**:
```csharp
// ❌ Too much memory requested
var hash = Argon2.Hash(
    password, salt,
    iterations: 3,
    memorySizeKB: 1048576,  // 1 GB - too much!
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id
);

// ✅ Reasonable memory usage
var hash = Argon2.Hash(
    password, salt,
    iterations: 3,
    memorySizeKB: 65536,  // 64 MB
    parallelism: 4,
    hashLength: 32,
    type: Argon2Type.Argon2id
);
```

## Performance Issues

### Slow Password Hashing

**Problem**: Argon2 hashing takes too long (>5 seconds)

**Solution**:
```csharp
// Option 1: Reduce memory and iterations
var hash = Argon2.Hash(
    password, salt,
    iterations: 2,        // Reduced from 3
    memorySizeKB: 19456,  // 19 MB (reduced from 64 MB)
    parallelism: 1,       // Reduced from 4
    hashLength: 32,
    type: Argon2Type.Argon2id
);

// Option 2: Use hardware acceleration
var hash = await heroCrypt.Argon2
    .WithPassword(password)
    .WithSecurityLevel(SecurityLevel.Medium)  // Lower than High
    .WithHardwareAcceleration()
    .HashAsync();
```

### Slow Encryption

**Problem**: Encryption is slower than expected

**Solutions**:

1. **Enable hardware acceleration**:
```csharp
var encrypted = await heroCrypt.PGP
    .WithData(plaintext)
    .WithPublicKey(publicKey)
    .WithHardwareAcceleration()  // Add this!
    .EncryptAsync();
```

2. **Use batch operations**:
```csharp
// Instead of encrypting one by one
var ciphertexts = await BatchOperations.EncryptBatchAsync(
    plaintexts,
    key,
    nonces
);
```

3. **Use faster algorithm**:
```csharp
// ChaCha20-Poly1305 is faster in software
var encrypted = ChaCha20Poly1305Cipher.Encrypt(plaintext, key, nonce, aad);

// AES-GCM is faster with AES-NI hardware
using var aesGcm = new AesGcm(key);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
```

### High Memory Usage

**Problem**: Application uses too much memory

**Solutions**:

1. **Use memory pooling**:
```csharp
using HeroCrypt.Performance.Memory;

var pool = CryptoMemoryPool.Shared;
var buffer = pool.Rent(size);
try
{
    // Use buffer
}
finally
{
    pool.Return(buffer, clearArray: true);
}
```

2. **Use Span<T>**:
```csharp
// Stack allocation instead of heap
Span<byte> buffer = stackalloc byte[32];
```

3. **Dispose SecureBuffer**:
```csharp
using (var buffer = new SecureBuffer(size))
{
    // Use buffer
} // Automatically disposed
```

## Platform-Specific Issues

### Windows: AES-OCB/AES-SIV Tests Fail

**Problem**: AES-OCB or AES-SIV tests crash on Windows

**Status**: Known issue (see [TEST_STATUS.md](../TEST_STATUS.md))

**Workaround**: Use AES-GCM instead
```csharp
// ❌ Don't use on Windows
// var encrypted = AesOcbCore.Encrypt(...);

// ✅ Use AES-GCM instead
using var aesGcm = new AesGcm(key);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
```

### macOS: AES-OCB/AES-SIV Tests Fail

**Problem**: Same as Windows

**Workaround**: Same as Windows - use AES-GCM

### Linux: Permission Denied (Memory Locking)

**Problem**:
```
Permission denied: Cannot lock memory
```

**Solution**: Increase `memlock` limit
```bash
# Temporary (current session)
ulimit -l unlimited

# Permanent (add to /etc/security/limits.conf)
* soft memlock unlimited
* hard memlock unlimited
```

### ARM: SIMD Not Available

**Problem**: NEON acceleration not working

**Check**:
```csharp
var capabilities = HardwareAccelerationDetector.DetectCapabilities();
if (!capabilities.HasNeon)
{
    Console.WriteLine("NEON not available, using portable implementation");
}
```

**Solution**: Ensure running on ARM64, not ARM32

## Memory Issues

### Memory Not Being Released

**Problem**: Memory usage keeps growing

**Solutions**:

1. **Dispose SecureBuffer**:
```csharp
// ❌ Not disposed
var buffer = new SecureBuffer(size);
// Memory leaked!

// ✅ Properly disposed
using var buffer = new SecureBuffer(size);
// or
buffer.Dispose();
```

2. **Clear sensitive data**:
```csharp
var key = new byte[32];
try
{
    // Use key
}
finally
{
    SecureMemoryOperations.SecureClear(key);
}
```

3. **Return pooled buffers**:
```csharp
var buffer = pool.Rent(size);
try
{
    // Use buffer
}
finally
{
    pool.Return(buffer, clearArray: true);
}
```

### Stack Overflow

**Problem**:
```
StackOverflowException
```

**Cause**: Allocating too much on stack with `stackalloc`

**Solution**:
```csharp
// ❌ Too large for stack
Span<byte> buffer = stackalloc byte[1024 * 1024];  // 1 MB!

// ✅ Use heap for large buffers
var buffer = new byte[1024 * 1024];
try
{
    // Use buffer
}
finally
{
    SecureMemoryOperations.SecureClear(buffer);
}

// ✅ Stack is OK for small buffers (<= 1024 bytes)
Span<byte> buffer = stackalloc byte[32];
```

## Encryption/Decryption Failures

### Decryption Returns Garbage

**Problem**: Decrypted data is not the original plaintext

**Causes**:
1. Wrong key
2. Wrong nonce
3. Corrupted ciphertext
4. Wrong algorithm

**Diagnostic**:
```csharp
// Verify encryption round-trip
var plaintext = "Hello, World!"u8.ToArray();
var key = new byte[32];
var nonce = new byte[12];
RandomNumberGenerator.Fill(key);
RandomNumberGenerator.Fill(nonce);

var ciphertext = ChaCha20Poly1305Cipher.Encrypt(plaintext, key, nonce, null);
var decrypted = ChaCha20Poly1305Cipher.Decrypt(ciphertext, key, nonce, null);

Debug.Assert(plaintext.SequenceEqual(decrypted), "Round-trip failed!");
```

### Cannot Decrypt Data Encrypted by Another System

**Problem**: Cannot decrypt data encrypted by Python/Java/JavaScript

**Solution**: Check format compatibility
```csharp
// Different systems may use different formats:
// 1. Nonce/IV may be prepended or separate
// 2. Tag may be appended or separate
// 3. Associated data may differ

// Example: Data from Python cryptography library
// Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
var nonce = ciphertext[..12];
var actualCiphertext = ciphertext[12..^16];
var tag = ciphertext[^16..];

// Need to extract and reassemble for HeroCrypt
var combined = new byte[actualCiphertext.Length + tag.Length];
actualCiphertext.CopyTo(combined, 0);
tag.CopyTo(combined, actualCiphertext.Length);

var plaintext = ChaCha20Poly1305Cipher.Decrypt(combined, key, nonce.ToArray(), null);
```

### PGP Key Format Issues

**Problem**: Cannot import PGP keys

**Solution**: Ensure correct format
```csharp
// HeroCrypt supports:
// - ASCII-armored PGP keys (-----BEGIN PGP PUBLIC KEY BLOCK-----)
// - Binary PGP keys

// Check key format
if (keyString.StartsWith("-----BEGIN PGP"))
{
    // ASCII-armored format
    await pgpService.ImportPublicKeyAsync(keyString);
}
else
{
    // May need to convert from other formats
}
```

## Key Management Issues

### Lost Encryption Keys

**Problem**: Cannot decrypt data because key was lost

**Prevention**:
```csharp
// 1. Use key backup
var masterKey = GenerateMasterKey();
await BackupKeyToSecureStorage(masterKey);

// 2. Use key derivation from password
var masterKey = Pbkdf2Core.DeriveKey(
    password: userPassword,
    salt: securelyStoredSalt,
    iterations: 600000,
    keyLength: 32,
    algorithm: HashAlgorithmName.SHA256
);

// 3. Use key escrow for enterprise
await keyEscrowService.DepositKeyAsync(masterKey, escrowPolicy);
```

### Key Rotation Failures

**Problem**: Cannot access data after key rotation

**Solution**: Implement versioned keys
```csharp
public class VersionedKey
{
    public int Version { get; set; }
    public byte[] Key { get; set; }
    public DateTime ValidFrom { get; set; }
    public DateTime? ValidTo { get; set; }
}

public class KeyRotationService
{
    private readonly Dictionary<int, VersionedKey> _keys = new();

    public byte[] GetKey(int version) => _keys[version].Key;

    public byte[] GetCurrentKey() => _keys.Values
        .Where(k => k.ValidTo == null)
        .OrderByDescending(k => k.Version)
        .First().Key;
}
```

### Hardware Security Module (HSM) Issues

**Problem**: Cannot connect to HSM

**Note**: HeroCrypt provides abstraction layers for HSM integration. You need vendor-specific SDKs.

**Solutions**:
```csharp
// 1. Check HSM connectivity
await hsmClient.PingAsync();

// 2. Verify credentials
await hsmClient.AuthenticateAsync(credentials);

// 3. Verify key exists
var keyExists = await hsmClient.KeyExistsAsync(keyId);

// 4. Use software fallback if HSM unavailable
byte[] key;
if (hsmAvailable)
{
    key = await hsmClient.GetKeyAsync(keyId);
}
else
{
    key = await GetKeyFromSecureStorage(keyId);
}
```

## Debugging Tips

### Enable Detailed Logging

```csharp
services.AddLogging(builder =>
{
    builder.AddConsole();
    builder.SetMinimumLevel(LogLevel.Debug);
});

services.AddHeroCrypt(options =>
{
    options.EnableDetailedLogging = true;
});
```

### Capture Stack Traces

```csharp
try
{
    var encrypted = Encrypt(plaintext, key);
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
    Console.WriteLine($"Stack trace: {ex.StackTrace}");
    Console.WriteLine($"Inner exception: {ex.InnerException?.Message}");
}
```

### Validate Inputs

```csharp
using HeroCrypt.Security;

// Add validation before operations
InputValidator.ValidateKeySize(key.Length, 32);
InputValidator.ValidateNonceSize(nonce.Length, 12);
InputValidator.ValidateNotNullOrEmpty(plaintext);
```

### Test with Known Test Vectors

```csharp
// Use RFC test vectors to verify correctness
var knownPlaintext = Convert.FromHexString("000102030405...");
var knownKey = Convert.FromHexString("000102030405...");
var knownNonce = Convert.FromHexString("000102030405...");
var expectedCiphertext = Convert.FromHexString("000102030405...");

var actualCiphertext = Encrypt(knownPlaintext, knownKey, knownNonce);
Debug.Assert(actualCiphertext.SequenceEqual(expectedCiphertext));
```

## Getting Help

### Documentation

1. **[Getting Started](getting-started.md)** - Quick start guide
2. **[Best Practices](best-practices.md)** - Security best practices
3. **[API Patterns](api-patterns.md)** - API design patterns
4. **[Performance Guide](performance-guide.md)** - Optimization guide
5. **[PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md)** - Feature status

### Support Channels

1. **GitHub Issues**: [Report issues](https://github.com/BeingCiteable/HeroCrypt/issues)
2. **Stack Overflow**: Tag questions with `herocrypt`
3. **Security Issues**: See [SECURITY.md](../SECURITY.md)

### Before Asking for Help

Provide:
- [ ] HeroCrypt version (`dotnet list package`)
- [ ] .NET version (`dotnet --version`)
- [ ] Operating system and version
- [ ] Minimal reproducible example
- [ ] Complete error message and stack trace
- [ ] What you've already tried

### Minimal Reproducible Example

```csharp
using HeroCrypt.Cryptography.Symmetric;
using System.Security.Cryptography;

// Minimal example showing the issue
var key = new byte[32];
var nonce = new byte[12];
RandomNumberGenerator.Fill(key);
RandomNumberGenerator.Fill(nonce);

var plaintext = "Hello"u8.ToArray();

try
{
    var ciphertext = ChaCha20Poly1305Cipher.Encrypt(plaintext, key, nonce, null);
    var decrypted = ChaCha20Poly1305Cipher.Decrypt(ciphertext, key, nonce, null);

    Console.WriteLine($"Success: {System.Text.Encoding.UTF8.GetString(decrypted)}");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}
```

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Invalid key size` | Wrong key length | Use correct size (32 for ChaCha20, AES-256) |
| `Invalid nonce size` | Wrong nonce length | Use 12 for ChaCha20, 24 for XChaCha20 |
| `MAC verification failed` | Wrong key/nonce/AAD or corrupted data | Verify all parameters match encryption |
| `Password not set` | Fluent API missing `WithPassword()` | Call `WithPassword()` before `HashAsync()` |
| `Out of memory` | Argon2 memory too high | Reduce `memorySizeKB` parameter |
| `Permission denied` | Cannot lock memory | Increase `memlock` limit (Linux) |
| `Platform not supported` | Feature not available | Check [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) |

## Still Having Issues?

If your issue isn't covered here:

1. Check [GitHub Issues](https://github.com/BeingCiteable/HeroCrypt/issues) for similar problems
2. Review [TEST_STATUS.md](../TEST_STATUS.md) for known platform issues
3. Check [PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md) for feature status
4. Create a new issue with all relevant details
