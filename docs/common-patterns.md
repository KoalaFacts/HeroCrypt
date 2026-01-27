# Common Patterns

This guide covers common usage patterns and best practices when working with HeroCrypt.

## Table of Contents

1. [Builder Disposal Pattern](#builder-disposal-pattern)
2. [Error Handling](#error-handling)
3. [Encryption/Decryption Workflows](#encryptiondecryption-workflows)
4. [Sign/Verify Workflows](#signverify-workflows)
5. [Key Derivation Chains](#key-derivation-chains)
6. [Text Format Selection](#text-format-selection)
7. [Thread Safety](#thread-safety)

## Builder Disposal Pattern

All HeroCrypt builders implement `IDisposable` and securely clear sensitive data when disposed.

### Basic Pattern

```csharp
// Using statement ensures secure cleanup
using var builder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey();

var result = builder.Encrypt("sensitive data");
// Builder and key material are securely cleared when scope exits
```

### Multiple Operations with Same Key

```csharp
using var builder = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithKey(key);

// Encrypt multiple messages with the same key
var result1 = builder.Encrypt(message1);
var result2 = builder.Encrypt(message2);
var result3 = builder.Encrypt(message3);
// Each encryption uses a unique nonce automatically
```

### Manual Disposal

```csharp
var builder = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(password)
    .WithRandomSalt();

try
{
    var derivedKey = builder.DeriveKey();
    // Use the key...
}
finally
{
    builder.Dispose();  // Always dispose, even on error
}
```

### Disposal Best Practices

| Practice | Description |
|----------|-------------|
| Always use `using` | Ensures cleanup even if exceptions occur |
| Dispose before exiting scope | Don't let builders outlive their usefulness |
| Don't dispose twice | Calling Dispose() multiple times is safe but unnecessary |
| Don't use after disposal | Throws `ObjectDisposedException` |

## Error Handling

### Exception Types

| Exception | When Thrown | How to Handle |
|-----------|-------------|---------------|
| `ArgumentException` | Invalid parameters | Validate inputs before calling |
| `ArgumentNullException` | Null required parameter | Check for null |
| `CryptographicException` | Crypto operation failed | Log and retry or fail gracefully |
| `NotSupportedException` | Algorithm not available | Check platform support first |
| `ObjectDisposedException` | Builder already disposed | Ensure proper scope management |
| `FormatException` | Invalid text encoding | Validate input format |

### Handling Decryption Failures

```csharp
try
{
    var plaintext = HeroCryptBuilder.Decrypt()
        .WithAesGcm()
        .WithKey(key)
        .WithNonce(nonce)
        .Decrypt(ciphertext);

    return plaintext;
}
catch (CryptographicException ex) when (ex.Message.Contains("authentication"))
{
    // Authentication tag validation failed - data was tampered
    _logger.LogWarning("Decryption failed: data integrity compromised");
    throw new SecurityException("Data integrity check failed", ex);
}
catch (CryptographicException ex)
{
    // Other crypto errors
    _logger.LogError(ex, "Decryption failed");
    throw;
}
```

### Checking Platform Support

```csharp
// Check before using post-quantum algorithms
if (!MLKemCore.IsSupported())
{
    // Fall back to classical encryption
    return EncryptWithX25519(data);
}

return EncryptWithMlKem(data);
```

### Validation Before Operations

```csharp
public byte[] EncryptData(byte[] data, byte[] key)
{
    // Validate inputs
    if (data == null || data.Length == 0)
        throw new ArgumentException("Data cannot be empty", nameof(data));

    if (key == null || key.Length != 32)
        throw new ArgumentException("Key must be 32 bytes", nameof(key));

    using var builder = HeroCryptBuilder.Encrypt()
        .WithChaCha20Poly1305()
        .WithKey(key);

    return builder.Encrypt(data).ToByteArray();
}
```

## Encryption/Decryption Workflows

### Simple Round-Trip

```csharp
// Encrypt
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey();

var keyHex = encryptor.GetKeyAsHex();
var result = encryptor.Encrypt("Hello, World!");

// Store or transmit: keyHex, result.NonceAsHex, result.CiphertextAsHex

// Decrypt (later, possibly different process)
var plaintext = HeroCryptBuilder.Decrypt()
    .WithAesGcm()
    .WithKeyFromHex(keyHex)
    .WithNonceFromHex(storedNonce)
    .DecryptFromHexToString(storedCiphertext);
```

### Using EncryptionResult Pattern

```csharp
// Encrypt and capture all components
using var encryptor = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithKey(key);

var result = encryptor.Encrypt(plaintext);

// Decrypt using the result directly
var decrypted = HeroCryptBuilder.Decrypt()
    .WithChaCha20Poly1305()
    .FromEncryptionResult(result)
    .WithKey(key)
    .Decrypt();
```

### Hybrid Encryption (Large Data)

```csharp
// For large files: generate ephemeral symmetric key
using var kdf = HeroCryptBuilder.DeriveKey()
    .WithHkdfSha256()
    .WithInputKeyMaterial(sharedSecret)
    .WithInfo("file-encryption");

var fileKey = kdf.DeriveKey(32);

// Encrypt file with symmetric cipher
using var cipher = HeroCryptBuilder.Encrypt()
    .WithChaCha20Poly1305()
    .WithKey(fileKey);

// Process file in chunks...
```

### Associated Data (AAD)

```csharp
// Include metadata in authentication
var metadata = Encoding.UTF8.GetBytes($"user:{userId}|timestamp:{DateTime.UtcNow:O}");

using var builder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithKey(key)
    .WithAssociatedData(metadata);

var result = builder.Encrypt(sensitiveData);
// Tampering with metadata will cause decryption to fail
```

## Sign/Verify Workflows

### Basic Sign and Verify

```csharp
// Generate key pair (once, store securely)
var (privateKey, publicKey) = HeroCryptBuilder.Sign()
    .WithEd25519()
    .GenerateKeyPair();

// Sign a document
var signature = HeroCryptBuilder.Sign()
    .WithEd25519()
    .WithKey(privateKey)
    .Sign(document);

// Verify (can be done by anyone with public key)
bool isValid = HeroCryptBuilder.Verify()
    .WithEd25519()
    .WithKey(publicKey)
    .WithSignature(signature)
    .Verify(document);
```

### HMAC for Message Authentication

```csharp
// Sender: Create authenticated message
using var signer = HeroCryptBuilder.Sign()
    .WithHmacSha256()
    .WithKey(sharedSecret);

var mac = signer.Sign(message);
// Send: message + mac

// Receiver: Verify authenticity
bool isAuthentic = HeroCryptBuilder.Verify()
    .WithHmacSha256()
    .WithKey(sharedSecret)
    .WithSignature(mac)
    .Verify(message);
```

### Signing with Text Output

```csharp
// Sign and get signature as Base64Url (for APIs)
var signatureBase64Url = HeroCryptBuilder.Sign()
    .WithEd25519()
    .WithKey(privateKey)
    .SignToBase64Url(document);

// Verify from Base64Url
bool isValid = HeroCryptBuilder.Verify()
    .WithEd25519()
    .WithKey(publicKey)
    .WithSignatureFromBase64Url(signatureBase64Url)
    .Verify(document);
```

## Key Derivation Chains

### Password to Multiple Keys

```csharp
// Derive master key from password
using var masterKdf = HeroCryptBuilder.DeriveKey()
    .WithArgon2id()
    .WithPassword(password)
    .WithSalt(salt);

var masterKey = masterKdf.DeriveKey(32);

// Derive purpose-specific keys using HKDF
var encryptionKey = HeroCryptBuilder.DeriveKey()
    .WithHkdfSha256()
    .WithInputKeyMaterial(masterKey)
    .WithInfo("encryption")
    .DeriveKey(32);

var authenticationKey = HeroCryptBuilder.DeriveKey()
    .WithHkdfSha256()
    .WithInputKeyMaterial(masterKey)
    .WithInfo("authentication")
    .DeriveKey(32);

var signingKey = HeroCryptBuilder.DeriveKey()
    .WithHkdfSha256()
    .WithInputKeyMaterial(masterKey)
    .WithInfo("signing")
    .DeriveKey(32);
```

### HD Wallet Key Derivation

```csharp
// Generate mnemonic
var mnemonic = HeroCryptBuilder.HdWallet()
    .GenerateMnemonic(24);

// Derive wallet keys
var wallet = HeroCryptBuilder.HdWallet()
    .FromMnemonic(mnemonic)
    .WithPassphrase(optionalPassphrase);

// Derive child keys for different accounts
var account0Key = wallet.DerivePath("m/44'/0'/0'");
var account1Key = wallet.DerivePath("m/44'/0'/1'");
```

## Text Format Selection

### When to Use Each Format

| Format | Use Case | Example |
|--------|----------|---------|
| Hex | Logging, debugging, display | `"a1b2c3d4..."` |
| Base64 | Database storage, JSON | `"obLD1A=="` |
| Base64Url | URLs, JWTs, API payloads | `"obLD1A"` (no padding) |

### API Request Example

```csharp
// Creating API-friendly payload
using var builder = HeroCryptBuilder.Encrypt()
    .WithAesGcm()
    .WithRandomKey();

var result = builder.Encrypt(sensitiveData);

var apiPayload = new
{
    key = builder.GetKeyAsBase64Url(),
    nonce = result.NonceAsBase64Url,
    data = result.CiphertextAsBase64Url
};

// Can be safely serialized to JSON and sent in URL
```

### Database Storage Example

```csharp
// Storing encrypted data in database
var dbRecord = new EncryptedRecord
{
    Id = Guid.NewGuid(),
    EncryptedData = result.CiphertextAsBase64,  // Compact storage
    Nonce = result.NonceAsHex,                   // Easy to debug
    CreatedAt = DateTime.UtcNow
};
```

## Thread Safety

### Builders Are NOT Thread-Safe for Operations

```csharp
// WRONG - Don't share a builder across threads for operations
var builder = HeroCryptBuilder.Encrypt().WithAesGcm().WithKey(key);
Parallel.For(0, 100, i =>
{
    builder.Encrypt(data[i]);  // UNSAFE!
});

// CORRECT - Create builder per thread
Parallel.For(0, 100, i =>
{
    using var builder = HeroCryptBuilder.Encrypt()
        .WithAesGcm()
        .WithKey(key);
    results[i] = builder.Encrypt(data[i]);
});
```

### Disposal Is Thread-Safe

```csharp
// Safe: Multiple threads can call Dispose
var builder = HeroCryptBuilder.Hash().WithSha256();

var tasks = Enumerable.Range(0, 10)
    .Select(_ => Task.Run(() => builder.Dispose()))
    .ToArray();

await Task.WhenAll(tasks);  // All calls complete safely
```

### Immutable Configuration Pattern

```csharp
// Thread-safe: Each operation gets its own builder
public class EncryptionService
{
    private readonly byte[] _key;

    public EncryptionService(byte[] key)
    {
        _key = (byte[])key.Clone();  // Defensive copy
    }

    public EncryptionResult Encrypt(byte[] data)
    {
        using var builder = HeroCryptBuilder.Encrypt()
            .WithChaCha20Poly1305()
            .WithKey(_key);

        return builder.Encrypt(data);
    }
}
```

## Related Documentation

- [API Patterns](api-patterns.md) - API design conventions
- [API Patterns - Text Encoding](api-patterns.md#text-encoding-conventions) - Encoding naming patterns
- [Best Practices](best-practices.md) - Security best practices
- [Troubleshooting](troubleshooting.md) - Common issues
- [Troubleshooting - Text Encoding](troubleshooting.md#text-encoding-issues) - Encoding errors
- [Algorithm Selection](algorithm-selection.md) - Choosing algorithms
