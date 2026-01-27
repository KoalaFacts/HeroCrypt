# API Patterns and Design Conventions

HeroCrypt is now builder-first: public entry points are the fluent builders, and everything else is core static primitives. There is no separate “service” layer.

## Table of Contents

1. [Architecture](#architecture)
2. [Fluent API Pattern](#fluent-api-pattern)
3. [Core Implementation Pattern](#core-implementation-pattern)
4. [Async/Await](#asyncawait)
5. [Memory Management](#memory-management)
6. [Error Handling](#error-handling)
7. [Naming Conventions](#naming-conventions)

## Architecture

Progressive disclosure:

```
+-------------------------------------------+
| Fluent API (HeroCryptBuilder, builders)   | <-- simplest
+-------------------------------------------+
| Core primitives (Argon2Core, Blake2bCore, |
| ChaCha20Poly1305Core, HkdfCore, etc.)     | <-- full control
+-------------------------------------------+
```

Start with builders. Drop to core only when you need maximum control over buffers or algorithm parameters.

```csharp
// PGP-style hybrid envelope (RSA + AES-GCM)
var keyPair = HeroCryptBuilder.Pgp()
    .WithKeySize(2048)
    .GenerateRsaKeyPair();

var envelope = HeroCryptBuilder.Pgp()
    .WithEncryptionAlgorithm(EncryptionAlgorithm.AesGcm)
    .Encrypt("hello", keyPair.PublicKey);

var plaintext = HeroCryptBuilder.Pgp()
    .DecryptToString(envelope, keyPair.PrivateKey);
```

## Fluent API Pattern

Builders are concrete classes; they validate inputs and keep allocations predictable.

```csharp
var ciphertext = HeroCryptBuilder.Encrypt()
    .WithAlgorithm(EncryptionAlgorithm.AesGcm)
    .WithKey(key)
    .WithAssociatedData(aad)
    .Build(plaintext);

var plaintext = HeroCryptBuilder.Decrypt()
    .WithAlgorithm(EncryptionAlgorithm.AesGcm)
    .WithKey(key)
    .WithNonce(ciphertext.Nonce)
    .WithAssociatedData(aad)
    .Build(ciphertext.Ciphertext);

var derived = HeroCryptBuilder.DeriveKey()
    .UsePBKDF2()
    .WithPassword(passwordBytes)
    .WithSalt(salt)
    .WithIterations(100_000)
    .WithHashAlgorithm(KeyManagement.HashAlgorithmName.SHA512)
    .WithKeyLength(32)
    .Build();
```

## Core Implementation Pattern

Core types are static and assume validated inputs. Use them when you need spans or bespoke parameter tuning.

```csharp
Span<byte> output = stackalloc byte[32];
Argon2Core.Hash(password, salt, iterations, memorySizeKB, parallelism, output.Length, Argon2Type.Argon2id);
```

Guidelines:
- Keep allocations explicit; prefer spans/buffers passed by the caller.
- Provide `Try*` helpers where a non-throwing path is useful.

## Async/Await

- Use async where it improves responsiveness (I/O, batching, telemetry). Most primitives are CPU-bound and stay sync.
- Library code should call `ConfigureAwait(false)` when awaiting.

```csharp
public async Task<byte[]> EncryptAsync(byte[] plaintext, byte[] key)
{
    await telemetry.RecordOperationAsync("encrypt").ConfigureAwait(false);
    return await Task.Run(() => HeroCryptBuilder.Encrypt().WithKey(key).Build(plaintext))
        .ConfigureAwait(false);
}
```

## Memory Management

- Prefer spans and caller-provided buffers in core layers to minimize allocations.
- Overwrite sensitive buffers when appropriate (see `SecureMemoryOperations`).
- Dispose of secure buffers deterministically.

## Error Handling

- Validate inputs in builders; keep core methods lean.
- Use clear exception messages; include expected/actual details.
- Provide `Try*` variants when callers need non-throwing flows.

## Naming Conventions

- Namespaces: `HeroCrypt` root; `HeroCrypt.Encryption`, `.Hashing`, `.KeyManagement`, `.Signatures`, `.Security`.
- Core implementations: `{Algorithm}Core` (e.g., `Argon2Core`, `HkdfCore`).
- Builders: `{Purpose}Builder` exposed via `HeroCryptBuilder`.
- Methods: verbs (`Encrypt`, `Decrypt`, `Hash`, `Verify`), async suffix where applicable, `Try*` for non-throwing patterns.

## Text Encoding Conventions

HeroCrypt uses consistent naming patterns for text encoding conversions (Hex, Base64, Base64Url):

### Output Encoding (Converting bytes to text)

| Context | Pattern | Example | Description |
|---------|---------|---------|-------------|
| Properties on result structs | `{Property}As{Format}` | `CiphertextAsHex` | Read-only format conversion of existing data |
| Action methods | `{Action}To{Format}` | `ComputeHashToHex()` | Returns result of action in specified format |
| Getter methods | `Get{Property}As{Format}` | `GetKeyAsHex()` | Retrieves and converts builder state |

### Input Decoding (Converting text to bytes)

| Context | Pattern | Example | Description |
|---------|---------|---------|-------------|
| Builder configuration | `With{Property}From{Format}` | `WithKeyFromHex()` | Decodes input and configures builder |
| Action methods | `{Action}From{Format}` | `DecryptFromBase64()` | Decodes input then performs action |
| Combined | `{Action}From{Format}To{Result}` | `DecryptFromHexToString()` | Decodes input, performs action, converts output |

### Format Names

- **Hex** - Lowercase hexadecimal (e.g., `"48656c6c6f"`)
- **Base64** - Standard Base64 with padding (e.g., `"SGVsbG8="`)
- **Base64Url** - URL-safe Base64 without padding (e.g., `"SGVsbG8"`)

### Examples

```csharp
// Result struct properties (AsXxx)
var result = encryptBuilder.Encrypt(data);
string hexCiphertext = result.CiphertextAsHex;
string b64Nonce = result.NonceAsBase64Url;

// Action methods returning encoded output (ToXxx)
string hexHash = hashBuilder.ComputeHashToHex(data);
string b64Signature = signBuilder.SignToBase64(data);

// Getter methods for builder state (GetXxxAsXxx)
string hexKey = encryptBuilder.GetKeyAsHex();
string b64Salt = kdfBuilder.GetSaltAsBase64();

// Input decoding (FromXxx)
var builder = decryptBuilder
    .WithKeyFromHex(hexKey)
    .WithNonceFromBase64Url(b64Nonce);

// Combined decode + action + encode
string plaintext = decryptBuilder.DecryptFromBase64UrlToString(b64Ciphertext);

// Keyed hashing (HMAC) with key from text
using var hmacBuilder = HeroCryptBuilder.Hash()
    .WithSha256()
    .WithKeyFromHex(secretKeyHex);
string macHex = hmacBuilder.ComputeHashToHex(message);
```

This consistent naming makes it easy to:
- Store cryptographic values in databases (Hex or Base64)
- Transmit values in JSON APIs (Base64Url for URL safety)
- Round-trip between text and binary without manual conversion

## Additional Resources

- [Getting Started](getting-started.md#working-with-text-formats-hex-base64-base64url) - Encoding examples
- [Troubleshooting](troubleshooting.md#text-encoding-issues) - Common encoding errors
- [Performance Guide](performance-guide.md#text-encoding-performance) - Encoding performance tips
- [Best Practices](best-practices.md) - Security best practices
