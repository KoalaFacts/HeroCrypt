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
