# Migration Guide

This guide highlights key changes in the refactored HeroCrypt API.

## Fluent Builders Replace Services

The service layer has been removed. Use the fluent builders or core primitives directly:

```csharp
// Argon2 password hashing
var salt = RandomNumberGenerator.GetBytes(16);
var hash = HeroCryptBuilder.DeriveKey()
    .UseArgon2()
    .WithPassword("password"u8.ToArray())
    .WithSalt(salt)
    .WithIterations(3)
    .WithParallelism(4)
    .WithKeyLength(32)
    .Build();
```

## Dependency Injection

There are no service types to register. If you need DI, wrap the builders or core primitives in your own types and register those.

## Deprecated/Removed

- All `*Service` classes (AeadService, Argon2HashingService, KeyDerivationService, RSA/PGP services, etc.) are removed.
- Interface abstractions are removed; builders and core types are the public surface.

## Recommendations

- Prefer builders for high-level operations.
- Drop to core primitives (e.g., `Argon2Core`, `HkdfCore`, `Encryption.Encrypt/Decrypt`) when you need span-based or highly tuned control.
