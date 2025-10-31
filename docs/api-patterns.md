# API Patterns and Design Conventions

This document describes the API patterns and design conventions used throughout HeroCrypt.

## Table of Contents

1. [API Design Principles](#api-design-principles)
2. [Service Layer Pattern](#service-layer-pattern)
3. [Fluent API Pattern](#fluent-api-pattern)
4. [Core Implementation Pattern](#core-implementation-pattern)
5. [Dependency Injection](#dependency-injection)
6. [Async/Await Patterns](#asyncawait-patterns)
7. [Memory Management Patterns](#memory-management-patterns)
8. [Error Handling Patterns](#error-handling-patterns)
9. [Naming Conventions](#naming-conventions)

## API Design Principles

### 1. Layered Architecture

HeroCrypt follows a three-layer architecture:

```
┌─────────────────────────────────────┐
│     Fluent API Layer                │  ← High-level, developer-friendly
│  (Argon2FluentBuilder, PgpBuilder)  │
├─────────────────────────────────────┤
│     Service Layer                   │  ← Business logic, validation
│  (Argon2HashingService, AeadService)│
├─────────────────────────────────────┤
│     Core Implementation Layer       │  ← Low-level cryptographic primitives
│  (Argon2Core, Blake2bCore)          │
└─────────────────────────────────────┘
```

### 2. Progressive Disclosure

APIs are designed for progressive complexity:

```csharp
// Level 1: Simple, opinionated API (Fluent)
await heroCrypt.Argon2
    .WithPassword("password")
    .WithSecurityLevel(SecurityLevel.High)
    .HashAsync();

// Level 2: Service with reasonable defaults
var service = new Argon2HashingService(Argon2Options.Default);
await service.HashAsync("password");

// Level 3: Core with full control
var hash = Argon2Core.Hash(
    password, salt, iterations, memory, parallelism, hashLength, type
);
```

### 3. Secure by Default

```csharp
// ✅ Default options are secure
var options = new Argon2Options();  // Already uses Argon2id, 64MB, 3 iterations

// ✅ Automatic memory cleanup
using var buffer = new SecureBuffer(32);  // Zeroed on disposal

// ✅ Validation by default
var service = new AeadService();
service.Encrypt(data, key, nonce);  // Validates key/nonce sizes automatically
```

## Service Layer Pattern

### Service Interface

```csharp
public interface IHashingService
{
    Task<string> HashAsync(string password);
    Task<bool> VerifyAsync(string password, string hash);
}
```

### Service Implementation

```csharp
public class Argon2HashingService : IHashingService
{
    private readonly Argon2Options _options;
    private readonly ILogger<Argon2HashingService>? _logger;

    public Argon2HashingService(Argon2Options options, ILogger<Argon2HashingService>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    public async Task<string> HashAsync(string password)
    {
        // Validate input
        ArgumentException.ThrowIfNullOrEmpty(password);

        // Log operation (without sensitive data)
        _logger?.LogInformation("Hashing password with Argon2");

        // Delegate to core implementation
        var result = await Task.Run(() => Argon2Core.Hash(
            System.Text.Encoding.UTF8.GetBytes(password),
            GenerateSalt(),
            _options.Iterations,
            _options.MemorySize,
            _options.Parallelism,
            _options.HashSize,
            _options.Type
        ));

        return Convert.ToBase64String(result);
    }
}
```

### Service Registration

```csharp
public static IServiceCollection AddArgon2(
    this IServiceCollection services,
    Action<Argon2Options>? configure = null)
{
    services.AddOptions<Argon2Options>()
        .Configure(options => configure?.Invoke(options));

    services.AddScoped<IHashingService, Argon2HashingService>();

    return services;
}
```

## Fluent API Pattern

### Builder Interface

```csharp
public interface IArgon2FluentBuilder
{
    IArgon2FluentBuilder WithPassword(string password);
    IArgon2FluentBuilder WithSecurityLevel(SecurityLevel level);
    IArgon2FluentBuilder WithMemory(int memorySizeKB);
    IArgon2FluentBuilder WithIterations(int iterations);
    IArgon2FluentBuilder WithParallelism(int parallelism);
    IArgon2FluentBuilder WithHardwareAcceleration();
    Task<string> HashAsync();
    Task<bool> VerifyAsync(string hash);
}
```

### Builder Implementation

```csharp
public class Argon2FluentBuilder : IArgon2FluentBuilder
{
    private string? _password;
    private SecurityLevel? _securityLevel;
    private int? _memorySizeKB;
    private int? _iterations;
    private int? _parallelism;
    private bool _useHardwareAcceleration;

    public IArgon2FluentBuilder WithPassword(string password)
    {
        _password = password ?? throw new ArgumentNullException(nameof(password));
        return this;
    }

    public IArgon2FluentBuilder WithSecurityLevel(SecurityLevel level)
    {
        _securityLevel = level;
        return this;
    }

    public IArgon2FluentBuilder WithMemory(int memorySizeKB)
    {
        if (memorySizeKB < 8)
            throw new ArgumentOutOfRangeException(nameof(memorySizeKB));

        _memorySizeKB = memorySizeKB;
        return this;
    }

    public async Task<string> HashAsync()
    {
        if (_password == null)
            throw new InvalidOperationException("Password not set");

        // Apply security level defaults
        ApplySecurityLevel();

        // Delegate to service or core
        var service = CreateService();
        return await service.HashAsync(_password);
    }

    private void ApplySecurityLevel()
    {
        if (_securityLevel == null) return;

        (_iterations, _memorySizeKB, _parallelism) = _securityLevel.Value switch
        {
            SecurityLevel.Low => (1, 8192, 1),
            SecurityLevel.Medium => (2, 19456, 1),
            SecurityLevel.High => (3, 65536, 4),
            SecurityLevel.VeryHigh => (4, 262144, 8),
            SecurityLevel.Military => (10, 1048576, 16),
            _ => throw new ArgumentException("Invalid security level")
        };
    }
}
```

### Fluent API Usage

```csharp
// Chain methods for configuration
var hash = await heroCrypt.Argon2
    .WithPassword("password")
    .WithSecurityLevel(SecurityLevel.High)
    .WithHardwareAcceleration()
    .HashAsync();
```

## Core Implementation Pattern

### Core Class Structure

```csharp
public static class Argon2Core
{
    // Primary API methods
    public static byte[] Hash(
        byte[] password,
        byte[] salt,
        int iterations,
        int memorySizeKB,
        int parallelism,
        int hashLength,
        Argon2Type type)
    {
        // Validate inputs
        ValidateInputs(password, salt, iterations, memorySizeKB, parallelism, hashLength);

        // Allocate memory
        using var memory = new SecureBuffer(memorySizeKB * 1024);

        // Perform computation
        var result = ComputeHash(password, salt, iterations, memorySizeKB, parallelism, hashLength, type);

        return result;
    }

    // Verify method with constant-time comparison
    public static bool Verify(byte[] hash, byte[] password)
    {
        // Parse hash to extract parameters
        var (salt, iterations, memory, parallelism, type) = ParseHash(hash);

        // Recompute hash
        var computedHash = Hash(password, salt, iterations, memory, parallelism, hash.Length, type);

        // Constant-time comparison
        return ConstantTimeOperations.Equals(hash, computedHash);
    }

    // Private helper methods
    private static void ValidateInputs(...)
    {
        if (password == null || password.Length == 0)
            throw new ArgumentException("Password cannot be empty");

        if (salt == null || salt.Length < 8)
            throw new ArgumentException("Salt must be at least 8 bytes");

        // ... more validation
    }
}
```

### Span-Based APIs

```csharp
// ✅ Prefer Span<T> for performance and safety
public static void Hash(
    ReadOnlySpan<byte> password,
    ReadOnlySpan<byte> salt,
    Span<byte> destination,
    int iterations,
    int memorySizeKB,
    int parallelism,
    Argon2Type type)
{
    // Stack-allocated buffers
    Span<byte> buffer = stackalloc byte[64];

    // Process data without heap allocations
}
```

## Dependency Injection

### Service Registration

```csharp
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddHeroCrypt(
        this IServiceCollection services,
        SecurityLevel securityLevel = SecurityLevel.High)
    {
        // Register core services
        services.AddSingleton<IHeroCrypt, HeroCryptService>();
        services.AddSingleton<ISecureMemoryManager, DefaultSecureMemoryManager>();
        services.AddSingleton<IHardwareAccelerator, DefaultHardwareAccelerator>();

        // Register abstraction services
        services.AddScoped<IHashingService, Argon2HashingService>();
        services.AddScoped<IAeadService, AeadService>();
        services.AddScoped<IKeyDerivationService, KeyDerivationService>();

        // Configure options
        services.Configure<HeroCryptOptions>(options =>
        {
            options.DefaultSecurityLevel = securityLevel;
            options.EnableHardwareAcceleration = true;
        });

        return services;
    }

    // Overload for custom configuration
    public static IServiceCollection AddHeroCrypt(
        this IServiceCollection services,
        Action<HeroCryptOptions> configure)
    {
        services.AddHeroCrypt();
        services.Configure(configure);
        return services;
    }
}
```

### Service Usage

```csharp
public class UserService
{
    private readonly IHashingService _hashingService;
    private readonly IAeadService _aeadService;
    private readonly ILogger<UserService> _logger;

    public UserService(
        IHashingService hashingService,
        IAeadService aeadService,
        ILogger<UserService> logger)
    {
        _hashingService = hashingService;
        _aeadService = aeadService;
        _logger = logger;
    }

    public async Task<string> HashPasswordAsync(string password)
    {
        return await _hashingService.HashAsync(password);
    }
}
```

## Async/Await Patterns

### Async by Default

```csharp
// ✅ GOOD: Async for I/O-bound operations
public async Task<byte[]> EncryptAsync(byte[] plaintext, byte[] key)
{
    await _telemetry.RecordOperationAsync("encrypt");
    return await Task.Run(() => EncryptCore(plaintext, key));
}

// ✅ GOOD: Sync for CPU-bound, quick operations
public byte[] ComputeHash(byte[] data)
{
    return Blake2bCore.ComputeHash(data, 32);
}
```

### ConfigureAwait

```csharp
// ✅ Library code: Use ConfigureAwait(false)
public async Task<string> HashAsync(string password)
{
    var result = await Task.Run(() => ComputeHash(password))
        .ConfigureAwait(false);

    return Convert.ToBase64String(result);
}
```

### Cancellation Support

```csharp
public async Task<byte[]> EncryptBatchAsync(
    IEnumerable<byte[]> plaintexts,
    byte[] key,
    CancellationToken cancellationToken = default)
{
    var results = new List<byte[]>();

    foreach (var plaintext in plaintexts)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var encrypted = await EncryptAsync(plaintext, key)
            .ConfigureAwait(false);

        results.Add(encrypted);
    }

    return results.ToArray();
}
```

## Memory Management Patterns

### IDisposable Pattern

```csharp
public class SecureBuffer : IDisposable
{
    private byte[] _buffer;
    private bool _disposed;

    public SecureBuffer(int size)
    {
        _buffer = GC.AllocateUninitializedArray<byte>(size, pinned: true);
        MemoryMarshal.TryGetMemoryHandle(_buffer, out var handle);
        // Lock memory to prevent swapping
    }

    public Span<byte> GetSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _buffer.AsSpan();
    }

    public void Dispose()
    {
        if (_disposed) return;

        // Secure erase
        SecureMemoryOperations.SecureClear(_buffer);

        // Unlock memory
        // ...

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~SecureBuffer()
    {
        Dispose();
    }
}
```

### Memory Pooling

```csharp
public class CryptoMemoryPool
{
    private readonly ArrayPool<byte> _pool = ArrayPool<byte>.Shared;

    public byte[] Rent(int minimumLength)
    {
        return _pool.Rent(minimumLength);
    }

    public void Return(byte[] buffer, bool clearArray = true)
    {
        if (clearArray)
        {
            SecureMemoryOperations.SecureClear(buffer);
        }
        _pool.Return(buffer);
    }
}
```

## Error Handling Patterns

### Custom Exceptions

```csharp
public class CryptographicOperationException : Exception
{
    public CryptographicOperationException(string message)
        : base(message) { }

    public CryptographicOperationException(string message, Exception innerException)
        : base(message, innerException) { }
}

public class InvalidKeyException : CryptographicOperationException
{
    public InvalidKeyException(string message)
        : base(message) { }
}
```

### Validation

```csharp
public static class InputValidator
{
    public static void ValidateKeySize(int keySize, int expectedSize)
    {
        if (keySize != expectedSize)
        {
            throw new ArgumentException(
                $"Invalid key size: expected {expectedSize}, got {keySize}",
                nameof(keySize));
        }
    }

    public static void ValidateNonceSize(int nonceSize, int expectedSize)
    {
        if (nonceSize != expectedSize)
        {
            throw new ArgumentException(
                $"Invalid nonce size: expected {expectedSize}, got {nonceSize}",
                nameof(nonceSize));
        }
    }
}
```

### Try Pattern

```csharp
// ✅ Provide Try* methods for non-throwing versions
public static bool TryEncrypt(
    ReadOnlySpan<byte> plaintext,
    ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> nonce,
    Span<byte> ciphertext,
    out int bytesWritten)
{
    bytesWritten = 0;

    if (key.Length != 32 || nonce.Length != 12)
        return false;

    try
    {
        Encrypt(plaintext, key, nonce, ciphertext);
        bytesWritten = plaintext.Length + 16;  // + tag
        return true;
    }
    catch
    {
        return false;
    }
}
```

## Naming Conventions

### Namespaces

```
HeroCrypt                          - Root
HeroCrypt.Abstractions             - Interfaces
HeroCrypt.Cryptography             - Core cryptographic implementations
HeroCrypt.Cryptography.Symmetric   - Symmetric encryption
HeroCrypt.Cryptography.Asymmetric  - Asymmetric encryption
HeroCrypt.Services                 - High-level services
HeroCrypt.Configuration            - Configuration and options
HeroCrypt.Memory                   - Memory management
HeroCrypt.Security                 - Security utilities
```

### Class Naming

```csharp
// Core implementations: {Algorithm}Core
public static class Argon2Core
public static class Blake2bCore
public static class ChaCha20Poly1305Core

// Services: {Algorithm}Service or {Purpose}Service
public class Argon2HashingService
public class AeadService
public class KeyDerivationService

// Fluent builders: {Algorithm}FluentBuilder
public class Argon2FluentBuilder
public class PgpFluentBuilder

// Interfaces: I{Purpose}
public interface IHashingService
public interface IAeadService
```

### Method Naming

```csharp
// Cryptographic operations
public static byte[] Hash(...)
public static byte[] Encrypt(...)
public static byte[] Decrypt(...)
public static bool Verify(...)

// Async methods
public async Task<string> HashAsync(...)
public async Task<byte[]> EncryptAsync(...)

// Try pattern
public static bool TryEncrypt(...)
public static bool TryDecrypt(...)

// Configuration methods (Fluent API)
public IBuilder WithPassword(...)
public IBuilder WithSecurityLevel(...)
```

### Parameter Naming

```csharp
// Consistent parameter names
byte[] plaintext     // Data to encrypt
byte[] ciphertext    // Encrypted data
byte[] key           // Cryptographic key
byte[] nonce         // Number used once
byte[] salt          // Random salt for password hashing
byte[] password      // User password
byte[] hash          // Cryptographic hash output
byte[] signature     // Digital signature
```

## Summary

HeroCrypt follows these key patterns:

1. **Three-layer architecture**: Core → Service → Fluent API
2. **Progressive disclosure**: Simple to advanced usage patterns
3. **Secure by default**: Safe defaults and automatic cleanup
4. **Dependency injection**: Full DI support with interfaces
5. **Async/await**: Async by default with ConfigureAwait(false)
6. **Memory safety**: IDisposable, pooling, secure cleanup
7. **Consistent naming**: Clear, predictable naming conventions
8. **Error handling**: Validation, custom exceptions, Try pattern

For implementation examples, see the `/examples` folder and production code in `/src/HeroCrypt`.
