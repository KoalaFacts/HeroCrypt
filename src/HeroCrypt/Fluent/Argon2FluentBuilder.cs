using System.Text;
using Microsoft.Extensions.Options;
using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;

namespace HeroCrypt.Fluent;

/// <summary>
/// Fluent builder implementation for Argon2 hashing operations
/// </summary>
public class Argon2FluentBuilder : IArgon2FluentBuilder
{
    private readonly HeroCryptOptions _options;
    private readonly IHardwareAccelerator _hardwareAccelerator;
    
    private byte[]? _password;
    private byte[]? _salt;
    private Argon2Options _argon2Options;
    private byte[]? _associatedData;
    private byte[]? _secret;
    private bool _useHardwareAcceleration;

    public Argon2FluentBuilder(IOptions<HeroCryptOptions> options, IHardwareAccelerator hardwareAccelerator)
    {
        _options = options.Value;
        _hardwareAccelerator = hardwareAccelerator;
        _argon2Options = new Argon2Options
        {
            Type = _options.DefaultArgon2Options.Type,
            Iterations = _options.DefaultArgon2Options.Iterations,
            MemorySize = _options.DefaultArgon2Options.MemorySize,
            Parallelism = _options.DefaultArgon2Options.Parallelism,
            HashSize = _options.DefaultArgon2Options.HashSize,
            SaltSize = _options.DefaultArgon2Options.SaltSize
        };
        _useHardwareAcceleration = _options.EnableHardwareAcceleration;
    }

    public IArgon2FluentBuilder WithPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        _password = Encoding.UTF8.GetBytes(password);
        return this;
    }

    public IArgon2FluentBuilder WithPassword(byte[] password)
    {
        _password = password ?? throw new ArgumentNullException(nameof(password));
        return this;
    }

    public IArgon2FluentBuilder WithSalt(string salt)
    {
        if (string.IsNullOrEmpty(salt))
            throw new ArgumentException("Salt cannot be null or empty", nameof(salt));

        _salt = Encoding.UTF8.GetBytes(salt);
        return this;
    }

    public IArgon2FluentBuilder WithSalt(byte[] salt)
    {
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        return this;
    }

    public IArgon2FluentBuilder WithMemory(int memoryKb)
    {
        if (memoryKb <= 0)
            throw new ArgumentException("Memory size must be positive", nameof(memoryKb));

        if (memoryKb > _options.MaxMemoryUsageKb)
            throw new ArgumentException($"Memory size exceeds maximum allowed ({_options.MaxMemoryUsageKb} KB)", nameof(memoryKb));

        _argon2Options.MemorySize = memoryKb;
        return this;
    }

    public IArgon2FluentBuilder WithMemory(MemorySize memorySize)
    {
        return WithMemory(memorySize.ValueInKb);
    }

    public IArgon2FluentBuilder WithIterations(int iterations)
    {
        if (iterations <= 0)
            throw new ArgumentException("Iterations must be positive", nameof(iterations));

        _argon2Options.Iterations = iterations;
        return this;
    }

    public IArgon2FluentBuilder WithParallelism(int parallelism)
    {
        if (parallelism <= 0)
            throw new ArgumentException("Parallelism must be positive", nameof(parallelism));

        _argon2Options.Parallelism = parallelism;
        return this;
    }

    public IArgon2FluentBuilder WithHashSize(int hashSize)
    {
        if (hashSize <= 0)
            throw new ArgumentException("Hash size must be positive", nameof(hashSize));

        _argon2Options.HashSize = hashSize;
        return this;
    }

    public IArgon2FluentBuilder WithType(Argon2Type type)
    {
        _argon2Options.Type = type;
        return this;
    }

    public IArgon2FluentBuilder WithAssociatedData(byte[] associatedData)
    {
        _associatedData = associatedData ?? throw new ArgumentNullException(nameof(associatedData));
        return this;
    }

    public IArgon2FluentBuilder WithSecret(byte[] secret)
    {
        _secret = secret ?? throw new ArgumentNullException(nameof(secret));
        return this;
    }

    public IArgon2FluentBuilder WithSecurityLevel(SecurityLevel securityLevel)
    {
        var policyOptions = SecurityPolicies.GetArgon2Policy(securityLevel);
        
        _argon2Options.Type = policyOptions.Type;
        _argon2Options.Iterations = policyOptions.Iterations;
        _argon2Options.MemorySize = policyOptions.MemorySize;
        _argon2Options.Parallelism = policyOptions.Parallelism;
        _argon2Options.HashSize = policyOptions.HashSize;
        _argon2Options.SaltSize = policyOptions.SaltSize;
        
        return this;
    }

    public IArgon2FluentBuilder WithHardwareAcceleration()
    {
        _useHardwareAcceleration = true;
        return this;
    }

    public async Task<string> HashAsync(CancellationToken cancellationToken = default)
    {
        ValidateConfiguration();

        var service = CreateService();
        var hashBytes = await HashBytesAsync(cancellationToken);
        
        // Prepend salt to hash for storage (similar to how Argon2HashingService works)
        var salt = _salt ?? GenerateSalt();
        var result = new byte[salt.Length + hashBytes.Length];
        Array.Copy(salt, 0, result, 0, salt.Length);
        Array.Copy(hashBytes, 0, result, salt.Length, hashBytes.Length);
        
        return Convert.ToBase64String(result);
    }

    public async Task<byte[]> HashBytesAsync(CancellationToken cancellationToken = default)
    {
        ValidateConfiguration();

        // Try hardware acceleration first if enabled
        if (_useHardwareAcceleration && _hardwareAccelerator.IsAvailable)
        {
            var acceleratedResult = await _hardwareAccelerator.AcceleratedHashAsync(
                _password!, "ARGON2", cancellationToken);
            
            if (acceleratedResult != null)
                return acceleratedResult;
        }

        // Fall back to software implementation
        var salt = _salt ?? GenerateSalt();
        
        return await Task.Run(() => Argon2Core.Hash(
            password: _password!,
            salt: salt,
            iterations: _argon2Options.Iterations,
            memorySize: _argon2Options.MemorySize,
            parallelism: _argon2Options.Parallelism,
            hashLength: _argon2Options.HashSize,
            type: _argon2Options.Type,
            associatedData: _associatedData,
            secret: _secret
        ), cancellationToken);
    }

    public async Task<bool> VerifyAsync(string hash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hash))
            return false;

        ValidateConfiguration();

        try
        {
            var hashBytes = Convert.FromBase64String(hash);
            
            if (hashBytes.Length <= _argon2Options.SaltSize)
                return false;

            // Extract salt from the beginning of the hash
            var salt = new byte[_argon2Options.SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, _argon2Options.SaltSize);

            // Extract the actual hash
            var expectedHash = new byte[hashBytes.Length - _argon2Options.SaltSize];
            Array.Copy(hashBytes, _argon2Options.SaltSize, expectedHash, 0, expectedHash.Length);

            // Compute hash with extracted salt
            var computedHash = await Task.Run(() => Argon2Core.Hash(
                password: _password!,
                salt: salt,
                iterations: _argon2Options.Iterations,
                memorySize: _argon2Options.MemorySize,
                parallelism: _argon2Options.Parallelism,
                hashLength: _argon2Options.HashSize,
                type: _argon2Options.Type,
                associatedData: _associatedData,
                secret: _secret
            ), cancellationToken);

            // Constant-time comparison
            return ConstantTimeEquals(expectedHash, computedHash);
        }
        catch
        {
            return false;
        }
    }

    private void ValidateConfiguration()
    {
        if (_password == null)
            throw new InvalidOperationException("Password must be set before hashing");

        // Validate RFC 9106 compliance
        if (_argon2Options.MemorySize < 8 * _argon2Options.Parallelism)
        {
            throw new ArgumentException(
                $"Memory size must be at least {8 * _argon2Options.Parallelism} KB for {_argon2Options.Parallelism} parallelism",
                nameof(_argon2Options.MemorySize));
        }
    }

    private Argon2HashingService CreateService()
    {
        return new Argon2HashingService(_argon2Options);
    }

    private byte[] GenerateSalt()
    {
        var salt = new byte[_argon2Options.SaltSize];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;

        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}