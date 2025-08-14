using System.Text;
using Microsoft.Extensions.Options;
using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;
using HeroCrypt.Memory;

namespace HeroCrypt.Fluent;

/// <summary>
/// Fluent builder implementation for Argon2 hashing operations
/// </summary>
public class Argon2FluentBuilder : IArgon2FluentBuilder, IDisposable
{
    private readonly HeroCryptOptions _options;
    private readonly IHardwareAccelerator _hardwareAccelerator;
    private readonly ICryptoTelemetry _telemetry;
    private readonly ISecureMemoryManager _memoryManager;
    
    private SecureBuffer? _password;
    private SecureBuffer? _salt;
    private Argon2Options _argon2Options;
    private SecureBuffer? _associatedData;
    private SecureBuffer? _secret;
    private bool _useHardwareAcceleration;
    private bool _disposed;

    public Argon2FluentBuilder(IOptions<HeroCryptOptions> options, IHardwareAccelerator hardwareAccelerator, ICryptoTelemetry telemetry, ISecureMemoryManager memoryManager)
    {
        _options = options.Value;
        _hardwareAccelerator = hardwareAccelerator;
        _telemetry = telemetry;
        _memoryManager = memoryManager;
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

        _password?.Dispose();
        _password = _memoryManager.AllocateFrom(Encoding.UTF8.GetBytes(password));
        return this;
    }

    public IArgon2FluentBuilder WithPassword(byte[] password)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));

        _password?.Dispose();
        _password = _memoryManager.AllocateFrom(password);
        return this;
    }

    public IArgon2FluentBuilder WithSalt(string salt)
    {
        if (string.IsNullOrEmpty(salt))
            throw new ArgumentException("Salt cannot be null or empty", nameof(salt));

        _salt?.Dispose();
        _salt = _memoryManager.AllocateFrom(Encoding.UTF8.GetBytes(salt));
        return this;
    }

    public IArgon2FluentBuilder WithSalt(byte[] salt)
    {
        if (salt == null)
            throw new ArgumentNullException(nameof(salt));

        _salt?.Dispose();
        _salt = _memoryManager.AllocateFrom(salt);
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
        if (associatedData == null)
            throw new ArgumentNullException(nameof(associatedData));

        _associatedData?.Dispose();
        _associatedData = _memoryManager.AllocateFrom(associatedData);
        return this;
    }

    public IArgon2FluentBuilder WithSecret(byte[] secret)
    {
        if (secret == null)
            throw new ArgumentNullException(nameof(secret));

        _secret?.Dispose();
        _secret = _memoryManager.AllocateFrom(secret);
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
        using var salt = _salt ?? GenerateSecureSalt();
        var result = new byte[salt.Size + hashBytes.Length];
        var saltArray = salt.ToArray();
        Array.Copy(saltArray, 0, result, 0, saltArray.Length);
        Array.Copy(hashBytes, 0, result, saltArray.Length, hashBytes.Length);
        
        // Clear temporary salt array
        Array.Clear(saltArray, 0, saltArray.Length);
        
        return Convert.ToBase64String(result);
    }

    public async Task<byte[]> HashBytesAsync(CancellationToken cancellationToken = default)
    {
        ValidateConfiguration();

        using var tracker = _telemetry.TrackOperation(
            "Argon2Hash", 
            _argon2Options.Type.ToString(), 
            _password!.Size,
            _useHardwareAcceleration && _hardwareAccelerator.IsAvailable);

        try
        {
            // Try hardware acceleration first if enabled
            if (_useHardwareAcceleration && _hardwareAccelerator.IsAvailable)
            {
                var acceleratedResult = await _hardwareAccelerator.AcceleratedHashAsync(
                    _password!.ToArray(), "ARGON2", cancellationToken);
                
                if (acceleratedResult != null)
                {
                    tracker.MarkSuccess();
                    return acceleratedResult;
                }
            }

            // Fall back to software implementation
            using var salt = _salt ?? GenerateSecureSalt();
            
            var result = await Task.Run(() => Argon2Core.Hash(
                password: _password!.ToArray(),
                salt: salt.ToArray(),
                iterations: _argon2Options.Iterations,
                memorySize: _argon2Options.MemorySize,
                parallelism: _argon2Options.Parallelism,
                hashLength: _argon2Options.HashSize,
                type: _argon2Options.Type,
                associatedData: _associatedData?.ToArray(),
                secret: _secret?.ToArray()
            ), cancellationToken);

            tracker.MarkSuccess();
            return result;
        }
        catch (Exception ex)
        {
            tracker.MarkFailure(ex.Message);
            throw;
        }
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
                password: _password!.ToArray(),
                salt: salt,
                iterations: _argon2Options.Iterations,
                memorySize: _argon2Options.MemorySize,
                parallelism: _argon2Options.Parallelism,
                hashLength: _argon2Options.HashSize,
                type: _argon2Options.Type,
                associatedData: _associatedData?.ToArray(),
                secret: _secret?.ToArray()
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

    private SecureBuffer GenerateSecureSalt()
    {
        using var pooledBuffer = _memoryManager.GetPooled(_argon2Options.SaltSize);
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        
#if NET6_0_OR_GREATER
        rng.GetBytes(pooledBuffer.AsSpan());
#else
        var tempBytes = new byte[_argon2Options.SaltSize];
        rng.GetBytes(tempBytes);
        tempBytes.AsSpan().CopyTo(pooledBuffer.AsSpan());
        Array.Clear(tempBytes, 0, tempBytes.Length);
#endif
        
        return _memoryManager.AllocateFrom(pooledBuffer.AsReadOnlySpan());
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

    public void Dispose()
    {
        if (!_disposed)
        {
            _password?.Dispose();
            _salt?.Dispose();
            _associatedData?.Dispose();
            _secret?.Dispose();
            
            _password = null;
            _salt = null;
            _associatedData = null;
            _secret = null;
            
            _disposed = true;
        }
    }
}