using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Argon2;
#if !NET8_0_OR_GREATER
using System;
#endif

namespace HeroCrypt.Services;

public sealed class Argon2HashingService : IHashingService
{
    private readonly Argon2Options _options;

    public Argon2HashingService() : this(new Argon2Options())
    {
    }

    public Argon2HashingService(Argon2Options options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<string> HashAsync(string input, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(input, nameof(input));
#endif
        return await HashAsync(Encoding.UTF8.GetBytes(input), cancellationToken);
    }

    public async Task<string> HashAsync(byte[] input, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(input);
#else
        ArgumentNullExceptionExtensions.ThrowIfNull(input, nameof(input));
#endif

        return await Task.Run(() =>
        {
            var salt = GenerateSalt();
            
            var hash = Argon2Core.Hash(
                input,
                salt,
                _options.Iterations,
                _options.MemorySize,
                _options.Parallelism,
                _options.HashSize,
                _options.Type);
            
            var result = new byte[_options.SaltSize + hash.Length];
            Array.Copy(salt, 0, result, 0, _options.SaltSize);
            Array.Copy(hash, 0, result, _options.SaltSize, hash.Length);
            
            return Convert.ToBase64String(result);
        }, cancellationToken);
    }

    public async Task<bool> VerifyAsync(string input, string hash, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(input, nameof(input));
#endif
        return await VerifyAsync(Encoding.UTF8.GetBytes(input), hash, cancellationToken);
    }

    public async Task<bool> VerifyAsync(byte[] input, string hash, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(input);
#else
        ArgumentNullExceptionExtensions.ThrowIfNull(input, nameof(input));
#endif
        
        // Return false for null or empty hash instead of throwing
        if (string.IsNullOrWhiteSpace(hash))
            return false;

        return await Task.Run(() =>
        {
            try
            {
                var hashBytes = Convert.FromBase64String(hash);
                
                if (hashBytes.Length <= _options.SaltSize)
                    return false;

                var salt = new byte[_options.SaltSize];
                Array.Copy(hashBytes, 0, salt, 0, _options.SaltSize);
                
                var storedHash = new byte[hashBytes.Length - _options.SaltSize];
                Array.Copy(hashBytes, _options.SaltSize, storedHash, 0, storedHash.Length);
                
                var computedHash = Argon2Core.Hash(
                    input,
                    salt,
                    _options.Iterations,
                    _options.MemorySize,
                    _options.Parallelism,
                    storedHash.Length,
                    _options.Type);
                
                return CryptographicOperations.FixedTimeEquals(storedHash, computedHash);
            }
            catch
            {
                return false;
            }
        }, cancellationToken);
    }

    private byte[] GenerateSalt()
    {
        var salt = new byte[_options.SaltSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }
}

public sealed class Argon2Options
{
    public int SaltSize { get; set; } = 16;
    public int HashSize { get; set; } = 32;
    public int Parallelism { get; set; } = 4;
    public int MemorySize { get; set; } = 65536;
    public int Iterations { get; set; } = 3;
    public Argon2Type Type { get; set; } = Argon2Type.Argon2id;
}