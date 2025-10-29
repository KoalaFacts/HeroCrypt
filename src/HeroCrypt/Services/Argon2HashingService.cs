using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Argon2;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
#if !NET8_0_OR_GREATER
using System;
#endif

namespace HeroCrypt.Services;

/// <summary>
/// Service for Argon2 password hashing operations.
/// Implements RFC 9106 compliant Argon2 password hashing with secure salt generation
/// and constant-time verification.
/// </summary>
/// <remarks>
/// This service is production-ready and suitable for password storage in production systems.
/// It supports all three Argon2 variants: Argon2d, Argon2i, and Argon2id (recommended).
///
/// <para>
/// <strong>Security Recommendations:</strong>
/// <list type="bullet">
/// <item>Use Argon2id for password hashing (hybrid mode, resistant to both side-channel and GPU attacks)</item>
/// <item>Minimum recommended parameters: 3 iterations, 64 MB memory, parallelism 4</item>
/// <item>Use unique random salts for each password (automatically handled)</item>
/// <item>Store the salt with the hash (automatically handled in output format)</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Create service with high security settings
/// var options = new Argon2Options
/// {
///     Type = Argon2Type.Argon2id,
///     Iterations = 3,
///     MemorySize = 65536,  // 64 MB
///     Parallelism = 4,
///     HashSize = 32
/// };
/// var service = new Argon2HashingService(options);
///
/// // Hash a password
/// string hash = await service.HashAsync("userPassword");
///
/// // Verify a password
/// bool isValid = await service.VerifyAsync("userPassword", hash);
/// </code>
/// </example>
public sealed class Argon2HashingService : IHashingService
{
    private readonly Argon2Options _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2HashingService"/> class with default options.
    /// </summary>
    /// <remarks>
    /// Default options provide a good balance of security and performance for most use cases.
    /// Uses Argon2id with 3 iterations, 64 MB memory, and parallelism of 4.
    /// </remarks>
    public Argon2HashingService() : this(new Argon2Options())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2HashingService"/> class with custom options.
    /// </summary>
    /// <param name="options">The Argon2 configuration options.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when options contain invalid values.</exception>
    public Argon2HashingService(Argon2Options options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        // Basic validation
        if (_options.Iterations < 1) throw new ArgumentException("Iterations must be positive", nameof(options));
        if (_options.MemorySize < 1) throw new ArgumentException("MemorySize must be positive", nameof(options));
        if (_options.Parallelism < 1) throw new ArgumentException("Parallelism must be positive", nameof(options));
        if (_options.HashSize < 1) throw new ArgumentException("HashSize must be positive", nameof(options));
    }

    /// <summary>
    /// Hashes a password string using Argon2.
    /// </summary>
    /// <param name="input">The password to hash.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>A Base64-encoded string containing the salt and hash.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="input"/> is null or whitespace.</exception>
    /// <remarks>
    /// The returned string contains both the salt and hash in a format that can be directly
    /// passed to <see cref="VerifyAsync(string, string, CancellationToken)"/> for verification.
    /// A new random salt is generated for each call.
    /// </remarks>
    public async Task<string> HashAsync(string input, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
#else
        if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(input));
#endif
        return await HashAsync(Encoding.UTF8.GetBytes(input), cancellationToken);
    }

    public async Task<string> HashAsync(byte[] input, CancellationToken cancellationToken = default)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(input);
#else
        if (input == null) throw new ArgumentNullException(nameof(input));
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
        if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(input));
#endif
        return await VerifyAsync(Encoding.UTF8.GetBytes(input), hash, cancellationToken);
    }

    public async Task<bool> VerifyAsync(byte[] input, string hash, CancellationToken cancellationToken = default)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(input);
#else
        if (input == null) throw new ArgumentNullException(nameof(input));
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

                // Use constant-time comparison
                return ConstantTimeEquals(storedHash, computedHash);
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
#if NETSTANDARD2_0
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
#else
        RandomNumberGenerator.Fill(salt);
#endif
        return salt;
    }

    /// <summary>
    /// Constant-time comparison to prevent timing attacks
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
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

public sealed class Argon2Options
{
    public int SaltSize { get; set; } = 16;
    public int HashSize { get; set; } = 32;
    public int Parallelism { get; set; } = 4;
    public int MemorySize { get; set; } = 65536;
    public int Iterations { get; set; } = 3;
    public Argon2Type Type { get; set; } = Argon2Type.Argon2id;
}