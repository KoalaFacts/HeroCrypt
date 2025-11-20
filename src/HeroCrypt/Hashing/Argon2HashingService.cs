using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Security;

namespace HeroCrypt.Hashing;

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
public sealed class Argon2HashingService : IPasswordHashingService
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
#if !NETSTANDARD2_0
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
#else
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(input));
        }
#endif
        var bytes = Encoding.UTF8.GetBytes(input);
        try
        {
            return await HashAsync(bytes, cancellationToken);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(bytes);
        }
    }

    /// <summary>
    /// Hashes a byte array using Argon2.
    /// </summary>
    /// <param name="input">The data to hash.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>A Base64-encoded string containing the salt and hash.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="input"/> is null.</exception>
    /// <remarks>
    /// The returned string contains both the salt and hash in a format that can be directly
    /// passed to <see cref="VerifyAsync(byte[], string, CancellationToken)"/> for verification.
    /// A new random salt is generated for each call.
    /// </remarks>
    public async Task<string> HashAsync(byte[] input, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(input);
#else
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }
#endif

        return await Task.Run(() =>
        {
            using var salt = new SecureByteArray(_options.SaltSize);

#if NETSTANDARD2_0
            using (var rng = RandomNumberGenerator.Create())
            {
                salt.WithBytes(s => rng.GetBytes(s));
            }
#else
            salt.WithBytes(s => RandomNumberGenerator.Fill(s));
#endif

            byte[]? hash = null;
            // Compute hash
            salt.WithBytes(s =>
            {
                hash = Argon2Core.Hash(
                    input,
                    s,
                    _options.Iterations,
                    _options.MemorySize,
                    _options.Parallelism,
                    _options.HashSize,
                    _options.Type);
            });

            try
            {
                if (hash == null)
                {
                    throw new InvalidOperationException("Failed to compute Argon2 hash.");
                }

                var result = new byte[_options.SaltSize + hash.Length];
                try
                {
                    salt.WithBytes(s => Array.Copy(s, 0, result, 0, _options.SaltSize));
                    Array.Copy(hash, 0, result, _options.SaltSize, hash.Length);

                    return Convert.ToBase64String(result);
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(result);
                }
            }
            finally
            {
                if (hash != null)
                {
                    SecureMemoryOperations.SecureClear(hash);
                }
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Verifies a password against an Argon2 hash.
    /// </summary>
    /// <param name="input">The password to verify.</param>
    /// <param name="hash">The hash to verify against (from <see cref="HashAsync(string, CancellationToken)"/>).</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>True if the password matches the hash, false otherwise.</returns>
    /// <remarks>
    /// Uses constant-time comparison to prevent timing attacks. Returns false for
    /// invalid or malformed hashes instead of throwing exceptions.
    /// </remarks>
    public async Task<bool> VerifyAsync(string input, string hash, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentException.ThrowIfNullOrWhiteSpace(input);
#else
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(input));
        }
#endif
        var bytes = Encoding.UTF8.GetBytes(input);
        try
        {
            return await VerifyAsync(bytes, hash, cancellationToken);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(bytes);
        }
    }

    /// <summary>
    /// Verifies a byte array against an Argon2 hash.
    /// </summary>
    /// <param name="input">The data to verify.</param>
    /// <param name="hash">The hash to verify against (from <see cref="HashAsync(byte[], CancellationToken)"/>).</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>True if the data matches the hash, false otherwise.</returns>
    /// <remarks>
    /// Uses constant-time comparison to prevent timing attacks. Returns false for
    /// invalid, malformed, or null hashes instead of throwing exceptions.
    /// </remarks>
    public async Task<bool> VerifyAsync(byte[] input, string hash, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(input);
#else
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }
#endif

        // Return false for null or empty hash instead of throwing
        if (string.IsNullOrWhiteSpace(hash))
        {
            return false;
        }

        return await Task.Run(() =>
        {
            try
            {
                var hashBytes = Convert.FromBase64String(hash);

                if (hashBytes.Length <= _options.SaltSize)
                {
                    return false;
                }

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
                return SecureMemoryOperations.ConstantTimeEquals(storedHash, computedHash);
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException || ex is CryptographicException)
            {
                return false;
            }
        }, cancellationToken);
    }
}

/// <summary>
/// Configuration options for Argon2 password hashing.
/// </summary>
/// <remarks>
/// These options control the computational cost and security level of Argon2 hashing.
/// Higher values provide better security but require more resources.
///
/// <para>
/// <strong>Recommended Settings:</strong>
/// <list type="bullet">
/// <item><strong>High Security (Production):</strong> 3 iterations, 64 MB memory, parallelism 4</item>
/// <item><strong>Medium Security:</strong> 2 iterations, 19 MB memory, parallelism 1</item>
/// <item><strong>Low Security (Testing):</strong> 1 iteration, 8 MB memory, parallelism 1</item>
/// </list>
/// </para>
/// </remarks>
public sealed class Argon2Options
{
    /// <summary>
    /// Gets or sets the size of the salt in bytes.
    /// Default is 16 bytes (128 bits).
    /// </summary>
    /// <value>
    /// The salt size in bytes. Must be at least 8 bytes per RFC 9106.
    /// </value>
    public int SaltSize { get; set; } = 16;

    /// <summary>
    /// Gets or sets the size of the output hash in bytes.
    /// Default is 32 bytes (256 bits).
    /// </summary>
    /// <value>
    /// The hash size in bytes. Must be at least 4 bytes.
    /// </value>
    public int HashSize { get; set; } = 32;

    /// <summary>
    /// Gets or sets the number of parallel threads to use during hashing.
    /// Default is 4.
    /// </summary>
    /// <value>
    /// The number of parallel threads. Higher values use more CPU cores
    /// but require more memory. Must be at least 1.
    /// </value>
    public int Parallelism { get; set; } = 4;

    /// <summary>
    /// Gets or sets the amount of memory to use for hashing, in kilobytes.
    /// Default is 65536 KB (64 MB).
    /// </summary>
    /// <value>
    /// The memory size in kilobytes. Higher values provide better resistance
    /// to GPU and ASIC attacks. Must be at least 8 KB per RFC 9106.
    /// </value>
    public int MemorySize { get; set; } = 65536;

    /// <summary>
    /// Gets or sets the number of iterations (passes over memory).
    /// Default is 3.
    /// </summary>
    /// <value>
    /// The number of iterations. Higher values increase computational cost
    /// and resistance to attacks. Must be at least 1 per RFC 9106.
    /// </value>
    public int Iterations { get; set; } = 3;

    /// <summary>
    /// Gets or sets the Argon2 variant to use.
    /// Default is Argon2id (recommended for password hashing).
    /// </summary>
    /// <value>
    /// The Argon2 variant:
    /// <list type="bullet">
    /// <item><strong>Argon2id:</strong> Hybrid mode, recommended for most use cases (default)</item>
    /// <item><strong>Argon2i:</strong> Optimized against side-channel attacks</item>
    /// <item><strong>Argon2d:</strong> Optimized against GPU attacks (less side-channel resistant)</item>
    /// </list>
    /// </value>
    public Argon2Type Type { get; set; } = Argon2Type.Argon2id;
}
