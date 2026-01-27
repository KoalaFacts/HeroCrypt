using HeroCrypt.Primitives.Blake2b;
using HeroCrypt.Primitives.Sha;
using HeroCrypt.Security;

namespace HeroCrypt.Operations;

/// <summary>
/// Fluent builder for hashing operations.
/// </summary>
/// <remarks>
/// <para>
/// This builder implements <see cref="IDisposable"/> to securely clear sensitive key material
/// from memory when the builder is no longer needed. It is recommended to use this builder
/// within a <c>using</c> statement when performing keyed hashing (HMAC).
/// </para>
/// </remarks>
public sealed class HashBuilder : IDisposable
{
    private HashingAlgorithm algorithm = HashingAlgorithm.Sha256;
    private byte[]? key;
    private int? outputLength;
    private bool allowLegacyAlgorithms;
    private bool disposed;

    private void ThrowIfDisposed()
    {
#if NETSTANDARD2_0
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(HashBuilder));
        }
#else
        ObjectDisposedException.ThrowIf(disposed, this);
#endif
    }

    private void ClearKey()
    {
        if (key == null) return;
        SecureMemoryOperations.SecureClear(key);
        key = null;
    }

    /// <summary>
    /// Releases all resources used by this builder and securely clears sensitive key material.
    /// </summary>
    public void Dispose()
    {
        if (disposed) return;
        ClearKey();
        disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Allows the use of legacy/deprecated algorithms (MD5, SHA-1) for this builder instance.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By default, legacy algorithms are blocked to prevent accidental use of insecure cryptography.
    /// Call this method to explicitly opt-in to legacy algorithm support for compatibility scenarios.
    /// </para>
    /// <para>
    /// <b>Warning:</b> Only use legacy algorithms when absolutely necessary for interoperability
    /// with existing systems. For new applications, use SHA-256, SHA-3, or Blake2b.
    /// </para>
    /// </remarks>
    /// <returns>This builder instance for method chaining.</returns>
    public HashBuilder AllowLegacyAlgorithms()
    {
        ThrowIfDisposed();
        allowLegacyAlgorithms = true;
        return this;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SHA-2 Family
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sets the hash algorithm to use.
    /// </summary>
    public HashBuilder WithAlgorithm(HashingAlgorithm algorithm)
    {
        ThrowIfDisposed();
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Use SHA-256 for hashing (default).
    /// </summary>
    public HashBuilder WithSha256() => WithAlgorithm(HashingAlgorithm.Sha256);

    /// <summary>
    /// Use SHA-384 for hashing.
    /// </summary>
    public HashBuilder WithSha384() => WithAlgorithm(HashingAlgorithm.Sha384);

    /// <summary>
    /// Use SHA-512 for hashing.
    /// </summary>
    public HashBuilder WithSha512() => WithAlgorithm(HashingAlgorithm.Sha512);

    // ─────────────────────────────────────────────────────────────────────────
    // SHA-3 Family (.NET 8+)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Use SHA3-256 for hashing.
    /// </summary>
    /// <remarks>Requires .NET 8 or later.</remarks>
    public HashBuilder WithSha3_256() => WithAlgorithm(HashingAlgorithm.Sha3_256);

    /// <summary>
    /// Use SHA3-384 for hashing.
    /// </summary>
    /// <remarks>Requires .NET 8 or later.</remarks>
    public HashBuilder WithSha3_384() => WithAlgorithm(HashingAlgorithm.Sha3_384);

    /// <summary>
    /// Use SHA3-512 for hashing.
    /// </summary>
    /// <remarks>Requires .NET 8 or later.</remarks>
    public HashBuilder WithSha3_512() => WithAlgorithm(HashingAlgorithm.Sha3_512);

    // ─────────────────────────────────────────────────────────────────────────
    // SHAKE XOF (.NET 9+)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Use SHAKE128 extendable output function.
    /// </summary>
    /// <param name="outputLength">Desired output length in bytes.</param>
    /// <remarks>Requires .NET 9 or later.</remarks>
    public HashBuilder WithShake128(int outputLength)
    {
        ThrowIfDisposed();
        algorithm = HashingAlgorithm.Shake128;
        this.outputLength = outputLength;
        return this;
    }

    /// <summary>
    /// Use SHAKE256 extendable output function.
    /// </summary>
    /// <param name="outputLength">Desired output length in bytes.</param>
    /// <remarks>Requires .NET 9 or later.</remarks>
    public HashBuilder WithShake256(int outputLength)
    {
        ThrowIfDisposed();
        algorithm = HashingAlgorithm.Shake256;
        this.outputLength = outputLength;
        return this;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Blake Family
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Use Blake2b with 256-bit output.
    /// </summary>
    public HashBuilder WithBlake2b256() => WithAlgorithm(HashingAlgorithm.Blake2b256);

    /// <summary>
    /// Use Blake2b with 512-bit output.
    /// </summary>
    public HashBuilder WithBlake2b512() => WithAlgorithm(HashingAlgorithm.Blake2b512);

    // ─────────────────────────────────────────────────────────────────────────
    // Legacy Algorithms (NOT RECOMMENDED)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Use SHA-1 for hashing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>WARNING:</b> SHA-1 is cryptographically broken.
    /// Only use for legacy compatibility (Git, old certificates).
    /// </para>
    /// <para>
    /// Requires calling <see cref="AllowLegacyAlgorithms"/> first, otherwise throws
    /// <see cref="StrictModeException"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="StrictModeException">
    /// Thrown if <see cref="AllowLegacyAlgorithms"/> was not called.
    /// </exception>
    [Obsolete("SHA-1 is cryptographically broken. Use WithSha256() or WithSha3_256() for new applications.")]
    public HashBuilder WithSha1()
    {
        ThrowIfLegacyNotAllowed("SHA-1", "Use SHA-256 or SHA-3 instead.");
        return WithAlgorithm(HashingAlgorithm.Sha1);
    }

    /// <summary>
    /// Use MD5 for hashing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>WARNING:</b> MD5 is cryptographically broken.
    /// Only use for checksums, cache keys, or legacy compatibility.
    /// </para>
    /// <para>
    /// Requires calling <see cref="AllowLegacyAlgorithms"/> first, otherwise throws
    /// <see cref="StrictModeException"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="StrictModeException">
    /// Thrown if <see cref="AllowLegacyAlgorithms"/> was not called.
    /// </exception>
    [Obsolete("MD5 is cryptographically broken. Use WithSha256() or WithBlake2b256() for new applications.")]
    public HashBuilder WithMd5()
    {
        ThrowIfLegacyNotAllowed("MD5", "Use SHA-256 or Blake2b instead.");
        return WithAlgorithm(HashingAlgorithm.Md5);
    }

    private void ThrowIfLegacyNotAllowed(string algorithm, string recommendation)
    {
        if (!allowLegacyAlgorithms)
        {
            throw new StrictModeException(algorithm, recommendation);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Keyed Hashing
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sets the key for keyed hashing (HMAC for SHA family, native keyed mode for Blake2).
    /// </summary>
    public HashBuilder WithKey(byte[] key)
    {
        ThrowIfDisposed();
        ClearKey();
        this.key = [.. key];
        return this;
    }

    /// <summary>
    /// Sets the key for keyed hashing from a hexadecimal string.
    /// </summary>
    /// <param name="hexKey">The key as a hexadecimal string (case-insensitive).</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <exception cref="FormatException">Thrown if the string is not a valid hexadecimal string.</exception>
    public HashBuilder WithKeyFromHex(string hexKey)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromHexString(hexKey);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the key for keyed hashing from a Base64-encoded string.
    /// </summary>
    /// <param name="base64Key">The key as a Base64-encoded string.</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <exception cref="FormatException">Thrown if the string is not valid Base64.</exception>
    public HashBuilder WithKeyFromBase64(string base64Key)
    {
        ThrowIfDisposed();
        var keyBytes = Convert.FromBase64String(base64Key);
        return WithKey(keyBytes);
    }

    /// <summary>
    /// Sets the key for keyed hashing from a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="base64UrlKey">The key as a URL-safe Base64-encoded string (with or without padding).</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// URL-safe Base64 uses '-' instead of '+', '_' instead of '/', and may omit padding '=' characters.
    /// This method accepts both padded and unpadded URL-safe Base64 strings.
    /// </remarks>
    /// <exception cref="FormatException">Thrown if the string is not valid URL-safe Base64.</exception>
    public HashBuilder WithKeyFromBase64Url(string base64UrlKey)
    {
        ThrowIfDisposed();
        var keyBytes = FromBase64Url(base64UrlKey);
        return WithKey(keyBytes);
    }

    private static byte[] FromBase64Url(string base64Url)
    {
        // Convert URL-safe Base64 to standard Base64
        var base64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        // Add padding if needed
        switch (base64.Length % 4)
        {
            case 0: break; // No padding needed
            case 1: break; // Invalid Base64 - let Convert.FromBase64String handle the error
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
            default: break; // Unreachable, but required for exhaustive switch
        }

        return Convert.FromBase64String(base64);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Compute Hash
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the hash of the data.
    /// </summary>
    public byte[] ComputeHash(byte[] data)
    {
        ThrowIfDisposed();
        InputValidator.ValidateByteArray(data, nameof(data));

        if (key != null)
        {
            InputValidator.ValidateByteArray(key, nameof(key));
            return ComputeKeyed(data, key, algorithm);
        }

        return Compute(data, algorithm, outputLength);
    }

    /// <summary>
    /// Computes the hash of the string data using UTF-8 encoding.
    /// </summary>
    /// <param name="data">The string data to hash.</param>
    /// <returns>The computed hash.</returns>
    public byte[] ComputeHash(string data)
    {
        return ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
    }

    /// <summary>
    /// Computes the hash of the data and returns it as a lowercase hexadecimal string.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The computed hash as a lowercase hexadecimal string.</returns>
    /// <remarks>
    /// This is a convenience method for scenarios where the hash needs to be stored or compared as text.
    /// For example: <c>"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"</c> (SHA-256 of empty string).
    /// </remarks>
    public string ComputeHashToHex(byte[] data)
    {
        var hash = ComputeHash(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Computes the hash of the string data (UTF-8 encoded) and returns it as a lowercase hexadecimal string.
    /// </summary>
    /// <param name="data">The string data to hash.</param>
    /// <returns>The computed hash as a lowercase hexadecimal string.</returns>
    /// <remarks>
    /// This is a convenience method for scenarios where the hash needs to be stored or compared as text.
    /// For example: <c>"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"</c> (SHA-256 of empty string).
    /// </remarks>
    public string ComputeHashToHex(string data)
    {
        return ComputeHashToHex(System.Text.Encoding.UTF8.GetBytes(data));
    }

    /// <summary>
    /// Computes the hash of the data and returns it as a Base64-encoded string.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The computed hash as a Base64-encoded string.</returns>
    /// <remarks>
    /// This is a convenience method for scenarios where the hash needs to be stored compactly as text,
    /// such as in HTTP headers, JWTs, or configuration files.
    /// </remarks>
    public string ComputeHashToBase64(byte[] data)
    {
        var hash = ComputeHash(data);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Computes the hash of the string data (UTF-8 encoded) and returns it as a Base64-encoded string.
    /// </summary>
    /// <param name="data">The string data to hash.</param>
    /// <returns>The computed hash as a Base64-encoded string.</returns>
    /// <remarks>
    /// This is a convenience method for scenarios where the hash needs to be stored compactly as text,
    /// such as in HTTP headers, JWTs, or configuration files.
    /// </remarks>
    public string ComputeHashToBase64(string data)
    {
        return ComputeHashToBase64(System.Text.Encoding.UTF8.GetBytes(data));
    }

    /// <summary>
    /// Computes the hash of the data and returns it as a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The computed hash as a URL-safe Base64-encoded string (no padding).</returns>
    /// <remarks>
    /// <para>
    /// URL-safe Base64 replaces '+' with '-', '/' with '_', and omits padding '=' characters.
    /// </para>
    /// <para>
    /// Use this method when embedding hashes in URLs, JWT tokens, or other contexts where
    /// standard Base64 characters may cause issues.
    /// </para>
    /// </remarks>
    public string ComputeHashToBase64Url(byte[] data)
    {
        var hash = ComputeHash(data);
        return ToBase64Url(hash);
    }

    /// <summary>
    /// Computes the hash of the string data (UTF-8 encoded) and returns it as a URL-safe Base64-encoded string.
    /// </summary>
    /// <param name="data">The string data to hash.</param>
    /// <returns>The computed hash as a URL-safe Base64-encoded string (no padding).</returns>
    public string ComputeHashToBase64Url(string data)
    {
        return ComputeHashToBase64Url(System.Text.Encoding.UTF8.GetBytes(data));
    }

    private static string ToBase64Url(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static byte[] Compute(byte[] data, HashingAlgorithm algorithm, int? outputLength)
    {
        return algorithm switch
        {
            // SHA-2 Family
            HashingAlgorithm.Sha256 => ShaCore.ComputeHashSha256(data),
            HashingAlgorithm.Sha384 => ShaCore.ComputeHashSha384(data),
            HashingAlgorithm.Sha512 => ShaCore.ComputeHashSha512(data),

            // SHA-3 Family (.NET 8+)
            HashingAlgorithm.Sha3_256 => ComputeSha3_256(data),
            HashingAlgorithm.Sha3_384 => ComputeSha3_384(data),
            HashingAlgorithm.Sha3_512 => ComputeSha3_512(data),

            // SHAKE XOF (.NET 9+)
            HashingAlgorithm.Shake128 => ComputeShake128(data, outputLength ?? 32),
            HashingAlgorithm.Shake256 => ComputeShake256(data, outputLength ?? 64),

            // Blake Family
            HashingAlgorithm.Blake2b256 => Blake2bCore.ComputeHash(data, outputLength: 32),
            HashingAlgorithm.Blake2b512 => Blake2bCore.ComputeHash(data, outputLength: 64),

            // Legacy (suppress obsolete warning for internal switch - user already warned at builder method)
#pragma warning disable CS0618
            HashingAlgorithm.Sha1 => ShaCore.ComputeHashSha1(data),
            HashingAlgorithm.Md5 => ShaCore.ComputeHashMd5(data),
#pragma warning restore CS0618

            // Not Implemented
            HashingAlgorithm.Sha224 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Sha512_256 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Blake2s256 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Blake3 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Ripemd160 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),

            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    private static byte[] ComputeKeyed(byte[] data, byte[] key, HashingAlgorithm algorithm)
    {
        return algorithm switch
        {
            // SHA-2 Family HMAC
            HashingAlgorithm.Sha256 => ShaCore.ComputeHashHmacSha256(data, key),
            HashingAlgorithm.Sha384 => ShaCore.ComputeHashHmacSha384(data, key),
            HashingAlgorithm.Sha512 => ShaCore.ComputeHashHmacSha512(data, key),

            // SHA-3 does not have HMAC variants in .NET - use SHA-2 HMAC or Blake2b keyed
            HashingAlgorithm.Sha3_256 => throw new NotSupportedException($"Keyed hashing with {algorithm} is not supported. Use SHA-256 HMAC or Blake2b keyed mode instead."),
            HashingAlgorithm.Sha3_384 => throw new NotSupportedException($"Keyed hashing with {algorithm} is not supported. Use SHA-384 HMAC or Blake2b keyed mode instead."),
            HashingAlgorithm.Sha3_512 => throw new NotSupportedException($"Keyed hashing with {algorithm} is not supported. Use SHA-512 HMAC or Blake2b keyed mode instead."),

            // SHAKE XOF does not support keyed mode
            HashingAlgorithm.Shake128 => throw new NotSupportedException($"Keyed hashing with {algorithm} is not supported."),
            HashingAlgorithm.Shake256 => throw new NotSupportedException($"Keyed hashing with {algorithm} is not supported."),

            // Blake Family (native keyed mode)
            HashingAlgorithm.Blake2b256 => Blake2bCore.ComputeHash(data, outputLength: 32, key),
            HashingAlgorithm.Blake2b512 => Blake2bCore.ComputeHash(data, outputLength: 64, key),

            // Legacy HMAC (suppress obsolete warning for internal switch - user already warned at builder method)
#pragma warning disable CS0618
            HashingAlgorithm.Sha1 => ShaCore.ComputeHashHmacSha1(data, key),
            HashingAlgorithm.Md5 => ShaCore.ComputeHashHmacMd5(data, key),
#pragma warning restore CS0618

            // Not Implemented
            HashingAlgorithm.Sha224 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Sha512_256 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Blake2s256 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Blake3 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),
            HashingAlgorithm.Ripemd160 => throw new NotImplementedException($"Algorithm {algorithm} is not yet implemented"),

            _ => throw new NotSupportedException($"Keyed hashing with {algorithm} is not supported")
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Platform-Specific Implementations
    // ─────────────────────────────────────────────────────────────────────────

    private static byte[] ComputeSha3_256(byte[] data)
    {
#if NET8_0_OR_GREATER
        return ShaCore.ComputeHashSha3_256(data);
#else
        throw new PlatformNotSupportedException("SHA3-256 requires .NET 8 or later.");
#endif
    }

    private static byte[] ComputeSha3_384(byte[] data)
    {
#if NET8_0_OR_GREATER
        return ShaCore.ComputeHashSha3_384(data);
#else
        throw new PlatformNotSupportedException("SHA3-384 requires .NET 8 or later.");
#endif
    }

    private static byte[] ComputeSha3_512(byte[] data)
    {
#if NET8_0_OR_GREATER
        return ShaCore.ComputeHashSha3_512(data);
#else
        throw new PlatformNotSupportedException("SHA3-512 requires .NET 8 or later.");
#endif
    }

    private static byte[] ComputeShake128(byte[] data, int outputLength)
    {
#if NET9_0_OR_GREATER
        return ShaCore.ComputeHashShake128(data, outputLength);
#else
        throw new PlatformNotSupportedException("SHAKE128 requires .NET 9 or later.");
#endif
    }

    private static byte[] ComputeShake256(byte[] data, int outputLength)
    {
#if NET9_0_OR_GREATER
        return ShaCore.ComputeHashShake256(data, outputLength);
#else
        throw new PlatformNotSupportedException("SHAKE256 requires .NET 9 or later.");
#endif
    }
}
