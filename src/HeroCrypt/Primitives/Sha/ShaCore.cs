using System.Security.Cryptography;

namespace HeroCrypt.Primitives.Sha;

/// <summary>
/// SHA cryptographic hash function family implementation.
/// Wraps the platform SHA implementations with consistent API.
/// </summary>
internal static class ShaCore
{
    /// <summary>
    /// Output size in bytes for MD5.
    /// </summary>
    public const int Md5HashSize = 16;

    /// <summary>
    /// Output size in bytes for SHA-1.
    /// </summary>
    public const int Sha1HashSize = 20;

    /// <summary>
    /// Output size in bytes for SHA-256.
    /// </summary>
    public const int Sha256HashSize = 32;

    /// <summary>
    /// Output size in bytes for SHA-384.
    /// </summary>
    public const int Sha384HashSize = 48;

    /// <summary>
    /// Output size in bytes for SHA-512.
    /// </summary>
    public const int Sha512HashSize = 64;

    // ─────────────────────────────────────────────────────────────────────────
    // Legacy Hash Functions (MD5, SHA-1) - NOT RECOMMENDED FOR SECURITY
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the MD5 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 16-byte MD5 hash.</returns>
    /// <remarks>
    /// <b>WARNING:</b> MD5 is cryptographically broken. Do not use for security purposes.
    /// Only use for checksums, cache keys, or legacy compatibility.
    /// </remarks>
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms - MD5 intentionally provided for legacy compatibility
    public static byte[] ComputeHashMd5(byte[] data)
    {
#if NETSTANDARD2_0
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
#else
        return MD5.HashData(data);
#endif
    }
#pragma warning restore CA5351

    /// <summary>
    /// Computes the SHA-1 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 20-byte SHA-1 hash.</returns>
    /// <remarks>
    /// <b>WARNING:</b> SHA-1 is cryptographically broken for collision resistance.
    /// Only use for Git compatibility or legacy systems.
    /// </remarks>
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - SHA-1 intentionally provided for legacy compatibility
    public static byte[] ComputeHashSha1(byte[] data)
    {
#if NETSTANDARD2_0
        using var sha = SHA1.Create();
        return sha.ComputeHash(data);
#else
        return SHA1.HashData(data);
#endif
    }
#pragma warning restore CA5350

    // ─────────────────────────────────────────────────────────────────────────
    // SHA-2 Family (SHA-256, SHA-384, SHA-512)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the SHA-256 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 32-byte SHA-256 hash.</returns>
    public static byte[] ComputeHashSha256(byte[] data)
    {
#if NETSTANDARD2_0
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
#else
        return SHA256.HashData(data);
#endif
    }

    /// <summary>
    /// Computes the SHA-384 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 48-byte SHA-384 hash.</returns>
    public static byte[] ComputeHashSha384(byte[] data)
    {
#if NETSTANDARD2_0
        using var sha = SHA384.Create();
        return sha.ComputeHash(data);
#else
        return SHA384.HashData(data);
#endif
    }

    /// <summary>
    /// Computes the SHA-512 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 64-byte SHA-512 hash.</returns>
    public static byte[] ComputeHashSha512(byte[] data)
    {
#if NETSTANDARD2_0
        using var sha = SHA512.Create();
        return sha.ComputeHash(data);
#else
        return SHA512.HashData(data);
#endif
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SHA-3 Family (SHA3-256, SHA3-384, SHA3-512) - .NET 8+ only
    // ─────────────────────────────────────────────────────────────────────────

#if NET8_0_OR_GREATER
    /// <summary>
    /// Computes the SHA3-256 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 32-byte SHA3-256 hash.</returns>
    public static byte[] ComputeHashSha3_256(byte[] data)
    {
        return SHA3_256.HashData(data);
    }

    /// <summary>
    /// Computes the SHA3-384 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 48-byte SHA3-384 hash.</returns>
    public static byte[] ComputeHashSha3_384(byte[] data)
    {
        return SHA3_384.HashData(data);
    }

    /// <summary>
    /// Computes the SHA3-512 hash of the input data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The 64-byte SHA3-512 hash.</returns>
    public static byte[] ComputeHashSha3_512(byte[] data)
    {
        return SHA3_512.HashData(data);
    }
#endif

    // ─────────────────────────────────────────────────────────────────────────
    // SHAKE XOF (Extendable Output Functions) - .NET 9+ only
    // ─────────────────────────────────────────────────────────────────────────

#if NET9_0_OR_GREATER
    /// <summary>
    /// Computes a SHAKE128 hash with the specified output length.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="outputLength">The desired output length in bytes.</param>
    /// <returns>The SHAKE128 hash with the specified length.</returns>
    public static byte[] ComputeHashShake128(byte[] data, int outputLength)
    {
        if (outputLength <= 0)
        {
            throw new ArgumentException("Output length must be positive", nameof(outputLength));
        }

        byte[] output = new byte[outputLength];
        Shake128.HashData(data, output);
        return output;
    }

    /// <summary>
    /// Computes a SHAKE256 hash with the specified output length.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="outputLength">The desired output length in bytes.</param>
    /// <returns>The SHAKE256 hash with the specified length.</returns>
    public static byte[] ComputeHashShake256(byte[] data, int outputLength)
    {
        if (outputLength <= 0)
        {
            throw new ArgumentException("Output length must be positive", nameof(outputLength));
        }

        byte[] output = new byte[outputLength];
        Shake256.HashData(data, output);
        return output;
    }
#endif

    // ─────────────────────────────────────────────────────────────────────────
    // HMAC Variants
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the HMAC-MD5 of the input data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>The 16-byte HMAC-MD5 tag.</returns>
    /// <remarks>
    /// <b>WARNING:</b> HMAC-MD5 is not recommended for new applications.
    /// While HMAC construction mitigates MD5's collision weakness,
    /// prefer HMAC-SHA256 or newer for new systems.
    /// </remarks>
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms - HMAC-MD5 intentionally provided for legacy compatibility
    public static byte[] ComputeHashHmacMd5(byte[] data, byte[] key)
    {
        using var hmac = new HMACMD5(key);
        return hmac.ComputeHash(data);
    }
#pragma warning restore CA5351

    /// <summary>
    /// Computes the HMAC-SHA-1 of the input data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>The 20-byte HMAC-SHA-1 tag.</returns>
    /// <remarks>
    /// <b>WARNING:</b> HMAC-SHA-1 is not recommended for new applications.
    /// Prefer HMAC-SHA256 or newer.
    /// </remarks>
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - HMAC-SHA1 intentionally provided for legacy compatibility
    public static byte[] ComputeHashHmacSha1(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA1(key);
        return hmac.ComputeHash(data);
    }
#pragma warning restore CA5350

    /// <summary>
    /// Computes the HMAC-SHA-256 of the input data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>The 32-byte HMAC-SHA-256 tag.</returns>
    public static byte[] ComputeHashHmacSha256(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    /// <summary>
    /// Computes the HMAC-SHA-384 of the input data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>The 48-byte HMAC-SHA-384 tag.</returns>
    public static byte[] ComputeHashHmacSha384(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA384(key);
        return hmac.ComputeHash(data);
    }

    /// <summary>
    /// Computes the HMAC-SHA-512 of the input data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>The 64-byte HMAC-SHA-512 tag.</returns>
    public static byte[] ComputeHashHmacSha512(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA512(key);
        return hmac.ComputeHash(data);
    }
}
