using System.Security.Cryptography;

namespace HeroCrypt.Polyfills;

/// <summary>
/// Provides helper methods for working with hash algorithms.
/// </summary>
internal static class HashAlgorithmHelper
{
    /// <summary>
    /// Gets the output length in bytes for the specified hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <returns>The output length in bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when the hash algorithm is not supported.</exception>
    public static int GetHashLength(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            return 20;
        }
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return 32;
        }
        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return 48;
        }
        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return 64;
        }
        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm));
    }

    /// <summary>
    /// Creates an HMAC instance for the specified hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>An HMAC instance configured with the specified algorithm and key.</returns>
    /// <exception cref="ArgumentException">Thrown when the hash algorithm is not supported.</exception>
    /// <remarks>
    /// SHA1 support is intentional for RFC 5869 HKDF compatibility.
    /// Users should prefer SHA256 or higher, but SHA1 is allowed per the standard.
    /// </remarks>
    public static HMAC CreateHmac(HashAlgorithmName hashAlgorithm, byte[] key)
    {
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - SHA1 needed for RFC compatibility
        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            return new HMACSHA1(key);
        }
#pragma warning restore CA5350
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return new HMACSHA256(key);
        }
        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return new HMACSHA384(key);
        }
        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return new HMACSHA512(key);
        }
        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm));
    }

    /// <summary>
    /// Creates an HMAC instance for the specified hash algorithm using a span key.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>An HMAC instance configured with the specified algorithm and key.</returns>
    public static HMAC CreateHmac(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> key)
    {
        return CreateHmac(hashAlgorithm, key.ToArray());
    }
}
