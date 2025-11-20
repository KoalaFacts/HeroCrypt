using System.Security.Cryptography;
using HeroCrypt.Cryptography.Primitives.Hash;

namespace HeroCrypt.Hashing;

/// <summary>
/// Unified hashing operations for various algorithms
/// </summary>
internal static class Hash
{
    /// <summary>
    /// Computes the hash of the input data using the specified algorithm
    /// </summary>
    /// <param name="data">The data to hash</param>
    /// <param name="algorithm">The hash algorithm to use</param>
    /// <returns>The computed hash</returns>
    /// <exception cref="ArgumentNullException">Thrown when data is null</exception>
    public static byte[] Compute(byte[] data, HashAlgorithm algorithm)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
#endif

        return algorithm switch
        {
            HashAlgorithm.Sha256 => ComputeSha256(data),
            HashAlgorithm.Sha384 => ComputeSha384(data),
            HashAlgorithm.Sha512 => ComputeSha512(data),
            HashAlgorithm.Blake2b256 => ComputeBlake2b(data, 32),
            HashAlgorithm.Blake2b512 => ComputeBlake2b(data, 64),
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Computes a keyed hash (MAC) using the specified algorithm
    /// </summary>
    /// <param name="data">The data to hash</param>
    /// <param name="key">The secret key</param>
    /// <param name="algorithm">The hash algorithm to use</param>
    /// <returns>The computed keyed hash</returns>
    /// <exception cref="ArgumentNullException">Thrown when data or key is null</exception>
    public static byte[] ComputeKeyed(byte[] data, byte[] key, HashAlgorithm algorithm)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }
#endif

        return algorithm switch
        {
            HashAlgorithm.Sha256 => ComputeHmacSha256(data, key),
            HashAlgorithm.Sha384 => ComputeHmacSha384(data, key),
            HashAlgorithm.Sha512 => ComputeHmacSha512(data, key),
            HashAlgorithm.Blake2b256 => Blake2bCore.ComputeHash(data, 32, key),
            HashAlgorithm.Blake2b512 => Blake2bCore.ComputeHash(data, 64, key),
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    #region SHA Family

    private static byte[] ComputeSha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static byte[] ComputeSha384(byte[] data)
    {
        using var sha = SHA384.Create();
        return sha.ComputeHash(data);
    }

    private static byte[] ComputeSha512(byte[] data)
    {
        using var sha = SHA512.Create();
        return sha.ComputeHash(data);
    }

    private static byte[] ComputeHmacSha256(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    private static byte[] ComputeHmacSha384(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA384(key);
        return hmac.ComputeHash(data);
    }

    private static byte[] ComputeHmacSha512(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA512(key);
        return hmac.ComputeHash(data);
    }

    #endregion

    #region Blake2b

    private static byte[] ComputeBlake2b(byte[] data, int hashLength)
    {
        return Blake2bCore.ComputeHash(data, hashLength);
    }

    #endregion
}
