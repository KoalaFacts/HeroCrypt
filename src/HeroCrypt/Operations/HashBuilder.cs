using HeroCrypt.Primitives.Blake2b;
using HeroCrypt.Primitives.Sha;
using HeroCrypt.Security;

namespace HeroCrypt.Operations;

/// <summary>
/// Fluent builder for hashing operations.
/// </summary>
public class HashBuilder
{
    private HashingAlgorithm algorithm = HashingAlgorithm.Sha256;
    private byte[]? key;
    private int? outputLength;
    private bool allowLegacyAlgorithms;

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
        this.key = key;
        return this;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Compute Hash
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the hash of the data.
    /// </summary>
    public byte[] ComputeHash(byte[] data)
    {
        InputValidator.ValidateByteArray(data, nameof(data));

        if (key != null)
        {
            InputValidator.ValidateByteArray(key, nameof(key));
            return ComputeKeyed(data, key, algorithm);
        }

        return Compute(data, algorithm, outputLength);
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
