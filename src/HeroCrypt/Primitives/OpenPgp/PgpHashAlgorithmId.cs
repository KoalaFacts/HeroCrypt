namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP hash algorithm identifiers as defined in RFC 4880 Section 9.4 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// These identifiers are used in signature packets to specify which hash algorithm
/// was used to compute the signature hash.
/// </para>
/// </remarks>
public enum PgpHashAlgorithmId : byte
{
    /// <summary>
    /// MD5 (128-bit output) - DEPRECATED, DO NOT USE.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 128 bits (16 bytes)</para>
    /// <para>
    /// <b>BROKEN - DO NOT USE FOR SECURITY.</b>
    /// Collision attacks are trivial.
    /// </para>
    /// </remarks>
    [Obsolete("MD5 is cryptographically broken and should not be used for signatures.")]
    Md5 = 1,

    /// <summary>
    /// SHA-1 (160-bit output) - DEPRECATED.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 160 bits (20 bytes)</para>
    /// <para>
    /// <b>DEPRECATED - NOT RECOMMENDED FOR SECURITY.</b>
    /// Collision attacks are practical (SHAttered attack, 2017).
    /// Only supported for verification of legacy signatures.
    /// </para>
    /// </remarks>
    [Obsolete("SHA-1 is deprecated due to collision attacks. Use SHA-256 or better.")]
    Sha1 = 2,

    /// <summary>
    /// RIPE-MD/160 (160-bit output).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 160 bits (20 bytes)</para>
    /// </remarks>
    RipeMd160 = 3,

    // IDs 4-7 are reserved

    /// <summary>
    /// SHA-256 (256-bit output) - RECOMMENDED.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para>
    /// Default choice for most applications. Provides 128-bit security level.
    /// </para>
    /// </remarks>
    Sha256 = 8,

    /// <summary>
    /// SHA-384 (384-bit output).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 384 bits (48 bytes)</para>
    /// <para>
    /// Provides 192-bit security level.
    /// </para>
    /// </remarks>
    Sha384 = 9,

    /// <summary>
    /// SHA-512 (512-bit output).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 512 bits (64 bytes)</para>
    /// <para>
    /// Maximum security SHA-2 variant. Provides 256-bit security level.
    /// Often faster than SHA-256 on 64-bit systems.
    /// </para>
    /// </remarks>
    Sha512 = 10,

    /// <summary>
    /// SHA-224 (224-bit output).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880</para>
    /// <para><b>Output size:</b> 224 bits (28 bytes)</para>
    /// </remarks>
    Sha224 = 11,

    /// <summary>
    /// SHA3-256 (256-bit output).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para><b>Output size:</b> 256 bits (32 bytes)</para>
    /// <para><b>Platform Support:</b> .NET 8+ only.</para>
    /// </remarks>
    Sha3_256 = 12,

    // ID 13 is reserved

    /// <summary>
    /// SHA3-512 (512-bit output).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para><b>Output size:</b> 512 bits (64 bytes)</para>
    /// <para><b>Platform Support:</b> .NET 8+ only.</para>
    /// </remarks>
    Sha3_512 = 14,
}

/// <summary>
/// Extension methods for <see cref="PgpHashAlgorithmId"/>.
/// </summary>
public static class ExtensionsToPgpHashAlgorithmId
{
    /// <summary>
    /// Gets the hash output size in bytes.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The hash output size in bytes.</returns>
    public static int GetHashSize(this PgpHashAlgorithmId algorithm)
    {
        return algorithm switch
        {
#pragma warning disable CS0618 // Obsolete
            PgpHashAlgorithmId.Md5 => 16,
            PgpHashAlgorithmId.Sha1 => 20,
#pragma warning restore CS0618
            PgpHashAlgorithmId.RipeMd160 => 20,
            PgpHashAlgorithmId.Sha224 => 28,
            PgpHashAlgorithmId.Sha256 => 32,
            PgpHashAlgorithmId.Sha384 => 48,
            PgpHashAlgorithmId.Sha512 => 64,
            PgpHashAlgorithmId.Sha3_256 => 32,
            PgpHashAlgorithmId.Sha3_512 => 64,
            _ => throw new ArgumentException($"Unknown hash algorithm: {algorithm}", nameof(algorithm))
        };
    }

    /// <summary>
    /// Gets the .NET HashAlgorithmName for the specified PGP hash algorithm.
    /// </summary>
    /// <param name="algorithm">The PGP hash algorithm.</param>
    /// <returns>The corresponding .NET HashAlgorithmName.</returns>
    public static System.Security.Cryptography.HashAlgorithmName GetHashAlgorithmName(this PgpHashAlgorithmId algorithm)
    {
        return algorithm switch
        {
#pragma warning disable CS0618 // Obsolete
            PgpHashAlgorithmId.Md5 => System.Security.Cryptography.HashAlgorithmName.MD5,
            PgpHashAlgorithmId.Sha1 => System.Security.Cryptography.HashAlgorithmName.SHA1,
#pragma warning restore CS0618
            PgpHashAlgorithmId.Sha256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
            PgpHashAlgorithmId.Sha384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
            PgpHashAlgorithmId.Sha512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
#if NET8_0_OR_GREATER
            PgpHashAlgorithmId.Sha3_256 => System.Security.Cryptography.HashAlgorithmName.SHA3_256,
            PgpHashAlgorithmId.Sha3_512 => System.Security.Cryptography.HashAlgorithmName.SHA3_512,
#endif
            _ => throw new NotSupportedException($"Hash algorithm {algorithm} is not supported on this platform.")
        };
    }

    /// <summary>
    /// Computes the hash of the specified data using the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <param name="data">The data to hash.</param>
    /// <returns>The computed hash.</returns>
    public static byte[] ComputeHash(this PgpHashAlgorithmId algorithm, ReadOnlySpan<byte> data)
    {
        using var hash = algorithm.CreateIncrementalHash();
#if NETSTANDARD2_0
        hash.AppendData(data.ToArray());
#else
        hash.AppendData(data);
#endif
        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Creates an incremental hash for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>An IncrementalHash instance.</returns>
    public static System.Security.Cryptography.IncrementalHash CreateIncrementalHash(this PgpHashAlgorithmId algorithm)
    {
        var name = algorithm.GetHashAlgorithmName();
        return System.Security.Cryptography.IncrementalHash.CreateHash(name);
    }
}
