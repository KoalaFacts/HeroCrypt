using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Argon2;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.S2K;

/// <summary>
/// OpenPGP String-to-Key (S2K) implementation as specified in RFC 4880 Section 3.7.
/// </summary>
/// <remarks>
/// S2K specifiers are used to convert a passphrase into a symmetric key.
/// Different types provide varying levels of security against brute-force attacks.
/// </remarks>
internal static class S2KCore
{
    /// <summary>
    /// Default salt size in bytes (RFC 4880 S2K types 0-3).
    /// </summary>
    public const int DEFAULT_SALT_SIZE = 8;

    /// <summary>
    /// Argon2 salt size in bytes (RFC 9580).
    /// </summary>
    public const int ARGON2_SALT_SIZE = 16;

    /// <summary>
    /// Default hash algorithm for S2K operations.
    /// </summary>
    public static readonly HashAlgorithmName DEFAULT_HASH = HashAlgorithmName.SHA256;

    /// <summary>
    /// Simple S2K (Type 0): Direct hash of passphrase.
    /// </summary>
    /// <remarks>
    /// WARNING: Simple S2K is NOT recommended for new applications.
    /// It provides minimal protection against brute-force attacks.
    /// Use Iterated S2K (Type 3) or Argon2 S2K (Type 4) instead.
    /// </remarks>
    /// <param name="password">The passphrase bytes.</param>
    /// <param name="keySize">Desired key size in bytes.</param>
    /// <param name="hashAlgorithm">Hash algorithm to use.</param>
    /// <returns>Derived key material.</returns>
    public static byte[] SimpleS2K(ReadOnlySpan<byte> password, int keySize, HashAlgorithmName hashAlgorithm)
    {
        ValidateKeySize(keySize);
        return DeriveWithPrefix(password, keySize, hashAlgorithm);
    }

    /// <summary>
    /// Salted S2K (Type 1): Hash of salt and passphrase.
    /// </summary>
    /// <remarks>
    /// Salted S2K provides protection against rainbow table attacks but is still
    /// vulnerable to brute-force. Use Iterated S2K (Type 3) or Argon2 for better security.
    /// </remarks>
    /// <param name="password">The passphrase bytes.</param>
    /// <param name="salt">8-byte salt value.</param>
    /// <param name="keySize">Desired key size in bytes.</param>
    /// <param name="hashAlgorithm">Hash algorithm to use.</param>
    /// <returns>Derived key material.</returns>
    public static byte[] SaltedS2K(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int keySize, HashAlgorithmName hashAlgorithm)
    {
        ValidateKeySize(keySize);
        if (salt.Length != DEFAULT_SALT_SIZE)
        {
            throw new ArgumentException($"Salt must be {DEFAULT_SALT_SIZE} bytes.", nameof(salt));
        }

        // Concatenate salt + password
        var combined = new byte[salt.Length + password.Length];
        salt.CopyTo(combined);
        password.CopyTo(combined.AsSpan(salt.Length));

        try
        {
            return DeriveWithPrefix(combined, keySize, hashAlgorithm);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(combined);
        }
    }

    /// <summary>
    /// Iterated and Salted S2K (Type 3): Iteratively hash salt and passphrase.
    /// </summary>
    /// <remarks>
    /// This is the recommended legacy S2K type. The count parameter specifies
    /// the number of bytes to be hashed (minimum is salt.Length + password.Length).
    /// </remarks>
    /// <param name="password">The passphrase bytes.</param>
    /// <param name="salt">8-byte salt value.</param>
    /// <param name="count">Iteration count (bytes to hash).</param>
    /// <param name="keySize">Desired key size in bytes.</param>
    /// <param name="hashAlgorithm">Hash algorithm to use.</param>
    /// <returns>Derived key material.</returns>
    public static byte[] IteratedS2K(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, long count, int keySize, HashAlgorithmName hashAlgorithm)
    {
        ValidateKeySize(keySize);
        if (salt.Length != DEFAULT_SALT_SIZE)
        {
            throw new ArgumentException($"Salt must be {DEFAULT_SALT_SIZE} bytes.", nameof(salt));
        }

        // Combined salt + password
        var combined = new byte[salt.Length + password.Length];
        salt.CopyTo(combined);
        password.CopyTo(combined.AsSpan(salt.Length));

        // Minimum count is the combined length
        var minCount = combined.Length;
        if (count < minCount)
        {
            count = minCount;
        }

        try
        {
            return DeriveIteratedKey(combined, count, keySize, hashAlgorithm);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(combined);
        }
    }

    /// <summary>
    /// Argon2 S2K (Type 4): Memory-hard key derivation using Argon2id.
    /// </summary>
    /// <remarks>
    /// <para>RFC 9580 Section 3.7.1.4 defines Argon2 S2K for OpenPGP.</para>
    /// <para>This is the recommended S2K type for new applications.</para>
    /// </remarks>
    /// <param name="password">The passphrase bytes.</param>
    /// <param name="salt">16-byte salt value (required by RFC 9580).</param>
    /// <param name="timePasses">Number of iterations (t parameter, 1-255).</param>
    /// <param name="parallelism">Parallelism degree (p parameter, 1-255).</param>
    /// <param name="memoryExponent">Memory exponent m where memory = 2^m KiB.</param>
    /// <param name="keySize">Desired key size in bytes.</param>
    /// <returns>Derived key material.</returns>
    public static byte[] Argon2S2K(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        byte timePasses,
        byte parallelism,
        byte memoryExponent,
        int keySize)
    {
        ValidateKeySize(keySize);

        if (salt.Length != ARGON2_SALT_SIZE)
        {
            throw new ArgumentException($"Argon2 salt must be {ARGON2_SALT_SIZE} bytes.", nameof(salt));
        }

        if (timePasses < 1)
        {
            throw new ArgumentException("Time passes must be at least 1.", nameof(timePasses));
        }

        if (parallelism < 1)
        {
            throw new ArgumentException("Parallelism must be at least 1.", nameof(parallelism));
        }

        // RFC 9580: memory = 2^m KiB
        var memorySizeKiB = 1 << memoryExponent;

        // Ensure minimum memory requirement: 8 * parallelism
        if (memorySizeKiB < 8 * parallelism)
        {
            throw new ArgumentException($"Memory exponent {memoryExponent} results in {memorySizeKiB} KiB which is less than minimum {8 * parallelism} KiB for parallelism {parallelism}.", nameof(memoryExponent));
        }

        return Argon2Core.Hash(
            password: password.ToArray(),
            salt: salt.ToArray(),
            iterations: timePasses,
            memorySize: memorySizeKiB,
            parallelism: parallelism,
            hashLength: keySize,
            type: Argon2Type.Argon2id);
    }

    /// <summary>
    /// Converts an S2K iteration count byte to actual count as per RFC 4880.
    /// </summary>
    /// <param name="encodedCount">The encoded count byte (0-255).</param>
    /// <returns>The actual iteration count.</returns>
    public static long DecodeIterationCount(byte encodedCount)
    {
        // c = (16 + (c & 15)) << ((c >> 4) + 6)
        return (16L + (encodedCount & 15)) << ((encodedCount >> 4) + 6);
    }

    /// <summary>
    /// Encodes an iteration count to the S2K byte format.
    /// </summary>
    /// <param name="count">The desired iteration count.</param>
    /// <returns>The encoded count byte.</returns>
    public static byte EncodeIterationCount(long count)
    {
        // Find the closest encoded value
        for (var c = 0; c <= 255; c++)
        {
            if (DecodeIterationCount((byte)c) >= count)
            {
                return (byte)c;
            }
        }
        return 255; // Maximum
    }

    /// <summary>
    /// Generates a random salt for S2K operations (8 bytes for types 0-3).
    /// </summary>
    /// <returns>An 8-byte random salt.</returns>
    public static byte[] GenerateSalt()
    {
        var salt = new byte[DEFAULT_SALT_SIZE];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Generates a random salt for Argon2 S2K (16 bytes per RFC 9580).
    /// </summary>
    /// <returns>A 16-byte random salt.</returns>
    public static byte[] GenerateArgon2Salt()
    {
        var salt = new byte[ARGON2_SALT_SIZE];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Maps OpenPGP hash algorithm ID to HashAlgorithmName.
    /// </summary>
    /// <param name="hashAlgorithm">OpenPGP hash algorithm ID.</param>
    /// <returns>The corresponding HashAlgorithmName.</returns>
    public static HashAlgorithmName MapHashAlgorithm(HashingAlgorithm hashAlgorithm)
    {
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
        return hashAlgorithm switch
        {
            HashingAlgorithm.Md5 => HashAlgorithmName.MD5,
            HashingAlgorithm.Sha1 => HashAlgorithmName.SHA1,
            HashingAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            HashingAlgorithm.Sha384 => HashAlgorithmName.SHA384,
            HashingAlgorithm.Sha512 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm))
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Gets the OpenPGP hash algorithm ID from HashAlgorithmName.
    /// </summary>
    /// <param name="hashAlgorithm">The HashAlgorithmName.</param>
    /// <returns>The corresponding OpenPGP hash algorithm.</returns>
    public static HashingAlgorithm GetHashingAlgorithm(HashAlgorithmName hashAlgorithm)
    {
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
        if (hashAlgorithm == HashAlgorithmName.MD5)
            return HashingAlgorithm.Md5;
        if (hashAlgorithm == HashAlgorithmName.SHA1)
            return HashingAlgorithm.Sha1;
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return HashingAlgorithm.Sha256;
        if (hashAlgorithm == HashAlgorithmName.SHA384)
            return HashingAlgorithm.Sha384;
        if (hashAlgorithm == HashAlgorithmName.SHA512)
            return HashingAlgorithm.Sha512;

        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm));
#pragma warning restore CS0618
    }

    /// <summary>
    /// Derives key using prefix expansion for keys longer than hash output.
    /// </summary>
    private static byte[] DeriveWithPrefix(ReadOnlySpan<byte> data, int keySize, HashAlgorithmName hashAlgorithm)
    {
        var hashSize = GetHashSize(hashAlgorithm);
        var result = new byte[keySize];
        var offset = 0;
        var prefixCount = 0;

        while (offset < keySize)
        {
            // Create input: prefix bytes + data
            var inputSize = prefixCount + data.Length;
            var input = new byte[inputSize];

            // Fill prefix with zeros
            for (var i = 0; i < prefixCount; i++)
            {
                input[i] = 0;
            }
            data.CopyTo(input.AsSpan(prefixCount));

            // Hash the input
            var hash = HashData(input, hashAlgorithm);
            var copyLen = Math.Min(hashSize, keySize - offset);
            hash.AsSpan(0, copyLen).CopyTo(result.AsSpan(offset));

            SecureMemoryOperations.SecureClear(input);
            SecureMemoryOperations.SecureClear(hash);

            offset += hashSize;
            prefixCount++;
        }

        return result;
    }

    /// <summary>
    /// Derives key using iterated hashing.
    /// </summary>
    private static byte[] DeriveIteratedKey(byte[] combined, long count, int keySize, HashAlgorithmName hashAlgorithm)
    {
        var hashSize = GetHashSize(hashAlgorithm);
        var result = new byte[keySize];
        var offset = 0;
        var prefixCount = 0;

        while (offset < keySize)
        {
            using var incrementalHash = IncrementalHash.CreateHash(hashAlgorithm);

            // Add prefix zeros
            if (prefixCount > 0)
            {
                var zeros = new byte[prefixCount];
                incrementalHash.AppendData(zeros);
            }

            // Iteratively hash combined data
            var remaining = count;
            while (remaining > 0)
            {
                var chunk = (int)Math.Min(remaining, combined.Length);
                incrementalHash.AppendData(combined, 0, chunk);
                remaining -= chunk;
            }

            var hash = incrementalHash.GetHashAndReset();
            var copyLen = Math.Min(hashSize, keySize - offset);
            hash.AsSpan(0, copyLen).CopyTo(result.AsSpan(offset));

            SecureMemoryOperations.SecureClear(hash);

            offset += hashSize;
            prefixCount++;
        }

        return result;
    }

    private static byte[] HashData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
#if NETSTANDARD2_0
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
#else
            return SHA256.HashData(data);
#endif
        }
        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
#if NETSTANDARD2_0
            using var sha = SHA384.Create();
            return sha.ComputeHash(data);
#else
            return SHA384.HashData(data);
#endif
        }
        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
#if NETSTANDARD2_0
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
#else
            return SHA512.HashData(data);
#endif
        }

        // Legacy algorithms (OpenPGP compatibility)
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - required for OpenPGP interoperability
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms - required for OpenPGP interoperability
        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
#if NETSTANDARD2_0
            using var sha = SHA1.Create();
            return sha.ComputeHash(data);
#else
            return SHA1.HashData(data);
#endif
        }
        if (hashAlgorithm == HashAlgorithmName.MD5)
        {
#if NETSTANDARD2_0
            using var md5 = MD5.Create();
            return md5.ComputeHash(data);
#else
            return MD5.HashData(data);
#endif
        }
#pragma warning restore CA5351
#pragma warning restore CA5350
#pragma warning restore CS0618

        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}. Use SHA256, SHA384, SHA512, SHA1 (legacy), or MD5 (legacy).", nameof(hashAlgorithm));
    }

    private static int GetHashSize(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return 32;
        if (hashAlgorithm == HashAlgorithmName.SHA384)
            return 48;
        if (hashAlgorithm == HashAlgorithmName.SHA512)
            return 64;
        if (hashAlgorithm == HashAlgorithmName.SHA1)
            return 20;
        if (hashAlgorithm == HashAlgorithmName.MD5)
            return 16;

        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}. Use SHA256, SHA384, SHA512, SHA1 (legacy), or MD5 (legacy).", nameof(hashAlgorithm));
    }

    private static void ValidateKeySize(int keySize)
    {
        if (keySize <= 0)
        {
            throw new ArgumentException("Key size must be positive.", nameof(keySize));
        }
        if (keySize > 1024)
        {
            throw new ArgumentException("Key size exceeds maximum (1024 bytes).", nameof(keySize));
        }
    }
}

/// <summary>
/// S2K type identifiers as per RFC 4880.
/// </summary>
public enum S2KType : byte
{
    /// <summary>Simple S2K (Type 0) - NOT recommended.</summary>
    Simple = 0,

    /// <summary>Salted S2K (Type 1).</summary>
    Salted = 1,

    /// <summary>Reserved (Type 2).</summary>
    Reserved = 2,

    /// <summary>Iterated and Salted S2K (Type 3) - Recommended for legacy compatibility.</summary>
    IteratedAndSalted = 3,

    /// <summary>Argon2 S2K (Type 4) - RFC 9580, strongest protection.</summary>
    Argon2 = 4
}
