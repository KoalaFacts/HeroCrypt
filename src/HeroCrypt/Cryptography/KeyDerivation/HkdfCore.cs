using HeroCrypt.Security;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.KeyDerivation;

/// <summary>
/// HKDF (HMAC-based Key Derivation Function) implementation
/// RFC 5869 compliant implementation for extracting and expanding keys
/// </summary>
internal static class HkdfCore
{
    /// <summary>
    /// Maximum output key material length for HKDF-Expand
    /// </summary>
    public const int MaxOutputLength = 255 * 64; // 255 * hash_len for SHA-512

    /// <summary>
    /// Performs HKDF key derivation (Extract + Expand)
    /// </summary>
    /// <param name="ikm">Input key material</param>
    /// <param name="salt">Salt value (optional, can be empty)</param>
    /// <param name="info">Application-specific context information (optional)</param>
    /// <param name="length">Length of output key material</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Derived key material</returns>
    public static byte[] DeriveKey(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info,
        int length, HashAlgorithmName hashAlgorithm)
    {
        if (length <= 0)
            throw new ArgumentException("Length must be positive", nameof(length));

        var hashLength = GetHashLength(hashAlgorithm);
        if (length > 255 * hashLength)
            throw new ArgumentException($"Length too large for hash algorithm (max: {255 * hashLength})", nameof(length));

        // Step 1: Extract
        var prk = Extract(ikm, salt, hashAlgorithm);

        try
        {
            // Step 2: Expand
            return Expand(prk, info, length, hashAlgorithm);
        }
        finally
        {
            // Clear pseudorandom key
            SecureMemoryOperations.SecureClear(prk);
        }
    }

    /// <summary>
    /// HKDF-Extract: Extracts a pseudorandom key from input key material
    /// </summary>
    /// <param name="ikm">Input key material</param>
    /// <param name="salt">Salt value (optional)</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Pseudorandom key</returns>
    public static byte[] Extract(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, HashAlgorithmName hashAlgorithm)
    {
        if (ikm.IsEmpty)
            throw new ArgumentException("Input key material cannot be empty", nameof(ikm));

        // If salt is empty, use zero-filled salt of hash length
        var actualSalt = salt.IsEmpty ? new byte[GetHashLength(hashAlgorithm)] : salt.ToArray();
        var ikmArray = ikm.ToArray();

        try
        {
            using var hmac = CreateHmac(hashAlgorithm, actualSalt);
            return hmac.ComputeHash(ikmArray);
        }
        finally
        {
            // Clear sensitive key material
            Array.Clear(ikmArray, 0, ikmArray.Length);

            if (salt.IsEmpty)
            {
                SecureMemoryOperations.SecureClear(actualSalt);
            }
            else
            {
                Array.Clear(actualSalt, 0, actualSalt.Length);
            }
        }
    }

    /// <summary>
    /// HKDF-Expand: Expands a pseudorandom key to desired length
    /// </summary>
    /// <param name="prk">Pseudorandom key from Extract phase</param>
    /// <param name="info">Application-specific context information</param>
    /// <param name="length">Desired output length</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Output key material</returns>
    public static byte[] Expand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length, HashAlgorithmName hashAlgorithm)
    {
        if (prk.IsEmpty)
            throw new ArgumentException("Pseudorandom key cannot be empty", nameof(prk));
        if (length <= 0)
            throw new ArgumentException("Length must be positive", nameof(length));

        var hashLength = GetHashLength(hashAlgorithm);
        if (length > 255 * hashLength)
            throw new ArgumentException($"Length too large (max: {255 * hashLength})", nameof(length));

        var n = (length + hashLength - 1) / hashLength; // Ceiling division
        var okm = new byte[length];
        var t = new byte[0]; // T(0) = empty string

        // Create arrays once to avoid memory leaks in loop
        var prkArray = prk.ToArray();
        var infoArray = info.IsEmpty ? null : info.ToArray();

        try
        {
            using var hmac = CreateHmac(hashAlgorithm, prkArray);

            for (var i = 1; i <= n; i++)
            {
                // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
                hmac.Initialize();

                if (t.Length > 0)
                    hmac.TransformBlock(t, 0, t.Length, null, 0);

                if (infoArray != null)
                    hmac.TransformBlock(infoArray, 0, infoArray.Length, null, 0);

                hmac.TransformFinalBlock(new[] { (byte)i }, 0, 1);
                t = hmac.Hash ?? throw new InvalidOperationException("HMAC computation failed");

                // Copy T(i) to output
                var copyLength = Math.Min(hashLength, length - (i - 1) * hashLength);
                Array.Copy(t, 0, okm, (i - 1) * hashLength, copyLength);
            }

            return okm;
        }
        finally
        {
            // Clear sensitive key material
            Array.Clear(prkArray, 0, prkArray.Length);
            if (infoArray != null)
                Array.Clear(infoArray, 0, infoArray.Length);
            SecureMemoryOperations.SecureClear(t);
        }
    }

    /// <summary>
    /// Creates HMAC instance for specified hash algorithm
    /// </summary>
    private static HMAC CreateHmac(HashAlgorithmName hashAlgorithm, byte[] key)
    {
        // SHA1 support is intentional for RFC 5869 HKDF compatibility
        // Users should prefer SHA256 or higher, but SHA1 is allowed per the standard
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
        if (hashAlgorithm == HashAlgorithmName.SHA1)
            return new HMACSHA1(key);
#pragma warning restore CA5350
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return new HMACSHA256(key);
        if (hashAlgorithm == HashAlgorithmName.SHA384)
            return new HMACSHA384(key);
        if (hashAlgorithm == HashAlgorithmName.SHA512)
            return new HMACSHA512(key);

        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm));
    }

    /// <summary>
    /// Gets hash output length for specified algorithm
    /// </summary>
    private static int GetHashLength(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA1)
            return 20;
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return 32;
        if (hashAlgorithm == HashAlgorithmName.SHA384)
            return 48;
        if (hashAlgorithm == HashAlgorithmName.SHA512)
            return 64;

        throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm));
    }

    /// <summary>
    /// Validates HKDF parameters
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> ikm, int length, HashAlgorithmName hashAlgorithm)
    {
        if (ikm.IsEmpty)
            throw new ArgumentException("Input key material cannot be empty", nameof(ikm));
        if (length <= 0)
            throw new ArgumentException("Length must be positive", nameof(length));

        var hashLength = GetHashLength(hashAlgorithm);
        if (length > 255 * hashLength)
            throw new ArgumentException($"Length too large for {hashAlgorithm} (max: {255 * hashLength})", nameof(length));
    }

    /// <summary>
    /// Gets the maximum output length for a given hash algorithm
    /// </summary>
    public static int GetMaxOutputLength(HashAlgorithmName hashAlgorithm)
    {
        return 255 * GetHashLength(hashAlgorithm);
    }

    /// <summary>
    /// Checks if a hash algorithm is supported
    /// </summary>
    public static bool IsHashAlgorithmSupported(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm == HashAlgorithmName.SHA1 ||
               hashAlgorithm == HashAlgorithmName.SHA256 ||
               hashAlgorithm == HashAlgorithmName.SHA384 ||
               hashAlgorithm == HashAlgorithmName.SHA512;
    }

    /// <summary>
    /// Gets recommended parameters for common use cases
    /// </summary>
    public static HkdfParameters GetRecommendedParameters(HkdfUseCase useCase)
    {
        return useCase switch
        {
            HkdfUseCase.GeneralPurpose => new HkdfParameters
            {
                HashAlgorithm = HashAlgorithmName.SHA256,
                RecommendedSaltLength = 32,
                Description = "General-purpose key derivation with SHA-256"
            },
            HkdfUseCase.HighSecurity => new HkdfParameters
            {
                HashAlgorithm = HashAlgorithmName.SHA512,
                RecommendedSaltLength = 64,
                Description = "High-security applications with SHA-512"
            },
            HkdfUseCase.LegacyCompatibility => new HkdfParameters
            {
                HashAlgorithm = HashAlgorithmName.SHA1,
                RecommendedSaltLength = 20,
                Description = "Legacy compatibility (SHA-1 not recommended for new applications)"
            },
            HkdfUseCase.TlsKeyDerivation => new HkdfParameters
            {
                HashAlgorithm = HashAlgorithmName.SHA256,
                RecommendedSaltLength = 32,
                Description = "TLS 1.3 key derivation with SHA-256"
            },
            _ => throw new ArgumentException($"Unknown use case: {useCase}", nameof(useCase))
        };
    }
}

/// <summary>
/// HKDF use cases for parameter recommendations
/// </summary>
public enum HkdfUseCase
{
    /// <summary>General-purpose key derivation</summary>
    GeneralPurpose,
    /// <summary>High-security applications</summary>
    HighSecurity,
    /// <summary>Legacy compatibility requirements</summary>
    LegacyCompatibility,
    /// <summary>TLS key derivation</summary>
    TlsKeyDerivation
}

/// <summary>
/// HKDF parameters for different use cases
/// </summary>
public class HkdfParameters
{
    /// <summary>Recommended hash algorithm</summary>
    public HashAlgorithmName HashAlgorithm { get; set; }

    /// <summary>Recommended salt length</summary>
    public int RecommendedSaltLength { get; set; }

    /// <summary>Description of the parameters</summary>
    public string Description { get; set; } = string.Empty;
}