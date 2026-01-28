using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Hkdf;

/// <summary>
/// HKDF (HMAC-based Key Derivation Function) implementation
/// RFC 5869 compliant implementation for extracting and expanding keys
/// </summary>
internal static class HkdfCore
{
    /// <summary>
    /// Maximum output key material length for HKDF-Expand
    /// </summary>
    public const int MAX_OUTPUT_LENGTH = 255 * 64; // 255 * hash_len for SHA-512

    /// <summary>
    /// Performs HKDF key derivation (Extract + Expand)
    /// </summary>
    /// <param name="ikm">Input key material</param>
    /// <param name="salt">Salt value (optional, can be empty)</param>
    /// <param name="info">Application-specific context information (optional)</param>
    /// <param name="length">Length of output key material</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Derived key material</returns>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int length,
        HashAlgorithmName hashAlgorithm)
    {
        // Validate hash algorithm against security policy (blocks SHA-1 at Standard+ level)
        SecurityPolicy.ValidateHash(hashAlgorithm.Name ?? "Unknown");

        if (length <= 0)
        {
            throw new ArgumentException("Length must be positive", nameof(length));
        }

        int hashLength = HashAlgorithmHelper.GetHashLength(hashAlgorithm);
        if (length > 255 * hashLength)
        {
            throw new ArgumentException($"Length too large for hash algorithm (max: {255 * hashLength})", nameof(length));
        }

        // Step 1: Extract
        byte[] prk = Extract(ikm, salt, hashAlgorithm);

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
        // Validate hash algorithm against security policy (blocks SHA-1 at Standard+ level)
        SecurityPolicy.ValidateHash(hashAlgorithm.Name ?? "Unknown");

        if (ikm.IsEmpty)
        {
            throw new ArgumentException("Input key material cannot be empty", nameof(ikm));
        }

        // If salt is empty, use zero-filled salt of hash length
        byte[] actualSalt = salt.IsEmpty ? new byte[HashAlgorithmHelper.GetHashLength(hashAlgorithm)] : salt.ToArray();
        byte[] ikmArray = ikm.ToArray();

        try
        {
            using var hmac = HashAlgorithmHelper.CreateHmac(hashAlgorithm, actualSalt);
            return hmac.ComputeHash(ikmArray);
        }
        finally
        {
            // Clear sensitive key material
            SecureMemoryOperations.SecureClear(ikmArray);

            // Always clear actualSalt - it's always a new allocation
            // (either zero-filled array or copy via ToArray())
            SecureMemoryOperations.SecureClear(actualSalt);
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
        // Validate hash algorithm against security policy (blocks SHA-1 at Standard+ level)
        SecurityPolicy.ValidateHash(hashAlgorithm.Name ?? "Unknown");

        if (prk.IsEmpty)
        {
            throw new ArgumentException("Pseudorandom key cannot be empty", nameof(prk));
        }
        if (length <= 0)
        {
            throw new ArgumentException("Length must be positive", nameof(length));
        }

        int hashLength = HashAlgorithmHelper.GetHashLength(hashAlgorithm);
        if (length > 255 * hashLength)
        {
            throw new ArgumentException($"Length too large (max: {255 * hashLength})", nameof(length));
        }

        int n = (length + hashLength - 1) / hashLength; // Ceiling division
        byte[] okm = new byte[length];
        byte[] t = []; // T(0) = empty string

        // Create arrays once to avoid memory leaks in loop
        byte[] prkArray = prk.ToArray();
        byte[]? infoArray = info.IsEmpty ? null : info.ToArray();

        try
        {
            using var hmac = HashAlgorithmHelper.CreateHmac(hashAlgorithm, prkArray);

            for (int i = 1; i <= n; i++)
            {
                // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
                hmac.Initialize();

                if (t.Length > 0)
                {
                    _ = hmac.TransformBlock(t, 0, t.Length, null, 0);
                }

                if (infoArray != null)
                {
                    _ = hmac.TransformBlock(infoArray, 0, infoArray.Length, null, 0);
                }

                _ = hmac.TransformFinalBlock([(byte)i], 0, 1);
                t = hmac.Hash ?? throw new InvalidOperationException("HMAC computation failed");

                // Copy T(i) to output
                int copyLength = Math.Min(hashLength, length - ((i - 1) * hashLength));
                Array.Copy(t, 0, okm, (i - 1) * hashLength, copyLength);
            }

            return okm;
        }
        finally
        {
            // Clear sensitive key material
            SecureMemoryOperations.SecureClear(prkArray);
            if (infoArray != null)
            {
                SecureMemoryOperations.SecureClear(infoArray);
            }
            SecureMemoryOperations.SecureClear(t);
        }
    }

    /// <summary>
    /// Validates HKDF parameters
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> ikm, int length, HashAlgorithmName hashAlgorithm)
    {
        if (ikm.IsEmpty)
        {
            throw new ArgumentException("Input key material cannot be empty", nameof(ikm));
        }
        if (length <= 0)
        {
            throw new ArgumentException("Length must be positive", nameof(length));
        }

        int hashLength = HashAlgorithmHelper.GetHashLength(hashAlgorithm);
        if (length > 255 * hashLength)
        {
            throw new ArgumentException($"Length too large for {hashAlgorithm} (max: {255 * hashLength})", nameof(length));
        }
    }

    /// <summary>
    /// Gets the maximum output length for a given hash algorithm
    /// </summary>
    public static int GetMAX_OUTPUT_LENGTH(HashAlgorithmName hashAlgorithm)
    {
        return 255 * HashAlgorithmHelper.GetHashLength(hashAlgorithm);
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
    /// <remarks>
    /// <para>
    /// The <see cref="HkdfUseCase.LegacyCompatibility"/> use case returns SHA-1 parameters
    /// but will throw <see cref="SecurityPolicyException"/> at <see cref="SecurityLevel.Standard"/>
    /// or higher. Use <see cref="SecurityPolicy.LegacyScope"/> to temporarily allow SHA-1
    /// when legacy compatibility is required.
    /// </para>
    /// </remarks>
    public static HkdfParameters GetRecommendedParameters(HkdfUseCase useCase)
    {
        var parameters = useCase switch
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

        // Validate the hash algorithm against security policy
        // This will throw SecurityPolicyException for SHA-1 at Standard+ level
        SecurityPolicy.ValidateHash(parameters.HashAlgorithm.Name ?? "Unknown");

        return parameters;
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
