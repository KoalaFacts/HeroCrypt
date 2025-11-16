#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.PostQuantum.Sphincs;

/// <summary>
/// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) wrapper for .NET 10+
/// Implements NIST FIPS 205 standard using .NET's native post-quantum cryptography support.
///
/// SLH-DSA (formerly SPHINCS+) provides quantum-resistant digital signatures based solely on
/// the security of hash functions, requiring no number-theoretic hardness assumptions.
///
/// Key advantages:
/// - Stateless (unlike XMSS/LMS, no state management required)
/// - Based only on hash function security (conservative security assumption)
/// - Provides both "small" (smaller signatures) and "fast" (faster signing) variants
///
/// Based on: FIPS 205 (SLH-DSA)
/// Security: Hash function security only
///
/// Availability: Requires .NET 10+ with:
/// - Windows: CNG with PQC support
/// - Linux: OpenSSL 3.5 or newer
///
/// Note: This API is marked as Experimental (SYSLIB5006) in .NET 10
/// </summary>
[Experimental("SYSLIB5006")]
public static class SlhDsaWrapper
{
    /// <summary>
    /// SLH-DSA security levels and variants (FIPS 205)
    /// </summary>
    public enum SecurityLevel
    {
        /// <summary>SLH-DSA-128s (SPHINCS+-128s): ~128-bit security, small signatures</summary>
        SlhDsa128s,

        /// <summary>SLH-DSA-128f (SPHINCS+-128f): ~128-bit security, fast signing</summary>
        SlhDsa128f,

        /// <summary>SLH-DSA-192s (SPHINCS+-192s): ~192-bit security, small signatures</summary>
        SlhDsa192s,

        /// <summary>SLH-DSA-192f (SPHINCS+-192f): ~192-bit security, fast signing</summary>
        SlhDsa192f,

        /// <summary>SLH-DSA-256s (SPHINCS+-256s): ~256-bit security, small signatures</summary>
        SlhDsa256s,

        /// <summary>SLH-DSA-256f (SPHINCS+-256f): ~256-bit security, fast signing</summary>
        SlhDsa256f
    }

    /// <summary>
    /// Represents an SLH-DSA key pair for signing and verification
    /// </summary>
    [Experimental("SYSLIB5006")]
    public sealed class SlhDsaKeyPair : IDisposable
    {
        private System.Security.Cryptography.SlhDsa? _key;
        private bool _disposed;

        /// <summary>
        /// Gets the public key in PEM format
        /// </summary>
        public string PublicKeyPem { get; }

        /// <summary>
        /// Gets the secret key in PEM format
        /// </summary>
        /// <remarks>
        /// ⚠️ SECURITY WARNING: This property contains sensitive cryptographic key material.
        /// The PEM string is stored in managed memory and cannot be securely cleared.
        /// Best practices:
        /// - Minimize the lifetime of this string in memory
        /// - Do not log or persist this value in plain text
        /// - Use secure storage (HSM, Key Vault) for production keys
        /// - Consider this value compromised if a memory dump occurs
        /// </remarks>
        public string SecretKeyPem { get; }

        /// <summary>
        /// Gets the security level of this key pair
        /// </summary>
        public SecurityLevel Level { get; }

        internal SlhDsaKeyPair(System.Security.Cryptography.SlhDsa key, SecurityLevel level)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
            Level = level;
            PublicKeyPem = key.ExportSubjectPublicKeyInfoPem();
            SecretKeyPem = key.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Signs data using this key pair
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="context">Optional context string for domain separation (max 255 bytes)</param>
        /// <returns>The signature</returns>
        /// <exception cref="ObjectDisposedException">If the key pair has been disposed</exception>
        /// <exception cref="CryptographicException">If signing fails</exception>
        public byte[] Sign(byte[] data, byte[]? context = null)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (_key == null)
                throw new InvalidOperationException("Key is not available");

            if (context != null && context.Length > 255)
                throw new ArgumentException("Context must be 255 bytes or less", nameof(context));

            if (context == null || context.Length == 0)
            {
                return _key.SignData(data);
            }
            else
            {
                return _key.SignData(data, context);
            }
        }

        /// <summary>
        /// Signs data and returns the signature as a byte array (span-based version)
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="context">Optional context string for domain separation</param>
        /// <returns>The signature</returns>
        public byte[] Sign(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_key == null)
                throw new InvalidOperationException("Key is not available");

            if (context.Length > 255)
                throw new ArgumentException("Context must be 255 bytes or less");

            return context.Length == 0
                ? _key.SignData(data.ToArray())
                : _key.SignData(data.ToArray(), context.ToArray());
        }

        /// <summary>
        /// Securely disposes of the key material
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _key?.Dispose();
                _key = null;
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Checks if SLH-DSA is supported on the current platform
    /// </summary>
    /// <returns>True if SLH-DSA is available, false otherwise</returns>
    public static bool IsSupported()
    {
        return System.Security.Cryptography.SlhDsa.IsSupported;
    }

    /// <summary>
    /// Generates a new SLH-DSA key pair for the specified security level
    /// </summary>
    /// <param name="level">The desired security level</param>
    /// <returns>A new SLH-DSA key pair</returns>
    /// <exception cref="PlatformNotSupportedException">If SLH-DSA is not supported on this platform</exception>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    [Experimental("SYSLIB5006")]
    public static SlhDsaKeyPair GenerateKeyPair(SecurityLevel level = SecurityLevel.SlhDsa128s)
    {
        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "SLH-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        var algorithm = ToSlhDsaAlgorithm(level);
        var key = System.Security.Cryptography.SlhDsa.GenerateKey(algorithm);
        return new SlhDsaKeyPair(key, level);
    }

    /// <summary>
    /// Verifies a signature using a public key
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <param name="data">The data that was signed</param>
    /// <param name="signature">The signature to verify</param>
    /// <param name="context">Optional context string used during signing</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    /// <exception cref="ArgumentNullException">If any required parameter is null</exception>
    /// <exception cref="PlatformNotSupportedException">If SLH-DSA is not supported</exception>
    [Experimental("SYSLIB5006")]
    public static bool Verify(string publicKeyPem, byte[] data, byte[] signature, byte[]? context = null)
    {
        ValidatePemFormat(publicKeyPem, nameof(publicKeyPem));

        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "SLH-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        if (context != null && context.Length > 255)
            throw new ArgumentException("Context must be 255 bytes or less", nameof(context));

        using var key = System.Security.Cryptography.SlhDsa.ImportFromPem(publicKeyPem);

        if (context == null || context.Length == 0)
        {
            return key.VerifyData(data, signature);
        }
        else
        {
            return key.VerifyData(data, signature, context);
        }
    }

    /// <summary>
    /// Verifies a signature using a public key with span-based API
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <param name="data">The data that was signed</param>
    /// <param name="signature">The signature to verify</param>
    /// <param name="context">Optional context string used during signing</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    [Experimental("SYSLIB5006")]
    public static bool Verify(string publicKeyPem, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default)
    {
        ValidatePemFormat(publicKeyPem, nameof(publicKeyPem));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "SLH-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        if (context.Length > 255)
            throw new ArgumentException("Context must be 255 bytes or less");

        using var key = System.Security.Cryptography.SlhDsa.ImportFromPem(publicKeyPem);
        return key.VerifyData(data, signature, context);
    }

    /// <summary>
    /// Imports a public key from PEM format
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <returns>A disposable SLH-DSA instance for verification</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    /// <exception cref="PlatformNotSupportedException">If SLH-DSA is not supported</exception>
    [Experimental("SYSLIB5006")]
    public static System.Security.Cryptography.SlhDsa ImportPublicKey(string publicKeyPem)
    {
        if (publicKeyPem == null)
            throw new ArgumentNullException(nameof(publicKeyPem));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "SLH-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        return System.Security.Cryptography.SlhDsa.ImportFromPem(publicKeyPem);
    }

    /// <summary>
    /// Gets recommended security level based on required security bits
    /// </summary>
    /// <param name="securityBits">Desired post-quantum security level in bits</param>
    /// <param name="preferSmall">If true, prefer "small" variant (smaller signatures); otherwise prefer "fast" variant</param>
    /// <returns>Recommended SLH-DSA security level</returns>
    public static SecurityLevel GetRecommendedLevel(int securityBits, bool preferSmall = true)
    {
        return (securityBits, preferSmall) switch
        {
            (<= 128, true) => SecurityLevel.SlhDsa128s,
            (<= 128, false) => SecurityLevel.SlhDsa128f,
            (<= 192, true) => SecurityLevel.SlhDsa192s,
            (<= 192, false) => SecurityLevel.SlhDsa192f,
            (_, true) => SecurityLevel.SlhDsa256s,
            (_, false) => SecurityLevel.SlhDsa256f
        };
    }

    /// <summary>
    /// Gets information about a specific security level
    /// </summary>
    /// <param name="level">The security level</param>
    /// <returns>Tuple of (security bits, signature size approx, description)</returns>
    public static (int SecurityBits, int SignatureSizeApprox, string Description) GetLevelInfo(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.SlhDsa128s => (128, 7856, "SLH-DSA-128s: ~128-bit security, small signatures"),
            SecurityLevel.SlhDsa128f => (128, 17088, "SLH-DSA-128f: ~128-bit security, fast signing"),
            SecurityLevel.SlhDsa192s => (192, 16224, "SLH-DSA-192s: ~192-bit security, small signatures"),
            SecurityLevel.SlhDsa192f => (192, 35664, "SLH-DSA-192f: ~192-bit security, fast signing"),
            SecurityLevel.SlhDsa256s => (256, 29792, "SLH-DSA-256s: ~256-bit security, small signatures"),
            SecurityLevel.SlhDsa256f => (256, 49856, "SLH-DSA-256f: ~256-bit security, fast signing"),
            _ => throw new ArgumentException($"Unknown security level: {level}", nameof(level))
        };
    }

    private static System.Security.Cryptography.SlhDsaAlgorithm ToSlhDsaAlgorithm(SecurityLevel level)
    {
        // SLH-DSA enum values don't exist yet in .NET 10 - will be added in future release
        throw new NotSupportedException("SLH-DSA is not yet available in .NET 10. The enum values are not defined in the current SDK.");
    }

    /// <summary>
    /// Validates that a string is in valid PEM format
    /// </summary>
    /// <param name="pem">The PEM string to validate</param>
    /// <param name="paramName">The parameter name for exception messages</param>
    /// <exception cref="ArgumentNullException">If pem is null</exception>
    /// <exception cref="ArgumentException">If pem is not valid PEM format</exception>
    private static void ValidatePemFormat(string pem, string paramName)
    {
        if (pem == null)
            throw new ArgumentNullException(paramName);

        if (string.IsNullOrWhiteSpace(pem))
            throw new ArgumentException("PEM string cannot be empty or whitespace", paramName);

        if (!pem.Contains("-----BEGIN") || !pem.Contains("-----END"))
            throw new ArgumentException(
                "Invalid PEM format. Expected PEM-encoded key with BEGIN/END markers",
                paramName);
    }
}
#endif
