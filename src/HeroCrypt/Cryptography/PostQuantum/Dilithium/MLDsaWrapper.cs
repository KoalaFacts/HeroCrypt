#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.PostQuantum.Dilithium;

/// <summary>
/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) wrapper for .NET 10+
/// Implements NIST FIPS 204 standard using .NET's native post-quantum cryptography support.
///
/// ML-DSA (formerly CRYSTALS-Dilithium) provides quantum-resistant digital signatures based on
/// the hardness of the Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems.
///
/// Based on: FIPS 204 (ML-DSA)
/// Security: MLWE and MSIS hardness assumptions
///
/// Availability: Requires .NET 10+ with:
/// - Windows: CNG with PQC support
/// - Linux: OpenSSL 3.5 or newer
/// </summary>
public static class MLDsaWrapper
{
    /// <summary>
    /// ML-DSA security levels (FIPS 204)
    /// </summary>
    public enum SecurityLevel
    {
        /// <summary>ML-DSA-44 (Dilithium2): ~128-bit post-quantum security, compact signatures</summary>
        MLDsa44,

        /// <summary>ML-DSA-65 (Dilithium3): ~192-bit post-quantum security, balanced</summary>
        MLDsa65,

        /// <summary>ML-DSA-87 (Dilithium5): ~256-bit post-quantum security, maximum security</summary>
        MLDsa87
    }

    /// <summary>
    /// Represents an ML-DSA key pair for signing and verification
    /// </summary>
    public sealed class MLDsaKeyPair : IDisposable
    {
        private MLDsa? _key;
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

        internal MLDsaKeyPair(MLDsa key, SecurityLevel level)
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

            // .NET 10 simplified signature API
            if (context == null || context.Length == 0)
            {
                return _key.SignData(data);
            }
            else
            {
                // With context support
                return _key.SignData(data, context);
            }
        }

        /// <summary>
        /// Tries to sign data and write the signature to a destination span
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="destination">The destination for the signature</param>
        /// <param name="bytesWritten">The number of bytes written</param>
        /// <param name="context">Optional context string for domain separation</param>
        /// <returns>True if successful, false if destination is too small</returns>
        public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten, ReadOnlySpan<byte> context = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_key == null)
                throw new InvalidOperationException("Key is not available");

            if (context.Length > 255)
                throw new ArgumentException("Context must be 255 bytes or less");

            return _key.TrySignData(data, destination, out bytesWritten, context);
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
    /// Checks if ML-DSA is supported on the current platform
    /// </summary>
    /// <returns>True if ML-DSA is available, false otherwise</returns>
    public static bool IsSupported()
    {
        return MLDsa.IsSupported;
    }

    /// <summary>
    /// Generates a new ML-DSA key pair for the specified security level
    /// </summary>
    /// <param name="level">The desired security level</param>
    /// <returns>A new ML-DSA key pair</returns>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is not supported on this platform</exception>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    public static MLDsaKeyPair GenerateKeyPair(SecurityLevel level = SecurityLevel.MLDsa65)
    {
        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        var algorithm = ToMLDsaAlgorithm(level);
        var key = MLDsa.GenerateKey(algorithm);
        return new MLDsaKeyPair(key, level);
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
    /// <exception cref="ArgumentException">If publicKeyPem is not valid PEM format or context exceeds 255 bytes</exception>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is not supported</exception>
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
                "ML-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        if (context != null && context.Length > 255)
            throw new ArgumentException("Context must be 255 bytes or less", nameof(context));

        using var key = MLDsa.ImportFromPem(publicKeyPem);

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
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    /// <exception cref="ArgumentException">If publicKeyPem is not valid PEM format or context exceeds 255 bytes</exception>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is not supported</exception>
    public static bool Verify(string publicKeyPem, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default)
    {
        ValidatePemFormat(publicKeyPem, nameof(publicKeyPem));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        if (context.Length > 255)
            throw new ArgumentException("Context must be 255 bytes or less");

        using var key = MLDsa.ImportFromPem(publicKeyPem);
        return key.VerifyData(data, signature, context);
    }

    /// <summary>
    /// Imports a public key from PEM format
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <returns>A disposable ML-DSA instance for verification</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    /// <exception cref="ArgumentException">If publicKeyPem is not valid PEM format</exception>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is not supported</exception>
    public static MLDsa ImportPublicKey(string publicKeyPem)
    {
        ValidatePemFormat(publicKeyPem, nameof(publicKeyPem));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        return MLDsa.ImportFromPem(publicKeyPem);
    }

    /// <summary>
    /// Gets recommended security level based on required security bits
    /// </summary>
    /// <param name="securityBits">Desired post-quantum security level in bits</param>
    /// <returns>Recommended ML-DSA security level</returns>
    public static SecurityLevel GetRecommendedLevel(int securityBits)
    {
        return securityBits switch
        {
            <= 128 => SecurityLevel.MLDsa44,
            <= 192 => SecurityLevel.MLDsa65,
            _ => SecurityLevel.MLDsa87
        };
    }

    /// <summary>
    /// Gets information about a specific security level
    /// </summary>
    /// <param name="level">The security level</param>
    /// <returns>Tuple of (security bits, signature size, description)</returns>
    public static (int SecurityBits, int SignatureSize, string Description) GetLevelInfo(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.MLDsa44 => (128, 2420, "ML-DSA-44: ~128-bit post-quantum security, compact signatures"),
            SecurityLevel.MLDsa65 => (192, 3309, "ML-DSA-65: ~192-bit post-quantum security, recommended"),
            SecurityLevel.MLDsa87 => (256, 4627, "ML-DSA-87: ~256-bit post-quantum security, maximum"),
            _ => throw new ArgumentException($"Unknown security level: {level}", nameof(level))
        };
    }

    private static MLDsaAlgorithm ToMLDsaAlgorithm(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.MLDsa44 => MLDsaAlgorithm.MLDsa44,
            SecurityLevel.MLDsa65 => MLDsaAlgorithm.MLDsa65,
            SecurityLevel.MLDsa87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentException($"Unknown security level: {level}", nameof(level))
        };
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
