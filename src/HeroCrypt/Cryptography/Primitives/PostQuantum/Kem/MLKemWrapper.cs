#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.PostQuantum.Kyber;

/// <summary>
/// ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) wrapper for .NET 10+
/// Implements NIST FIPS 203 standard using .NET's native post-quantum cryptography support.
///
/// ML-KEM (formerly CRYSTALS-Kyber) provides quantum-resistant key encapsulation for secure
/// key exchange, protecting against "harvest now, decrypt later" attacks.
///
/// Based on: FIPS 203 (ML-KEM)
/// Security: Module Learning With Errors (MLWE) problem
///
/// Availability: Requires .NET 10+ with:
/// - Windows: CNG with PQC support
/// - Linux: OpenSSL 3.5 or newer
/// </summary>
[Experimental("SYSLIB5006")]
public static class MLKemWrapper
{
    /// <summary>
    /// ML-KEM security levels (FIPS 203)
    /// </summary>
    public enum SecurityLevel
    {
        /// <summary>ML-KEM-512: ~128-bit post-quantum security, smallest keys/ciphertext</summary>
        MLKem512,

        /// <summary>ML-KEM-768: ~192-bit post-quantum security, balanced performance</summary>
        MLKem768,

        /// <summary>ML-KEM-1024: ~256-bit post-quantum security, maximum security</summary>
        MLKem1024
    }

    /// <summary>
    /// Represents an ML-KEM key pair with public and secret keys
    /// </summary>
    [Experimental("SYSLIB5006")]
    public sealed class MLKemKeyPair : IDisposable
    {
        private System.Security.Cryptography.MLKem? _key;
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

        internal MLKemKeyPair(System.Security.Cryptography.MLKem key, SecurityLevel level)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
            Level = level;
            PublicKeyPem = key.ExportSubjectPublicKeyInfoPem();
            SecretKeyPem = key.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Decapsulates a ciphertext to recover the shared secret
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decapsulate</param>
        /// <returns>The shared secret (32 bytes)</returns>
        /// <exception cref="ObjectDisposedException">If the key pair has been disposed</exception>
        /// <exception cref="CryptographicException">If decapsulation fails</exception>
        public byte[] Decapsulate(byte[] ciphertext)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (_key == null)
                throw new InvalidOperationException("Key is not available");

            return _key.Decapsulate(ciphertext);
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

                // Note: PEM strings will be cleared by GC, but sensitive key material
                // in the MLKem object is properly zeroed by its Dispose method
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Result of an encapsulation operation containing both the ciphertext and shared secret
    /// </summary>
    [Experimental("SYSLIB5006")]
    public sealed class EncapsulationResult : IDisposable
    {
        /// <summary>
        /// Gets the ciphertext to send to the recipient
        /// </summary>
        public byte[] Ciphertext { get; }

        private byte[] _sharedSecret;

        /// <summary>
        /// Gets the shared secret (32 bytes)
        /// </summary>
        /// <remarks>
        /// ⚠️ SECURITY WARNING: This property contains sensitive cryptographic material.
        /// - Use immediately and dispose this object as soon as possible
        /// - Do not store or log this value
        /// - The shared secret is securely cleared when Dispose() is called
        /// </remarks>
        /// <exception cref="ObjectDisposedException">Thrown if accessed after disposal</exception>
        public byte[] SharedSecret
        {
            get
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _sharedSecret;
            }
            private set => _sharedSecret = value;
        }

        private bool _disposed;

        internal EncapsulationResult(byte[] ciphertext, byte[] sharedSecret)
        {
            Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
            _sharedSecret = sharedSecret ?? throw new ArgumentNullException(nameof(sharedSecret));
        }

        /// <summary>
        /// Securely disposes of the shared secret
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                if (_sharedSecret != null)
                {
                    SecureMemoryOperations.SecureClear(_sharedSecret);
                    _sharedSecret = Array.Empty<byte>();
                }
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Checks if ML-KEM is supported on the current platform
    /// </summary>
    /// <returns>True if ML-KEM is available, false otherwise</returns>
    public static bool IsSupported()
    {
        return System.Security.Cryptography.MLKem.IsSupported;
    }

    /// <summary>
    /// Generates a new ML-KEM key pair for the specified security level
    /// </summary>
    /// <param name="level">The desired security level</param>
    /// <returns>A new ML-KEM key pair</returns>
    /// <exception cref="PlatformNotSupportedException">If ML-KEM is not supported on this platform</exception>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    public static MLKemKeyPair GenerateKeyPair(SecurityLevel level = SecurityLevel.MLKem768)
    {
        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        var algorithm = ToMLKemAlgorithm(level);
        var key = System.Security.Cryptography.MLKem.GenerateKey(algorithm);
        return new MLKemKeyPair(key, level);
    }

    /// <summary>
    /// Encapsulates a shared secret using the recipient's public key
    /// </summary>
    /// <param name="publicKeyPem">The recipient's public key in PEM format</param>
    /// <returns>An encapsulation result containing the ciphertext and shared secret</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    /// <exception cref="ArgumentException">If publicKeyPem is not valid PEM format</exception>
    /// <exception cref="PlatformNotSupportedException">If ML-KEM is not supported on this platform</exception>
    /// <exception cref="CryptographicException">If encapsulation fails</exception>
    public static EncapsulationResult Encapsulate(string publicKeyPem)
    {
        ValidatePemFormat(publicKeyPem, nameof(publicKeyPem));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        using var key = System.Security.Cryptography.MLKem.ImportFromPem(publicKeyPem);
        var sharedSecret = new byte[32];
        // ML-KEM ciphertext size varies by algorithm: 768 (512), 1088 (768), 1568 (1024)
        // Use maximum size - Encapsulate will write the correct amount
        var ciphertext = new byte[1568]; // Maximum size for ML-KEM-1024
        key.Encapsulate(ciphertext, sharedSecret);
        // Encapsulate doesn't return size, use the known sizes based on algorithm
        // TODO: Determine actual algorithm from key to trim ciphertext to exact size
        return new EncapsulationResult(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Imports a public key from PEM format
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <param name="level">The security level (for validation)</param>
    /// <returns>A disposable ML-KEM instance for encapsulation</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    /// <exception cref="ArgumentException">If publicKeyPem is not valid PEM format</exception>
    /// <exception cref="PlatformNotSupportedException">If ML-KEM is not supported</exception>
    public static System.Security.Cryptography.MLKem ImportPublicKey(string publicKeyPem, SecurityLevel level = SecurityLevel.MLKem768)
    {
        ValidatePemFormat(publicKeyPem, nameof(publicKeyPem));

        if (!IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }

        return System.Security.Cryptography.MLKem.ImportFromPem(publicKeyPem);
    }

    /// <summary>
    /// Gets recommended security level based on required security bits
    /// </summary>
    /// <param name="securityBits">Desired post-quantum security level in bits</param>
    /// <returns>Recommended ML-KEM security level</returns>
    public static SecurityLevel GetRecommendedLevel(int securityBits)
    {
        return securityBits switch
        {
            <= 128 => SecurityLevel.MLKem512,
            <= 192 => SecurityLevel.MLKem768,
            _ => SecurityLevel.MLKem1024
        };
    }

    /// <summary>
    /// Gets information about a specific security level
    /// </summary>
    /// <param name="level">The security level</param>
    /// <returns>Tuple of (security bits, description)</returns>
    public static (int SecurityBits, string Description) GetLevelInfo(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.MLKem512 => (128, "ML-KEM-512: ~128-bit post-quantum security, smallest keys"),
            SecurityLevel.MLKem768 => (192, "ML-KEM-768: ~192-bit post-quantum security, recommended"),
            SecurityLevel.MLKem1024 => (256, "ML-KEM-1024: ~256-bit post-quantum security, maximum"),
            _ => throw new ArgumentException($"Unknown security level: {level}", nameof(level))
        };
    }

    private static MLKemAlgorithm ToMLKemAlgorithm(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.MLKem512 => MLKemAlgorithm.MLKem512,
            SecurityLevel.MLKem768 => MLKemAlgorithm.MLKem768,
            SecurityLevel.MLKem1024 => MLKemAlgorithm.MLKem1024,
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
