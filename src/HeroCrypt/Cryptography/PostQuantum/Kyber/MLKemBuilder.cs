#if NET10_0_OR_GREATER
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.PostQuantum.Kyber;

/// <summary>
/// Fluent builder for ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) operations
/// Provides an intuitive API for quantum-resistant key encapsulation
/// </summary>
/// <example>
/// <code>
/// // Generate key pair with builder pattern
/// using var keyPair = MLKem.Create()
///     .WithSecurityLevel(MLKemBuilder.SecurityLevel.MLKem768)
///     .GenerateKeyPair();
///
/// // Encapsulate shared secret
/// var (ciphertext, sharedSecret) = MLKem.Create()
///     .WithPublicKey(publicKeyPem)
///     .Encapsulate();
///
/// // Decapsulate
/// var recovered = MLKem.Create()
///     .WithKeyPair(keyPair)
///     .Decapsulate(ciphertext);
/// </code>
/// </example>
public class MLKemBuilder : IDisposable
{
    private MLKemWrapper.SecurityLevel _securityLevel = MLKemWrapper.SecurityLevel.MLKem768;
    private string? _publicKeyPem;
    private MLKemWrapper.MLKemKeyPair? _keyPair;
    private bool _disposed;

    /// <summary>
    /// Creates a new ML-KEM builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    /// <exception cref="PlatformNotSupportedException">If ML-KEM is not supported on this platform</exception>
    public static MLKemBuilder Create()
    {
        if (!MLKemWrapper.IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }
        return new MLKemBuilder();
    }

    private MLKemBuilder() { }

    /// <summary>
    /// Sets the security level for key generation
    /// </summary>
    /// <param name="level">The desired security level (default: MLKem768)</param>
    /// <returns>The builder instance for method chaining</returns>
    public MLKemBuilder WithSecurityLevel(MLKemWrapper.SecurityLevel level)
    {
        _securityLevel = level;
        return this;
    }

    /// <summary>
    /// Sets the security level based on required post-quantum security bits
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <returns>The builder instance for method chaining</returns>
    public MLKemBuilder WithSecurityBits(int securityBits)
    {
        _securityLevel = MLKemWrapper.GetRecommendedLevel(securityBits);
        return this;
    }

    /// <summary>
    /// Sets the public key for encapsulation operations
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    public MLKemBuilder WithPublicKey(string publicKeyPem)
    {
        if (publicKeyPem == null)
            throw new ArgumentNullException(nameof(publicKeyPem));

        _publicKeyPem = publicKeyPem;
        return this;
    }

    /// <summary>
    /// Sets an existing key pair for decapsulation operations
    /// </summary>
    /// <param name="keyPair">An existing ML-KEM key pair</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If keyPair is null</exception>
    public MLKemBuilder WithKeyPair(MLKemWrapper.MLKemKeyPair keyPair)
    {
        if (keyPair == null)
            throw new ArgumentNullException(nameof(keyPair));

        _keyPair = keyPair;
        return this;
    }

    /// <summary>
    /// Generates a new ML-KEM key pair with the configured security level
    /// </summary>
    /// <returns>A new ML-KEM key pair</returns>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    public MLKemWrapper.MLKemKeyPair GenerateKeyPair()
    {
        return MLKemWrapper.GenerateKeyPair(_securityLevel);
    }

    /// <summary>
    /// Encapsulates a shared secret using the configured public key
    /// </summary>
    /// <returns>An encapsulation result containing ciphertext and shared secret</returns>
    /// <exception cref="InvalidOperationException">If no public key is configured</exception>
    /// <exception cref="CryptographicException">If encapsulation fails</exception>
    public MLKemWrapper.EncapsulationResult Encapsulate()
    {
        if (_publicKeyPem == null)
            throw new InvalidOperationException("Public key must be set before encapsulation. Use WithPublicKey()");

        return MLKemWrapper.Encapsulate(_publicKeyPem);
    }

    /// <summary>
    /// Decapsulates a ciphertext to recover the shared secret using the configured key pair
    /// </summary>
    /// <param name="ciphertext">The ciphertext to decapsulate</param>
    /// <returns>The recovered shared secret (32 bytes)</returns>
    /// <exception cref="ArgumentNullException">If ciphertext is null</exception>
    /// <exception cref="InvalidOperationException">If no key pair is configured</exception>
    /// <exception cref="CryptographicException">If decapsulation fails</exception>
    public byte[] Decapsulate(byte[] ciphertext)
    {
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));

        if (_keyPair == null)
            throw new InvalidOperationException("Key pair must be set before decapsulation. Use WithKeyPair()");

        return _keyPair.Decapsulate(ciphertext);
    }

    /// <summary>
    /// Gets information about the configured security level
    /// </summary>
    /// <returns>Tuple of (security bits, description)</returns>
    public (int SecurityBits, string Description) GetLevelInfo()
    {
        return MLKemWrapper.GetLevelInfo(_securityLevel);
    }

    /// <summary>
    /// Disposes the builder and any managed resources
    /// Note: Does not dispose externally provided key pairs
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            // Note: We don't dispose _keyPair as it was provided externally
            // The caller is responsible for disposing it
            _disposed = true;
        }
    }
}

/// <summary>
/// Provides a short-hand fluent API for ML-KEM operations
/// </summary>
public static class MLKem
{
    /// <summary>
    /// Creates a new ML-KEM builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    public static MLKemBuilder Create() => MLKemBuilder.Create();

    /// <summary>
    /// Quick method to generate a key pair with recommended security (ML-KEM-768)
    /// </summary>
    /// <returns>A new ML-KEM key pair</returns>
    public static MLKemWrapper.MLKemKeyPair GenerateKeyPair() =>
        MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);

    /// <summary>
    /// Quick method to generate a key pair with specified security level
    /// </summary>
    /// <param name="level">The security level</param>
    /// <returns>A new ML-KEM key pair</returns>
    public static MLKemWrapper.MLKemKeyPair GenerateKeyPair(MLKemWrapper.SecurityLevel level) =>
        MLKemWrapper.GenerateKeyPair(level);
}
#endif
