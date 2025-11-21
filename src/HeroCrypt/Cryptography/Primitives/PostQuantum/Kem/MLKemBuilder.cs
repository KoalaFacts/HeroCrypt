#if NET10_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
#pragma warning disable SYSLIB5006 // ML-KEM APIs are experimental in .NET 10 preview

namespace HeroCrypt.Cryptography.Primitives.PostQuantum.Kem;

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
[Experimental("SYSLIB5006")]
public class MLKemBuilder : IDisposable
{
    private MLKemWrapper.SecurityLevel securityLevel = MLKemWrapper.SecurityLevel.MLKem768;
    private string? publicKeyPem;
    private MLKemWrapper.MLKemKeyPair? keyPair;
    private bool disposed;

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
        securityLevel = level;
        return this;
    }

    /// <summary>
    /// Sets the security level based on required post-quantum security bits
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <returns>The builder instance for method chaining</returns>
    public MLKemBuilder WithSecurityBits(int securityBits)
    {
        securityLevel = MLKemWrapper.GetRecommendedLevel(securityBits);
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
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(publicKeyPem);
#else
        if (publicKeyPem == null)
        {
            throw new ArgumentNullException(nameof(publicKeyPem));
        }
#endif

        this.publicKeyPem = publicKeyPem;
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
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(keyPair);
#else
        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }
#endif

        this.keyPair = keyPair;
        return this;
    }

    /// <summary>
    /// Generates a new ML-KEM key pair with the configured security level
    /// </summary>
    /// <returns>A new ML-KEM key pair</returns>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    public MLKemWrapper.MLKemKeyPair GenerateKeyPair()
    {
        return MLKemWrapper.GenerateKeyPair(securityLevel);
    }

    /// <summary>
    /// Encapsulates a shared secret using the configured public key
    /// </summary>
    /// <returns>An encapsulation result containing ciphertext and shared secret</returns>
    /// <exception cref="InvalidOperationException">If no public key is configured</exception>
    /// <exception cref="CryptographicException">If encapsulation fails</exception>
    public MLKemWrapper.EncapsulationResult Encapsulate()
    {
        if (publicKeyPem == null)
        {
            throw new InvalidOperationException("Public key must be set before encapsulation. Use WithPublicKey()");
        }

        return MLKemWrapper.Encapsulate(publicKeyPem);
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
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(ciphertext);
#else
        if (ciphertext == null)
        {
            throw new ArgumentNullException(nameof(ciphertext));
        }
#endif

        if (keyPair == null)
        {
            throw new InvalidOperationException("Key pair must be set before decapsulation. Use WithKeyPair()");
        }

        return keyPair.Decapsulate(ciphertext);
    }

    /// <summary>
    /// Gets information about the configured security level
    /// </summary>
    /// <returns>Tuple of (security bits, description)</returns>
    public (int SecurityBits, string Description) GetLevelInfo()
    {
        return MLKemWrapper.GetLevelInfo(securityLevel);
    }

    /// <summary>
    /// Disposes the builder and any managed resources
    /// Note: Does not dispose externally provided key pairs
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            // Note: We don't dispose keyPair as it was provided externally
            // The caller is responsible for disposing it
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}

#pragma warning restore SYSLIB5006
#endif
