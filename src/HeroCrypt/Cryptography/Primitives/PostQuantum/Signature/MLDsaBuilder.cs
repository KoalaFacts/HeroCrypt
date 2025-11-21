#if NET10_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

#pragma warning disable SYSLIB5006 // ML-DSA APIs are experimental in .NET 10 preview
namespace HeroCrypt.Cryptography.Primitives.PostQuantum.Signature;

/// <summary>
/// Fluent builder for ML-DSA (Module-Lattice-Based Digital Signature Algorithm) operations
/// Provides an intuitive API for quantum-resistant digital signatures
/// </summary>
/// <example>
/// <code>
/// // Generate key pair and sign
/// using var keyPair = MLDsa.Create()
///     .WithSecurityLevel(MLDsaBuilder.SecurityLevel.MLDsa65)
///     .GenerateKeyPair();
///
/// var signature = MLDsa.Create()
///     .WithKeyPair(keyPair)
///     .WithData(messageBytes)
///     .Sign();
///
/// // Verify signature
/// bool isValid = MLDsa.Create()
///     .WithPublicKey(publicKeyPem)
///     .WithData(messageBytes)
///     .Verify(signature);
/// </code>
/// </example>
[Experimental("SYSLIB5006")]
public class MLDsaBuilder : IDisposable
{
    private MLDsaWrapper.SecurityLevel securityLevel = MLDsaWrapper.SecurityLevel.MLDsa65;
    private string? publicKeyPem;
    private MLDsaWrapper.MLDsaKeyPair? keyPair;
    private byte[]? data;
    private byte[]? context;
    private bool disposed;

    /// <summary>
    /// Creates a new ML-DSA builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is not supported on this platform</exception>
    public static MLDsaBuilder Create()
    {
        if (!MLDsaWrapper.IsSupported())
        {
            throw new PlatformNotSupportedException(
                "ML-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }
        return new MLDsaBuilder();
    }

    private MLDsaBuilder() { }

    /// <summary>
    /// Sets the security level for key generation
    /// </summary>
    /// <param name="level">The desired security level (default: MLDsa65)</param>
    /// <returns>The builder instance for method chaining</returns>
    public MLDsaBuilder WithSecurityLevel(MLDsaWrapper.SecurityLevel level)
    {
        securityLevel = level;
        return this;
    }

    /// <summary>
    /// Sets the security level based on required post-quantum security bits
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <returns>The builder instance for method chaining</returns>
    public MLDsaBuilder WithSecurityBits(int securityBits)
    {
        securityLevel = MLDsaWrapper.GetRecommendedLevel(securityBits);
        return this;
    }

    /// <summary>
    /// Sets the public key for verification operations
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    public MLDsaBuilder WithPublicKey(string publicKeyPem)
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
    /// Sets an existing key pair for signing operations
    /// </summary>
    /// <param name="keyPair">An existing ML-DSA key pair</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If keyPair is null</exception>
    public MLDsaBuilder WithKeyPair(MLDsaWrapper.MLDsaKeyPair keyPair)
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
    /// Sets the data to be signed or verified
    /// </summary>
    /// <param name="data">The data bytes</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If data is null</exception>
    public MLDsaBuilder WithData(byte[] data)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
#endif

        this.data = data;
        return this;
    }

    /// <summary>
    /// Sets the data to be signed or verified from a string
    /// </summary>
    /// <param name="data">The data string (UTF-8 encoded)</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If data is null</exception>
    public MLDsaBuilder WithData(string data)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
#endif

        this.data = System.Text.Encoding.UTF8.GetBytes(data);
        return this;
    }

    /// <summary>
    /// Sets an optional context string for domain separation (max 255 bytes)
    /// </summary>
    /// <param name="context">The context bytes</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">If context exceeds 255 bytes</exception>
    public MLDsaBuilder WithContext(byte[] context)
    {
        if (context != null && context.Length > 255)
        {
            throw new ArgumentException("Context must be 255 bytes or less", nameof(context));
        }

        this.context = context;
        return this;
    }

    /// <summary>
    /// Sets an optional context string for domain separation from a string
    /// </summary>
    /// <param name="context">The context string (UTF-8 encoded, max 255 bytes)</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">If context exceeds 255 bytes when encoded</exception>
    public MLDsaBuilder WithContext(string context)
    {
        if (context == null)
        {
            this.context = null;
            return this;
        }

        var contextBytes = System.Text.Encoding.UTF8.GetBytes(context);
        if (contextBytes.Length > 255)
        {
            throw new ArgumentException("Context must be 255 bytes or less when UTF-8 encoded", nameof(context));
        }

        this.context = contextBytes;
        return this;
    }

    /// <summary>
    /// Generates a new ML-DSA key pair with the configured security level
    /// </summary>
    /// <returns>A new ML-DSA key pair</returns>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    public MLDsaWrapper.MLDsaKeyPair GenerateKeyPair()
    {
        return MLDsaWrapper.GenerateKeyPair(securityLevel);
    }

    /// <summary>
    /// Signs the configured data using the configured key pair
    /// </summary>
    /// <returns>The signature bytes</returns>
    /// <exception cref="InvalidOperationException">If key pair or data is not configured</exception>
    /// <exception cref="CryptographicException">If signing fails</exception>
    public byte[] Sign()
    {
        if (keyPair == null)
        {
            throw new InvalidOperationException("Key pair must be set before signing. Use WithKeyPair()");
        }

        if (data == null)
        {
            throw new InvalidOperationException("Data must be set before signing. Use WithData()");
        }

        return keyPair.Sign(data, context);
    }

    /// <summary>
    /// Verifies the signature against the configured data and public key
    /// </summary>
    /// <param name="signature">The signature to verify</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    /// <exception cref="ArgumentNullException">If signature is null</exception>
    /// <exception cref="InvalidOperationException">If public key or data is not configured</exception>
    public bool Verify(byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);

        if (publicKeyPem == null)
        {
            throw new InvalidOperationException("Public key must be set before verification. Use WithPublicKey()");
        }

        if (data == null)
        {
            throw new InvalidOperationException("Data must be set before verification. Use WithData()");
        }

        return MLDsaWrapper.Verify(publicKeyPem, data, signature, context);
    }

    /// <summary>
    /// Gets information about the configured security level
    /// </summary>
    /// <returns>Tuple of (security bits, signature size, description)</returns>
    public (int SecurityBits, int SignatureSize, string Description) GetLevelInfo()
    {
        return MLDsaWrapper.GetLevelInfo(securityLevel);
    }

    /// <summary>
    /// Disposes the builder and clears sensitive data
    /// Note: Does not dispose externally provided key pairs
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            // Clear sensitive data
            if (data != null)
            {
                Array.Clear(data, 0, data.Length);
                data = null;
            }

            if (context != null)
            {
                Array.Clear(context, 0, context.Length);
                context = null;
            }

            // Note: We don't dispose keyPair as it was provided externally
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}

#endif
