#if NET10_0_OR_GREATER
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.PostQuantum.Dilithium;

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
public class MLDsaBuilder : IDisposable
{
    private MLDsaWrapper.SecurityLevel _securityLevel = MLDsaWrapper.SecurityLevel.MLDsa65;
    private string? _publicKeyPem;
    private MLDsaWrapper.MLDsaKeyPair? _keyPair;
    private byte[]? _data;
    private byte[]? _context;
    private bool _disposed;

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
        _securityLevel = level;
        return this;
    }

    /// <summary>
    /// Sets the security level based on required post-quantum security bits
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <returns>The builder instance for method chaining</returns>
    public MLDsaBuilder WithSecurityBits(int securityBits)
    {
        _securityLevel = MLDsaWrapper.GetRecommendedLevel(securityBits);
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
        if (publicKeyPem == null)
            throw new ArgumentNullException(nameof(publicKeyPem));

        _publicKeyPem = publicKeyPem;
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
        if (keyPair == null)
            throw new ArgumentNullException(nameof(keyPair));

        _keyPair = keyPair;
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
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        _data = data;
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
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        _data = System.Text.Encoding.UTF8.GetBytes(data);
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
            throw new ArgumentException("Context must be 255 bytes or less", nameof(context));

        _context = context;
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
            _context = null;
            return this;
        }

        var contextBytes = System.Text.Encoding.UTF8.GetBytes(context);
        if (contextBytes.Length > 255)
            throw new ArgumentException("Context must be 255 bytes or less when UTF-8 encoded", nameof(context));

        _context = contextBytes;
        return this;
    }

    /// <summary>
    /// Generates a new ML-DSA key pair with the configured security level
    /// </summary>
    /// <returns>A new ML-DSA key pair</returns>
    /// <exception cref="CryptographicException">If key generation fails</exception>
    public MLDsaWrapper.MLDsaKeyPair GenerateKeyPair()
    {
        return MLDsaWrapper.GenerateKeyPair(_securityLevel);
    }

    /// <summary>
    /// Signs the configured data using the configured key pair
    /// </summary>
    /// <returns>The signature bytes</returns>
    /// <exception cref="InvalidOperationException">If key pair or data is not configured</exception>
    /// <exception cref="CryptographicException">If signing fails</exception>
    public byte[] Sign()
    {
        if (_keyPair == null)
            throw new InvalidOperationException("Key pair must be set before signing. Use WithKeyPair()");

        if (_data == null)
            throw new InvalidOperationException("Data must be set before signing. Use WithData()");

        return _keyPair.Sign(_data, _context);
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
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        if (_publicKeyPem == null)
            throw new InvalidOperationException("Public key must be set before verification. Use WithPublicKey()");

        if (_data == null)
            throw new InvalidOperationException("Data must be set before verification. Use WithData()");

        return MLDsaWrapper.Verify(_publicKeyPem, _data, signature, _context);
    }

    /// <summary>
    /// Gets information about the configured security level
    /// </summary>
    /// <returns>Tuple of (security bits, signature size, description)</returns>
    public (int SecurityBits, int SignatureSize, string Description) GetLevelInfo()
    {
        return MLDsaWrapper.GetLevelInfo(_securityLevel);
    }

    /// <summary>
    /// Disposes the builder and clears sensitive data
    /// Note: Does not dispose externally provided key pairs
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            // Clear sensitive data
            if (_data != null)
            {
                Array.Clear(_data, 0, _data.Length);
                _data = null;
            }

            if (_context != null)
            {
                Array.Clear(_context, 0, _context.Length);
                _context = null;
            }

            // Note: We don't dispose _keyPair as it was provided externally
            _disposed = true;
        }
    }
}

/// <summary>
/// Provides a short-hand fluent API for ML-DSA operations
/// </summary>
public static class MLDsa
{
    /// <summary>
    /// Creates a new ML-DSA builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    public static MLDsaBuilder Create() => MLDsaBuilder.Create();

    /// <summary>
    /// Quick method to generate a key pair with recommended security (ML-DSA-65)
    /// </summary>
    /// <returns>A new ML-DSA key pair</returns>
    public static MLDsaWrapper.MLDsaKeyPair GenerateKeyPair() =>
        MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

    /// <summary>
    /// Quick method to generate a key pair with specified security level
    /// </summary>
    /// <param name="level">The security level</param>
    /// <returns>A new ML-DSA key pair</returns>
    public static MLDsaWrapper.MLDsaKeyPair GenerateKeyPair(MLDsaWrapper.SecurityLevel level) =>
        MLDsaWrapper.GenerateKeyPair(level);

    /// <summary>
    /// Quick method to verify a signature
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <param name="data">The data that was signed</param>
    /// <param name="signature">The signature to verify</param>
    /// <returns>True if valid, false otherwise</returns>
    public static bool Verify(string publicKeyPem, byte[] data, byte[] signature) =>
        MLDsaWrapper.Verify(publicKeyPem, data, signature);
}
#endif
