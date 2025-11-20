#if NET10_0_OR_GREATER
#pragma warning disable SYSLIB5006 // SLH-DSA wrapper uses experimental APIs in .NET 10 preview
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Primitives.PostQuantum.Sphincs;

/// <summary>
/// Fluent builder for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) operations
/// Provides an intuitive API for quantum-resistant hash-based signatures
/// </summary>
/// <example>
/// <code>
/// // Generate key pair and sign (prefer small signatures)
/// using var keyPair = SlhDsa.Create()
///     .WithSecurityBits(128, preferSmall: true)
///     .GenerateKeyPair();
///
/// var signature = SlhDsa.Create()
///     .WithKeyPair(keyPair)
///     .WithData(messageBytes)
///     .Sign();
///
/// // Verify signature
/// bool isValid = SlhDsa.Create()
///     .WithPublicKey(publicKeyPem)
///     .WithData(messageBytes)
///     .Verify(signature);
/// </code>
/// </example>

public class SlhDsaBuilder : IDisposable
{
    private SlhDsaWrapper.SecurityLevel _securityLevel = SlhDsaWrapper.SecurityLevel.SlhDsa128s;
    private string? _publicKeyPem;
    private SlhDsaWrapper.SlhDsaKeyPair? _keyPair;
    private byte[]? _data;
    private byte[]? _context;
    private bool _disposed;

    /// <summary>
    /// Creates a new SLH-DSA builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    /// <exception cref="PlatformNotSupportedException">If SLH-DSA is not supported on this platform</exception>

    public static SlhDsaBuilder Create()
    {
        if (!SlhDsaWrapper.IsSupported())
        {
            throw new PlatformNotSupportedException(
                "SLH-DSA is not supported on this platform. " +
                "Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
        }
        return new SlhDsaBuilder();
    }

    private SlhDsaBuilder() { }

    /// <summary>
    /// Sets the security level for key generation
    /// </summary>
    /// <param name="level">The desired security level (default: SlhDsa128s)</param>
    /// <returns>The builder instance for method chaining</returns>
    public SlhDsaBuilder WithSecurityLevel(SlhDsaWrapper.SecurityLevel level)
    {
        _securityLevel = level;
        return this;
    }

    /// <summary>
    /// Sets the security level based on required post-quantum security bits and variant preference
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <param name="preferSmall">If true, prefer "small" variant (smaller signatures); otherwise prefer "fast" variant</param>
    /// <returns>The builder instance for method chaining</returns>
    public SlhDsaBuilder WithSecurityBits(int securityBits, bool preferSmall = true)
    {
        _securityLevel = SlhDsaWrapper.GetRecommendedLevel(securityBits, preferSmall);
        return this;
    }

    /// <summary>
    /// Explicitly chooses the "small" variant for smaller signatures (slower signing)
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <returns>The builder instance for method chaining</returns>
    public SlhDsaBuilder WithSmallVariant(int securityBits = 128)
    {
        return WithSecurityBits(securityBits, preferSmall: true);
    }

    /// <summary>
    /// Explicitly chooses the "fast" variant for faster signing (larger signatures)
    /// </summary>
    /// <param name="securityBits">Required security bits (128, 192, or 256)</param>
    /// <returns>The builder instance for method chaining</returns>
    public SlhDsaBuilder WithFastVariant(int securityBits = 128)
    {
        return WithSecurityBits(securityBits, preferSmall: false);
    }

    /// <summary>
    /// Sets the public key for verification operations
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If publicKeyPem is null</exception>
    public SlhDsaBuilder WithPublicKey(string publicKeyPem)
    {
        ArgumentNullException.ThrowIfNull(publicKeyPem);

        _publicKeyPem = publicKeyPem;
        return this;
    }

    /// <summary>
    /// Sets an existing key pair for signing operations
    /// </summary>
    /// <param name="keyPair">An existing SLH-DSA key pair</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If keyPair is null</exception>
    public SlhDsaBuilder WithKeyPair(SlhDsaWrapper.SlhDsaKeyPair keyPair)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(keyPair);
#else
        if (keyPair == null)
        {
            throw new ArgumentNullException(nameof(keyPair));
        }
#endif

        _keyPair = keyPair;
        return this;
    }

    /// <summary>
    /// Sets the data to be signed or verified
    /// </summary>
    /// <param name="data">The data bytes</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If data is null</exception>
    public SlhDsaBuilder WithData(byte[] data)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
#endif

        _data = data;
        return this;
    }

    /// <summary>
    /// Sets the data to be signed or verified from a string
    /// </summary>
    /// <param name="data">The data string (UTF-8 encoded)</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">If data is null</exception>
    public SlhDsaBuilder WithData(string data)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
#endif

        _data = System.Text.Encoding.UTF8.GetBytes(data);
        return this;
    }

    /// <summary>
    /// Sets an optional context string for domain separation (max 255 bytes)
    /// </summary>
    /// <param name="context">The context bytes</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">If context exceeds 255 bytes</exception>
    public SlhDsaBuilder WithContext(byte[] context)
    {
        if (context != null && context.Length > 255)
        {
            throw new ArgumentException("Context must be 255 bytes or less", nameof(context));
        }

        _context = context;
        return this;
    }

    /// <summary>
    /// Sets an optional context string for domain separation from a string
    /// </summary>
    /// <param name="context">The context string (UTF-8 encoded, max 255 bytes)</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">If context exceeds 255 bytes when encoded</exception>
    public SlhDsaBuilder WithContext(string context)
    {
        if (context == null)
        {
            _context = null;
            return this;
        }

        var contextBytes = System.Text.Encoding.UTF8.GetBytes(context);
        if (contextBytes.Length > 255)
        {
            throw new ArgumentException("Context must be 255 bytes or less when UTF-8 encoded", nameof(context));
        }

        _context = contextBytes;
        return this;
    }

    /// <summary>
    /// Generates a new SLH-DSA key pair with the configured security level
    /// </summary>
    /// <returns>A new SLH-DSA key pair</returns>
    /// <exception cref="CryptographicException">If key generation fails</exception>

    public SlhDsaWrapper.SlhDsaKeyPair GenerateKeyPair()
    {
        return SlhDsaWrapper.GenerateKeyPair(_securityLevel);
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
        {
            throw new InvalidOperationException("Key pair must be set before signing. Use WithKeyPair()");
        }

        if (_data == null)
        {
            throw new InvalidOperationException("Data must be set before signing. Use WithData()");
        }

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
        ArgumentNullException.ThrowIfNull(signature);

        if (_publicKeyPem == null)
        {
            throw new InvalidOperationException("Public key must be set before verification. Use WithPublicKey()");
        }

        if (_data == null)
        {
            throw new InvalidOperationException("Data must be set before verification. Use WithData()");
        }

        return SlhDsaWrapper.Verify(_publicKeyPem, _data, signature, _context);
    }

    /// <summary>
    /// Gets information about the configured security level
    /// </summary>
    /// <returns>Tuple of (security bits, approximate signature size, description)</returns>
    public (int SecurityBits, int SignatureSizeApprox, string Description) GetLevelInfo()
    {
        return SlhDsaWrapper.GetLevelInfo(_securityLevel);
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
            GC.SuppressFinalize(this);
        }
    }
}

/// <summary>
/// Provides a short-hand fluent API for SLH-DSA operations
/// </summary>

public static class SlhDsa
{
    /// <summary>
    /// Creates a new SLH-DSA builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>

    public static SlhDsaBuilder Create() => SlhDsaBuilder.Create();

    /// <summary>
    /// Quick method to generate a key pair with recommended security (SLH-DSA-128s)
    /// </summary>
    /// <returns>A new SLH-DSA key pair</returns>

    public static SlhDsaWrapper.SlhDsaKeyPair GenerateKeyPair() =>
        SlhDsaWrapper.GenerateKeyPair(SlhDsaWrapper.SecurityLevel.SlhDsa128s);

    /// <summary>
    /// Quick method to generate a key pair with specified security level
    /// </summary>
    /// <param name="level">The security level</param>
    /// <returns>A new SLH-DSA key pair</returns>

    public static SlhDsaWrapper.SlhDsaKeyPair GenerateKeyPair(SlhDsaWrapper.SecurityLevel level) =>
        SlhDsaWrapper.GenerateKeyPair(level);

    /// <summary>
    /// Quick method to verify a signature
    /// </summary>
    /// <param name="publicKeyPem">The public key in PEM format</param>
    /// <param name="data">The data that was signed</param>
    /// <param name="signature">The signature to verify</param>
    /// <returns>True if valid, false otherwise</returns>

    public static bool Verify(string publicKeyPem, byte[] data, byte[] signature) =>
        SlhDsaWrapper.Verify(publicKeyPem, data, signature);
}
#endif
#pragma warning restore SYSLIB5006
