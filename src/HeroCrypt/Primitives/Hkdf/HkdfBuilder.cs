using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Hkdf;

/// <summary>
/// Fluent builder for HKDF (HMAC-based Key Derivation Function) operations.
/// Implements RFC 5869 compliant key derivation.
/// </summary>
/// <example>
/// <code>
/// // Derive key from input key material
/// using var builder = HkdfBuilder.Create()
///     .WithInputKeyMaterial(ikm)
///     .WithSalt(salt)
///     .WithInfo(info)
///     .WithOutputLength(32)
///     .WithHashAlgorithm(HashAlgorithmName.SHA256);
/// var derivedKey = builder.DeriveKey();
///
/// // Derive key with general purpose preset
/// using var simpleBuilder = HkdfBuilder.Create()
///     .WithGeneralPurposePreset()
///     .WithInputKeyMaterial(ikm)
///     .WithOutputLength(32);
/// var key = simpleBuilder.DeriveKey();
/// </code>
/// </example>
public sealed class HkdfBuilder : IDisposable
{
    private const int DefaultOutputLength = 32;

    private byte[]? ikm;
    private byte[]? salt;
    private byte[]? info;
    private int outputLength = DefaultOutputLength;
    private HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
    private bool disposed;

    private HkdfBuilder() { }

    /// <summary>
    /// Creates a new HKDF builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static HkdfBuilder Create() => new();

    /// <summary>
    /// Sets the input key material.
    /// </summary>
    /// <param name="ikm">The input key material bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If ikm is null.</exception>
    /// <exception cref="ArgumentException">If ikm is empty.</exception>
    public HkdfBuilder WithInputKeyMaterial(byte[] ikm)
    {
        ArgumentHelper.ThrowIfNull(ikm);
        if (ikm.Length == 0)
        {
            throw new ArgumentException("Input key material cannot be empty.", nameof(ikm));
        }

        ClearInputKeyMaterial();
        this.ikm = [.. ikm];
        return this;
    }

    /// <summary>
    /// Sets the input key material.
    /// </summary>
    /// <param name="ikm">The input key material bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If ikm is empty.</exception>
    public HkdfBuilder WithInputKeyMaterial(ReadOnlySpan<byte> ikm)
    {
        if (ikm.IsEmpty)
        {
            throw new ArgumentException("Input key material cannot be empty.", nameof(ikm));
        }

        ClearInputKeyMaterial();
        this.ikm = ikm.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the input key material from a UTF-8 encoded string.
    /// </summary>
    /// <param name="ikm">The input key material string.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If ikm is null.</exception>
    /// <exception cref="ArgumentException">If ikm is empty.</exception>
    public HkdfBuilder WithInputKeyMaterial(string ikm)
    {
        ArgumentHelper.ThrowIfNull(ikm);
        if (ikm.Length == 0)
        {
            throw new ArgumentException("Input key material cannot be empty.", nameof(ikm));
        }

        ClearInputKeyMaterial();
        this.ikm = Encoding.UTF8.GetBytes(ikm);
        return this;
    }

    /// <summary>
    /// Sets the salt value. If not set, a zero-filled salt will be used.
    /// </summary>
    /// <param name="salt">The salt bytes (optional).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithSalt(byte[]? salt)
    {
        ClearSalt();
        this.salt = salt != null ? [.. salt] : null;
        return this;
    }

    /// <summary>
    /// Sets the salt value. If not set, a zero-filled salt will be used.
    /// </summary>
    /// <param name="salt">The salt bytes (optional).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithSalt(ReadOnlySpan<byte> salt)
    {
        ClearSalt();
        this.salt = salt.IsEmpty ? null : salt.ToArray();
        return this;
    }

    /// <summary>
    /// Generates and sets a random salt based on the hash algorithm length.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithRandomSalt()
    {
        var hashLength = GetHashLength(hashAlgorithm);
        ClearSalt();
        salt = new byte[hashLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return this;
    }

    /// <summary>
    /// Sets the application-specific context information (info parameter).
    /// </summary>
    /// <param name="info">The context information bytes (optional).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithInfo(byte[]? info)
    {
        ClearInfo();
        this.info = info != null ? [.. info] : null;
        return this;
    }

    /// <summary>
    /// Sets the application-specific context information (info parameter).
    /// </summary>
    /// <param name="info">The context information bytes (optional).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithInfo(ReadOnlySpan<byte> info)
    {
        ClearInfo();
        this.info = info.IsEmpty ? null : info.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the application-specific context information from a UTF-8 string.
    /// </summary>
    /// <param name="info">The context information string.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If info is null.</exception>
    public HkdfBuilder WithInfo(string info)
    {
        ArgumentHelper.ThrowIfNull(info);
        ClearInfo();
        this.info = Encoding.UTF8.GetBytes(info);
        return this;
    }

    /// <summary>
    /// Sets the desired output length in bytes.
    /// </summary>
    /// <param name="length">Output length in bytes (must be positive and not exceed maximum for hash algorithm).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If length is invalid.</exception>
    public HkdfBuilder WithOutputLength(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Output length must be positive.", nameof(length));
        }

        var maxLength = HkdfCore.GetMAX_OUTPUT_LENGTH(hashAlgorithm);
        if (length > maxLength)
        {
            throw new ArgumentException($"Output length exceeds maximum of {maxLength} bytes for {hashAlgorithm}.", nameof(length));
        }

        outputLength = length;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm to use for HKDF.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm (SHA256, SHA384, or SHA512).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If hash algorithm is not supported.</exception>
    public HkdfBuilder WithHashAlgorithm(HashAlgorithmName hashAlgorithm)
    {
        if (!HkdfCore.IsHashAlgorithmSupported(hashAlgorithm))
        {
            throw new ArgumentException($"Hash algorithm {hashAlgorithm} is not supported.", nameof(hashAlgorithm));
        }

        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /// <summary>
    /// Configures parameters for general-purpose key derivation with SHA-256.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithGeneralPurposePreset()
    {
        hashAlgorithm = HashAlgorithmName.SHA256;
        return this;
    }

    /// <summary>
    /// Configures parameters for high-security applications with SHA-512.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithHighSecurityPreset()
    {
        hashAlgorithm = HashAlgorithmName.SHA512;
        outputLength = 64;
        return this;
    }

    /// <summary>
    /// Configures parameters for TLS 1.3 key derivation with SHA-256.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public HkdfBuilder WithTlsPreset()
    {
        hashAlgorithm = HashAlgorithmName.SHA256;
        return this;
    }

    /// <summary>
    /// Derives a key using the configured parameters.
    /// </summary>
    /// <returns>The derived key material.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If input key material is not set.</exception>
    public byte[] DeriveKey()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateState();

        return HkdfCore.DeriveKey(
            ikm!,
            salt ?? ReadOnlySpan<byte>.Empty,
            info ?? ReadOnlySpan<byte>.Empty,
            outputLength,
            hashAlgorithm
        );
    }

    /// <summary>
    /// Performs only the Extract phase of HKDF, returning the pseudorandom key.
    /// </summary>
    /// <returns>The pseudorandom key from the Extract phase.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If input key material is not set.</exception>
    public byte[] Extract()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        if (ikm == null)
        {
            throw new InvalidOperationException("Input key material has not been set. Use WithInputKeyMaterial() first.");
        }

        return HkdfCore.Extract(
            ikm,
            salt ?? ReadOnlySpan<byte>.Empty,
            hashAlgorithm
        );
    }

    /// <summary>
    /// Performs only the Expand phase of HKDF using the provided pseudorandom key.
    /// </summary>
    /// <param name="prk">Pseudorandom key from Extract phase.</param>
    /// <returns>The derived key material.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="ArgumentNullException">If prk is null.</exception>
    /// <exception cref="ArgumentException">If prk is empty.</exception>
    public byte[] Expand(byte[] prk)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ArgumentHelper.ThrowIfNull(prk);
        if (prk.Length == 0)
        {
            throw new ArgumentException("Pseudorandom key cannot be empty.", nameof(prk));
        }

        return HkdfCore.Expand(
            prk,
            info ?? ReadOnlySpan<byte>.Empty,
            outputLength,
            hashAlgorithm
        );
    }

    /// <summary>
    /// Gets the salt that was set or generated.
    /// </summary>
    /// <returns>A copy of the salt bytes, or null if not set.</returns>
    public byte[]? GetSalt()
    {
        return salt != null ? [.. salt] : null;
    }

    private void ValidateState()
    {
        if (ikm == null)
        {
            throw new InvalidOperationException("Input key material has not been set. Use WithInputKeyMaterial() first.");
        }
    }

    private static int GetHashLength(HashAlgorithmName hashAlgorithm)
    {
        return hashAlgorithm.Name switch
        {
            "SHA1" => 20,
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => 32
        };
    }

    private void ClearInputKeyMaterial()
    {
        if (ikm != null)
        {
            SecureMemoryOperations.SecureClear(ikm);
            ikm = null;
        }
    }

    private void ClearSalt()
    {
        if (salt != null)
        {
            SecureMemoryOperations.SecureClear(salt);
            salt = null;
        }
    }

    private void ClearInfo()
    {
        if (info != null)
        {
            SecureMemoryOperations.SecureClear(info);
            info = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearInputKeyMaterial();
            ClearSalt();
            ClearInfo();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
