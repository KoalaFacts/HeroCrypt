using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Ed25519;

/// <summary>
/// Fluent builder for Ed25519 digital signature operations.
/// Provides high-security elliptic curve signatures according to RFC 8032.
/// </summary>
/// <example>
/// <code>
/// // Generate a key pair
/// using var builder = Ed25519Builder.Create();
/// var (privateKey, publicKey) = builder.GenerateKeyPair();
///
/// // Sign a message
/// using var signer = Ed25519Builder.Create()
///     .WithPrivateKey(privateKey)
///     .WithMessage(message);
/// var signature = signer.Sign();
///
/// // Verify a signature
/// using var verifier = Ed25519Builder.Create()
///     .WithPublicKey(publicKey)
///     .WithMessage(message)
///     .WithSignature(signature);
/// bool isValid = verifier.Verify();
///
/// // Derive public key from private key
/// using var deriver = Ed25519Builder.Create()
///     .WithPrivateKey(privateKey);
/// var derivedPublicKey = deriver.DerivePublicKey();
/// </code>
/// </example>
public sealed class Ed25519Builder : IDisposable
{
    private const int PrivateKeySize = Ed25519Core.PRIVATE_KEY_SIZE;
    private const int PublicKeySize = Ed25519Core.PUBLIC_KEY_SIZE;
    private const int SignatureSize = Ed25519Core.SIGNATURE_SIZE;

    private byte[]? privateKey;
    private byte[]? publicKey;
    private byte[]? message;
    private byte[]? signature;
    private bool disposed;

    private Ed25519Builder() { }

    /// <summary>
    /// Creates a new Ed25519 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Ed25519Builder Create() => new();

    /// <summary>
    /// Sets the private key for signing or key derivation operations.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key seed.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null.</exception>
    /// <exception cref="ArgumentException">If privateKey is not 32 bytes.</exception>
    public Ed25519Builder WithPrivateKey(byte[] privateKey)
    {
        ArgumentHelper.ThrowIfNull(privateKey);
        if (privateKey.Length != PrivateKeySize)
        {
            throw new ArgumentException($"Private key must be {PrivateKeySize} bytes, but was {privateKey.Length} bytes.", nameof(privateKey));
        }

        ClearPrivateKey();
        this.privateKey = [.. privateKey];
        return this;
    }

    /// <summary>
    /// Sets the private key for signing or key derivation operations.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key seed.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If privateKey is not 32 bytes.</exception>
    public Ed25519Builder WithPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != PrivateKeySize)
        {
            throw new ArgumentException($"Private key must be {PrivateKeySize} bytes, but was {privateKey.Length} bytes.", nameof(privateKey));
        }

        ClearPrivateKey();
        this.privateKey = privateKey.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the public key for signature verification operations.
    /// </summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If publicKey is null.</exception>
    /// <exception cref="ArgumentException">If publicKey is not 32 bytes.</exception>
    public Ed25519Builder WithPublicKey(byte[] publicKey)
    {
        ArgumentHelper.ThrowIfNull(publicKey);
        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentException($"Public key must be {PublicKeySize} bytes, but was {publicKey.Length} bytes.", nameof(publicKey));
        }

        ClearPublicKey();
        this.publicKey = [.. publicKey];
        return this;
    }

    /// <summary>
    /// Sets the public key for signature verification operations.
    /// </summary>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If publicKey is not 32 bytes.</exception>
    public Ed25519Builder WithPublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentException($"Public key must be {PublicKeySize} bytes, but was {publicKey.Length} bytes.", nameof(publicKey));
        }

        ClearPublicKey();
        this.publicKey = publicKey.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the message to be signed or verified.
    /// </summary>
    /// <param name="message">The message bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Ed25519Builder WithMessage(byte[]? message)
    {
        ClearMessage();
        this.message = message != null ? [.. message] : null;
        return this;
    }

    /// <summary>
    /// Sets the message to be signed or verified.
    /// </summary>
    /// <param name="message">The message bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public Ed25519Builder WithMessage(ReadOnlySpan<byte> message)
    {
        ClearMessage();
        this.message = message.IsEmpty ? null : message.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the signature to be verified.
    /// </summary>
    /// <param name="signature">The 64-byte signature.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If signature is null.</exception>
    /// <exception cref="ArgumentException">If signature is not 64 bytes.</exception>
    public Ed25519Builder WithSignature(byte[] signature)
    {
        ArgumentHelper.ThrowIfNull(signature);
        if (signature.Length != SignatureSize)
        {
            throw new ArgumentException($"Signature must be {SignatureSize} bytes, but was {signature.Length} bytes.", nameof(signature));
        }

        ClearSignature();
        this.signature = [.. signature];
        return this;
    }

    /// <summary>
    /// Sets the signature to be verified.
    /// </summary>
    /// <param name="signature">The 64-byte signature.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If signature is not 64 bytes.</exception>
    public Ed25519Builder WithSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length != SignatureSize)
        {
            throw new ArgumentException($"Signature must be {SignatureSize} bytes, but was {signature.Length} bytes.", nameof(signature));
        }

        ClearSignature();
        this.signature = signature.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a new Ed25519 key pair.
    /// </summary>
    /// <returns>A tuple containing the private key seed (32 bytes) and public key (32 bytes).</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        return Ed25519Core.GenerateKeyPair();
    }

    /// <summary>
    /// Derives the public key from the private key.
    /// </summary>
    /// <returns>The 32-byte public key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If private key is not set.</exception>
    public byte[] DerivePublicKey()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePrivateKey();
        return Ed25519Core.DerivePublicKey(privateKey!);
    }

    /// <summary>
    /// Signs the message using the private key.
    /// </summary>
    /// <returns>The 64-byte signature.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If private key or message is not set.</exception>
    public byte[] Sign()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePrivateKey();
        ValidateMessage();
        return Ed25519Core.Sign(message!, privateKey!);
    }

    /// <summary>
    /// Verifies the signature against the message using the public key.
    /// </summary>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If public key, message, or signature is not set.</exception>
    public bool Verify()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePublicKey();
        ValidateMessage();
        ValidateSignature();
        return Ed25519Core.Verify(message!, signature!, publicKey!);
    }

    private void ValidatePrivateKey()
    {
        if (privateKey == null)
        {
            throw new InvalidOperationException("Private key has not been set. Use WithPrivateKey() first.");
        }
    }

    private void ValidatePublicKey()
    {
        if (publicKey == null)
        {
            throw new InvalidOperationException("Public key has not been set. Use WithPublicKey() first.");
        }
    }

    private void ValidateMessage()
    {
        if (message == null)
        {
            throw new InvalidOperationException("Message has not been set. Use WithMessage() first.");
        }
    }

    private void ValidateSignature()
    {
        if (signature == null)
        {
            throw new InvalidOperationException("Signature has not been set. Use WithSignature() first.");
        }
    }

    private void ClearPrivateKey()
    {
        if (privateKey != null)
        {
            SecureMemoryOperations.SecureClear(privateKey);
            privateKey = null;
        }
    }

    private void ClearPublicKey()
    {
        if (publicKey != null)
        {
            SecureMemoryOperations.SecureClear(publicKey);
            publicKey = null;
        }
    }

    private void ClearMessage()
    {
        if (message != null)
        {
            SecureMemoryOperations.SecureClear(message);
            message = null;
        }
    }

    private void ClearSignature()
    {
        if (signature != null)
        {
            SecureMemoryOperations.SecureClear(signature);
            signature = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearPrivateKey();
            ClearPublicKey();
            ClearMessage();
            ClearSignature();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
