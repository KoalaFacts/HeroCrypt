using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>
/// Fluent builder for secp256k1 elliptic curve operations.
/// Provides digital signatures and key management for blockchain applications.
/// </summary>
/// <remarks>
/// <para>
/// The secp256k1 curve is widely used in blockchain technologies, including Bitcoin and Ethereum.
/// It provides 128-bit security and supports both compressed and uncompressed public key formats.
/// </para>
/// <para><b>Platform Support:</b></para>
/// <list type="bullet">
///   <item>Windows: Fully supported via CNG</item>
///   <item>Linux: Fully supported via OpenSSL</item>
///   <item>macOS: Not natively supported - requires libsecp256k1</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// // Generate a key pair
/// using var builder = Secp256k1Builder.Create();
/// var (privateKey, publicKey) = builder.GenerateKeyPair();
///
/// // Sign a message hash
/// using var signer = Secp256k1Builder.Create()
///     .WithPrivateKey(privateKey)
///     .WithMessageHash(messageHash);
/// var signature = signer.Sign();
///
/// // Verify a signature
/// using var verifier = Secp256k1Builder.Create()
///     .WithPublicKey(publicKey)
///     .WithMessageHash(messageHash)
///     .WithSignature(signature);
/// bool isValid = verifier.Verify();
///
/// // Compress a public key
/// using var compressor = Secp256k1Builder.Create()
///     .WithPublicKey(uncompressedPublicKey);
/// var compressed = compressor.CompressPublicKey();
///
/// // Decompress a public key
/// using var decompressor = Secp256k1Builder.Create()
///     .WithPublicKey(compressedPublicKey);
/// var uncompressed = decompressor.DecompressPublicKey();
/// </code>
/// </example>
public sealed class Secp256k1Builder : IDisposable
{
    private const int PrivateKeySize = Secp256k1Core.PRIVATE_KEY_SIZE;
    private const int UncompressedPublicKeySize = Secp256k1Core.UNCOMPRESSED_PUBLIC_KEY_SIZE;
    private const int CompressedPublicKeySize = Secp256k1Core.COMPRESSED_PUBLIC_KEY_SIZE;
    private const int SignatureSize = Secp256k1Core.SIGNATURE_SIZE;

    private byte[]? privateKey;
    private byte[]? publicKey;
    private byte[]? messageHash;
    private byte[]? signature;
    private bool disposed;

    private Secp256k1Builder() { }

    /// <summary>
    /// Creates a new secp256k1 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Secp256k1Builder Create() => new();

    /// <summary>
    /// Sets the private key for signing or key derivation operations.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null.</exception>
    /// <exception cref="ArgumentException">If privateKey is not 32 bytes.</exception>
    public Secp256k1Builder WithPrivateKey(byte[] privateKey)
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
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If privateKey is not 32 bytes.</exception>
    public Secp256k1Builder WithPrivateKey(ReadOnlySpan<byte> privateKey)
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
    /// Sets the public key for signature verification or compression operations.
    /// </summary>
    /// <param name="publicKey">The public key (33 or 65 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If publicKey is null.</exception>
    /// <exception cref="ArgumentException">If publicKey is not 33 or 65 bytes.</exception>
    public Secp256k1Builder WithPublicKey(byte[] publicKey)
    {
        ArgumentHelper.ThrowIfNull(publicKey);
        if (publicKey.Length is not CompressedPublicKeySize and not UncompressedPublicKeySize)
        {
            throw new ArgumentException($"Public key must be {CompressedPublicKeySize} or {UncompressedPublicKeySize} bytes, but was {publicKey.Length} bytes.", nameof(publicKey));
        }

        ClearPublicKey();
        this.publicKey = [.. publicKey];
        return this;
    }

    /// <summary>
    /// Sets the public key for signature verification or compression operations.
    /// </summary>
    /// <param name="publicKey">The public key (33 or 65 bytes).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If publicKey is not 33 or 65 bytes.</exception>
    public Secp256k1Builder WithPublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length is not CompressedPublicKeySize and not UncompressedPublicKeySize)
        {
            throw new ArgumentException($"Public key must be {CompressedPublicKeySize} or {UncompressedPublicKeySize} bytes, but was {publicKey.Length} bytes.", nameof(publicKey));
        }

        ClearPublicKey();
        this.publicKey = publicKey.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the message hash to be signed or verified.
    /// </summary>
    /// <param name="messageHash">The 32-byte message hash (e.g., SHA-256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If messageHash is null.</exception>
    /// <exception cref="ArgumentException">If messageHash is not 32 bytes.</exception>
    public Secp256k1Builder WithMessageHash(byte[] messageHash)
    {
        ArgumentHelper.ThrowIfNull(messageHash);
        if (messageHash.Length != 32)
        {
            throw new ArgumentException($"Message hash must be 32 bytes, but was {messageHash.Length} bytes.", nameof(messageHash));
        }

        ClearMessageHash();
        this.messageHash = [.. messageHash];
        return this;
    }

    /// <summary>
    /// Sets the message hash to be signed or verified.
    /// </summary>
    /// <param name="messageHash">The 32-byte message hash (e.g., SHA-256).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If messageHash is not 32 bytes.</exception>
    public Secp256k1Builder WithMessageHash(ReadOnlySpan<byte> messageHash)
    {
        if (messageHash.Length != 32)
        {
            throw new ArgumentException($"Message hash must be 32 bytes, but was {messageHash.Length} bytes.", nameof(messageHash));
        }

        ClearMessageHash();
        this.messageHash = messageHash.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the signature to be verified.
    /// </summary>
    /// <param name="signature">The 64-byte signature (r || s).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If signature is null.</exception>
    /// <exception cref="ArgumentException">If signature is not 64 bytes.</exception>
    public Secp256k1Builder WithSignature(byte[] signature)
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
    /// <param name="signature">The 64-byte signature (r || s).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If signature is not 64 bytes.</exception>
    public Secp256k1Builder WithSignature(ReadOnlySpan<byte> signature)
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
    /// Generates a new secp256k1 key pair.
    /// </summary>
    /// <returns>A tuple containing the private key (32 bytes) and uncompressed public key (65 bytes).</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        return Secp256k1Core.GenerateKeyPair();
    }

    /// <summary>
    /// Signs the message hash using the private key.
    /// </summary>
    /// <returns>The 64-byte signature (r || s).</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If private key or message hash is not set.</exception>
    public byte[] Sign()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePrivateKey();
        ValidateMessageHash();
        return Secp256k1Core.Sign(messageHash!, privateKey!);
    }

    /// <summary>
    /// Verifies the signature against the message hash using the public key.
    /// </summary>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If public key, message hash, or signature is not set.</exception>
    public bool Verify()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePublicKey();
        ValidateMessageHash();
        ValidateSignature();
        return Secp256k1Core.Verify(messageHash!, signature!, publicKey!);
    }

    /// <summary>
    /// Compresses the public key.
    /// </summary>
    /// <returns>The 33-byte compressed public key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If public key is not set or is not uncompressed.</exception>
    public byte[] CompressPublicKey()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePublicKey();

        if (publicKey!.Length != UncompressedPublicKeySize)
        {
            throw new InvalidOperationException($"Public key must be uncompressed ({UncompressedPublicKeySize} bytes) to compress it.");
        }

        return Secp256k1Core.CompressPublicKey(publicKey);
    }

    /// <summary>
    /// Decompresses the public key.
    /// </summary>
    /// <returns>The 65-byte uncompressed public key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If public key is not set or is not compressed.</exception>
    public byte[] DecompressPublicKey()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePublicKey();

        if (publicKey!.Length != CompressedPublicKeySize)
        {
            throw new InvalidOperationException($"Public key must be compressed ({CompressedPublicKeySize} bytes) to decompress it.");
        }

        return Secp256k1Core.DecompressPublicKey(publicKey);
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

    private void ValidateMessageHash()
    {
        if (messageHash == null)
        {
            throw new InvalidOperationException("Message hash has not been set. Use WithMessageHash() first.");
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

    private void ClearMessageHash()
    {
        if (messageHash != null)
        {
            SecureMemoryOperations.SecureClear(messageHash);
            messageHash = null;
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
            ClearMessageHash();
            ClearSignature();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
