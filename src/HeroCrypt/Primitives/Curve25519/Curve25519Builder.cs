using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Curve25519;

/// <summary>
/// Fluent builder for Curve25519 (X25519) key agreement operations.
/// Provides high-speed elliptic curve Diffie-Hellman (ECDH) according to RFC 7748.
/// </summary>
/// <remarks>
/// X25519 is a Diffie-Hellman key agreement scheme using Curve25519.
/// It enables two parties to establish a shared secret over an insecure channel.
/// </remarks>
/// <example>
/// <code>
/// // Generate a key pair
/// using var builder = Curve25519Builder.Create();
/// var (privateKey, publicKey) = builder.GenerateKeyPair();
///
/// // Derive public key from private key
/// using var deriver = Curve25519Builder.Create()
///     .WithPrivateKey(privateKey);
/// var derivedPublicKey = deriver.DerivePublicKey();
///
/// // Compute shared secret (Alice's side)
/// using var aliceBuilder = Curve25519Builder.Create()
///     .WithPrivateKey(alicePrivateKey)
///     .WithRemotePublicKey(bobPublicKey);
/// var aliceSharedSecret = aliceBuilder.ComputeSharedSecret();
///
/// // Compute shared secret (Bob's side)
/// using var bobBuilder = Curve25519Builder.Create()
///     .WithPrivateKey(bobPrivateKey)
///     .WithRemotePublicKey(alicePublicKey);
/// var bobSharedSecret = bobBuilder.ComputeSharedSecret();
/// // aliceSharedSecret will equal bobSharedSecret
/// </code>
/// </example>
public sealed class Curve25519Builder : IDisposable
{
    private const int KeySize = 32;

    private byte[]? privateKey;
    private byte[]? remotePublicKey;
    private bool disposed;

    private Curve25519Builder() { }

    /// <summary>
    /// Creates a new Curve25519 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Curve25519Builder Create() => new();

    /// <summary>
    /// Sets the local private key for key agreement or key derivation operations.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null.</exception>
    /// <exception cref="ArgumentException">If privateKey is not 32 bytes.</exception>
    public Curve25519Builder WithPrivateKey(byte[] privateKey)
    {
        ArgumentHelper.ThrowIfNull(privateKey);
        if (privateKey.Length != KeySize)
        {
            throw new ArgumentException($"Private key must be {KeySize} bytes, but was {privateKey.Length} bytes.", nameof(privateKey));
        }

        ClearPrivateKey();
        this.privateKey = [.. privateKey];
        return this;
    }

    /// <summary>
    /// Sets the local private key for key agreement or key derivation operations.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If privateKey is not 32 bytes.</exception>
    public Curve25519Builder WithPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != KeySize)
        {
            throw new ArgumentException($"Private key must be {KeySize} bytes, but was {privateKey.Length} bytes.", nameof(privateKey));
        }

        ClearPrivateKey();
        this.privateKey = privateKey.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the remote party's public key for key agreement operations.
    /// </summary>
    /// <param name="remotePublicKey">The 32-byte remote public key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If remotePublicKey is null.</exception>
    /// <exception cref="ArgumentException">If remotePublicKey is not 32 bytes.</exception>
    public Curve25519Builder WithRemotePublicKey(byte[] remotePublicKey)
    {
        ArgumentHelper.ThrowIfNull(remotePublicKey);
        if (remotePublicKey.Length != KeySize)
        {
            throw new ArgumentException($"Remote public key must be {KeySize} bytes, but was {remotePublicKey.Length} bytes.", nameof(remotePublicKey));
        }

        ClearRemotePublicKey();
        this.remotePublicKey = [.. remotePublicKey];
        return this;
    }

    /// <summary>
    /// Sets the remote party's public key for key agreement operations.
    /// </summary>
    /// <param name="remotePublicKey">The 32-byte remote public key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">If remotePublicKey is not 32 bytes.</exception>
    public Curve25519Builder WithRemotePublicKey(ReadOnlySpan<byte> remotePublicKey)
    {
        if (remotePublicKey.Length != KeySize)
        {
            throw new ArgumentException($"Remote public key must be {KeySize} bytes, but was {remotePublicKey.Length} bytes.", nameof(remotePublicKey));
        }

        ClearRemotePublicKey();
        this.remotePublicKey = remotePublicKey.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a new Curve25519 key pair.
    /// </summary>
    /// <returns>A tuple containing the private key (32 bytes) and public key (32 bytes).</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        var privateKey = Curve25519Core.GeneratePrivateKey();
        var publicKey = Curve25519Core.DerivePublicKey(privateKey);
        return (privateKey, publicKey);
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
        return Curve25519Core.DerivePublicKey(privateKey!);
    }

    /// <summary>
    /// Computes the shared secret using the local private key and remote public key.
    /// </summary>
    /// <returns>The 32-byte shared secret.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If private key or remote public key is not set.</exception>
    public byte[] ComputeSharedSecret()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePrivateKey();
        ValidateRemotePublicKey();
        return Curve25519Core.ComputeSharedSecret(privateKey!, remotePublicKey!);
    }

    private void ValidatePrivateKey()
    {
        if (privateKey == null)
        {
            throw new InvalidOperationException("Private key has not been set. Use WithPrivateKey() first.");
        }
    }

    private void ValidateRemotePublicKey()
    {
        if (remotePublicKey == null)
        {
            throw new InvalidOperationException("Remote public key has not been set. Use WithRemotePublicKey() first.");
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

    private void ClearRemotePublicKey()
    {
        if (remotePublicKey != null)
        {
            SecureMemoryOperations.SecureClear(remotePublicKey);
            remotePublicKey = null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearPrivateKey();
            ClearRemotePublicKey();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
