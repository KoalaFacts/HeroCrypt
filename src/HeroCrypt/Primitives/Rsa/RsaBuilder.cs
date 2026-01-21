using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Rsa;

/// <summary>
/// Fluent builder for RSA cryptographic operations.
/// Provides encryption, decryption, signing, and verification with configurable key sizes.
/// </summary>
/// <remarks>
/// <para>
/// RSA (Rivest-Shamir-Adleman) is a widely-used public-key cryptosystem for secure data transmission
/// and digital signatures. This builder supports multiple key sizes and padding modes.
/// </para>
/// <para><b>Recommended Key Sizes:</b></para>
/// <list type="bullet">
///   <item>2048 bits: Minimum recommended for current use</item>
///   <item>3072 bits: Recommended for sensitive data</item>
///   <item>4096 bits: Maximum security (slower performance)</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// // Generate a key pair
/// using var builder = RsaBuilder.Create()
///     .WithKeySize(RsaKeySize.Rsa2048);
/// var (privateKey, publicKey) = builder.GenerateKeyPair();
///
/// // Encrypt data
/// using var encryptor = RsaBuilder.Create()
///     .WithPublicKey(publicKey)
///     .WithData(plaintext);
/// var ciphertext = encryptor.Encrypt();
///
/// // Decrypt data
/// using var decryptor = RsaBuilder.Create()
///     .WithPrivateKey(privateKey)
///     .WithData(ciphertext);
/// var decrypted = decryptor.Decrypt();
///
/// // Sign data
/// using var signer = RsaBuilder.Create()
///     .WithPrivateKey(privateKey)
///     .WithData(data);
/// var signature = signer.Sign();
///
/// // Verify signature
/// using var verifier = RsaBuilder.Create()
///     .WithPublicKey(publicKey)
///     .WithData(data)
///     .WithSignature(signature);
/// bool isValid = verifier.Verify();
/// </code>
/// </example>
public sealed class RsaBuilder : IDisposable
{
    private RsaKeySize keySize = RsaKeySize.Rsa2048;
    private RsaPaddingMode paddingMode = RsaPaddingMode.Oaep;
    private HashAlgorithmName? hashAlgorithm = HashAlgorithmName.SHA256;
    private RsaPrivateKey? privateKey;
    private RsaPublicKey? publicKey;
    private byte[]? data;
    private byte[]? signature;
    private bool disposed;

    private RsaBuilder() { }

    /// <summary>
    /// Creates a new RSA builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static RsaBuilder Create() => new();

    /// <summary>
    /// Sets the key size for key generation operations.
    /// </summary>
    /// <param name="keySize">The RSA key size.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public RsaBuilder WithKeySize(RsaKeySize keySize)
    {
        this.keySize = keySize;
        return this;
    }

    /// <summary>
    /// Sets the padding mode for encryption and decryption operations.
    /// </summary>
    /// <param name="paddingMode">The padding mode.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public RsaBuilder WithPaddingMode(RsaPaddingMode paddingMode)
    {
        this.paddingMode = paddingMode;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for OAEP padding mode.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm (e.g., SHA256, SHA384, SHA512).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public RsaBuilder WithHashAlgorithm(HashAlgorithmName hashAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /// <summary>
    /// Sets the private key for decryption or signing operations.
    /// </summary>
    /// <param name="privateKey">The RSA private key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null.</exception>
    public RsaBuilder WithPrivateKey(RsaPrivateKey privateKey)
    {
        ArgumentHelper.ThrowIfNull(privateKey);
        ClearPrivateKey();
        this.privateKey = privateKey;
        return this;
    }

    /// <summary>
    /// Sets the public key for encryption or verification operations.
    /// </summary>
    /// <param name="publicKey">The RSA public key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If publicKey is null.</exception>
    public RsaBuilder WithPublicKey(RsaPublicKey publicKey)
    {
        ArgumentHelper.ThrowIfNull(publicKey);
        ClearPublicKey();
        this.publicKey = publicKey;
        return this;
    }

    /// <summary>
    /// Sets the data for encryption, decryption, signing, or verification operations.
    /// </summary>
    /// <param name="data">The data bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public RsaBuilder WithData(byte[]? data)
    {
        ClearData();
        this.data = data != null ? [.. data] : null;
        return this;
    }

    /// <summary>
    /// Sets the data for encryption, decryption, signing, or verification operations.
    /// </summary>
    /// <param name="data">The data bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public RsaBuilder WithData(ReadOnlySpan<byte> data)
    {
        ClearData();
        this.data = data.IsEmpty ? null : data.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the signature for verification operations.
    /// </summary>
    /// <param name="signature">The signature bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If signature is null.</exception>
    public RsaBuilder WithSignature(byte[] signature)
    {
        ArgumentHelper.ThrowIfNull(signature);
        ClearSignature();
        this.signature = [.. signature];
        return this;
    }

    /// <summary>
    /// Sets the signature for verification operations.
    /// </summary>
    /// <param name="signature">The signature bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public RsaBuilder WithSignature(ReadOnlySpan<byte> signature)
    {
        ClearSignature();
        this.signature = signature.IsEmpty ? null : signature.ToArray();
        return this;
    }

    /// <summary>
    /// Generates a new RSA key pair with the configured key size.
    /// </summary>
    /// <returns>A tuple containing the private key and public key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public (RsaPrivateKey PrivateKey, RsaPublicKey PublicKey) GenerateKeyPair()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        var keyPair = RsaCore.GenerateKeyPair((int)keySize);
        return (keyPair.PrivateKey, keyPair.PublicKey);
    }

    /// <summary>
    /// Encrypts the data using the public key.
    /// </summary>
    /// <returns>The encrypted data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If public key or data is not set.</exception>
    public byte[] Encrypt()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePublicKey();
        ValidateData();
        return RsaCore.Encrypt(data!, publicKey!, paddingMode, hashAlgorithm);
    }

    /// <summary>
    /// Decrypts the data using the private key.
    /// </summary>
    /// <returns>The decrypted data.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If private key or data is not set.</exception>
    public byte[] Decrypt()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePrivateKey();
        ValidateData();
        return RsaCore.Decrypt(data!, privateKey!, paddingMode, hashAlgorithm);
    }

    /// <summary>
    /// Signs the data using the private key with RSA-SHA256.
    /// </summary>
    /// <returns>The digital signature.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If private key or data is not set.</exception>
    public byte[] Sign()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePrivateKey();
        ValidateData();
        return RsaCore.Sign(data!, privateKey!);
    }

    /// <summary>
    /// Verifies the signature against the data using the public key.
    /// </summary>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If public key, data, or signature is not set.</exception>
    public bool Verify()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidatePublicKey();
        ValidateData();
        ValidateSignature();
        return RsaCore.Verify(data!, signature!, publicKey!);
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

    private void ValidateData()
    {
        if (data == null)
        {
            throw new InvalidOperationException("Data has not been set. Use WithData() first.");
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
        // SECURITY NOTE: System.Numerics.BigInteger is immutable and cannot be securely cleared.
        // This is a known limitation of .NET's BigInteger implementation. The private key material
        // (D, P, Q, DP, DQ, InverseQ) stored in RsaPrivateKey uses BigInteger internally.
        //
        // Mitigations:
        // 1. The .NET runtime's RSA implementation (RSACryptoServiceProvider/RSACng) handles
        //    its own key material securely with proper disposal.
        // 2. Applications handling highly sensitive keys should consider:
        //    - Using hardware security modules (HSM) via CNG
        //    - Minimizing key lifetime in memory
        //    - Running in isolated processes with restricted memory access
        //
        // Reference: https://github.com/dotnet/runtime/issues/27966
        privateKey = null;
    }

    private void ClearPublicKey()
    {
        // Public keys don't require secure clearing as they are not secret,
        // but we null the reference for consistency.
        publicKey = null;
    }

    private void ClearData()
    {
        if (data != null)
        {
            SecureMemoryOperations.SecureClear(data);
            data = null;
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
            ClearData();
            ClearSignature();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}

/// <summary>
/// Specifies the RSA key size in bits.
/// </summary>
public enum RsaKeySize
{
    /// <summary>
    /// 2048-bit RSA key (minimum recommended).
    /// </summary>
    Rsa2048 = 2048,

    /// <summary>
    /// 3072-bit RSA key (recommended for sensitive data).
    /// </summary>
    Rsa3072 = 3072,

    /// <summary>
    /// 4096-bit RSA key (maximum security).
    /// </summary>
    Rsa4096 = 4096
}
