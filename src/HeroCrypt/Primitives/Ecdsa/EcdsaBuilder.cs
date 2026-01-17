using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Ecdsa;

/// <summary>
/// Fluent builder for ECDSA digital signature operations using NIST curves.
/// Supports P-256, P-384, and P-521 curves as used in OpenPGP (RFC 6637).
/// </summary>
/// <example>
/// <code>
/// // Generate a key pair
/// using var builder = EcdsaBuilder.Create()
///     .WithCurve(EcdsaCurve.P256);
/// var keyPair = builder.GenerateKeyPair();
///
/// // Sign data
/// using var signer = EcdsaBuilder.Create()
///     .WithKeyParameters(keyPair)
///     .WithData(message);
/// var signature = signer.Sign();
///
/// // Verify a signature
/// var publicKey = EcdsaCore.ExtractPublicKey(keyPair);
/// using var verifier = EcdsaBuilder.Create()
///     .WithKeyParameters(publicKey)
///     .WithData(message)
///     .WithSignature(signature);
/// bool isValid = verifier.Verify();
/// </code>
/// </example>
public sealed class EcdsaBuilder : IDisposable
{
    private ECParameters? keyParameters;
    private byte[]? data;
    private byte[]? hash;
    private byte[]? signature;
    private bool disposed;

    private EcdsaBuilder() { }

    /// <summary>
    /// Creates a new ECDSA builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static EcdsaBuilder Create() => new();

    /// <summary>
    /// Gets the current curve.
    /// </summary>
    public EcdsaCurve Curve { get; private set; } = EcdsaCurve.P256;

    /// <summary>
    /// Gets the current hash algorithm.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; private set; } = HashAlgorithmName.SHA256;

    /// <summary>
    /// Sets the elliptic curve to use.
    /// </summary>
    /// <param name="curve">The NIST curve to use.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithCurve(EcdsaCurve curve)
    {
        Curve = curve;
        // Update default hash algorithm to match curve
        HashAlgorithm = EcdsaCore.GetRecommendedHashAlgorithm((int)curve);
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for signing/verification.
    /// </summary>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
    {
        HashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the key parameters for signing or verification operations.
    /// </summary>
    /// <param name="parameters">The EC parameters containing the key.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithKeyParameters(ECParameters parameters)
    {
        keyParameters = parameters;
        return this;
    }

    /// <summary>
    /// Sets the key from raw components (OpenPGP format).
    /// </summary>
    /// <param name="d">The private key scalar (optional, null for public key only).</param>
    /// <param name="x">The public key X coordinate.</param>
    /// <param name="y">The public key Y coordinate.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithRawKey(byte[]? d, byte[] x, byte[] y)
    {
        ArgumentHelper.ThrowIfNull(x);
        ArgumentHelper.ThrowIfNull(y);

        keyParameters = EcdsaCore.CreateParameters((int)Curve, d, x, y);
        return this;
    }

    /// <summary>
    /// Sets the public key from raw coordinates (OpenPGP format).
    /// </summary>
    /// <param name="x">The public key X coordinate.</param>
    /// <param name="y">The public key Y coordinate.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithPublicKey(byte[] x, byte[] y)
    {
        ArgumentHelper.ThrowIfNull(x);
        ArgumentHelper.ThrowIfNull(y);

        keyParameters = EcdsaCore.CreatePublicKeyParameters((int)Curve, x, y);
        return this;
    }

    /// <summary>
    /// Sets the data to be signed or verified.
    /// </summary>
    /// <param name="data">The data bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithData(byte[]? data)
    {
        ClearData();
        this.data = data != null ? [.. data] : null;
        return this;
    }

    /// <summary>
    /// Sets the data to be signed or verified.
    /// </summary>
    /// <param name="data">The data bytes.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithData(ReadOnlySpan<byte> data)
    {
        ClearData();
        this.data = data.IsEmpty ? null : data.ToArray();
        return this;
    }

    /// <summary>
    /// Sets a pre-computed hash to be signed or verified.
    /// When set, this hash is used directly instead of hashing the data.
    /// </summary>
    /// <param name="hash">The pre-computed hash.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithHash(byte[]? hash)
    {
        ClearHash();
        this.hash = hash != null ? [.. hash] : null;
        return this;
    }

    /// <summary>
    /// Sets a pre-computed hash to be signed or verified.
    /// </summary>
    /// <param name="hash">The pre-computed hash.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithHash(ReadOnlySpan<byte> hash)
    {
        ClearHash();
        this.hash = hash.IsEmpty ? null : hash.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the signature for verification operations.
    /// </summary>
    /// <param name="signature">The ECDSA signature in IEEE P1363 format (r || s).</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If signature is null.</exception>
    public EcdsaBuilder WithSignature(byte[] signature)
    {
        ArgumentHelper.ThrowIfNull(signature);
        ClearSignature();
        this.signature = [.. signature];
        return this;
    }

    /// <summary>
    /// Sets the signature for verification operations.
    /// </summary>
    /// <param name="signature">The ECDSA signature in IEEE P1363 format (r || s).</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithSignature(ReadOnlySpan<byte> signature)
    {
        ClearSignature();
        this.signature = signature.ToArray();
        return this;
    }

    /// <summary>
    /// Sets the signature from raw (r, s) components.
    /// </summary>
    /// <param name="r">The r component of the signature.</param>
    /// <param name="s">The s component of the signature.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public EcdsaBuilder WithSignatureRaw(byte[] r, byte[] s)
    {
        ArgumentHelper.ThrowIfNull(r);
        ArgumentHelper.ThrowIfNull(s);

        ClearSignature();
        signature = new byte[r.Length + s.Length];
        Array.Copy(r, 0, signature, 0, r.Length);
        Array.Copy(s, 0, signature, r.Length, s.Length);
        return this;
    }

    /// <summary>
    /// Generates a new ECDSA key pair.
    /// </summary>
    /// <returns>The EC parameters containing the key pair.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    public ECParameters GenerateKeyPair()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        var parameters = EcdsaCore.GenerateKeyPair((int)Curve);
        keyParameters = parameters;
        return parameters;
    }

    /// <summary>
    /// Extracts the public key from the current key parameters.
    /// </summary>
    /// <returns>EC parameters containing only the public key.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key parameters are not set.</exception>
    public ECParameters ExtractPublicKey()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateKeyParameters();
        return EcdsaCore.ExtractPublicKey(keyParameters!.Value);
    }

    /// <summary>
    /// Signs the data or hash using the key parameters.
    /// </summary>
    /// <returns>The signature in IEEE P1363 format (r || s).</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key parameters or data/hash is not set.</exception>
    public byte[] Sign()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateKeyParameters();
        ValidatePrivateKey();

        if (hash != null)
        {
            return EcdsaCore.SignHash(hash, keyParameters!.Value);
        }

        ValidateData();
        return EcdsaCore.SignData(data!, keyParameters!.Value, HashAlgorithm);
    }

    /// <summary>
    /// Signs and returns the raw signature components (r, s).
    /// </summary>
    /// <returns>A tuple containing the (r, s) signature components.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key parameters or hash is not set.</exception>
    public (byte[] r, byte[] s) SignRaw()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateKeyParameters();
        ValidatePrivateKey();

        byte[] hashToSign;
        if (hash != null)
        {
            hashToSign = hash;
        }
        else
        {
            ValidateData();
            hashToSign = ComputeHash(data!);
        }

        return EcdsaCore.SignHashRaw(hashToSign, keyParameters!.Value);
    }

    /// <summary>
    /// Verifies the signature against the data or hash using the key parameters.
    /// </summary>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key parameters, data/hash, or signature is not set.</exception>
    public bool Verify()
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateKeyParameters();
        ValidateSignature();

        if (hash != null)
        {
            return EcdsaCore.VerifyHash(hash, signature!, keyParameters!.Value);
        }

        ValidateData();
        return EcdsaCore.VerifyData(data!, signature!, keyParameters!.Value, HashAlgorithm);
    }

    /// <summary>
    /// Verifies a signature using raw (r, s) components.
    /// </summary>
    /// <param name="r">The r component of the signature.</param>
    /// <param name="s">The s component of the signature.</param>
    /// <returns>True if valid, false otherwise.</returns>
    /// <exception cref="ObjectDisposedException">If the builder has been disposed.</exception>
    /// <exception cref="InvalidOperationException">If key parameters or hash is not set.</exception>
    public bool VerifyRaw(byte[] r, byte[] s)
    {
        ArgumentHelper.ThrowIfDisposed(disposed, this);
        ValidateKeyParameters();

        byte[] hashToVerify;
        if (hash != null)
        {
            hashToVerify = hash;
        }
        else
        {
            ValidateData();
            hashToVerify = ComputeHash(data!);
        }

        return EcdsaCore.VerifyHashRaw(hashToVerify, r, s, keyParameters!.Value);
    }

    /// <summary>
    /// Gets the current key parameters.
    /// </summary>
    /// <returns>The EC parameters, or null if not set.</returns>
    public ECParameters? GetKeyParameters() => keyParameters;

    private byte[] ComputeHash(byte[] inputData)
    {
#if NETSTANDARD2_0
        if (HashAlgorithm == HashAlgorithmName.SHA256)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(inputData);
        }
        if (HashAlgorithm == HashAlgorithmName.SHA384)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(inputData);
        }
        if (HashAlgorithm == HashAlgorithmName.SHA512)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(inputData);
        }
        throw new InvalidOperationException($"Unsupported hash algorithm: {HashAlgorithm}");
#else
        if (HashAlgorithm == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(inputData);
        }
        if (HashAlgorithm == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(inputData);
        }
        if (HashAlgorithm == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(inputData);
        }
        throw new InvalidOperationException($"Unsupported hash algorithm: {HashAlgorithm}");
#endif
    }

    private void ValidateKeyParameters()
    {
        if (keyParameters == null)
        {
            throw new InvalidOperationException("Key parameters have not been set. Use WithKeyParameters(), WithRawKey(), or GenerateKeyPair() first.");
        }
    }

    private void ValidatePrivateKey()
    {
        if (keyParameters?.D == null)
        {
            throw new InvalidOperationException("Private key (D parameter) is required for signing. Use a key with private key data.");
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

    private void ClearData()
    {
        if (data != null)
        {
            SecureMemoryOperations.SecureClear(data);
            data = null;
        }
    }

    private void ClearHash()
    {
        if (hash != null)
        {
            SecureMemoryOperations.SecureClear(hash);
            hash = null;
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

    private void ClearKeyParameters()
    {
        if (keyParameters?.D != null)
        {
            SecureMemoryOperations.SecureClear(keyParameters.Value.D);
        }
        keyParameters = null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            ClearKeyParameters();
            ClearData();
            ClearHash();
            ClearSignature();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
