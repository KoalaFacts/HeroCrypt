using HeroCrypt.Security;

namespace HeroCrypt.Operations;

/// <summary>
/// Fluent builder for signature verification operations.
/// </summary>
/// <remarks>
/// <para>
/// This builder implements <see cref="IDisposable"/> to securely clear sensitive key material
/// from memory when the builder is no longer needed. While public keys are not sensitive,
/// for symmetric MACs (HMAC, AES-CMAC, Poly1305), the key used for verification is a shared
/// secret. It is recommended to use this builder within a <c>using</c> statement when using
/// symmetric MAC algorithms.
/// </para>
/// </remarks>
public sealed class VerificationBuilder : IDisposable
{
    private SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;
    private byte[]? publicKey;
    private byte[]? signature;
    private bool disposed;

    private void ThrowIfDisposed()
    {
#if NETSTANDARD2_0
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(VerificationBuilder));
        }
#else
        ObjectDisposedException.ThrowIf(disposed, this);
#endif
    }

    private void ClearPublicKey()
    {
        if (publicKey == null) return;
        SecureMemoryOperations.SecureClear(publicKey);
        publicKey = null;
    }

    private void ClearSignature()
    {
        if (signature == null) return;
        SecureMemoryOperations.SecureClear(signature);
        signature = null;
    }

    /// <summary>
    /// Releases all resources used by this builder and securely clears sensitive key material.
    /// </summary>
    public void Dispose()
    {
        if (disposed) return;
        ClearPublicKey();
        ClearSignature();
        disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Sets the signature algorithm to use.
    /// </summary>
    public VerificationBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        ThrowIfDisposed();
        this.algorithm = algorithm;
        return this;
    }

    // HMAC (Symmetric MAC)
    /// <summary>Use HMAC-SHA256 for verification.</summary>
    public VerificationBuilder WithHmacSha256() => WithAlgorithm(SignatureAlgorithm.HmacSha256);
    /// <summary>Use HMAC-SHA384 for verification.</summary>
    public VerificationBuilder WithHmacSha384() => WithAlgorithm(SignatureAlgorithm.HmacSha384);
    /// <summary>Use HMAC-SHA512 for verification.</summary>
    public VerificationBuilder WithHmacSha512() => WithAlgorithm(SignatureAlgorithm.HmacSha512);

    // AES-CMAC (Symmetric MAC)
    /// <summary>Use AES-CMAC with 128-bit key for verification.</summary>
    public VerificationBuilder WithAesCmac128() => WithAlgorithm(SignatureAlgorithm.AesCmac128);
    /// <summary>Use AES-CMAC with 192-bit key for verification.</summary>
    public VerificationBuilder WithAesCmac192() => WithAlgorithm(SignatureAlgorithm.AesCmac192);
    /// <summary>Use AES-CMAC with 256-bit key for verification.</summary>
    public VerificationBuilder WithAesCmac256() => WithAlgorithm(SignatureAlgorithm.AesCmac256);

    // Poly1305 (One-time MAC)
    /// <summary>Use Poly1305 one-time authenticator for verification.</summary>
    public VerificationBuilder WithPoly1305() => WithAlgorithm(SignatureAlgorithm.Poly1305);

    // RSA-PKCS#1 v1.5 Signatures
    /// <summary>Use RSA-PKCS#1 v1.5 with SHA-256 for verification.</summary>
    public VerificationBuilder WithRsaSha256() => WithAlgorithm(SignatureAlgorithm.RsaSha256);
    /// <summary>Use RSA-PKCS#1 v1.5 with SHA-384 for verification.</summary>
    public VerificationBuilder WithRsaSha384() => WithAlgorithm(SignatureAlgorithm.RsaSha384);
    /// <summary>Use RSA-PKCS#1 v1.5 with SHA-512 for verification.</summary>
    public VerificationBuilder WithRsaSha512() => WithAlgorithm(SignatureAlgorithm.RsaSha512);

    // RSA-PSS Signatures (Recommended)
    /// <summary>Use RSA-PSS with SHA-256 for verification (recommended over PKCS#1 v1.5).</summary>
    public VerificationBuilder WithRsaPssSha256() => WithAlgorithm(SignatureAlgorithm.RsaPssSha256);
    /// <summary>Use RSA-PSS with SHA-384 for verification.</summary>
    public VerificationBuilder WithRsaPssSha384() => WithAlgorithm(SignatureAlgorithm.RsaPssSha384);
    /// <summary>Use RSA-PSS with SHA-512 for verification.</summary>
    public VerificationBuilder WithRsaPssSha512() => WithAlgorithm(SignatureAlgorithm.RsaPssSha512);

    // ECDSA NIST Curves
    /// <summary>Use ECDSA P-256 with SHA-256 for verification.</summary>
    public VerificationBuilder WithEcdsaP256() => WithAlgorithm(SignatureAlgorithm.EcdsaP256Sha256);
    /// <summary>Use ECDSA P-384 with SHA-384 for verification.</summary>
    public VerificationBuilder WithEcdsaP384() => WithAlgorithm(SignatureAlgorithm.EcdsaP384Sha384);
    /// <summary>Use ECDSA P-521 with SHA-512 for verification.</summary>
    public VerificationBuilder WithEcdsaP521() => WithAlgorithm(SignatureAlgorithm.EcdsaP521Sha512);

    // ECDSA Blockchain Curves
    /// <summary>Use secp256k1 ECDSA for verification (Bitcoin, Ethereum).</summary>
    public VerificationBuilder WithSecp256k1() => WithAlgorithm(SignatureAlgorithm.Secp256k1);

    // EdDSA
    /// <summary>Use Ed25519 for verification (default, recommended).</summary>
    public VerificationBuilder WithEd25519() => WithAlgorithm(SignatureAlgorithm.Ed25519);

#if NET10_0_OR_GREATER
    // ML-DSA Post-Quantum Signatures
    /// <summary>Use ML-DSA-44 post-quantum signature for verification (128-bit security).</summary>
    public VerificationBuilder WithMLDsa44() => WithAlgorithm(SignatureAlgorithm.MLDsa44);
    /// <summary>Use ML-DSA-65 post-quantum signature for verification (192-bit security).</summary>
    public VerificationBuilder WithMLDsa65() => WithAlgorithm(SignatureAlgorithm.MLDsa65);
    /// <summary>Use ML-DSA-87 post-quantum signature for verification (256-bit security).</summary>
    public VerificationBuilder WithMLDsa87() => WithAlgorithm(SignatureAlgorithm.MLDsa87);
#endif

    /// <summary>
    /// Sets the public key for asymmetric signature verification (RSA, ECDSA, Ed25519, ML-DSA).
    /// </summary>
    /// <param name="publicKey">The public key bytes.</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// For symmetric MAC verification (HMAC, AES-CMAC, Poly1305), use <see cref="WithKey(byte[])"/> instead,
    /// which is semantically more appropriate as these use shared secret keys rather than public keys.
    /// </remarks>
    public VerificationBuilder WithPublicKey(byte[] publicKey)
    {
        ThrowIfDisposed();
        ClearPublicKey();
        this.publicKey = [.. publicKey];
        return this;
    }

    /// <summary>
    /// Sets the shared secret key for symmetric MAC verification (HMAC, AES-CMAC, Poly1305).
    /// </summary>
    /// <param name="key">The shared secret key bytes.</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <remarks>
    /// <para>
    /// This method is an alias for <see cref="WithPublicKey(byte[])"/> but with semantics more appropriate
    /// for symmetric MACs where the key is a shared secret rather than a public key.
    /// </para>
    /// <para>
    /// Use this method when working with:
    /// </para>
    /// <list type="bullet">
    /// <item><description>HMAC-SHA256/384/512</description></item>
    /// <item><description>AES-CMAC-128/192/256</description></item>
    /// <item><description>Poly1305</description></item>
    /// </list>
    /// <para>
    /// For asymmetric verification (RSA, ECDSA, Ed25519, ML-DSA), use <see cref="WithPublicKey(byte[])"/>.
    /// </para>
    /// </remarks>
    public VerificationBuilder WithKey(byte[] key) => WithPublicKey(key);

    /// <summary>
    /// Sets the signature to verify.
    /// </summary>
    public VerificationBuilder WithSignature(byte[] signature)
    {
        ThrowIfDisposed();
        ClearSignature();
        this.signature = [.. signature];
        return this;
    }

    /// <summary>
    /// Verifies the signature against the data.
    /// </summary>
    public bool Verify(byte[] data)
    {
        ThrowIfDisposed();

        if (publicKey == null)
            throw new InvalidOperationException("Public key must be set using WithPublicKey()");

        if (signature == null)
            throw new InvalidOperationException("Signature must be set using WithSignature()");

        InputValidator.ValidateByteArray(data, nameof(data));
        InputValidator.ValidateByteArray(signature, nameof(signature));
        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        return SignatureBuilder.VerifyInternal(data, signature, publicKey, algorithm);
    }

    /// <summary>
    /// Verifies the signature against the string data using UTF-8 encoding.
    /// </summary>
    /// <param name="data">The string data to verify.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public bool Verify(string data)
    {
        return Verify(System.Text.Encoding.UTF8.GetBytes(data));
    }
}
