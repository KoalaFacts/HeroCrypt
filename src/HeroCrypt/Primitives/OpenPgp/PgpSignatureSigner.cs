using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for creating OpenPGP signatures.
/// </summary>
/// <remarks>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// var signed = PgpSignatureSigner.Create()
///     .WithSecretKey(secretKey)
///     .WithSha256()
///     .Sign(data);
/// </code>
/// </para>
/// <para>
/// <b>Default behavior:</b>
/// <list type="bullet">
///   <item>Hash algorithm: SHA-256</item>
///   <item>Signature version: follows the signing key (V4 or V6)</item>
///   <item>Signature type: BinaryDocument (0x00)</item>
/// </list>
/// </para>
/// </remarks>
public sealed class PgpSignatureSigner : IDisposable
{
    private PgpSecretKeyPacket? secretKey;
    private PgpHashAlgorithmId hashAlgorithm = PgpHashAlgorithmId.Sha256;
    private PgpSignatureType signatureType = PgpSignatureType.BinaryDocument;
    private bool useVersion6;
    private bool disposed;

    private PgpSignatureSigner()
    {
    }

    /// <summary>
    /// Creates a new signature signer.
    /// </summary>
    /// <returns>A new PgpSignatureSigner instance.</returns>
    public static PgpSignatureSigner Create() => new();

    /// <summary>
    /// Sets the secret key to use for signing.
    /// </summary>
    /// <param name="key">The secret key packet.</param>
    /// <returns>This signer for chaining.</returns>
    /// <exception cref="ArgumentException">If the key is encrypted or not suitable for signing.</exception>
    public PgpSignatureSigner WithSecretKey(PgpSecretKeyPacket key)
    {
        ThrowIfDisposed();

        if (key.IsEncrypted)
        {
            throw new ArgumentException("Secret key is encrypted. Decrypt it first or provide a passphrase.", nameof(key));
        }

        // Verify the key algorithm supports signing
        var algo = key.Algorithm;
        if (algo != PgpPublicKeyAlgorithm.RsaEncryptOrSign &&
#pragma warning disable CS0618 // Obsolete
            algo != PgpPublicKeyAlgorithm.RsaSignOnly &&
#pragma warning restore CS0618
            algo != PgpPublicKeyAlgorithm.Dsa &&
            algo != PgpPublicKeyAlgorithm.Ecdsa &&
            algo != PgpPublicKeyAlgorithm.Ed25519 &&
#pragma warning disable CS0618 // Obsolete
            algo != PgpPublicKeyAlgorithm.EdDsaLegacy)
#pragma warning restore CS0618
        {
            throw new ArgumentException($"Key algorithm {algo} does not support signing.", nameof(key));
        }

        if (useVersion6 && key.PublicKey.Version != 6)
        {
            throw new ArgumentException("Version 6 signatures require a version 6 signing key.", nameof(key));
        }

        secretKey = key;
        useVersion6 = key.PublicKey.Version == 6;
        return this;
    }

    /// <summary>
    /// Sets the secret key ring to use for signing (uses the primary signing key).
    /// </summary>
    /// <param name="keyRing">The secret key ring.</param>
    /// <returns>This signer for chaining.</returns>
    public PgpSignatureSigner WithSecretKeyRing(PgpSecretKeyRing keyRing)
    {
        ThrowIfDisposed();

        // Find the signing-capable key (primary key or signing subkey)
        foreach (var subkey in keyRing.Subkeys)
        {
            var algo = subkey.PublicKey.Algorithm;
            if (algo == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete
                algo == PgpPublicKeyAlgorithm.RsaSignOnly ||
#pragma warning restore CS0618
                algo == PgpPublicKeyAlgorithm.Dsa ||
                algo == PgpPublicKeyAlgorithm.Ecdsa ||
                algo == PgpPublicKeyAlgorithm.Ed25519)
            {
                return WithSecretKey(subkey);
            }
        }

        // Fall back to master key
        return WithSecretKey(keyRing.MasterKey);
    }

    /// <summary>
    /// Sets the hash algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>This signer for chaining.</returns>
    public PgpSignatureSigner WithHashAlgorithm(PgpHashAlgorithmId algorithm)
    {
        ThrowIfDisposed();
        if (algorithm != PgpHashAlgorithmId.Sha256 && algorithm != PgpHashAlgorithmId.Sha384 &&
            algorithm != PgpHashAlgorithmId.Sha512 && algorithm != PgpHashAlgorithmId.Sha3_256 &&
            algorithm != PgpHashAlgorithmId.Sha3_512)
        {
            throw new ArgumentException("Signature hash algorithm is unsupported or weak.", nameof(algorithm));
        }
        hashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Uses SHA-256 for hashing (default).
    /// </summary>
    public PgpSignatureSigner WithSha256() => WithHashAlgorithm(PgpHashAlgorithmId.Sha256);

    /// <summary>
    /// Uses SHA-384 for hashing.
    /// </summary>
    public PgpSignatureSigner WithSha384() => WithHashAlgorithm(PgpHashAlgorithmId.Sha384);

    /// <summary>
    /// Uses SHA-512 for hashing.
    /// </summary>
    public PgpSignatureSigner WithSha512() => WithHashAlgorithm(PgpHashAlgorithmId.Sha512);

    /// <summary>
    /// Uses SHA3-256 for hashing (.NET 8+ only).
    /// </summary>
    public PgpSignatureSigner WithSha3_256() => WithHashAlgorithm(PgpHashAlgorithmId.Sha3_256);

    /// <summary>
    /// Sets the signature type.
    /// </summary>
    /// <param name="type">The signature type.</param>
    /// <returns>This signer for chaining.</returns>
    public PgpSignatureSigner WithSignatureType(PgpSignatureType type)
    {
        ThrowIfDisposed();
        if (type != PgpSignatureType.BinaryDocument && type != PgpSignatureType.CanonicalTextDocument)
        {
            throw new ArgumentException("Document signing requires a document signature type.", nameof(type));
        }
        signatureType = type;
        return this;
    }

    /// <summary>
    /// Uses V6 signature format (RFC 9580).
    /// </summary>
    /// <returns>This signer for chaining.</returns>
    public PgpSignatureSigner WithVersion6()
    {
        ThrowIfDisposed();
        if (secretKey.HasValue && secretKey.Value.PublicKey.Version != 6)
        {
            throw new InvalidOperationException("Version 6 signatures require a version 6 signing key.");
        }
        useVersion6 = true;
        return this;
    }

    /// <summary>
    /// Signs the specified data and returns a signed message.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signed message.</returns>
    /// <exception cref="InvalidOperationException">If no secret key has been set.</exception>
    public PgpSignedMessage Sign(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        if (!secretKey.HasValue)
        {
            throw new InvalidOperationException("No secret key has been set. Call WithSecretKey() first.");
        }

        var signature = CreateSignature(data);

        // Create One-Pass Signature packet
        var keyId = secretKey.Value.GetKeyId();
        var onePassSig = useVersion6
            ? PgpOnePassSignaturePacket.CreateV6(
                signatureType,
                (byte)hashAlgorithm,
                (byte)secretKey.Value.Algorithm,
                signature.Salt,
                secretKey.Value.ComputeFingerprint(),
                isNested: true)
            : PgpOnePassSignaturePacket.CreateV3(
                signatureType,
                (byte)hashAlgorithm,
                (byte)secretKey.Value.Algorithm,
                keyId,
                isNested: true);

        return new PgpSignedMessage(
            data.ToArray(),
            signature,
            onePassSig,
            PgpLiteralDataFormat.Binary,
            string.Empty,
            DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Signs text with canonicalization.
    /// </summary>
    /// <param name="text">The text to sign.</param>
    /// <returns>The signed message.</returns>
    public PgpSignedMessage SignText(string text)
    {
        ThrowIfDisposed();

#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(text);
#else
        if (text == null) throw new ArgumentNullException(nameof(text));
#endif

        // Set signature type to canonical text
        signatureType = PgpSignatureType.CanonicalTextDocument;

        // Canonicalize text line endings without changing signed whitespace
        var canonicalized = CanonicalizeText(text);
        var data = System.Text.Encoding.UTF8.GetBytes(canonicalized);

        return Sign(data);
    }

    /// <summary>
    /// Creates a detached signature for the specified data.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <returns>The signature packet.</returns>
    public PgpSignaturePacket CreateDetachedSignature(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        if (!secretKey.HasValue)
        {
            throw new InvalidOperationException("No secret key has been set. Call WithSecretKey() first.");
        }

        return CreateSignature(data);
    }

    private PgpSignaturePacket CreateSignature(ReadOnlySpan<byte> data)
    {
        byte version = useVersion6 ? (byte)6 : (byte)4;
        var pubAlgo = (byte)secretKey!.Value.Algorithm;
        var hashAlgo = (byte)hashAlgorithm;

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(DateTimeOffset.UtcNow)
        };

        // Add issuer fingerprint for V4+ signatures
        var fingerprint = secretKey.Value.ComputeFingerprint();
        hashedSubpackets.Add(PgpSignatureSubpacket.CreateIssuerFingerprint(version, fingerprint));

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>();

        // Add issuer key ID to unhashed (for V4)
        var keyId = secretKey.Value.GetKeyId();
        unhashedSubpackets.Add(PgpSignatureSubpacket.CreateIssuerKeyId(keyId));

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Generate salt for V6
        byte[] salt = useVersion6 ? GenerateSalt(hashAlgorithm) : [];

        // Compute the hash
        byte[] hash = PgpSignatureHashHelper.ComputeDocumentHash(
            data,
            version,
            (byte)signatureType,
            pubAlgo,
            hashAlgo,
            hashedSubpacketData,
            salt);

        // Get hash prefix (first 2 bytes)
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create the signature
        byte[] signatureData = CreateSignatureData(hash);

        // Build the signature packet
        if (useVersion6)
        {
            return PgpSignaturePacket.CreateV6(
                signatureType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                salt,
                signatureData);
        }
        else
        {
            return PgpSignaturePacket.CreateV4(
                signatureType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                signatureData);
        }
    }


    private byte[] CreateSignatureData(byte[] hash)
    {
        var algo = secretKey!.Value.Algorithm;

        if (algo == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete
            algo == PgpPublicKeyAlgorithm.RsaSignOnly)
#pragma warning restore CS0618
        {
            return CreateRsaSignature(hash);
        }
        else if (algo == PgpPublicKeyAlgorithm.Ed25519)
        {
            return CreateEd25519Signature(hash);
        }
        else if (algo == PgpPublicKeyAlgorithm.Ecdsa)
        {
            return CreateEcdsaSignature(hash);
        }
        else
        {
            throw new NotSupportedException($"Signing with algorithm {algo} is not yet supported.");
        }
    }

    private byte[] CreateRsaSignature(byte[] hash)
    {
        // Extract RSA private key components
        var (d, p, q, _) = secretKey!.Value.ReadRsaSecretKey();
        var (n, e) = secretKey.Value.PublicKey.ReadRsaKey();

        // Use RsaCore infrastructure which handles all the RSA operations
        var rsaPrivateKey = new RsaPrivateKey(n, d, p, q, e);
        var rsaCore = new RsaCore();
        var rsaParams = rsaCore.ToRsaParameters(rsaPrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        // Sign the hash
        var signature = rsa.SignHash(hash, hashAlgorithm.GetHashAlgorithmName(), RSASignaturePadding.Pkcs1);

        // Encode as MPI using Mpi helper
        int mpiLen = Mpi.GetEncodedLength(signature);
        var mpiBuffer = new byte[mpiLen];
        Mpi.Write(signature, mpiBuffer);
        return mpiBuffer;
    }

    private byte[] CreateEd25519Signature(byte[] hash)
    {
        // Read the Ed25519 private key from the secret key packet
        var ed25519PrivateKey = secretKey!.Value.ReadEcSecretKey();

        try
        {
            // Ed25519 in OpenPGP signs the hash (which includes the signature trailer)
            // Ed25519Core.Sign returns a 64-byte signature
            var signature = new Ed25519Core().Sign(hash, ed25519PrivateKey);

            // Return raw 64-byte signature (no MPI encoding for native format keys)
            return signature;
        }
        finally
        {
            // Clear the private key from memory for security
            SecureMemoryOperations.SecureClear(ed25519PrivateKey);
        }
    }

    private byte[] CreateEcdsaSignature(byte[] hash)
    {
        throw new NotSupportedException("ECDSA signing is not yet implemented.");
    }

    private static string CanonicalizeText(string text)
    {
        var lines = text.Split(["\r\n", "\r", "\n"], StringSplitOptions.None);
        return string.Join("\r\n", lines);
    }

    private static byte[] GenerateSalt(PgpHashAlgorithmId hashAlg)
    {
        int saltLen = PgpSignaturePacket.GetExpectedSaltLength((byte)hashAlg);
        var salt = new byte[saltLen];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    private void ThrowIfDisposed()
    {
#if NET8_0_OR_GREATER
        ObjectDisposedException.ThrowIf(disposed, this);
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(PgpSignatureSigner));
        }
#endif
    }

    /// <summary>
    /// Disposes of resources.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            secretKey = null;
            disposed = true;
        }
    }
}
