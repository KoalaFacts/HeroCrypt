using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for creating OpenPGP key revocation signatures.
/// </summary>
/// <remarks>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// // Revoke a key
/// var revocation = PgpKeyRevoker.Create()
///     .WithSecretKey(secretKey)
///     .WithReason(PgpRevocationReason.KeyCompromised, "Key was stolen")
///     .RevokeKey();
///
/// // Revoke a subkey
/// var subkeyRevocation = PgpKeyRevoker.Create()
///     .WithSecretKey(masterSecretKey)
///     .WithSubkey(subkeyPublicKey)
///     .WithReason(PgpRevocationReason.KeySuperseded)
///     .RevokeSubkey();
///
/// // Add revocation to key ring
/// var revokedRing = originalRing.AddRevocationSignature(revocation);
/// </code>
/// </para>
/// </remarks>
public sealed class PgpKeyRevoker : IDisposable
{
    private PgpSecretKeyPacket? secretKey;
    private PgpPublicKeyPacket? subkey;
    private PgpRevocationReason reason = PgpRevocationReason.NoReason;
    private string? reasonText;
    private DateTimeOffset? revocationTime;
    private bool disposed;

    private PgpKeyRevoker()
    {
    }

    /// <summary>
    /// Creates a new key revoker.
    /// </summary>
    /// <returns>A new PgpKeyRevoker instance.</returns>
    public static PgpKeyRevoker Create() => new();

    /// <summary>
    /// Sets the secret key used to create the revocation signature.
    /// </summary>
    /// <param name="key">The secret key (must be the key being revoked or its master key).</param>
    /// <returns>This revoker for chaining.</returns>
    /// <remarks>
    /// <para>
    /// For key revocation (0x20), this should be the key being revoked.
    /// For subkey revocation (0x28), this should be the master key.
    /// </para>
    /// </remarks>
    public PgpKeyRevoker WithSecretKey(PgpSecretKeyPacket key)
    {
        ThrowIfDisposed();
        secretKey = key;
        return this;
    }

    /// <summary>
    /// Sets the subkey to revoke (for subkey revocation).
    /// </summary>
    /// <param name="subkeyPublicKey">The public key packet of the subkey to revoke.</param>
    /// <returns>This revoker for chaining.</returns>
    public PgpKeyRevoker WithSubkey(PgpPublicKeyPacket subkeyPublicKey)
    {
        ThrowIfDisposed();
        subkey = subkeyPublicKey;
        return this;
    }

    /// <summary>
    /// Sets the revocation reason.
    /// </summary>
    /// <param name="revocationReason">The reason for revocation.</param>
    /// <param name="text">Optional human-readable explanation.</param>
    /// <returns>This revoker for chaining.</returns>
    public PgpKeyRevoker WithReason(PgpRevocationReason revocationReason, string? text = null)
    {
        ThrowIfDisposed();
        reason = revocationReason;
        reasonText = text;
        return this;
    }

    /// <summary>
    /// Sets the revocation timestamp.
    /// </summary>
    /// <param name="time">The revocation time. If not set, current UTC time is used.</param>
    /// <returns>This revoker for chaining.</returns>
    public PgpKeyRevoker WithRevocationTime(DateTimeOffset time)
    {
        ThrowIfDisposed();
        revocationTime = time;
        return this;
    }

    /// <summary>
    /// Creates a key revocation signature (type 0x20).
    /// </summary>
    /// <returns>The revocation signature packet.</returns>
    /// <exception cref="InvalidOperationException">If the secret key is not set.</exception>
    /// <remarks>
    /// <para>
    /// A key revocation signature revokes the entire key. It should be made by
    /// the key being revoked. Once revoked, the key should not be used for
    /// new signatures or encryption.
    /// </para>
    /// <para>
    /// For hard revocations (KeyCompromised), all prior signatures become suspect.
    /// For soft revocations, prior signatures remain valid.
    /// </para>
    /// </remarks>
    public PgpSignaturePacket RevokeKey()
    {
        ThrowIfDisposed();

        if (!secretKey.HasValue)
        {
            throw new InvalidOperationException("Secret key must be set before revoking.");
        }

        if (secretKey.Value.IsEncrypted)
        {
            throw new InvalidOperationException("Secret key must be decrypted before creating revocation signature.");
        }

        return CreateRevocationSignature(
            PgpSignatureType.KeyRevocation,
            secretKey.Value.PublicKey,
            null);
    }

    /// <summary>
    /// Creates a subkey revocation signature (type 0x28).
    /// </summary>
    /// <returns>The subkey revocation signature packet.</returns>
    /// <exception cref="InvalidOperationException">If the secret key or subkey is not set.</exception>
    /// <remarks>
    /// <para>
    /// A subkey revocation signature revokes a specific subkey. It must be made
    /// by the master key (not the subkey being revoked).
    /// </para>
    /// </remarks>
    public PgpSignaturePacket RevokeSubkey()
    {
        ThrowIfDisposed();

        if (!secretKey.HasValue)
        {
            throw new InvalidOperationException("Master secret key must be set before revoking subkey.");
        }

        if (!subkey.HasValue)
        {
            throw new InvalidOperationException("Subkey must be set before creating subkey revocation.");
        }

        if (secretKey.Value.IsEncrypted)
        {
            throw new InvalidOperationException("Secret key must be decrypted before creating revocation signature.");
        }

        return CreateRevocationSignature(
            PgpSignatureType.SubkeyRevocation,
            secretKey.Value.PublicKey,
            subkey.Value);
    }

    private PgpSignaturePacket CreateRevocationSignature(
        PgpSignatureType sigType,
        PgpPublicKeyPacket publicKey,
        PgpPublicKeyPacket? subkeyToRevoke)
    {
        byte version = publicKey.Version;
        byte pubAlgo = (byte)publicKey.Algorithm;
        byte hashAlgo = (byte)PgpHashAlgorithmId.Sha256;
        var timestamp = revocationTime ?? DateTimeOffset.UtcNow;

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(timestamp),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, publicKey.ComputeFingerprint()),
            PgpSignatureSubpacket.CreateReasonForRevocation(reason, reasonText, isCritical: false)
        };

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateIssuerKeyId(publicKey.GetKeyId())
        };

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Compute hash
        var hash = sigType == PgpSignatureType.SubkeyRevocation && subkeyToRevoke.HasValue
            ? ComputeSubkeyRevocationHash(
                publicKey,
                subkeyToRevoke.Value,
                version,
                (byte)sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpacketData)
            : ComputeKeyRevocationHash(
                publicKey,
                version,
                (byte)sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpacketData);

        // Get hash prefix
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create signature
        byte[] signatureData = CreateSignatureData(hash);

        // Build signature packet
        if (version == 6)
        {
            var salt = GenerateSalt();
            return PgpSignaturePacket.CreateV6(
                sigType,
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
                sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                signatureData);
        }
    }

    private static byte[] ComputeKeyRevocationHash(
        PgpPublicKeyPacket publicKey,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        return PgpSignatureHashHelper.ComputeKeySignatureHash(
            publicKey,
            secondaryKey: null,
            version,
            sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpackets);
    }

    private static byte[] ComputeSubkeyRevocationHash(
        PgpPublicKeyPacket masterKey,
        PgpPublicKeyPacket subkeyPacket,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        return PgpSignatureHashHelper.ComputeKeySignatureHash(
            masterKey,
            subkeyPacket,
            version,
            sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpackets);
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
        else
        {
            throw new NotSupportedException($"Signing with algorithm {algo} is not yet supported for revocation.");
        }
    }

    private byte[] CreateRsaSignature(byte[] hash)
    {
        // Extract RSA private key components
        var (d, p, q, _) = secretKey!.Value.ReadRsaSecretKey();
        var (n, e) = secretKey.Value.PublicKey.ReadRsaKey();

        // Use RsaCore infrastructure which handles all the RSA operations
        var rsaPrivateKey = new RsaPrivateKey(n, d, p, q, e);
        var rsaParams = RsaCore.ToRsaParameters(rsaPrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        // Sign the hash
        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

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
            var signature = Ed25519Core.Sign(hash, ed25519PrivateKey);

            // Return raw 64-byte signature (no MPI encoding for native format keys)
            return signature;
        }
        finally
        {
            // Clear the private key from memory for security
            SecureMemoryOperations.SecureClear(ed25519PrivateKey);
        }
    }

    private static byte[] GenerateSalt()
    {
        // For SHA-256, salt is 16 bytes per RFC 9580
        var salt = new byte[16];
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
            throw new ObjectDisposedException(nameof(PgpKeyRevoker));
        }
#endif
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            secretKey = null;
            subkey = null;
            reasonText = null;
            disposed = true;
        }
    }
}
