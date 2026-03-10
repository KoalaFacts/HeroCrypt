using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for creating OpenPGP key rotation (transition) signatures.
/// </summary>
/// <remarks>
/// <para>
/// Key rotation creates a trust chain from an old key to a new key. The old key
/// signs the new key to indicate that the user has transitioned to the new key.
/// </para>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// // Rotate from old key to new key
/// var rotation = PgpKeyRotator.Create()
///     .FromOldKey(oldSecretKey)
///     .ToNewKey(newPublicKeyRing)
///     .WithRevocation(PgpRevocationReason.KeySuperseded, "Rotating to stronger key")
///     .Rotate();
///
/// // Access results
/// var transitionSignature = rotation.TransitionSignature;
/// var oldKeyRevocation = rotation.OldKeyRevocation;
/// var certifiedNewKeyRing = rotation.CertifiedNewKeyRing;
/// </code>
/// </para>
/// <para>
/// <b>How key rotation works:</b>
/// <list type="bullet">
///   <item>The old key creates a direct key signature (0x1F) on the new key</item>
///   <item>This establishes a trust chain from old key to new key</item>
///   <item>Optionally, the old key is revoked with "KeySuperseded" reason</item>
///   <item>The transition signature can be added to the new key's certifications</item>
/// </list>
/// </para>
/// </remarks>
public sealed class PgpKeyRotator : IDisposable
{
    private PgpSecretKeyPacket? oldSecretKey;
    private PgpPublicKeyRing? newKeyRing;
    private PgpRevocationReason? revocationReason;
    private string? revocationText;
    private DateTimeOffset? rotationTime;
    private bool disposed;

    private PgpKeyRotator()
    {
    }

    /// <summary>
    /// Creates a new key rotator.
    /// </summary>
    /// <returns>A new PgpKeyRotator instance.</returns>
    public static PgpKeyRotator Create() => new();

    /// <summary>
    /// Sets the old secret key that will sign the new key.
    /// </summary>
    /// <param name="key">The old secret key (must be decrypted).</param>
    /// <returns>This rotator for chaining.</returns>
    /// <exception cref="ArgumentException">If the key is encrypted.</exception>
    /// <remarks>
    /// <para>
    /// The old key must be capable of signing (RSA or Ed25519).
    /// It will create a direct key signature on the new key to establish
    /// the trust chain for key rotation.
    /// </para>
    /// </remarks>
    public PgpKeyRotator FromOldKey(PgpSecretKeyPacket key)
    {
        ThrowIfDisposed();

        if (key.IsEncrypted)
        {
            throw new ArgumentException("Old secret key must be decrypted before key rotation.", nameof(key));
        }

        oldSecretKey = key;
        return this;
    }

    /// <summary>
    /// Sets the old secret key ring (uses the master key for signing).
    /// </summary>
    /// <param name="keyRing">The old secret key ring.</param>
    /// <returns>This rotator for chaining.</returns>
    public PgpKeyRotator FromOldKeyRing(PgpSecretKeyRing keyRing)
    {
        ThrowIfDisposed();
        return FromOldKey(keyRing.MasterKey);
    }

    /// <summary>
    /// Sets the new key that will receive the transition signature.
    /// </summary>
    /// <param name="newPublicKeyRing">The new key's public key ring.</param>
    /// <returns>This rotator for chaining.</returns>
    public PgpKeyRotator ToNewKey(PgpPublicKeyRing newPublicKeyRing)
    {
        ThrowIfDisposed();
        newKeyRing = newPublicKeyRing;
        return this;
    }

    /// <summary>
    /// Sets the new key from a key generator result.
    /// </summary>
    /// <param name="generatorResult">The result from PgpKeyGenerator.</param>
    /// <returns>This rotator for chaining.</returns>
    public PgpKeyRotator ToNewKey(PgpKeyGeneratorResult generatorResult)
    {
        ThrowIfDisposed();
        newKeyRing = generatorResult.PublicKeyRing;
        return this;
    }

    /// <summary>
    /// Configures optional revocation of the old key.
    /// </summary>
    /// <param name="reason">The revocation reason (typically KeySuperseded).</param>
    /// <param name="text">Optional human-readable explanation.</param>
    /// <returns>This rotator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// When set, the rotation will also create a revocation signature for the old key.
    /// For key rotation, <see cref="PgpRevocationReason.KeySuperseded"/> is typically used.
    /// </para>
    /// </remarks>
    public PgpKeyRotator WithRevocation(PgpRevocationReason reason, string? text = null)
    {
        ThrowIfDisposed();
        revocationReason = reason;
        revocationText = text;
        return this;
    }

    /// <summary>
    /// Sets the rotation timestamp.
    /// </summary>
    /// <param name="time">The rotation time. If not set, current UTC time is used.</param>
    /// <returns>This rotator for chaining.</returns>
    public PgpKeyRotator WithRotationTime(DateTimeOffset time)
    {
        ThrowIfDisposed();
        rotationTime = time;
        return this;
    }

    /// <summary>
    /// Performs the key rotation.
    /// </summary>
    /// <returns>The key rotation result containing signatures and certified key ring.</returns>
    /// <exception cref="InvalidOperationException">If old key or new key is not set.</exception>
    /// <remarks>
    /// <para>
    /// This creates:
    /// <list type="bullet">
    ///   <item>A direct key signature (0x1F) from old key on new key</item>
    ///   <item>Optionally, a key revocation signature (0x20) for the old key</item>
    ///   <item>A new public key ring with the transition signature added</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpKeyRotationResult Rotate()
    {
        ThrowIfDisposed();

        if (!oldSecretKey.HasValue)
        {
            throw new InvalidOperationException("Old secret key must be set. Call FromOldKey() first.");
        }

        if (newKeyRing == null)
        {
            throw new InvalidOperationException("New key must be set. Call ToNewKey() first.");
        }

        var timestamp = rotationTime ?? DateTimeOffset.UtcNow;

        // Create transition signature (old key signs new key)
        var transitionSignature = CreateTransitionSignature(
            oldSecretKey.Value,
            newKeyRing.Value.MasterKey,
            timestamp);

        // Create revocation signature if requested
        PgpSignaturePacket? revocationSignature = null;
        if (revocationReason.HasValue)
        {
            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(oldSecretKey.Value)
                .WithReason(revocationReason.Value, revocationText)
                .WithRevocationTime(timestamp);

            revocationSignature = revoker.RevokeKey();
        }

        // Add transition signature to new key ring
        var certifiedNewKeyRing = newKeyRing.Value.AddSignature(transitionSignature);

        return new PgpKeyRotationResult(
            transitionSignature,
            revocationSignature,
            certifiedNewKeyRing,
            oldSecretKey.Value.PublicKey,
            newKeyRing.Value.MasterKey);
    }

    private PgpSignaturePacket CreateTransitionSignature(
        PgpSecretKeyPacket oldKey,
        PgpPublicKeyPacket newKey,
        DateTimeOffset timestamp)
    {
        byte version = oldKey.PublicKey.Version;
        byte pubAlgo = (byte)oldKey.Algorithm;
        byte hashAlgo = (byte)PgpHashAlgorithmId.Sha256;

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(timestamp),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, oldKey.ComputeFingerprint()),
        };

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateIssuerKeyId(oldKey.GetKeyId())
        };

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Compute the hash (direct key signature over new key)
        byte[] hash = ComputeDirectKeySignatureHash(
            newKey,
            version,
            (byte)PgpSignatureType.DirectKey,
            pubAlgo,
            hashAlgo,
            hashedSubpacketData);

        // Get hash prefix
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create signature
        byte[] signatureData = CreateSignatureData(oldKey, hash);

        // Build signature packet
        if (version == 6)
        {
            var salt = GenerateSalt();
            return PgpSignaturePacket.CreateV6(
                PgpSignatureType.DirectKey,
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
                PgpSignatureType.DirectKey,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                signatureData);
        }
    }

    private static byte[] ComputeDirectKeySignatureHash(
        PgpPublicKeyPacket targetKey,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        return PgpSignatureHashHelper.ComputeKeySignatureHash(
            targetKey,
            secondaryKey: null,
            version,
            sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpackets);
    }

    private static byte[] CreateSignatureData(PgpSecretKeyPacket secretKey, byte[] hash)
    {
        var algo = secretKey.Algorithm;

        if (algo == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete
            algo == PgpPublicKeyAlgorithm.RsaSignOnly)
#pragma warning restore CS0618
        {
            return CreateRsaSignature(secretKey, hash);
        }
        else if (algo == PgpPublicKeyAlgorithm.Ed25519)
        {
            return CreateEd25519Signature(secretKey, hash);
        }
        else
        {
            throw new NotSupportedException($"Signing with algorithm {algo} is not yet supported for key rotation.");
        }
    }

    private static byte[] CreateRsaSignature(PgpSecretKeyPacket secretKey, byte[] hash)
    {
        // Extract RSA private key components
        var (d, p, q, _) = secretKey.ReadRsaSecretKey();
        var (n, e) = secretKey.PublicKey.ReadRsaKey();

        // Use RsaCore infrastructure
        var rsaPrivateKey = new RsaPrivateKey(n, d, p, q, e);
        var rsaParams = RsaCore.ToRsaParameters(rsaPrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        // Sign the hash
        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Encode as MPI
        int mpiLen = Mpi.GetEncodedLength(signature);
        var mpiBuffer = new byte[mpiLen];
        Mpi.Write(signature, mpiBuffer);
        return mpiBuffer;
    }

    private static byte[] CreateEd25519Signature(PgpSecretKeyPacket secretKey, byte[] hash)
    {
        // Read the Ed25519 private key
        var ed25519PrivateKey = secretKey.ReadEcSecretKey();

        try
        {
            // Ed25519 in OpenPGP signs the hash
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
            throw new ObjectDisposedException(nameof(PgpKeyRotator));
        }
#endif
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!disposed)
        {
            oldSecretKey = null;
            newKeyRing = null;
            revocationText = null;
            disposed = true;
        }
    }
}

/// <summary>
/// Result of a key rotation operation.
/// </summary>
/// <remarks>
/// <para>
/// Contains all the signatures and key rings produced by the rotation.
/// </para>
/// </remarks>
public readonly struct PgpKeyRotationResult
{
    /// <summary>
    /// Creates a new key rotation result.
    /// </summary>
    internal PgpKeyRotationResult(
        PgpSignaturePacket transitionSignature,
        PgpSignaturePacket? oldKeyRevocation,
        PgpPublicKeyRing certifiedNewKeyRing,
        PgpPublicKeyPacket oldPublicKey,
        PgpPublicKeyPacket newPublicKey)
    {
        TransitionSignature = transitionSignature;
        OldKeyRevocation = oldKeyRevocation;
        CertifiedNewKeyRing = certifiedNewKeyRing;
        OldPublicKey = oldPublicKey;
        NewPublicKey = newPublicKey;
    }

    /// <summary>
    /// Gets the transition signature (direct key signature from old key on new key).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This signature (type 0x1F) establishes the trust chain from the old key
    /// to the new key. It should be distributed along with the new public key.
    /// </para>
    /// </remarks>
    public PgpSignaturePacket TransitionSignature { get; }

    /// <summary>
    /// Gets the old key revocation signature, if revocation was requested.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This signature (type 0x20) revokes the old key. It should be distributed
    /// to key servers and correspondents to indicate the old key is no longer valid.
    /// </para>
    /// </remarks>
    public PgpSignaturePacket? OldKeyRevocation { get; }

    /// <summary>
    /// Gets the new public key ring with the transition signature added.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This key ring includes the transition signature from the old key,
    /// providing continuity of trust for users who trusted the old key.
    /// </para>
    /// </remarks>
    public PgpPublicKeyRing CertifiedNewKeyRing { get; }

    /// <summary>
    /// Gets the old public key.
    /// </summary>
    public PgpPublicKeyPacket OldPublicKey { get; }

    /// <summary>
    /// Gets the new public key.
    /// </summary>
    public PgpPublicKeyPacket NewPublicKey { get; }

    /// <summary>
    /// Gets the fingerprint of the old key.
    /// </summary>
    public byte[] OldKeyFingerprint => OldPublicKey.ComputeFingerprint();

    /// <summary>
    /// Gets the fingerprint of the new key.
    /// </summary>
    public byte[] NewKeyFingerprint => NewPublicKey.ComputeFingerprint();

    /// <summary>
    /// Gets whether the old key was revoked as part of the rotation.
    /// </summary>
    public bool OldKeyWasRevoked => OldKeyRevocation.HasValue;
}
