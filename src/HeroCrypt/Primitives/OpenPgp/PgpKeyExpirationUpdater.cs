using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Updates the expiration time on existing OpenPGP keys.
/// </summary>
/// <remarks>
/// <para>
/// This class creates a new self-signature with an updated KeyExpirationTime subpacket.
/// The new signature supersedes any previous self-signature for expiration purposes.
/// </para>
/// <para>
/// <b>Usage:</b>
/// <code>
/// // Extend a key's expiration by 1 year
/// using var updater = PgpKeyExpirationUpdater.Create()
///     .WithSecretKeyRing(secretKeyRing)
///     .WithNewExpiration(TimeSpan.FromDays(365));
///
/// var (newPublicKeyRing, newSecretKeyRing) = updater.Update();
/// </code>
/// </para>
/// <para>
/// <b>Note:</b> Updating key expiration requires the secret key to sign the new self-signature.
/// </para>
/// </remarks>
public sealed class PgpKeyExpirationUpdater : IDisposable
{
    private PgpSecretKeyRing? secretKeyRing;
    private TimeSpan? newExpiration;
    private DateTimeOffset? timestamp;
    private bool disposed;

    private PgpKeyExpirationUpdater()
    {
    }

    /// <summary>
    /// Creates a new key expiration updater.
    /// </summary>
    /// <returns>A new updater builder instance.</returns>
    public static PgpKeyExpirationUpdater Create() => new();

    /// <summary>
    /// Sets the secret key ring containing the key to update.
    /// </summary>
    /// <param name="secretKeyRing">The secret key ring with the master key.</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyExpirationUpdater WithSecretKeyRing(PgpSecretKeyRing secretKeyRing)
    {
        ThrowIfDisposed();
        this.secretKeyRing = secretKeyRing;
        return this;
    }

    /// <summary>
    /// Sets the new expiration time as a duration from the key creation time.
    /// </summary>
    /// <param name="lifetime">The new key lifetime. Use TimeSpan.Zero to remove expiration (never expires).</param>
    /// <returns>This builder for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If lifetime is negative or exceeds ~136 years.</exception>
    public PgpKeyExpirationUpdater WithNewExpiration(TimeSpan lifetime)
    {
        ThrowIfDisposed();

        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime cannot be negative.");
        }

        if (lifetime.TotalSeconds > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime exceeds maximum value (~136 years).");
        }

        this.newExpiration = lifetime == TimeSpan.Zero ? null : lifetime;
        return this;
    }

    /// <summary>
    /// Sets the new expiration to a specific date.
    /// </summary>
    /// <param name="expirationDate">The new expiration date.</param>
    /// <returns>This builder for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If the expiration date is before the key creation time.</exception>
    public PgpKeyExpirationUpdater WithNewExpirationDate(DateTimeOffset expirationDate)
    {
        ThrowIfDisposed();

        if (secretKeyRing == null)
        {
            throw new InvalidOperationException("Secret key ring must be set before specifying expiration date.");
        }

        var keyCreationTime = secretKeyRing.Value.MasterKey.PublicKey.CreationTime;
        var lifetime = expirationDate - keyCreationTime;

        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(expirationDate), "Expiration date cannot be before key creation time.");
        }

        return WithNewExpiration(lifetime);
    }

    /// <summary>
    /// Removes the expiration time (key will never expire).
    /// </summary>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyExpirationUpdater WithNoExpiration()
    {
        ThrowIfDisposed();
        this.newExpiration = null;
        return this;
    }

    /// <summary>
    /// Sets a custom timestamp for the new self-signature.
    /// </summary>
    /// <param name="timestamp">The signature timestamp.</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyExpirationUpdater WithTimestamp(DateTimeOffset timestamp)
    {
        ThrowIfDisposed();
        this.timestamp = timestamp;
        return this;
    }

    /// <summary>
    /// Creates the updated key rings with the new expiration.
    /// </summary>
    /// <returns>A tuple containing the updated public and secret key rings.</returns>
    /// <exception cref="InvalidOperationException">If required parameters are not set.</exception>
    public (PgpPublicKeyRing PublicKeyRing, PgpSecretKeyRing SecretKeyRing) Update()
    {
        ThrowIfDisposed();
        ValidateState();

        var masterSecretKey = secretKeyRing!.Value.MasterKey;
        var masterPublicKey = masterSecretKey.PublicKey;
        var version = masterPublicKey.Version;
        var sigTimestamp = timestamp ?? DateTimeOffset.UtcNow;

        // Get the first user ID from the key ring
        if (secretKeyRing.Value.UserIds.Count == 0)
        {
            throw new InvalidOperationException("Key ring has no user IDs.");
        }
        var userIdPacket = secretKeyRing.Value.UserIds[0];

        // Create the new self-certification signature with updated expiration
        var newCertification = CreateUpdatedCertification(
            masterPublicKey,
            masterSecretKey,
            userIdPacket,
            version,
            sigTimestamp);

        // Build new key rings with the additional signature
        var newPublicKeyRing = secretKeyRing.Value.ExtractPublicKeyRing().AddSignature(newCertification);
        var newSecretKeyRing = secretKeyRing.Value.AddSignature(newCertification);

        return (newPublicKeyRing, newSecretKeyRing);
    }

    private void ValidateState()
    {
        if (secretKeyRing == null)
        {
            throw new InvalidOperationException("Secret key ring must be set using WithSecretKeyRing().");
        }
    }

    private PgpSignaturePacket CreateUpdatedCertification(
        PgpPublicKeyPacket publicKey,
        PgpSecretKeyPacket secretKey,
        PgpUserIdPacket userIdPacket,
        byte version,
        DateTimeOffset sigTimestamp)
    {
        var sigType = PgpSignatureType.PositiveCertification;
        var pubAlgo = (byte)publicKey.Algorithm;
        var hashAlgo = (byte)PgpHashAlgorithmId.Sha256;

        // Get existing key flags from the key ring's self-signature
        var keyFlags = GetExistingKeyFlags();

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(sigTimestamp),
            PgpSignatureSubpacket.CreateKeyFlags(keyFlags),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, publicKey.ComputeFingerprint()),
            PgpSignatureSubpacket.CreateFeatures(PgpFeatures.ModificationDetection)
        };

        // Add key expiration if set (omit if no expiration - never expires)
        if (newExpiration.HasValue)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreateKeyExpirationTime(newExpiration.Value));
        }

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateIssuerKeyId(publicKey.GetKeyId())
        };

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Compute the certification hash
        var hash = PgpSignatureHashHelper.ComputeCertificationHash(
            publicKey,
            userIdPacket,
            version,
            (byte)sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpacketData);

        // Get hash prefix
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create signature
        byte[] signatureData = CreateSignatureData(secretKey, hash);

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

    private PgpKeyCapabilities GetExistingKeyFlags()
    {
        // Look for key flags in existing self-signatures
        foreach (var sig in secretKeyRing!.Value.Signatures)
        {
            if (sig.SignatureType == PgpSignatureType.GenericCertification ||
                sig.SignatureType == PgpSignatureType.PersonaCertification ||
                sig.SignatureType == PgpSignatureType.CasualCertification ||
                sig.SignatureType == PgpSignatureType.PositiveCertification)
            {
                foreach (var subpacket in sig.HashedSubpackets)
                {
                    if (subpacket.Type == PgpSignatureSubpacketType.KeyFlags)
                    {
                        return subpacket.GetKeyFlags();
                    }
                }
            }
        }

        // Default flags if none found
        return PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign;
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
            throw new NotSupportedException($"Signature algorithm {algo} is not supported for expiration updates.");
        }
    }

    private static byte[] CreateRsaSignature(PgpSecretKeyPacket secretKey, byte[] hash)
    {
        var (d, p, q, _) = secretKey.ReadRsaSecretKey();
        var (n, e) = secretKey.PublicKey.ReadRsaKey();

        var rsaPrivateKey = new RsaPrivateKey(n, d, p, q, e);
        var rsaParams = RsaCore.ToRsaParameters(rsaPrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        int mpiLen = Mpi.GetEncodedLength(signature);
        var mpiBuffer = new byte[mpiLen];
        Mpi.Write(signature, mpiBuffer);
        return mpiBuffer;
    }

    private static byte[] CreateEd25519Signature(PgpSecretKeyPacket secretKey, byte[] hash)
    {
        var ed25519PrivateKey = secretKey.ReadEcSecretKey();
        return Ed25519Core.Sign(hash, ed25519PrivateKey);
    }

    private static byte[] GenerateSalt()
    {
        int saltLen = PgpSignaturePacket.GetExpectedSaltLength((byte)PgpHashAlgorithmId.Sha256);
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
            throw new ObjectDisposedException(nameof(PgpKeyExpirationUpdater));
        }
#endif
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
        }
    }
}
