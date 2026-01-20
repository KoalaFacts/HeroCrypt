using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Creates certification signatures for User IDs on OpenPGP keys.
/// </summary>
/// <remarks>
/// <para>
/// This class implements User ID certification as defined in RFC 4880 Section 5.2.1.
/// Certifications are used in the Web of Trust model to indicate that a signer has
/// verified the binding between a public key and a User ID.
/// </para>
/// <para>
/// <b>Certification Levels:</b>
/// <list type="bullet">
///   <item><b>Generic (0x10):</b> No particular assertion about verification</item>
///   <item><b>Persona (0x11):</b> No verification done - "I haven't checked"</item>
///   <item><b>Casual (0x12):</b> Casual verification - "I did some checking"</item>
///   <item><b>Positive (0x13):</b> Substantial verification - "I have thoroughly verified"</item>
/// </list>
/// </para>
/// <para>
/// <b>Usage:</b>
/// <code>
/// using var certifier = PgpKeyCertifier.Create()
///     .WithCertifyingKey(mySecretKey)
///     .WithTargetKey(theirPublicKey)
///     .WithUserId(theirUserId)
///     .WithCertificationLevel(PgpCertificationLevel.Casual);
///
/// var certification = certifier.Certify();
/// var certifiedKey = theirPublicKey.AddCertification(certification);
/// </code>
/// </para>
/// </remarks>
public sealed class PgpKeyCertifier : IDisposable
{
    private PgpSecretKeyPacket? certifyingKey;
    private PgpPublicKeyPacket? targetKey;
    private PgpUserIdPacket? targetUserId;
    private PgpCertificationLevel certificationLevel = PgpCertificationLevel.Generic;
    private DateTimeOffset? timestamp;
    private bool disposed;

    private PgpKeyCertifier()
    {
    }

    /// <summary>
    /// Creates a new key certifier builder.
    /// </summary>
    /// <returns>A new certifier builder instance.</returns>
    public static PgpKeyCertifier Create() => new();

    /// <summary>
    /// Sets the secret key used to sign the certification.
    /// </summary>
    /// <param name="secretKey">The certifying secret key (must have certification capability).</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyCertifier WithCertifyingKey(PgpSecretKeyPacket secretKey)
    {
        ThrowIfDisposed();
        certifyingKey = secretKey;
        return this;
    }

    /// <summary>
    /// Sets the public key to certify.
    /// </summary>
    /// <param name="publicKey">The public key being certified.</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyCertifier WithTargetKey(PgpPublicKeyPacket publicKey)
    {
        ThrowIfDisposed();
        targetKey = publicKey;
        return this;
    }

    /// <summary>
    /// Sets the User ID to certify.
    /// </summary>
    /// <param name="userId">The User ID packet to certify.</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyCertifier WithUserId(PgpUserIdPacket userId)
    {
        ThrowIfDisposed();
        targetUserId = userId;
        return this;
    }

    /// <summary>
    /// Sets the User ID to certify by string value.
    /// </summary>
    /// <param name="userId">The User ID string (e.g., "Name &lt;email@example.com&gt;").</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyCertifier WithUserId(string userId)
    {
        ThrowIfDisposed();
        targetUserId = new PgpUserIdPacket(userId);
        return this;
    }

    /// <summary>
    /// Sets the certification level.
    /// </summary>
    /// <param name="level">The certification level indicating degree of verification.</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyCertifier WithCertificationLevel(PgpCertificationLevel level)
    {
        ThrowIfDisposed();
        certificationLevel = level;
        return this;
    }

    /// <summary>
    /// Sets a custom timestamp for the certification.
    /// </summary>
    /// <param name="timestamp">The certification timestamp.</param>
    /// <returns>This builder for chaining.</returns>
    public PgpKeyCertifier WithTimestamp(DateTimeOffset timestamp)
    {
        ThrowIfDisposed();
        this.timestamp = timestamp;
        return this;
    }

    /// <summary>
    /// Creates the certification signature.
    /// </summary>
    /// <returns>The certification signature packet.</returns>
    /// <exception cref="InvalidOperationException">Required parameters not set.</exception>
    public PgpSignaturePacket Certify()
    {
        ThrowIfDisposed();
        ValidateState();

        var certifyingKeyPub = certifyingKey!.Value.PublicKey;
        var sigType = MapCertificationLevel(certificationLevel);
        byte version = DetermineVersion(certifyingKeyPub.Algorithm);
        byte pubAlgo = (byte)certifyingKeyPub.Algorithm;
        byte hashAlgo = (byte)PgpHashAlgorithmId.Sha256;
        var creationTime = timestamp ?? DateTimeOffset.UtcNow;

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(creationTime),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, certifyingKeyPub.ComputeFingerprint())
        };

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateIssuerKeyId(certifyingKeyPub.GetKeyId())
        };

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Compute the certification hash
        byte[] hash = PgpSignatureHashHelper.ComputeCertificationHash(
            targetKey!.Value,
            targetUserId!.Value,
            version,
            (byte)sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpacketData);

        // Get hash prefix
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create signature data
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

    /// <summary>
    /// Creates a certification and adds it to the target public key ring.
    /// </summary>
    /// <param name="targetKeyRing">The public key ring to certify.</param>
    /// <returns>The key ring with the certification added.</returns>
    /// <exception cref="InvalidOperationException">Required parameters not set or User ID not found.</exception>
    public PgpPublicKeyRing CertifyKeyRing(PgpPublicKeyRing targetKeyRing)
    {
        ThrowIfDisposed();

        if (certifyingKey == null)
        {
            throw new InvalidOperationException("Certifying key must be set.");
        }

        if (targetUserId == null)
        {
            throw new InvalidOperationException("Target User ID must be set.");
        }

        // Set the target key from the key ring if not already set
        if (targetKey == null)
        {
            targetKey = targetKeyRing.MasterKey;
        }

        var certification = Certify();
        return targetKeyRing.AddCertification(targetUserId.Value, certification);
    }

    private void ValidateState()
    {
        if (certifyingKey == null)
        {
            throw new InvalidOperationException("Certifying key must be set using WithCertifyingKey().");
        }

        if (targetKey == null)
        {
            throw new InvalidOperationException("Target key must be set using WithTargetKey().");
        }

        if (targetUserId == null)
        {
            throw new InvalidOperationException("Target User ID must be set using WithUserId().");
        }
    }

    private static PgpSignatureType MapCertificationLevel(PgpCertificationLevel level) => level switch
    {
        PgpCertificationLevel.Generic => PgpSignatureType.GenericCertification,
        PgpCertificationLevel.Persona => PgpSignatureType.PersonaCertification,
        PgpCertificationLevel.Casual => PgpSignatureType.CasualCertification,
        PgpCertificationLevel.Positive => PgpSignatureType.PositiveCertification,
        _ => throw new ArgumentOutOfRangeException(nameof(level))
    };

    private static byte DetermineVersion(PgpPublicKeyAlgorithm algorithm)
    {
        // Ed25519 and X25519 require V6
        return algorithm switch
        {
            PgpPublicKeyAlgorithm.Ed25519 => 6,
            PgpPublicKeyAlgorithm.X25519 => 6,
            _ => 4
        };
    }

    private byte[] CreateSignatureData(byte[] hash)
    {
        var algo = certifyingKey!.Value.Algorithm;

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
            throw new NotSupportedException($"Signature algorithm {algo} is not supported for certifications.");
        }
    }

    private byte[] CreateRsaSignature(byte[] hash)
    {
        // Extract RSA private key components
        var (d, p, q, _) = certifyingKey!.Value.ReadRsaSecretKey();
        var (n, e) = certifyingKey.Value.PublicKey.ReadRsaKey();

        // Use RsaCore infrastructure which handles all the RSA operations
        var rsaPrivateKey = new RsaPrivateKey(n, d, p, q, e);
        var rsaParams = RsaCore.ToRsaParameters(rsaPrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Encode as MPI
        int mpiLen = Mpi.GetEncodedLength(signature);
        var mpiBuffer = new byte[mpiLen];
        Mpi.Write(signature, mpiBuffer);
        return mpiBuffer;
    }

    private byte[] CreateEd25519Signature(byte[] hash)
    {
        // Read the Ed25519 private key from the secret key packet
        var ed25519PrivateKey = certifyingKey!.Value.ReadEcSecretKey();

        // Ed25519 in OpenPGP signs the hash (which includes the signature trailer)
        var signature = Ed25519Core.Sign(hash, ed25519PrivateKey);
        return signature;
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
            throw new ObjectDisposedException(nameof(PgpKeyCertifier));
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

/// <summary>
/// Certification levels for User ID certifications.
/// </summary>
/// <remarks>
/// <para>
/// These levels correspond to OpenPGP signature types 0x10-0x13 and indicate
/// the degree of verification performed by the certifier.
/// </para>
/// </remarks>
public enum PgpCertificationLevel
{
    /// <summary>
    /// Generic certification (0x10) - no particular assertion about verification.
    /// </summary>
    Generic = 0x10,

    /// <summary>
    /// Persona certification (0x11) - no verification performed.
    /// </summary>
    /// <remarks>
    /// "I have not checked whether this person is who they claim to be."
    /// </remarks>
    Persona = 0x11,

    /// <summary>
    /// Casual certification (0x12) - casual verification performed.
    /// </summary>
    /// <remarks>
    /// "I have done some casual checking that this person is who they claim to be."
    /// </remarks>
    Casual = 0x12,

    /// <summary>
    /// Positive certification (0x13) - substantial verification performed.
    /// </summary>
    /// <remarks>
    /// "I have done substantial verification that this person is who they claim to be."
    /// </remarks>
    Positive = 0x13
}
