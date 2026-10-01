using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for verifying OpenPGP signatures.
/// </summary>
/// <remarks>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// var result = PgpSignatureVerifier.Create()
///     .WithPublicKey(publicKey)
///     .Verify(data, signature);
///
/// if (result.IsValid)
/// {
///     Console.WriteLine($"Signed by: {result.SignerKeyId}");
/// }
/// </code>
/// </para>
/// </remarks>
public sealed class PgpSignatureVerifier : IDisposable
{
    private readonly List<PgpPublicKeyPacket> publicKeys = [];
    private bool disposed;

    private PgpSignatureVerifier()
    {
    }

    /// <summary>
    /// Creates a new signature verifier.
    /// </summary>
    /// <returns>A new PgpSignatureVerifier instance.</returns>
    public static PgpSignatureVerifier Create() => new();

    /// <summary>
    /// Adds a public key for verification.
    /// </summary>
    /// <param name="publicKey">The public key packet.</param>
    /// <returns>This verifier for chaining.</returns>
    public PgpSignatureVerifier WithPublicKey(PgpPublicKeyPacket publicKey)
    {
        ThrowIfDisposed();
        publicKeys.Add(publicKey);
        return this;
    }

    /// <summary>
    /// Adds all keys from a public key ring for verification.
    /// </summary>
    /// <param name="keyRing">The public key ring.</param>
    /// <returns>This verifier for chaining.</returns>
    public PgpSignatureVerifier WithPublicKeyRing(PgpPublicKeyRing keyRing)
    {
        ThrowIfDisposed();
        publicKeys.Add(keyRing.MasterKey);
        foreach (var subkey in keyRing.Subkeys)
        {
            publicKeys.Add(subkey);
        }

        return this;
    }

    /// <summary>
    /// Verifies a detached signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature packet.</param>
    /// <returns>The verification result.</returns>
    public PgpSignatureResult Verify(ReadOnlySpan<byte> data, PgpSignaturePacket signature)
    {
        ThrowIfDisposed();

        if (signature.SignatureType != PgpSignatureType.BinaryDocument &&
            signature.SignatureType != PgpSignatureType.CanonicalTextDocument)
        {
            return PgpSignatureResult.Invalid("Document verification requires a document signature.");
        }

        if (publicKeys.Count == 0)
        {
            return PgpSignatureResult.Invalid("No public keys provided for verification.");
        }

        // Issuer metadata can only constrain candidates. Successful attribution
        // always comes from the key that performs cryptographic verification.
        PgpSignatureResult result = PgpSignatureResult.Invalid("No matching verification key.");
        foreach (var key in publicKeys)
        {
            result = VerifyWithKey(data, signature, key);
            if (result.IsValid)
            {
                return result;
            }
        }

        return result;
    }

    /// <summary>
    /// Verifies an inline signed message.
    /// </summary>
    /// <param name="signedMessage">The signed message.</param>
    /// <returns>The verification result.</returns>
    public PgpSignatureResult Verify(PgpSignedMessage signedMessage)
    {
        ThrowIfDisposed();
        var signature = signedMessage.Signature;
        if (signedMessage.OnePassSignature is { } onePass &&
            (onePass.Version != (signature.Version == 4 ? 3 : 6) ||
             onePass.SignatureType != signature.SignatureType ||
             onePass.HashAlgorithm != signature.HashAlgorithm ||
             onePass.PublicKeyAlgorithm != signature.PublicKeyAlgorithm ||
             !onePass.IsNested || !onePass.Salt.Span.SequenceEqual(signature.Salt.Span)))
        {
            return PgpSignatureResult.Invalid("One-pass signature metadata does not match the signature.");
        }

        var result = Verify(signedMessage.Data.Span, signature);
        if (result.IsValid && signedMessage.OnePassSignature is { } ops &&
            !ops.KeyIdOrFingerprint.Span.SequenceEqual(ops.Version == 3 ? result.SignerKeyId : result.SignerFingerprint))
        {
            return PgpSignatureResult.Invalid("One-pass signer does not match the verification key.");
        }

        return result;
    }

    /// <summary>
    /// Tries to verify a detached signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature packet.</param>
    /// <param name="result">The verification result.</param>
    /// <param name="error">Error message if verification setup failed.</param>
    /// <returns>True if verification could be attempted (check result.IsValid for success).</returns>
    public bool TryVerify(ReadOnlySpan<byte> data, PgpSignaturePacket signature, out PgpSignatureResult result, out string? error)
    {
        ThrowIfDisposed();
        error = null;

        try
        {
            result = Verify(data, signature);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            result = PgpSignatureResult.Invalid(ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Verifies a key revocation signature (type 0x20).
    /// </summary>
    /// <param name="signature">The revocation signature.</param>
    /// <param name="revokedKey">The public key being revoked (which also signed the revocation).</param>
    /// <returns>The verification result.</returns>
    /// <remarks>
    /// <para>
    /// A key revocation signature (type 0x20) is made by the key being revoked.
    /// The signature covers the key material itself, not external data.
    /// </para>
    /// </remarks>
    public PgpSignatureResult VerifyKeyRevocation(PgpSignaturePacket signature, PgpPublicKeyPacket revokedKey)
    {
        ThrowIfDisposed();

        if (signature.SignatureType != PgpSignatureType.KeyRevocation)
        {
            return PgpSignatureResult.Invalid(
                $"Expected KeyRevocation (0x20) signature but got {signature.SignatureType}.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyKeyBasedSignature(signature, revokedKey, revokedKey, null);
    }

    /// <summary>
    /// Verifies a subkey revocation signature (type 0x28).
    /// </summary>
    /// <param name="signature">The subkey revocation signature.</param>
    /// <param name="masterKey">The master key that signed the revocation.</param>
    /// <param name="revokedSubkey">The subkey being revoked.</param>
    /// <returns>The verification result.</returns>
    /// <remarks>
    /// <para>
    /// A subkey revocation signature (type 0x28) is made by the master key,
    /// not the subkey being revoked. The signature covers both the master key
    /// and the subkey material.
    /// </para>
    /// </remarks>
    public PgpSignatureResult VerifySubkeyRevocation(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket masterKey,
        PgpPublicKeyPacket revokedSubkey)
    {
        ThrowIfDisposed();

        if (signature.SignatureType != PgpSignatureType.SubkeyRevocation)
        {
            return PgpSignatureResult.Invalid(
                $"Expected SubkeyRevocation (0x28) signature but got {signature.SignatureType}.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyKeyBasedSignature(signature, masterKey, masterKey, revokedSubkey);
    }

    /// <summary>
    /// Verifies a direct key signature (type 0x1F).
    /// </summary>
    /// <param name="signature">The direct key signature.</param>
    /// <param name="signingKey">The public key that created the signature.</param>
    /// <param name="targetKey">The target key that was signed.</param>
    /// <returns>The verification result.</returns>
    /// <remarks>
    /// <para>
    /// A direct key signature (type 0x1F) is used to certify a key without
    /// binding to a specific User ID. It's commonly used in key rotation
    /// where the old key signs the new key to establish a trust chain.
    /// </para>
    /// </remarks>
    public PgpSignatureResult VerifyDirectKeySignature(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket signingKey,
        PgpPublicKeyPacket targetKey)
    {
        ThrowIfDisposed();

        if (signature.SignatureType != PgpSignatureType.DirectKey)
        {
            return PgpSignatureResult.Invalid(
                $"Expected DirectKey (0x1F) signature but got {signature.SignatureType}.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyKeyBasedSignature(signature, signingKey, targetKey, null);
    }

    /// <summary>
    /// Verifies a key rotation transition signature.
    /// </summary>
    /// <param name="signature">The transition signature (direct key signature from old key).</param>
    /// <param name="oldKey">The old public key that signed the transition.</param>
    /// <param name="newKey">The new public key that was certified.</param>
    /// <returns>The verification result.</returns>
    /// <remarks>
    /// <para>
    /// This is a convenience method for verifying key rotation. It's equivalent to
    /// calling <see cref="VerifyDirectKeySignature"/> with the old key as the signer
    /// and the new key as the target.
    /// </para>
    /// </remarks>
    public PgpSignatureResult VerifyTransitionSignature(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket oldKey,
        PgpPublicKeyPacket newKey)
    {
        ThrowIfDisposed();

        // Transition signatures are direct key signatures (0x1F)
        if (signature.SignatureType != PgpSignatureType.DirectKey)
        {
            return PgpSignatureResult.Invalid(
                $"Expected DirectKey (0x1F) transition signature but got {signature.SignatureType}.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyKeyBasedSignature(signature, oldKey, newKey, null);
    }

    /// <summary>
    /// Verifies a subkey binding signature (type 0x18).
    /// </summary>
    /// <param name="signature">The subkey binding signature.</param>
    /// <param name="masterKey">The master key that signed the binding.</param>
    /// <param name="subkey">The subkey being bound.</param>
    /// <returns>The verification result.</returns>
    /// <remarks>
    /// <para>
    /// A subkey binding signature (type 0x18) is made by the master key to bind
    /// a subkey to the key ring. The signature covers both the master key and subkey.
    /// </para>
    /// </remarks>
    public PgpSignatureResult VerifySubkeyBinding(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket masterKey,
        PgpPublicKeyPacket subkey)
    {
        ThrowIfDisposed();

        if (signature.SignatureType != PgpSignatureType.SubkeyBinding)
        {
            return PgpSignatureResult.Invalid(
                $"Expected SubkeyBinding (0x18) signature but got {signature.SignatureType}.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyKeyBasedSignature(signature, masterKey, masterKey, subkey);
    }

    /// <summary>
    /// Verifies a User ID certification signature (types 0x10-0x13).
    /// </summary>
    /// <param name="signature">The certification signature.</param>
    /// <param name="certifyingKey">The public key that created the certification.</param>
    /// <param name="certifiedKey">The public key being certified.</param>
    /// <param name="userId">The User ID being certified.</param>
    /// <returns>The verification result.</returns>
    /// <remarks>
    /// <para>
    /// Certification signatures are used in the Web of Trust model to indicate
    /// that someone has verified the binding between a key and a User ID.
    /// </para>
    /// <para>
    /// Certification levels:
    /// <list type="bullet">
    ///   <item>0x10 - Generic: no particular assertion</item>
    ///   <item>0x11 - Persona: no verification done</item>
    ///   <item>0x12 - Casual: some casual verification</item>
    ///   <item>0x13 - Positive: substantial verification</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpSignatureResult VerifyCertification(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket certifyingKey,
        PgpPublicKeyPacket certifiedKey,
        PgpUserIdPacket userId)
    {
        ThrowIfDisposed();

        // Validate signature type
        if (signature.SignatureType != PgpSignatureType.GenericCertification &&
            signature.SignatureType != PgpSignatureType.PersonaCertification &&
            signature.SignatureType != PgpSignatureType.CasualCertification &&
            signature.SignatureType != PgpSignatureType.PositiveCertification)
        {
            return PgpSignatureResult.Invalid(
                $"Expected certification signature (0x10-0x13) but got {signature.SignatureType}.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyCertificationSignature(signature, certifyingKey, certifiedKey, userId);
    }

    /// <summary>
    /// Verifies a self-certification (key owner certifying their own User ID).
    /// </summary>
    /// <param name="signature">The self-certification signature.</param>
    /// <param name="publicKey">The public key (both certifier and certified).</param>
    /// <param name="userId">The User ID being certified.</param>
    /// <returns>The verification result.</returns>
    public PgpSignatureResult VerifySelfCertification(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket publicKey,
        PgpUserIdPacket userId)
    {
        return VerifyCertification(signature, publicKey, publicKey, userId);
    }

    // Cryptographic target association only; this does not evaluate certification-revocation policy.
    internal PgpSignatureResult VerifySelfCertificationRevocation(PgpSignaturePacket signature,
        PgpPublicKeyPacket publicKey, PgpUserIdPacket userId)
    {
        ThrowIfDisposed();
        if (signature.SignatureType != PgpSignatureType.CertificationRevocation)
            return PgpSignatureResult.Invalid("Expected a certification revocation.", signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm, (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm, signature.Version);
        return VerifyCertificationSignature(signature, publicKey, publicKey, userId);
    }

    /// <summary>
    /// Core method for verifying certification signatures.
    /// </summary>
    private PgpSignatureResult VerifyCertificationSignature(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket certifyingKey,
        PgpPublicKeyPacket certifiedKey,
        PgpUserIdPacket userId)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)signature.HashAlgorithm;
        var sigType = signature.SignatureType;
        var version = signature.Version;

        try
        {
            ValidateSignature(signature, certifyingKey);

            // Compute the certification hash
            byte[] computedHash = PgpSignatureHashHelper.ComputeCertificationHash(
                certifiedKey,
                userId,
                signature.Version,
                (byte)signature.SignatureType,
                (byte)(PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.HashAlgorithm,
                PgpSignatureSubpacket.WriteAll(signature.HashedSubpackets), signature.Salt.ToArray());

            // Verify hash prefix
            ushort computedPrefix = BinaryPrimitives.ReadUInt16BigEndian(computedHash);
            if (computedPrefix != signature.HashPrefix)
            {
                return PgpSignatureResult.Invalid(
                    "Hash prefix mismatch.",
                    sigType,
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }

            // Verify the signature using the certifying key
            bool isValid = VerifySignatureData(computedHash, signature.SignatureData.ToArray(), certifyingKey, hashAlgorithm);

            if (isValid)
            {
                return PgpSignatureResult.Valid(
                    sigType,
                    signature.GetCreationTime(),
                    certifyingKey.GetKeyId(),
                    certifyingKey.ComputeFingerprint(),
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }
            else
            {
                return PgpSignatureResult.Invalid(
                    "Signature cryptographic verification failed.",
                    sigType,
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }
        }
        catch (Exception ex)
        {
            return PgpSignatureResult.Invalid(
                $"Verification error: {ex.Message}",
                sigType,
                hashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                version);
        }
    }

    /// <summary>
    /// Core method for verifying key-based signatures.
    /// </summary>
    private PgpSignatureResult VerifyKeyBasedSignature(
        PgpSignaturePacket signature,
        PgpPublicKeyPacket signingKey,
        PgpPublicKeyPacket primaryKey,
        PgpPublicKeyPacket? secondaryKey)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)signature.HashAlgorithm;
        var sigType = signature.SignatureType;
        var version = signature.Version;

        try
        {
            ValidateSignature(signature, signingKey);

            // Compute the hash based on signature type
            byte[] computedHash = PgpSignatureHashHelper.ComputeKeySignatureHash(
                primaryKey,
                secondaryKey,
                signature.Version,
                (byte)signature.SignatureType,
                (byte)(PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.HashAlgorithm,
                PgpSignatureSubpacket.WriteAll(signature.HashedSubpackets),
                signature.Salt.ToArray());

            // Verify hash prefix
            ushort computedPrefix = BinaryPrimitives.ReadUInt16BigEndian(computedHash);
            if (computedPrefix != signature.HashPrefix)
            {
                return PgpSignatureResult.Invalid(
                    "Hash prefix mismatch.",
                    sigType,
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }

            // Verify the signature using the signing key
            bool isValid = VerifySignatureData(computedHash, signature.SignatureData.ToArray(), signingKey, hashAlgorithm);

            if (isValid)
            {
                return PgpSignatureResult.Valid(
                    sigType,
                    signature.GetCreationTime(),
                    signingKey.GetKeyId(),
                    signingKey.ComputeFingerprint(),
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }
            else
            {
                return PgpSignatureResult.Invalid(
                    "Signature cryptographic verification failed.",
                    sigType,
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }
        }
        catch (Exception ex)
        {
            return PgpSignatureResult.Invalid(
                $"Verification error: {ex.Message}",
                sigType,
                hashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                version);
        }
    }


    private PgpSignatureResult VerifyWithKey(ReadOnlySpan<byte> data, PgpSignaturePacket signature, PgpPublicKeyPacket publicKey)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)signature.HashAlgorithm;
        var sigType = signature.SignatureType;
        var version = signature.Version;

        try
        {
            ValidateSignature(signature, publicKey);

            // Compute the hash
            byte[] computedHash = PgpSignatureHashHelper.ComputeDocumentHash(
                data,
                signature.Version,
                (byte)signature.SignatureType,
                (byte)(PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.HashAlgorithm,
                PgpSignatureSubpacket.WriteAll(signature.HashedSubpackets),
                signature.Salt.ToArray());

            // Verify hash prefix
            ushort computedPrefix = BinaryPrimitives.ReadUInt16BigEndian(computedHash);
            if (computedPrefix != signature.HashPrefix)
            {
                return PgpSignatureResult.Invalid(
                    "Hash prefix mismatch.",
                    sigType,
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }

            // Verify the signature
            bool isValid = VerifySignatureData(computedHash, signature.SignatureData.ToArray(), publicKey, hashAlgorithm);

            if (isValid)
            {
                return PgpSignatureResult.Valid(
                    sigType,
                    signature.GetCreationTime(),
                    publicKey.GetKeyId(),
                    publicKey.ComputeFingerprint(),
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }
            else
            {
                return PgpSignatureResult.Invalid(
                    "Signature cryptographic verification failed.",
                    sigType,
                    hashAlgorithm,
                    (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                    version);
            }
        }
        catch (Exception ex)
        {
            return PgpSignatureResult.Invalid(
                $"Verification error: {ex.Message}",
                sigType,
                hashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                version);
        }
    }


    private static bool VerifySignatureData(byte[] hash, byte[] signatureData, PgpPublicKeyPacket publicKey, PgpHashAlgorithmId hashAlg)
    {
        var algo = publicKey.Algorithm;

        if (algo == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete
            algo == PgpPublicKeyAlgorithm.RsaSignOnly)
#pragma warning restore CS0618
        {
            return VerifyRsaSignature(hash, signatureData, publicKey, hashAlg);
        }
        else if (algo == PgpPublicKeyAlgorithm.Ed25519)
        {
            return VerifyEd25519Signature(hash, signatureData, publicKey);
        }
        else if (algo == PgpPublicKeyAlgorithm.Ecdsa)
        {
            return VerifyEcdsaSignature(hash, signatureData, publicKey);
        }
        else
        {
            throw new NotSupportedException($"Verification with algorithm {algo} is not yet supported.");
        }
    }

    private static bool VerifyRsaSignature(byte[] hash, byte[] signatureData, PgpPublicKeyPacket publicKey, PgpHashAlgorithmId hashAlg)
    {
        // Read the signature MPI - returns the raw big integer value
        var signatureValue = Mpi.Read(signatureData, out var consumed);
        if (consumed != signatureData.Length || Mpi.GetEncodedLength(signatureValue) != consumed)
        {
            return false;
        }

        var canonical = new byte[consumed];
        Mpi.Write(signatureValue, canonical);
        if (!canonical.AsSpan().SequenceEqual(signatureData))
        {
            return false;
        }

        // Extract public key components
        var (n, e) = publicKey.ReadRsaKey();

        // Use RsaCore infrastructure
        var rsaPublicKey = new RsaPublicKey(n, e);
        var rsaCore = new RsaCore();
        var rsaParams = rsaCore.ToRsaParameters(rsaPublicKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        // Convert BigInteger to bytes for signature
        // Use same approach as RsaCore for BigInteger to bytes
        byte[] signatureBytes = BigIntegerToBytes(signatureValue);

        // Pad if needed
        if (signatureBytes.Length < rsaParams.Modulus!.Length)
        {
            var padded = new byte[rsaParams.Modulus.Length];
            Array.Copy(signatureBytes, 0, padded, rsaParams.Modulus.Length - signatureBytes.Length, signatureBytes.Length);
            signatureBytes = padded;
        }

        return rsa.VerifyHash(hash, signatureBytes, hashAlg.GetHashAlgorithmName(), RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Converts a BigInteger to big-endian bytes (unsigned).
    /// Same approach as RsaCore.BigIntegerToBytes.
    /// </summary>
    private static byte[] BigIntegerToBytes(BigInteger value)
    {
        if (value.IsZero)
        {
            return [0];
        }

        var littleEndian = value.ToByteArray();
        var length = littleEndian.Length;

        // Skip sign byte if present
        while (length > 1 && littleEndian[length - 1] == 0)
        {
            length--;
        }

        var result = new byte[length];
        for (var i = 0; i < length; i++)
        {
            result[i] = littleEndian[length - 1 - i];
        }

        return result;
    }

    private static bool VerifyEd25519Signature(byte[] hash, byte[] signatureData, PgpPublicKeyPacket publicKey)
    {
        // Read the Ed25519 public key (32 bytes)
        var ed25519PublicKey = publicKey.ReadNativePublicKey();

        // The signature data should be 64 bytes for Ed25519
        if (signatureData.Length != 64)
        {
            return false;
        }

        // Verify using Ed25519Core
        return new Ed25519Core().Verify(hash, signatureData, ed25519PublicKey);
    }

    private static bool VerifyEcdsaSignature(byte[] hash, byte[] signatureData, PgpPublicKeyPacket publicKey)
    {
        throw new NotSupportedException("ECDSA verification is not yet implemented.");
    }

    private static void ValidateSignature(PgpSignaturePacket signature, PgpPublicKeyPacket key)
    {
        if ((signature.Version != 4 && signature.Version != 6) || signature.Version != key.Version ||
            signature.PublicKeyAlgorithm != (byte)key.Algorithm)
        {
            throw new ArgumentException("Signature version or algorithm does not match the verification key.");
        }

        var hashAlgorithm = (PgpHashAlgorithmId)signature.HashAlgorithm;
        if (hashAlgorithm != PgpHashAlgorithmId.Sha256 && hashAlgorithm != PgpHashAlgorithmId.Sha384 &&
            hashAlgorithm != PgpHashAlgorithmId.Sha512 && hashAlgorithm != PgpHashAlgorithmId.Sha3_256 &&
            hashAlgorithm != PgpHashAlgorithmId.Sha3_512)
        {
            throw new ArgumentException("Signature hash algorithm is unsupported or weak.");
        }

        if (signature.Version == 6 && signature.Salt.Length != PgpSignaturePacket.GetExpectedSaltLength(signature.HashAlgorithm))
        {
            throw new ArgumentException("Signature salt length does not match its hash algorithm.");
        }

        var fingerprint = key.ComputeFingerprint();
        var keyId = key.GetKeyId();
        ValidateSubpackets(signature.HashedSubpackets, key.Version, fingerprint, keyId, hashed: true);
        ValidateSubpackets(signature.UnhashedSubpackets, key.Version, fingerprint, keyId, hashed: false);
    }

    private static void ValidateSubpackets(IReadOnlyList<PgpSignatureSubpacket> subpackets, byte keyVersion,
        byte[] fingerprint, byte[] keyId, bool hashed)
    {
        var seen = new HashSet<PgpSignatureSubpacketType>();
        foreach (var packet in subpackets)
        {
            // Knowing a type identifier is insufficient: critical semantics must
            // actually be evaluated. Context, notation and trust policy are absent.
            if (packet.IsCritical && (!hashed ||
                (packet.Type != PgpSignatureSubpacketType.SignatureCreationTime &&
                 packet.Type != PgpSignatureSubpacketType.IssuerFingerprint &&
                 packet.Type != PgpSignatureSubpacketType.IssuerKeyId)))
            {
                throw new ArgumentException("Unsupported critical signature subpacket.");
            }

            if (packet.Type == PgpSignatureSubpacketType.IssuerFingerprint)
            {
                if (!seen.Add(packet.Type) || packet.Data.Length != fingerprint.Length + 1 ||
                    packet.Data.Span[0] != keyVersion || !packet.Data.Span.Slice(1).SequenceEqual(fingerprint))
                {
                    throw new ArgumentException("Issuer fingerprint does not match the verification key.");
                }
            }
            else if (packet.Type == PgpSignatureSubpacketType.IssuerKeyId)
            {
                if (!seen.Add(packet.Type) || !packet.Data.Span.SequenceEqual(keyId))
                {
                    throw new ArgumentException("Issuer key ID does not match the verification key.");
                }
            }
            else if (packet.Type == PgpSignatureSubpacketType.SignatureCreationTime ||
                     packet.Type == PgpSignatureSubpacketType.SignatureExpirationTime ||
                     packet.Type == PgpSignatureSubpacketType.KeyExpirationTime)
            {
                if (!seen.Add(packet.Type) || packet.Data.Length != 4)
                {
                    throw new ArgumentException("Malformed or duplicate signature time subpacket.");
                }
            }
        }
    }

    private void ThrowIfDisposed()
    {
#if NET8_0_OR_GREATER
        ObjectDisposedException.ThrowIf(disposed, this);
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(PgpSignatureVerifier));
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
            publicKeys.Clear();
            disposed = true;
        }
    }
}
