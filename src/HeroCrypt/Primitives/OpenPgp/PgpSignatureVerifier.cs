using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
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

    #region Key Configuration

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

    #endregion

    #region Verification

    /// <summary>
    /// Verifies a detached signature.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature packet.</param>
    /// <returns>The verification result.</returns>
    public PgpSignatureResult Verify(ReadOnlySpan<byte> data, PgpSignaturePacket signature)
    {
        ThrowIfDisposed();

        if (publicKeys.Count == 0)
        {
            return PgpSignatureResult.Invalid("No public keys provided for verification.");
        }

        // Find the matching key
        var signerKeyId = signature.GetIssuerKeyId();
        var signerFingerprint = signature.GetIssuerFingerprint();

        PgpPublicKeyPacket? matchingKey = null;

        foreach (var key in publicKeys)
        {
            var keyId = key.GetKeyId();
            var fingerprint = key.ComputeFingerprint();

            // Match by fingerprint (preferred) or key ID
            if (signerFingerprint != null && fingerprint.AsSpan().SequenceEqual(signerFingerprint))
            {
                matchingKey = key;
                break;
            }

            if (signerKeyId != null && keyId.AsSpan().SequenceEqual(signerKeyId))
            {
                matchingKey = key;
                break;
            }
        }

        // If no match found, try all keys
        if (!matchingKey.HasValue && signerKeyId == null && signerFingerprint == null)
        {
            // Try each key
            foreach (var key in publicKeys)
            {
                var result = VerifyWithKey(data, signature, key);
                if (result.IsValid)
                {
                    return result;
                }
            }

            return PgpSignatureResult.Invalid(
                "Signature verification failed with all available keys.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        if (!matchingKey.HasValue)
        {
            return PgpSignatureResult.Invalid(
                signerKeyId != null
                    ? $"No key found with ID {Convert.ToHexString(signerKeyId)}."
                    : "No matching key found for signature.",
                signature.SignatureType,
                (PgpHashAlgorithmId)signature.HashAlgorithm,
                (PgpPublicKeyAlgorithm)signature.PublicKeyAlgorithm,
                signature.Version);
        }

        return VerifyWithKey(data, signature, matchingKey.Value);
    }

    /// <summary>
    /// Verifies an inline signed message.
    /// </summary>
    /// <param name="signedMessage">The signed message.</param>
    /// <returns>The verification result.</returns>
    public PgpSignatureResult Verify(PgpSignedMessage signedMessage)
    {
        ThrowIfDisposed();
        return Verify(signedMessage.Data.Span, signedMessage.Signature);
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

    #endregion

    #region Internal Verification

    private PgpSignatureResult VerifyWithKey(ReadOnlySpan<byte> data, PgpSignaturePacket signature, PgpPublicKeyPacket publicKey)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)signature.HashAlgorithm;
        var sigType = signature.SignatureType;
        var version = signature.Version;

        try
        {
            // Compute the hash
            byte[] computedHash = ComputeSignatureHash(
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
                    signature.GetIssuerKeyId(),
                    signature.GetIssuerFingerprint(),
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

    private static byte[] ComputeSignatureHash(
        ReadOnlySpan<byte> data,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets,
        byte[] salt)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)hashAlgo;
        using var hash = hashAlgorithm.CreateIncrementalHash();

        // For V6, hash salt first
        if (version == 6 && salt.Length > 0)
        {
            hash.AppendData(salt);
        }

        // Hash the data
        hash.AppendData(data.ToArray());

        // Build and hash the header
        if (version == 4)
        {
            var header = new byte[6 + hashedSubpackets.Length];
            header[0] = version;
            header[1] = sigType;
            header[2] = pubAlgo;
            header[3] = hashAlgo;
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), (ushort)hashedSubpackets.Length);
            Array.Copy(hashedSubpackets, 0, header, 6, hashedSubpackets.Length);
            hash.AppendData(header);

            // V4 trailer: version(1) + 0xFF(1) + length(4)
            var trailer = new byte[6];
            trailer[0] = version;
            trailer[1] = 0xFF;
            uint totalLen = (uint)(4 + hashedSubpackets.Length);
            BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), totalLen);
            hash.AppendData(trailer);
        }
        else // V6
        {
            var header = new byte[8 + hashedSubpackets.Length];
            header[0] = version;
            header[1] = sigType;
            header[2] = pubAlgo;
            header[3] = hashAlgo;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashedSubpackets.Length);
            Array.Copy(hashedSubpackets, 0, header, 8, hashedSubpackets.Length);
            hash.AppendData(header);

            // V6 trailer: version(1) + 0xFF(1) + length(8)
            var trailer = new byte[10];
            trailer[0] = version;
            trailer[1] = 0xFF;
            ulong totalLen = (ulong)(4 + hashedSubpackets.Length);
            BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(2), totalLen);
            hash.AppendData(trailer);
        }

        return hash.GetHashAndReset();
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
        var signatureValue = Mpi.Read(signatureData, out _);

        // Extract public key components
        var (n, e) = publicKey.ReadRsaKey();

        // Use RsaCore infrastructure
        var rsaPublicKey = new RsaPublicKey(n, e);
        var rsaParams = RsaCore.ToRsaParameters(rsaPublicKey);

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
        throw new NotSupportedException("Ed25519 verification is not yet implemented.");
    }

    private static bool VerifyEcdsaSignature(byte[] hash, byte[] signatureData, PgpPublicKeyPacket publicKey)
    {
        throw new NotSupportedException("ECDSA verification is not yet implemented.");
    }

    #endregion

    #region Helpers

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

    #endregion
}
