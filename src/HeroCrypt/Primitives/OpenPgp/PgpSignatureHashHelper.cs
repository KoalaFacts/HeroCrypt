using System.Buffers.Binary;
using System.Security.Cryptography;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Computes V4 and V6 signature hashes using RFC 9580 section 5.2.4.
/// V6 salt precedes all signed material; both versions use a six-byte trailer.
/// </summary>
internal static class PgpSignatureHashHelper
{
    /// <summary>
    /// Hashes document data, normalizing canonical text line endings, followed by the signature header and trailer.
    /// </summary>
    /// <param name="data">The signed document bytes.</param>
    /// <param name="version">Signature version, 4 or 6.</param>
    /// <param name="sigType">Binary or canonical text signature type.</param>
    /// <param name="pubAlgo">The signing algorithm identifier.</param>
    /// <param name="hashAlgo">The hash algorithm identifier.</param>
    /// <param name="hashedSubpackets">Serialized authenticated subpackets.</param>
    /// <param name="salt">The V6 salt, or an empty array for V4.</param>
    /// <returns>The complete signature digest.</returns>
    public static byte[] ComputeDocumentHash(ReadOnlySpan<byte> data, byte version, byte sigType,
        byte pubAlgo, byte hashAlgo, byte[] hashedSubpackets, byte[] salt)
    {
        using var hash = ((PgpHashAlgorithmId)hashAlgo).CreateIncrementalHash();
        AppendSalt(hash, version, hashAlgo, salt);
        byte[] material = data.ToArray();
        if (sigType == (byte)PgpSignatureType.CanonicalTextDocument)
        {
            // Normalize line endings only. Whitespace is part of an ordinary text signature.
            using var canonical = new MemoryStream();
            for (int i = 0; i < material.Length; i++)
            {
                byte value = material[i];
                if (value == 13 || value == 10)
                {
                    canonical.WriteByte(13);
                    canonical.WriteByte(10);
                    if (value == 13 && i + 1 < material.Length && material[i + 1] == 10) i++;
                }
                else canonical.WriteByte(value);
            }
            material = canonical.ToArray();
        }
        hash.AppendData(material);
        AppendSignatureTrailer(hash, version, sigType, pubAlgo, hashAlgo, hashedSubpackets);
        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Hashes one or two public key bodies for direct-key, binding or revocation signatures.
    /// </summary>
    /// <param name="primaryKey">The first signed public key.</param>
    /// <param name="secondaryKey">The optional second signed public key.</param>
    /// <param name="version">Signature version, which determines both key prefixes.</param>
    /// <param name="sigType">The key signature type.</param>
    /// <param name="pubAlgo">The signing algorithm identifier.</param>
    /// <param name="hashAlgo">The hash algorithm identifier.</param>
    /// <param name="hashedSubpackets">Serialized authenticated subpackets.</param>
    /// <param name="salt">The V6 salt, or an empty array for V4.</param>
    /// <returns>The complete signature digest.</returns>
    public static byte[] ComputeKeySignatureHash(PgpPublicKeyPacket primaryKey,
        PgpPublicKeyPacket? secondaryKey, byte version, byte sigType, byte pubAlgo,
        byte hashAlgo, byte[] hashedSubpackets, byte[] salt)
    {
        using var hash = ((PgpHashAlgorithmId)hashAlgo).CreateIncrementalHash();
        AppendSalt(hash, version, hashAlgo, salt);
        AppendKeyMaterial(hash, primaryKey, version);
        if (secondaryKey.HasValue) AppendKeyMaterial(hash, secondaryKey.Value, version);
        AppendSignatureTrailer(hash, version, sigType, pubAlgo, hashAlgo, hashedSubpackets);
        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Hashes a public key and User ID for a certification signature, including the V6 salt when present.
    /// </summary>
    /// <param name="certifiedKey">The public key being certified.</param>
    /// <param name="userId">The User ID being certified.</param>
    /// <param name="version">Signature version, which determines the key prefix.</param>
    /// <param name="sigType">The certification signature type.</param>
    /// <param name="pubAlgo">The signing algorithm identifier.</param>
    /// <param name="hashAlgo">The hash algorithm identifier.</param>
    /// <param name="hashedSubpackets">Serialized authenticated subpackets.</param>
    /// <param name="salt">The V6 salt, or an empty array for V4.</param>
    /// <returns>The complete signature digest.</returns>
    public static byte[] ComputeCertificationHash(PgpPublicKeyPacket certifiedKey,
        PgpUserIdPacket userId, byte version, byte sigType, byte pubAlgo,
        byte hashAlgo, byte[] hashedSubpackets, byte[] salt)
    {
        using var hash = ((PgpHashAlgorithmId)hashAlgo).CreateIncrementalHash();
        AppendSalt(hash, version, hashAlgo, salt);
        AppendKeyMaterial(hash, certifiedKey, version);
        byte[] body = userId.ToArray();
        var prefix = new byte[5];
        prefix[0] = 0xB4;
        BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)body.Length);
        hash.AppendData(prefix);
        hash.AppendData(body);
        AppendSignatureTrailer(hash, version, sigType, pubAlgo, hashAlgo, hashedSubpackets);
        return hash.GetHashAndReset();
    }

    private static void AppendSalt(IncrementalHash hash, byte version, byte hashAlgo, byte[] salt)
    {
        if (version != 4 && version != 6) throw new ArgumentOutOfRangeException(nameof(version));
        if (version == 6)
        {
            if (salt.Length != PgpSignaturePacket.GetExpectedSaltLength(hashAlgo))
                throw new ArgumentException("Signature salt length does not match its hash algorithm.", nameof(salt));
            hash.AppendData(salt);
        }
        else if (salt.Length != 0) throw new ArgumentException("V4 signatures cannot contain salt.", nameof(salt));
    }

    private static void AppendKeyMaterial(IncrementalHash hash, PgpPublicKeyPacket key, byte signatureVersion)
    {
        byte[] body = key.ToArray();
        var prefix = new byte[signatureVersion == 4 ? 3 : 5];
        prefix[0] = signatureVersion == 4 ? (byte)0x99 : (byte)0x9B;
        if (signatureVersion == 4) BinaryPrimitives.WriteUInt16BigEndian(prefix.AsSpan(1), checked((ushort)body.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)body.Length);
        hash.AppendData(prefix);
        hash.AppendData(body);
    }

    private static void AppendSignatureTrailer(IncrementalHash hash, byte version, byte sigType,
        byte pubAlgo, byte hashAlgo, byte[] hashedSubpackets)
    {
        int overhead = version == 4 ? 6 : 8;
        var header = new byte[overhead + hashedSubpackets.Length];
        header[0] = version;
        header[1] = sigType;
        header[2] = pubAlgo;
        header[3] = hashAlgo;
        if (version == 4) BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), checked((ushort)hashedSubpackets.Length));
        else BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashedSubpackets.Length);
        hashedSubpackets.CopyTo(header, overhead);
        hash.AppendData(header);
        var trailer = new byte[] { version, 0xFF, 0, 0, 0, 0 };
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), (uint)header.Length);
        hash.AppendData(trailer);
    }
}
