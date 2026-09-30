using System.Buffers.Binary;
using System.Security.Cryptography;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Computes V4 and V6 signature hashes using RFC 9580 section 5.2.4.
/// V6 salt precedes all signed material; both versions use a six-byte trailer.
/// </summary>
internal static class PgpSignatureHashHelper
{
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
