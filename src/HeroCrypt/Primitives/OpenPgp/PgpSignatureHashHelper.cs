using System.Buffers.Binary;
using System.Security.Cryptography;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Centralized helper for computing signature hashes according to RFC 4880 (V4) and RFC 9580 (V6).
/// </summary>
/// <remarks>
/// <para>
/// This class provides shared methods for signature hash computation to ensure consistency
/// across all signature creation and verification code paths.
/// </para>
/// <para>
/// <b>Hash computation for signatures:</b>
/// <list type="bullet">
///   <item>Data signatures: hash(data || signature_header || trailer)</item>
///   <item>Key signatures: hash(key_material || signature_header || trailer)</item>
///   <item>Two-key signatures (binding/revocation): hash(primary_key || secondary_key || signature_header || trailer)</item>
/// </list>
/// </para>
/// <para>
/// <b>Trailer length calculation:</b>
/// <list type="bullet">
///   <item>V4: 4 + hashed_subpackets_length (version + sigType + pubAlgo + hashAlgo)</item>
///   <item>V6: 6 + hashed_subpackets_length (version + sigType + pubAlgo + hashAlgo + 4-byte length field overhead)</item>
/// </list>
/// </para>
/// </remarks>
internal static class PgpSignatureHashHelper
{
    /// <summary>
    /// Appends key material to the hash with the 0x99 tag prefix.
    /// </summary>
    /// <param name="hash">The incremental hash to append to.</param>
    /// <param name="keyPacket">The public key packet to hash.</param>
    /// <remarks>
    /// Per RFC 4880 Section 5.2.4, key material is hashed as:
    /// 0x99 || 2-byte length || key body
    /// </remarks>
    public static void AppendKeyMaterial(IncrementalHash hash, PgpPublicKeyPacket keyPacket)
    {
        byte[] keyBody = keyPacket.ToArray();
        var tag = new byte[3];
        tag[0] = 0x99;
        BinaryPrimitives.WriteUInt16BigEndian(tag.AsSpan(1), (ushort)keyBody.Length);
        hash.AppendData(tag);
        hash.AppendData(keyBody);
    }

    /// <summary>
    /// Appends User ID material to the hash with the 0xB4 tag prefix.
    /// </summary>
    /// <param name="hash">The incremental hash to append to.</param>
    /// <param name="userIdPacket">The User ID packet to hash.</param>
    /// <remarks>
    /// Per RFC 4880 Section 5.2.4, User ID is hashed as:
    /// 0xB4 || 4-byte length || user ID body
    /// </remarks>
    public static void AppendUserIdMaterial(IncrementalHash hash, PgpUserIdPacket userIdPacket)
    {
        byte[] userIdBody = userIdPacket.ToArray();
        var tag = new byte[5];
        tag[0] = 0xB4;
        BinaryPrimitives.WriteUInt32BigEndian(tag.AsSpan(1), (uint)userIdBody.Length);
        hash.AppendData(tag);
        hash.AppendData(userIdBody);
    }

    /// <summary>
    /// Appends User Attribute material to the hash with the 0xD1 tag prefix.
    /// </summary>
    /// <param name="hash">The incremental hash to append to.</param>
    /// <param name="userAttributeData">The User Attribute data to hash.</param>
    /// <remarks>
    /// Per RFC 4880 Section 5.2.4, User Attribute is hashed as:
    /// 0xD1 || 4-byte length || user attribute body
    /// </remarks>
    public static void AppendUserAttributeMaterial(IncrementalHash hash, byte[] userAttributeData)
    {
        var tag = new byte[5];
        tag[0] = 0xD1;
        BinaryPrimitives.WriteUInt32BigEndian(tag.AsSpan(1), (uint)userAttributeData.Length);
        hash.AppendData(tag);
        hash.AppendData(userAttributeData);
    }

    /// <summary>
    /// Appends the signature header and trailer to the hash.
    /// </summary>
    /// <param name="hash">The incremental hash to append to.</param>
    /// <param name="version">Signature version (4 or 6).</param>
    /// <param name="sigType">Signature type.</param>
    /// <param name="pubAlgo">Public key algorithm.</param>
    /// <param name="hashAlgo">Hash algorithm.</param>
    /// <param name="hashedSubpackets">Serialized hashed subpackets.</param>
    /// <remarks>
    /// <para>
    /// This method appends both the signature header (containing the signature parameters
    /// and hashed subpackets) and the final trailer to the hash.
    /// </para>
    /// <para>
    /// <b>V4 format:</b>
    /// <list type="bullet">
    ///   <item>Header: version(1) + sigType(1) + pubAlgo(1) + hashAlgo(1) + length(2) + subpackets</item>
    ///   <item>Trailer: version(1) + 0xFF(1) + totalLen(4)</item>
    ///   <item>Total length = 4 + subpackets.Length</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>V6 format:</b>
    /// <list type="bullet">
    ///   <item>Header: version(1) + sigType(1) + pubAlgo(1) + hashAlgo(1) + length(4) + subpackets</item>
    ///   <item>Trailer: version(1) + 0xFF(1) + totalLen(8)</item>
    ///   <item>Total length = 6 + subpackets.Length (extra 2 bytes for 4-byte vs 2-byte length field)</item>
    /// </list>
    /// </para>
    /// </remarks>
    public static void AppendSignatureTrailer(
        IncrementalHash hash,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        if (version == 4)
        {
            AppendV4SignatureTrailer(hash, sigType, pubAlgo, hashAlgo, hashedSubpackets);
        }
        else
        {
            AppendV6SignatureTrailer(hash, sigType, pubAlgo, hashAlgo, hashedSubpackets);
        }
    }

    /// <summary>
    /// Appends V4 signature header and trailer.
    /// </summary>
    private static void AppendV4SignatureTrailer(
        IncrementalHash hash,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        // Header: version + sigType + pubAlgo + hashAlgo + 2-byte length + subpackets
        var header = new byte[6 + hashedSubpackets.Length];
        header[0] = 4; // version
        header[1] = sigType;
        header[2] = pubAlgo;
        header[3] = hashAlgo;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), (ushort)hashedSubpackets.Length);
        Array.Copy(hashedSubpackets, 0, header, 6, hashedSubpackets.Length);
        hash.AppendData(header);

        // Trailer: version + 0xFF + 4-byte total length
        // Total length = 4 (version + sigType + pubAlgo + hashAlgo) + subpackets length
        var trailer = new byte[6];
        trailer[0] = 4; // version
        trailer[1] = 0xFF;
        uint totalLen = (uint)(4 + hashedSubpackets.Length);
        BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), totalLen);
        hash.AppendData(trailer);
    }

    /// <summary>
    /// Appends V6 signature header and trailer.
    /// </summary>
    private static void AppendV6SignatureTrailer(
        IncrementalHash hash,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        // Header: version + sigType + pubAlgo + hashAlgo + 4-byte length + subpackets
        var header = new byte[8 + hashedSubpackets.Length];
        header[0] = 6; // version
        header[1] = sigType;
        header[2] = pubAlgo;
        header[3] = hashAlgo;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashedSubpackets.Length);
        Array.Copy(hashedSubpackets, 0, header, 8, hashedSubpackets.Length);
        hash.AppendData(header);

        // Trailer: version + 0xFF + 8-byte total length
        // Total length = 6 (version + sigType + pubAlgo + hashAlgo + 2 extra bytes for 4-byte length field) + subpackets length
        // The V6 format uses a 4-byte length field instead of V4's 2-byte field, adding 2 bytes to the total
        var trailer = new byte[10];
        trailer[0] = 6; // version
        trailer[1] = 0xFF;
        ulong totalLen = (ulong)(6 + hashedSubpackets.Length);
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(2), totalLen);
        hash.AppendData(trailer);
    }

    /// <summary>
    /// Computes the hash for a key-based signature (revocation, binding, direct key).
    /// </summary>
    /// <param name="primaryKey">The primary key to hash.</param>
    /// <param name="secondaryKey">Optional secondary key (for binding/revocation signatures).</param>
    /// <param name="version">Signature version.</param>
    /// <param name="sigType">Signature type.</param>
    /// <param name="pubAlgo">Public key algorithm.</param>
    /// <param name="hashAlgo">Hash algorithm.</param>
    /// <param name="hashedSubpackets">Serialized hashed subpackets.</param>
    /// <returns>The computed hash.</returns>
    public static byte[] ComputeKeySignatureHash(
        PgpPublicKeyPacket primaryKey,
        PgpPublicKeyPacket? secondaryKey,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)hashAlgo;
        using var hash = hashAlgorithm.CreateIncrementalHash();

        // Hash primary key
        AppendKeyMaterial(hash, primaryKey);

        // Hash secondary key if present (for binding/revocation)
        if (secondaryKey.HasValue)
        {
            AppendKeyMaterial(hash, secondaryKey.Value);
        }

        // Hash signature trailer
        AppendSignatureTrailer(hash, version, sigType, pubAlgo, hashAlgo, hashedSubpackets);

        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Computes the hash for a User ID certification signature (0x10-0x13).
    /// </summary>
    /// <param name="certifiedKey">The public key being certified.</param>
    /// <param name="userId">The User ID being certified.</param>
    /// <param name="version">Signature version.</param>
    /// <param name="sigType">Signature type (0x10-0x13).</param>
    /// <param name="pubAlgo">Public key algorithm of the certifying key.</param>
    /// <param name="hashAlgo">Hash algorithm.</param>
    /// <param name="hashedSubpackets">Serialized hashed subpackets.</param>
    /// <returns>The computed hash.</returns>
    /// <remarks>
    /// <para>
    /// Per RFC 4880 Section 5.2.4, certification signatures hash:
    /// public_key || user_id || signature_trailer
    /// </para>
    /// <para>
    /// This method is used for:
    /// <list type="bullet">
    ///   <item>Self-signatures (key owner certifying their own User ID)</item>
    ///   <item>Third-party certifications (certifying someone else's User ID)</item>
    /// </list>
    /// </para>
    /// </remarks>
    public static byte[] ComputeCertificationHash(
        PgpPublicKeyPacket certifiedKey,
        PgpUserIdPacket userId,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        var hashAlgorithm = (PgpHashAlgorithmId)hashAlgo;
        using var hash = hashAlgorithm.CreateIncrementalHash();

        // Hash the certified key
        AppendKeyMaterial(hash, certifiedKey);

        // Hash the User ID
        AppendUserIdMaterial(hash, userId);

        // Hash signature trailer
        AppendSignatureTrailer(hash, version, sigType, pubAlgo, hashAlgo, hashedSubpackets);

        return hash.GetHashAndReset();
    }
}
