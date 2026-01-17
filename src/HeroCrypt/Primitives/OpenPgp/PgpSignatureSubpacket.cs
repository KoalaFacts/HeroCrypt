using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a signature subpacket as defined in RFC 4880 Section 5.2.3.1.
/// </summary>
/// <remarks>
/// <para>
/// Signature subpackets contain additional information about a signature.
/// Each subpacket has a type, optional critical flag, and variable-length data.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// +--------+------+-----------+
/// | Length | Type |   Data    |
/// | 1-5 B  | 1 B  | variable  |
/// +--------+------+-----------+
/// </code>
/// </para>
/// <para>
/// The critical bit (bit 7) of the type byte indicates whether the subpacket
/// must be understood for the signature to be valid.
/// </para>
/// </remarks>
public readonly struct PgpSignatureSubpacket
{
    /// <summary>
    /// The critical bit mask for the type byte.
    /// </summary>
    public const byte CriticalBit = 0x80;

    /// <summary>
    /// Gets the subpacket type.
    /// </summary>
    public PgpSignatureSubpacketType Type { get; }

    /// <summary>
    /// Gets whether this subpacket is critical.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Critical subpackets MUST be understood by the implementation.
    /// If a critical subpacket is not recognized, the signature is invalid.
    /// </para>
    /// </remarks>
    public bool IsCritical { get; }

    /// <summary>
    /// Gets the subpacket data.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// Initializes a new signature subpacket.
    /// </summary>
    /// <param name="type">The subpacket type.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <param name="data">The subpacket data.</param>
    public PgpSignatureSubpacket(PgpSignatureSubpacketType type, bool isCritical, ReadOnlyMemory<byte> data)
    {
        Type = type;
        IsCritical = isCritical;
        Data = data;
    }

    /// <summary>
    /// Creates a signature creation time subpacket.
    /// </summary>
    /// <param name="time">The signature creation time.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreateSignatureCreationTime(DateTimeOffset time, bool isCritical = false)
    {
        var data = new byte[4];
        long unixTime = time.ToUnixTimeSeconds();
        if (unixTime < 0) unixTime = 0;
        if (unixTime > uint.MaxValue) unixTime = uint.MaxValue;
        BinaryPrimitives.WriteUInt32BigEndian(data, (uint)unixTime);
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.SignatureCreationTime, isCritical, data);
    }

    /// <summary>
    /// Creates a signature expiration time subpacket.
    /// </summary>
    /// <param name="secondsAfterCreation">Seconds after creation time when signature expires. 0 = never expires.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreateSignatureExpirationTime(uint secondsAfterCreation, bool isCritical = false)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(data, secondsAfterCreation);
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.SignatureExpirationTime, isCritical, data);
    }

    /// <summary>
    /// Creates an issuer key ID subpacket.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreateIssuerKeyId(ReadOnlySpan<byte> keyId, bool isCritical = false)
    {
        if (keyId.Length != 8)
        {
            throw new ArgumentException("Key ID must be 8 bytes.", nameof(keyId));
        }

        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.IssuerKeyId, isCritical, keyId.ToArray());
    }

    /// <summary>
    /// Creates a key flags subpacket.
    /// </summary>
    /// <param name="flags">The key capability flags.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreateKeyFlags(PgpKeyCapabilities flags, bool isCritical = false)
    {
        // Key flags can be multiple bytes, but typically one byte suffices
        var value = (byte)flags;
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.KeyFlags, isCritical, new byte[] { value });
    }

    /// <summary>
    /// Creates an issuer fingerprint subpacket (RFC 9580).
    /// </summary>
    /// <param name="keyVersion">The key version (4 or 6).</param>
    /// <param name="fingerprint">The key fingerprint.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreateIssuerFingerprint(byte keyVersion, ReadOnlySpan<byte> fingerprint, bool isCritical = false)
    {
        var data = new byte[1 + fingerprint.Length];
        data[0] = keyVersion;
        fingerprint.CopyTo(data.AsSpan(1));
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.IssuerFingerprint, isCritical, data);
    }

    /// <summary>
    /// Creates a features subpacket.
    /// </summary>
    /// <param name="features">The feature flags.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreateFeatures(PgpFeatures features, bool isCritical = false)
    {
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.Features, isCritical, new byte[] { (byte)features });
    }

    /// <summary>
    /// Creates a preferred symmetric algorithms subpacket.
    /// </summary>
    /// <param name="algorithmIds">The algorithm IDs in preference order.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreatePreferredSymmetricAlgorithms(ReadOnlySpan<byte> algorithmIds, bool isCritical = false)
    {
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.PreferredSymmetricAlgorithms, isCritical, algorithmIds.ToArray());
    }

    /// <summary>
    /// Creates a preferred hash algorithms subpacket.
    /// </summary>
    /// <param name="algorithmIds">The algorithm IDs in preference order.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreatePreferredHashAlgorithms(ReadOnlySpan<byte> algorithmIds, bool isCritical = false)
    {
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.PreferredHashAlgorithms, isCritical, algorithmIds.ToArray());
    }

    /// <summary>
    /// Creates a preferred compression algorithms subpacket.
    /// </summary>
    /// <param name="algorithmIds">The algorithm IDs in preference order.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    public static PgpSignatureSubpacket CreatePreferredCompressionAlgorithms(ReadOnlySpan<byte> algorithmIds, bool isCritical = false)
    {
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.PreferredCompressionAlgorithms, isCritical, algorithmIds.ToArray());
    }

    /// <summary>
    /// Gets the signature creation time from this subpacket.
    /// </summary>
    /// <returns>The signature creation time.</returns>
    /// <exception cref="InvalidOperationException">If this is not a creation time subpacket or data is invalid.</exception>
    public DateTimeOffset GetSignatureCreationTime()
    {
        if (Type != PgpSignatureSubpacketType.SignatureCreationTime)
        {
            throw new InvalidOperationException($"Expected SignatureCreationTime subpacket, got {Type}.");
        }

        if (Data.Length < 4)
        {
            throw new InvalidOperationException("Signature creation time data too short.");
        }

        uint timestamp = BinaryPrimitives.ReadUInt32BigEndian(Data.Span);
        return DateTimeOffset.FromUnixTimeSeconds(timestamp);
    }

    /// <summary>
    /// Gets the issuer key ID from this subpacket.
    /// </summary>
    /// <returns>The 8-byte key ID.</returns>
    /// <exception cref="InvalidOperationException">If this is not an issuer key ID subpacket or data is invalid.</exception>
    public byte[] GetIssuerKeyId()
    {
        if (Type != PgpSignatureSubpacketType.IssuerKeyId)
        {
            throw new InvalidOperationException($"Expected IssuerKeyId subpacket, got {Type}.");
        }

        if (Data.Length < 8)
        {
            throw new InvalidOperationException("Issuer key ID data too short.");
        }

        return Data.Slice(0, 8).ToArray();
    }

    /// <summary>
    /// Gets the key flags from this subpacket.
    /// </summary>
    /// <returns>The key flags.</returns>
    /// <exception cref="InvalidOperationException">If this is not a key flags subpacket.</exception>
    public PgpKeyCapabilities GetKeyFlags()
    {
        if (Type != PgpSignatureSubpacketType.KeyFlags)
        {
            throw new InvalidOperationException($"Expected KeyFlags subpacket, got {Type}.");
        }

        if (Data.Length < 1)
        {
            return PgpKeyCapabilities.None;
        }

        return (PgpKeyCapabilities)Data.Span[0];
    }

    /// <summary>
    /// Reads a subpacket from a span.
    /// </summary>
    /// <param name="source">The source span.</param>
    /// <returns>The parsed subpacket.</returns>
    /// <exception cref="ArgumentException">If the source is too short or malformed.</exception>
    public static PgpSignatureSubpacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var subpacket, out _, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return subpacket;
    }

    /// <summary>
    /// Tries to read a subpacket from a span.
    /// </summary>
    /// <param name="source">The source span.</param>
    /// <param name="subpacket">The parsed subpacket if successful.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the subpacket was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSignatureSubpacket subpacket, out int bytesConsumed, out string error)
    {
        subpacket = default;
        bytesConsumed = 0;
        error = string.Empty;

        if (source.Length < 2)
        {
            error = "Source too short for subpacket header.";
            return false;
        }

        // Parse length
        int length;
        int lengthBytes;

        byte first = source[0];
        if (first < 192)
        {
            length = first;
            lengthBytes = 1;
        }
        else if (first < 255)
        {
            if (source.Length < 2)
            {
                error = "Source too short for two-byte length.";
                return false;
            }

            length = ((first - 192) << 8) + source[1] + 192;
            lengthBytes = 2;
        }
        else
        {
            if (source.Length < 5)
            {
                error = "Source too short for five-byte length.";
                return false;
            }

            length = (source[1] << 24) | (source[2] << 16) | (source[3] << 8) | source[4];
            lengthBytes = 5;
        }

        if (length < 1)
        {
            error = "Subpacket length must be at least 1 (for type byte).";
            return false;
        }

        int totalLength = lengthBytes + length;
        if (source.Length < totalLength)
        {
            error = $"Source too short for subpacket data. Expected {totalLength} bytes, got {source.Length}.";
            return false;
        }

        // Parse type (with critical bit)
        byte typeByte = source[lengthBytes];
        bool isCritical = (typeByte & CriticalBit) != 0;
        var type = (PgpSignatureSubpacketType)(typeByte & 0x7F);

        // Extract data (length includes the type byte)
        int dataLength = length - 1;
        var data = dataLength > 0 ? source.Slice(lengthBytes + 1, dataLength).ToArray() : [];

        subpacket = new PgpSignatureSubpacket(type, isCritical, data);
        bytesConsumed = totalLength;
        return true;
    }

    /// <summary>
    /// Reads all subpackets from a subpacket area.
    /// </summary>
    /// <param name="source">The source span containing all subpackets.</param>
    /// <returns>List of parsed subpackets.</returns>
    public static List<PgpSignatureSubpacket> ReadAll(ReadOnlySpan<byte> source)
    {
        var result = new List<PgpSignatureSubpacket>();
        int offset = 0;

        while (offset < source.Length)
        {
            if (!TryRead(source.Slice(offset), out var subpacket, out var consumed, out var error))
            {
                throw new ArgumentException($"Failed to parse subpacket at offset {offset}: {error}");
            }

            result.Add(subpacket);
            offset += consumed;
        }

        return result;
    }

    /// <summary>
    /// Gets the encoded length of this subpacket.
    /// </summary>
    /// <returns>The number of bytes needed to encode this subpacket.</returns>
    public int GetEncodedLength()
    {
        int contentLength = 1 + Data.Length; // type + data
        return GetLengthEncodingSize(contentLength) + contentLength;
    }

    /// <summary>
    /// Writes this subpacket to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            throw new ArgumentException($"Destination too small. Need {encodedLength} bytes.", nameof(destination));
        }

        int contentLength = 1 + Data.Length;
        int offset = WriteLengthEncoding(contentLength, destination);

        // Write type byte with critical bit
        destination[offset++] = (byte)((byte)Type | (IsCritical ? CriticalBit : 0));

        // Write data
        Data.Span.CopyTo(destination.Slice(offset));
        offset += Data.Length;

        return offset;
    }

    /// <summary>
    /// Writes this subpacket to a byte array.
    /// </summary>
    /// <returns>The encoded subpacket.</returns>
    public byte[] ToArray()
    {
        var result = new byte[GetEncodedLength()];
        Write(result);
        return result;
    }

    /// <summary>
    /// Writes multiple subpackets to a byte array.
    /// </summary>
    /// <param name="subpackets">The subpackets to write.</param>
    /// <returns>The encoded subpackets.</returns>
    public static byte[] WriteAll(IEnumerable<PgpSignatureSubpacket> subpackets)
    {
        var totalLength = 0;
        foreach (var sp in subpackets)
        {
            totalLength += sp.GetEncodedLength();
        }

        var result = new byte[totalLength];
        var offset = 0;
        foreach (var sp in subpackets)
        {
            offset += sp.Write(result.AsSpan(offset));
        }

        return result;
    }

    private static int GetLengthEncodingSize(int length)
    {
        if (length < 192)
        {
            return 1;
        }

        if (length < 16320) // 192 + 8128 = 8320, but RFC says 16319 is max for 2-byte
        {
            return 2;
        }

        return 5;
    }

    private static int WriteLengthEncoding(int length, Span<byte> destination)
    {
        if (length < 192)
        {
            destination[0] = (byte)length;
            return 1;
        }

        if (length < 16320)
        {
            int adjusted = length - 192;
            destination[0] = (byte)((adjusted >> 8) + 192);
            destination[1] = (byte)(adjusted & 0xFF);
            return 2;
        }

        destination[0] = 255;
        destination[1] = (byte)(length >> 24);
        destination[2] = (byte)(length >> 16);
        destination[3] = (byte)(length >> 8);
        destination[4] = (byte)length;
        return 5;
    }

    /// <summary>
    /// Returns a string representation of this subpacket.
    /// </summary>
    public override string ToString()
    {
        var criticalStr = IsCritical ? " (critical)" : "";
        return $"Subpacket({Type}{criticalStr}, {Data.Length} bytes)";
    }
}

/// <summary>
/// Key capability flags as defined in RFC 4880 Section 5.2.3.21.
/// </summary>
[Flags]
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix
public enum PgpKeyCapabilities : byte
#pragma warning restore CA1711
{
    /// <summary>
    /// No flags set.
    /// </summary>
    None = 0,

    /// <summary>
    /// This key may be used to certify other keys.
    /// </summary>
    Certify = 0x01,

    /// <summary>
    /// This key may be used to sign data.
    /// </summary>
    Sign = 0x02,

    /// <summary>
    /// This key may be used to encrypt communications.
    /// </summary>
    EncryptCommunications = 0x04,

    /// <summary>
    /// This key may be used to encrypt storage.
    /// </summary>
    EncryptStorage = 0x08,

    /// <summary>
    /// The private component of this key may have been split by a secret-sharing mechanism.
    /// </summary>
    SplitKey = 0x10,

    /// <summary>
    /// This key may be used for authentication.
    /// </summary>
    Authentication = 0x20,

    /// <summary>
    /// The private component of this key may be in the possession of more than one person.
    /// </summary>
    GroupKey = 0x80,
}

/// <summary>
/// Feature flags as defined in RFC 4880 Section 5.2.3.24 and RFC 9580.
/// </summary>
[Flags]
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix
public enum PgpFeatures : byte
#pragma warning restore CA1711
{
    /// <summary>
    /// No features.
    /// </summary>
    None = 0,

    /// <summary>
    /// Modification Detection (SEIPD v1 with MDC).
    /// </summary>
    ModificationDetection = 0x01,

    /// <summary>
    /// AEAD Encrypted Data (SEIPD v2 or AEAD packets).
    /// </summary>
    AeadEncryptedData = 0x02,

    /// <summary>
    /// Version 6 public keys (RFC 9580).
    /// </summary>
    Version6Keys = 0x04,
}
