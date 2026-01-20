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
    /// Creates a key expiration time subpacket.
    /// </summary>
    /// <param name="secondsAfterCreation">Seconds after key creation time when key expires. 0 = never expires.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    /// <remarks>
    /// <para>
    /// This subpacket specifies when the key expires. The time is measured from the
    /// key's creation timestamp. A value of 0 means the key never expires.
    /// </para>
    /// <para>
    /// This subpacket is typically included in the self-signature on the key.
    /// </para>
    /// </remarks>
    public static PgpSignatureSubpacket CreateKeyExpirationTime(uint secondsAfterCreation, bool isCritical = false)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(data, secondsAfterCreation);
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.KeyExpirationTime, isCritical, data);
    }

    /// <summary>
    /// Creates a key expiration time subpacket from a TimeSpan.
    /// </summary>
    /// <param name="lifetime">The key lifetime. Must be positive or TimeSpan.Zero (never expires).</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If lifetime is negative or exceeds maximum value.</exception>
    public static PgpSignatureSubpacket CreateKeyExpirationTime(TimeSpan lifetime, bool isCritical = false)
    {
        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime cannot be negative.");
        }

        var totalSeconds = lifetime.TotalSeconds;
        if (totalSeconds > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime exceeds maximum value (~136 years).");
        }

        return CreateKeyExpirationTime((uint)totalSeconds, isCritical);
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
    /// Creates a preferred AEAD algorithms subpacket (RFC 9580).
    /// </summary>
    /// <param name="cipherAeadPairs">Pairs of (symmetric cipher, AEAD algorithm) in preference order.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    /// <remarks>
    /// <para>
    /// Per RFC 9580, this subpacket contains pairs of bytes where each pair is
    /// (symmetric cipher algorithm ID, AEAD algorithm ID). Common AEAD values:
    /// <list type="bullet">
    ///   <item>1 = EAX</item>
    ///   <item>2 = OCB</item>
    ///   <item>3 = GCM</item>
    /// </list>
    /// </para>
    /// </remarks>
    public static PgpSignatureSubpacket CreatePreferredAeadAlgorithms(ReadOnlySpan<byte> cipherAeadPairs, bool isCritical = false)
    {
        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.PreferredAeadAlgorithms, isCritical, cipherAeadPairs.ToArray());
    }

    /// <summary>
    /// Creates a reason for revocation subpacket.
    /// </summary>
    /// <param name="reason">The revocation reason code.</param>
    /// <param name="reasonText">Optional human-readable text explaining the revocation.</param>
    /// <param name="isCritical">Whether the subpacket is critical.</param>
    /// <returns>A new subpacket.</returns>
    /// <remarks>
    /// <para>
    /// This subpacket is used in key revocation (0x20), subkey revocation (0x28),
    /// and certification revocation (0x30) signatures.
    /// </para>
    /// <para>
    /// The reason text is optional and encoded as UTF-8.
    /// </para>
    /// </remarks>
    public static PgpSignatureSubpacket CreateReasonForRevocation(
        PgpRevocationReason reason,
        string? reasonText = null,
        bool isCritical = false)
    {
        byte[] textBytes = string.IsNullOrEmpty(reasonText)
            ? []
            : System.Text.Encoding.UTF8.GetBytes(reasonText);

        var data = new byte[1 + textBytes.Length];
        data[0] = (byte)reason;
        textBytes.CopyTo(data, 1);

        return new PgpSignatureSubpacket(PgpSignatureSubpacketType.ReasonForRevocation, isCritical, data);
    }

    /// <summary>
    /// Gets the revocation reason from this subpacket.
    /// </summary>
    /// <returns>A tuple containing the reason code and optional reason text.</returns>
    /// <exception cref="InvalidOperationException">If this is not a reason for revocation subpacket.</exception>
    public (PgpRevocationReason Reason, string? ReasonText) GetRevocationReason()
    {
        if (Type != PgpSignatureSubpacketType.ReasonForRevocation)
        {
            throw new InvalidOperationException($"Expected ReasonForRevocation subpacket, got {Type}.");
        }

        if (Data.Length < 1)
        {
            throw new InvalidOperationException("Reason for revocation data too short.");
        }

        var reason = (PgpRevocationReason)Data.Span[0];
        string? reasonText = Data.Length > 1
            ? System.Text.Encoding.UTF8.GetString(Data.Span.Slice(1))
            : null;

        return (reason, reasonText);
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
    /// Gets the key expiration time from this subpacket.
    /// </summary>
    /// <returns>The number of seconds after key creation when the key expires, or 0 if never.</returns>
    /// <exception cref="InvalidOperationException">If this is not a key expiration time subpacket or data is invalid.</exception>
    public uint GetKeyExpirationTime()
    {
        if (Type != PgpSignatureSubpacketType.KeyExpirationTime)
        {
            throw new InvalidOperationException($"Expected KeyExpirationTime subpacket, got {Type}.");
        }

        if (Data.Length < 4)
        {
            throw new InvalidOperationException("Key expiration time data too short.");
        }

        return BinaryPrimitives.ReadUInt32BigEndian(Data.Span);
    }

    /// <summary>
    /// Gets the key expiration time as a TimeSpan.
    /// </summary>
    /// <returns>The key lifetime, or null if the key never expires.</returns>
    /// <exception cref="InvalidOperationException">If this is not a key expiration time subpacket or data is invalid.</exception>
    public TimeSpan? GetKeyExpirationTimeAsTimeSpan()
    {
        var seconds = GetKeyExpirationTime();
        return seconds == 0 ? null : TimeSpan.FromSeconds(seconds);
    }

    /// <summary>
    /// Gets the signature expiration time from this subpacket.
    /// </summary>
    /// <returns>The number of seconds after signature creation when it expires, or 0 if never.</returns>
    /// <exception cref="InvalidOperationException">If this is not a signature expiration time subpacket or data is invalid.</exception>
    public uint GetSignatureExpirationTime()
    {
        if (Type != PgpSignatureSubpacketType.SignatureExpirationTime)
        {
            throw new InvalidOperationException($"Expected SignatureExpirationTime subpacket, got {Type}.");
        }

        if (Data.Length < 4)
        {
            throw new InvalidOperationException("Signature expiration time data too short.");
        }

        return BinaryPrimitives.ReadUInt32BigEndian(Data.Span);
    }

    /// <summary>
    /// Gets the preferred symmetric algorithms from this subpacket.
    /// </summary>
    /// <returns>The array of algorithm IDs in order of preference.</returns>
    /// <exception cref="InvalidOperationException">If this is not a preferred symmetric algorithms subpacket.</exception>
    public byte[] GetPreferredSymmetricAlgorithms()
    {
        if (Type != PgpSignatureSubpacketType.PreferredSymmetricAlgorithms)
        {
            throw new InvalidOperationException($"Expected PreferredSymmetricAlgorithms subpacket, got {Type}.");
        }

        return Data.ToArray();
    }

    /// <summary>
    /// Gets the preferred hash algorithms from this subpacket.
    /// </summary>
    /// <returns>The array of algorithm IDs in order of preference.</returns>
    /// <exception cref="InvalidOperationException">If this is not a preferred hash algorithms subpacket.</exception>
    public byte[] GetPreferredHashAlgorithms()
    {
        if (Type != PgpSignatureSubpacketType.PreferredHashAlgorithms)
        {
            throw new InvalidOperationException($"Expected PreferredHashAlgorithms subpacket, got {Type}.");
        }

        return Data.ToArray();
    }

    /// <summary>
    /// Gets the preferred compression algorithms from this subpacket.
    /// </summary>
    /// <returns>The array of algorithm IDs in order of preference.</returns>
    /// <exception cref="InvalidOperationException">If this is not a preferred compression algorithms subpacket.</exception>
    public byte[] GetPreferredCompressionAlgorithms()
    {
        if (Type != PgpSignatureSubpacketType.PreferredCompressionAlgorithms)
        {
            throw new InvalidOperationException($"Expected PreferredCompressionAlgorithms subpacket, got {Type}.");
        }

        return Data.ToArray();
    }

    /// <summary>
    /// Gets the preferred AEAD algorithms from this subpacket.
    /// </summary>
    /// <returns>The array of algorithm IDs in order of preference (pairs of cipher+aead).</returns>
    /// <exception cref="InvalidOperationException">If this is not a preferred AEAD algorithms subpacket.</exception>
    /// <remarks>
    /// <para>
    /// Per RFC 9580, this subpacket contains pairs of bytes: each pair is
    /// (symmetric cipher algorithm, AEAD algorithm). The pairs are in order of preference.
    /// </para>
    /// </remarks>
    public byte[] GetPreferredAeadAlgorithms()
    {
        if (Type != PgpSignatureSubpacketType.PreferredAeadAlgorithms)
        {
            throw new InvalidOperationException($"Expected PreferredAeadAlgorithms subpacket, got {Type}.");
        }

        return Data.ToArray();
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

            // Read as uint first to avoid signed overflow, then validate
            uint lengthU = ((uint)source[1] << 24) | ((uint)source[2] << 16) | ((uint)source[3] << 8) | source[4];
            if (lengthU > int.MaxValue)
            {
                error = "Subpacket length exceeds maximum supported size.";
                return false;
            }

            length = (int)lengthU;
            lengthBytes = 5;
        }

        if (length < 1)
        {
            error = "Subpacket length must be at least 1 (for type byte).";
            return false;
        }

        // Check for overflow in total length calculation
        if (length > int.MaxValue - lengthBytes)
        {
            error = "Subpacket length would cause overflow.";
            return false;
        }

        int totalLength = lengthBytes + length;
        if (source.Length < totalLength)
        {
            error = "Source too short for subpacket data.";
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
    /// <exception cref="OverflowException">If the encoded length would overflow.</exception>
    public int GetEncodedLength()
    {
        // Check for overflow: 1 (type) + Data.Length + 5 (max length encoding)
        if (Data.Length > int.MaxValue - 6)
        {
            throw new OverflowException("Subpacket data is too large to encode.");
        }

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
    /// <exception cref="OverflowException">If the total length would overflow.</exception>
    public static byte[] WriteAll(IEnumerable<PgpSignatureSubpacket> subpackets)
    {
        long totalLength = 0;
        var subpacketList = subpackets as IReadOnlyList<PgpSignatureSubpacket> ?? subpackets.ToList();

        foreach (var sp in subpacketList)
        {
            totalLength += sp.GetEncodedLength();
            if (totalLength > int.MaxValue)
            {
                throw new OverflowException("Total subpacket length exceeds maximum supported size.");
            }
        }

        var result = new byte[totalLength];
        var offset = 0;
        foreach (var sp in subpacketList)
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
