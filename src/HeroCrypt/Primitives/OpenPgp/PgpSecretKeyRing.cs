using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents an OpenPGP secret key ring containing a master secret key, subkeys,
/// user IDs, user attributes, and associated signatures.
/// </summary>
/// <remarks>
/// <para>
/// A secret key ring contains the private key material needed for signing and decryption.
/// The structure mirrors <see cref="PgpPublicKeyRing"/> but uses Secret Key packets.
/// </para>
/// <para>
/// <b>Structure (RFC 4880 Section 11.2):</b>
/// <code>
/// - One Secret-Key packet (master)
/// - Zero or more revocation signatures
/// - Zero or more Direct Key signatures
/// - One or more User ID packets
///   - Zero or more Signature packets (certifications)
/// - Zero or more User Attribute packets
///   - Zero or more Signature packets
/// - Zero or more Secret-Subkey packets
///   - Zero or more Signature packets (binding)
/// </code>
/// </para>
/// <para>
/// Secret key material may be encrypted with a passphrase using S2K (String-to-Key).
/// </para>
/// <para>
/// This type is immutable. All modification methods return new instances.
/// </para>
/// </remarks>
public readonly struct PgpSecretKeyRing : IEquatable<PgpSecretKeyRing>
{
    private readonly Dictionary<ulong, int>? keyIdIndex;

    /// <summary>
    /// Gets the master (primary) secret key.
    /// </summary>
    public PgpSecretKeyPacket MasterKey { get; }

    /// <summary>
    /// Gets the secret subkeys bound to this key ring.
    /// </summary>
    public IReadOnlyList<PgpSecretKeyPacket> Subkeys { get; }

    /// <summary>
    /// Gets the user IDs associated with this key ring.
    /// </summary>
    public IReadOnlyList<PgpUserIdPacket> UserIds { get; }

    /// <summary>
    /// Gets the user attributes (e.g., photo IDs) associated with this key ring.
    /// </summary>
    public IReadOnlyList<PgpUserAttributePacket> UserAttributes { get; }

    /// <summary>
    /// Gets all signatures in this key ring (certifications, bindings, revocations).
    /// </summary>
    public IReadOnlyList<PgpSignaturePacket> Signatures { get; }

    /// <summary>
    /// Gets the key ID of the master key.
    /// </summary>
    public byte[] MasterKeyId => MasterKey.GetKeyId();

    /// <summary>
    /// Gets the fingerprint of the master key.
    /// </summary>
    public byte[] MasterFingerprint => MasterKey.ComputeFingerprint();

    /// <summary>
    /// Gets the version of the master key (4 or 6).
    /// </summary>
    public byte Version => MasterKey.Version;

    /// <summary>
    /// Gets the creation time of the master key.
    /// </summary>
    public DateTimeOffset CreationTime => MasterKey.CreationTime;

    /// <summary>
    /// Gets whether the master key is encrypted with a passphrase.
    /// </summary>
    public bool IsEncrypted => MasterKey.IsEncrypted;

    /// <summary>
    /// Gets the total number of keys (master + subkeys).
    /// </summary>
    public int KeyCount => 1 + Subkeys.Count;

    /// <summary>
    /// Initializes a new secret key ring with the specified components.
    /// </summary>
    /// <param name="masterKey">The master secret key.</param>
    /// <param name="subkeys">The secret subkeys (optional).</param>
    /// <param name="userIds">The user IDs (optional).</param>
    /// <param name="userAttributes">The user attributes (optional).</param>
    /// <param name="signatures">The signatures (optional).</param>
    public PgpSecretKeyRing(
        PgpSecretKeyPacket masterKey,
        IReadOnlyList<PgpSecretKeyPacket>? subkeys = null,
        IReadOnlyList<PgpUserIdPacket>? userIds = null,
        IReadOnlyList<PgpUserAttributePacket>? userAttributes = null,
        IReadOnlyList<PgpSignaturePacket>? signatures = null)
    {
        if (masterKey.IsSubkey)
        {
            throw new ArgumentException("Master key cannot be a subkey packet.", nameof(masterKey));
        }

        MasterKey = masterKey;
        Subkeys = subkeys ?? [];
        UserIds = userIds ?? [];
        UserAttributes = userAttributes ?? [];
        Signatures = signatures ?? [];

        // Validate all subkeys have IsSubkey = true
        foreach (var subkey in Subkeys)
        {
            if (!subkey.IsSubkey)
            {
                throw new ArgumentException("All subkeys must have IsSubkey = true.", nameof(subkeys));
            }
        }

        // Build key ID index for fast lookup
        keyIdIndex = BuildKeyIdIndex(MasterKey, Subkeys);
    }

    /// <summary>
    /// Creates a secret key ring with a master key and optional components.
    /// </summary>
    /// <param name="masterKey">The master secret key.</param>
    /// <param name="userIds">The user IDs (optional).</param>
    /// <param name="signatures">The signatures (optional).</param>
    /// <returns>A new secret key ring.</returns>
    public static PgpSecretKeyRing Create(
        PgpSecretKeyPacket masterKey,
        IEnumerable<PgpUserIdPacket>? userIds = null,
        IEnumerable<PgpSignaturePacket>? signatures = null)
    {
        return new PgpSecretKeyRing(
            masterKey,
            subkeys: null,
            userIds: userIds?.ToList(),
            userAttributes: null,
            signatures: signatures?.ToList());
    }

    /// <summary>
    /// Creates a secret key ring with all components.
    /// </summary>
    /// <param name="masterKey">The master secret key.</param>
    /// <param name="subkeys">The secret subkeys.</param>
    /// <param name="userIds">The user IDs.</param>
    /// <param name="userAttributes">The user attributes.</param>
    /// <param name="signatures">The signatures.</param>
    /// <returns>A new secret key ring.</returns>
    public static PgpSecretKeyRing Create(
        PgpSecretKeyPacket masterKey,
        IEnumerable<PgpSecretKeyPacket>? subkeys,
        IEnumerable<PgpUserIdPacket>? userIds,
        IEnumerable<PgpUserAttributePacket>? userAttributes,
        IEnumerable<PgpSignaturePacket>? signatures)
    {
        return new PgpSecretKeyRing(
            masterKey,
            subkeys?.ToList(),
            userIds?.ToList(),
            userAttributes?.ToList(),
            signatures?.ToList());
    }

    /// <summary>
    /// Reads a secret key ring from a span.
    /// </summary>
    /// <param name="source">The source span containing the key ring data.</param>
    /// <returns>The parsed secret key ring.</returns>
    /// <exception cref="ArgumentException">If the data is malformed.</exception>
    public static PgpSecretKeyRing Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var keyRing, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return keyRing;
    }

    /// <summary>
    /// Reads a secret key ring from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the key ring data.</param>
    /// <returns>The parsed secret key ring.</returns>
    /// <exception cref="InvalidDataException">If the data is malformed.</exception>
    public static PgpSecretKeyRing Read(Stream stream)
    {
        if (!TryRead(stream, out var keyRing, out var error))
        {
            throw new InvalidDataException(error);
        }

        return keyRing;
    }

    /// <summary>
    /// Tries to read a secret key ring from a span.
    /// </summary>
    /// <param name="source">The source span containing the key ring data.</param>
    /// <param name="keyRing">The parsed key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the key ring was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSecretKeyRing keyRing, out string? error)
    {
        keyRing = default;
        error = null;

        using var stream = new MemoryStream(source.ToArray());
        return TryRead(stream, out keyRing, out error);
    }

    /// <summary>
    /// Tries to read a secret key ring from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the key ring data.</param>
    /// <param name="keyRing">The parsed key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the key ring was parsed successfully.</returns>
    public static bool TryRead(Stream stream, out PgpSecretKeyRing keyRing, out string? error)
    {
        keyRing = default;
        error = null;

        using var reader = new PgpPacketReader(stream, leaveOpen: true);

        // First packet must be a SecretKey (Tag 5)
        if (!reader.ReadNextPacket(out var tag, out var body))
        {
            error = "Empty stream - no packets found.";
            return false;
        }

        if (tag != PgpPacketTag.SecretKey)
        {
            error = $"Expected SecretKey packet (Tag 5), got {tag}.";
            return false;
        }

        if (!PgpSecretKeyPacket.TryRead(body.Span, isSubkey: false, out var masterKey, out var packetError))
        {
            error = $"Failed to parse master key: {packetError}";
            return false;
        }

        List<PgpSecretKeyPacket> subkeys = [];
        List<PgpUserIdPacket> userIds = [];
        List<PgpUserAttributePacket> userAttributes = [];
        List<PgpSignaturePacket> signatures = [];

        // Read remaining packets
        while (reader.ReadNextPacket(out tag, out body))
        {
#pragma warning disable IDE0010 // PgpPacketTag has many values; we only handle relevant ones
            switch (tag)
            {
                case PgpPacketTag.SecretKey:
                    // Next key ring starts - we're done with this one
                    goto done;

                case PgpPacketTag.SecretSubkey:
                    if (!PgpSecretKeyPacket.TryRead(body.Span, isSubkey: true, out var subkey, out packetError))
                    {
                        error = $"Failed to parse subkey: {packetError}";
                        return false;
                    }
                    subkeys.Add(subkey);
                    break;

                case PgpPacketTag.UserId:
                    if (!PgpUserIdPacket.TryRead(body.Span, out var userId, out packetError))
                    {
                        error = $"Failed to parse user ID: {packetError}";
                        return false;
                    }
                    userIds.Add(userId);
                    break;

                case PgpPacketTag.UserAttribute:
                    if (!PgpUserAttributePacket.TryRead(body.Span, out var userAttr, out packetError))
                    {
                        error = $"Failed to parse user attribute: {packetError}";
                        return false;
                    }
                    userAttributes.Add(userAttr);
                    break;

                case PgpPacketTag.Signature:
                    if (!PgpSignaturePacket.TryRead(body.Span, out var signature, out packetError))
                    {
                        error = $"Failed to parse signature: {packetError}";
                        return false;
                    }
                    signatures.Add(signature);
                    break;

                case PgpPacketTag.Trust:
                    // Trust packets are implementation-specific - skip them
                    break;

                default:
                    // Unknown or unsupported packet - skip
                    break;
            }
#pragma warning restore IDE0010
        }

    done:
        keyRing = new PgpSecretKeyRing(masterKey, subkeys, userIds, userAttributes, signatures);
        return true;
    }

    /// <summary>
    /// Gets a secret key by its key ID.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <returns>The secret key, or null if not found.</returns>
    public PgpSecretKeyPacket? GetSecretKey(ReadOnlySpan<byte> keyId)
    {
        if (keyId.Length != 8)
        {
            return null;
        }

        ulong keyIdValue = BinaryPrimitives.ReadUInt64BigEndian(keyId);

        if (keyIdIndex == null || !keyIdIndex.TryGetValue(keyIdValue, out int index))
        {
            return null;
        }

        if (index == -1)
        {
            return MasterKey;
        }

        if (index >= 0 && index < Subkeys.Count)
        {
            return Subkeys[index];
        }

        return null;
    }

    /// <summary>
    /// Gets a secret key by its fingerprint.
    /// </summary>
    /// <param name="fingerprint">The key fingerprint (20 bytes for V4, 32 bytes for V6).</param>
    /// <returns>The secret key, or null if not found.</returns>
    public PgpSecretKeyPacket? GetSecretKeyByFingerprint(ReadOnlySpan<byte> fingerprint)
    {
        // Check master key
        if (fingerprint.SequenceEqual(MasterKey.ComputeFingerprint()))
        {
            return MasterKey;
        }

        // Check subkeys
        foreach (var subkey in Subkeys)
        {
            if (fingerprint.SequenceEqual(subkey.ComputeFingerprint()))
            {
                return subkey;
            }
        }

        return null;
    }

    /// <summary>
    /// Checks if this key ring contains a key with the specified key ID.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <returns>True if the key ring contains the key.</returns>
    public bool ContainsKey(ReadOnlySpan<byte> keyId)
    {
        return GetSecretKey(keyId) != null;
    }

    /// <summary>
    /// Extracts the public key ring from this secret key ring.
    /// </summary>
    /// <returns>A new public key ring containing only the public key material.</returns>
    public PgpPublicKeyRing ExtractPublicKeyRing()
    {
        // Extract public key from master
        var masterPublic = MasterKey.PublicKey;

        // Extract public keys from subkeys
        var subkeysPublic = Subkeys.Select(sk => sk.PublicKey).ToList();

        return new PgpPublicKeyRing(masterPublic, subkeysPublic, UserIds, UserAttributes, Signatures);
    }

    /// <summary>
    /// Adds a secret subkey to this key ring.
    /// </summary>
    /// <param name="subkey">The secret subkey to add.</param>
    /// <param name="bindingSignature">The subkey binding signature.</param>
    /// <returns>A new key ring with the added subkey.</returns>
    public PgpSecretKeyRing AddSubkey(PgpSecretKeyPacket subkey, PgpSignaturePacket bindingSignature)
    {
        if (!subkey.IsSubkey)
        {
            throw new ArgumentException("Subkey must have IsSubkey = true.", nameof(subkey));
        }

        if (bindingSignature.SignatureType != PgpSignatureType.SubkeyBinding)
        {
            throw new ArgumentException("Binding signature must be of type SubkeyBinding (0x18).", nameof(bindingSignature));
        }

        List<PgpSecretKeyPacket> newSubkeys = [.. Subkeys, subkey];
        List<PgpSignaturePacket> newSignatures = [.. Signatures, bindingSignature];

        return new PgpSecretKeyRing(MasterKey, newSubkeys, UserIds, UserAttributes, newSignatures);
    }

    /// <summary>
    /// Removes a secret subkey from this key ring.
    /// </summary>
    /// <param name="keyId">The key ID of the subkey to remove.</param>
    /// <returns>A new key ring without the specified subkey.</returns>
    public PgpSecretKeyRing RemoveSubkey(ReadOnlySpan<byte> keyId)
    {
        var targetKeyId = keyId.ToArray();
        var newSubkeys = Subkeys.Where(sk => !sk.GetKeyId().AsSpan().SequenceEqual(targetKeyId)).ToList();

        if (newSubkeys.Count == Subkeys.Count)
        {
            // Key not found - return unchanged
            return this;
        }

        return new PgpSecretKeyRing(MasterKey, newSubkeys, UserIds, UserAttributes, Signatures);
    }

    /// <summary>
    /// Adds a user ID to this key ring.
    /// </summary>
    /// <param name="userId">The user ID to add.</param>
    /// <param name="certification">Optional certification signature.</param>
    /// <returns>A new key ring with the added user ID.</returns>
    public PgpSecretKeyRing AddUserId(PgpUserIdPacket userId, PgpSignaturePacket? certification = null)
    {
        List<PgpUserIdPacket> newUserIds = [.. UserIds, userId];
        List<PgpSignaturePacket> newSignatures = certification.HasValue
            ? [.. Signatures, certification.Value]
            : [.. Signatures];

        return new PgpSecretKeyRing(MasterKey, Subkeys, newUserIds, UserAttributes, newSignatures);
    }

    /// <summary>
    /// Adds a signature to this key ring.
    /// </summary>
    /// <param name="signature">The signature to add.</param>
    /// <returns>A new key ring with the added signature.</returns>
    public PgpSecretKeyRing AddSignature(PgpSignaturePacket signature)
    {
        List<PgpSignaturePacket> newSignatures = [.. Signatures, signature];
        return new PgpSecretKeyRing(MasterKey, Subkeys, UserIds, UserAttributes, newSignatures);
    }

    /// <summary>
    /// Securely clears all sensitive key material from memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method zeros out the secret key material in the master key and all subkeys.
    /// Call this when you no longer need the key ring to minimize the window during which
    /// sensitive data resides in memory.
    /// </para>
    /// <para>
    /// <b>Important:</b> Since this is a value type (struct), any copies made before
    /// calling this method will still contain the original data.
    /// </para>
    /// </remarks>
    public void ClearSensitiveData()
    {
        MasterKey.ClearSensitiveData();

        foreach (var subkey in Subkeys)
        {
            subkey.ClearSensitiveData();
        }
    }

    /// <summary>
    /// Gets the total encoded length of this key ring.
    /// </summary>
    /// <returns>The number of bytes needed to encode the key ring.</returns>
    public int GetEncodedLength()
    {
        int length = 0;

        // Master key packet (header + body)
        length += GetPacketEncodedLength(MasterKey.GetEncodedLength());

        // User IDs
        foreach (var userId in UserIds)
        {
            length += GetPacketEncodedLength(userId.GetEncodedLength());
        }

        // User attributes
        foreach (var userAttr in UserAttributes)
        {
            length += GetPacketEncodedLength(userAttr.GetEncodedLength());
        }

        // Signatures
        foreach (var sig in Signatures)
        {
            length += GetPacketEncodedLength(sig.GetEncodedLength());
        }

        // Subkeys
        foreach (var subkey in Subkeys)
        {
            length += GetPacketEncodedLength(subkey.GetEncodedLength());
        }

        return length;
    }

    /// <summary>
    /// Writes the key ring to a span.
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

        using var ms = new MemoryStream();
        using var writer = new PgpPacketWriter(ms);

        WriteTo(writer);

        var result = ms.ToArray();
        result.CopyTo(destination);
        return result.Length;
    }

    /// <summary>
    /// Writes the key ring to a byte array.
    /// </summary>
    /// <returns>The encoded key ring.</returns>
    public byte[] ToArray()
    {
        using var ms = new MemoryStream();
        using var writer = new PgpPacketWriter(ms);

        WriteTo(writer);

        return ms.ToArray();
    }

    /// <summary>
    /// Writes the key ring using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        // Write master key
        MasterKey.WriteTo(writer, format);

        // Write user IDs
        foreach (var userId in UserIds)
        {
            userId.WriteTo(writer, format);
        }

        // Write user attributes
        foreach (var userAttr in UserAttributes)
        {
            userAttr.WriteTo(writer, format);
        }

        // Categorize signatures
        List<PgpSignaturePacket> certSigs = [];
        List<PgpSignaturePacket> subkeySigs = [];
        List<PgpSignaturePacket> otherSigs = [];

        foreach (var sig in Signatures)
        {
            if (sig.SignatureType == PgpSignatureType.SubkeyBinding ||
                sig.SignatureType == PgpSignatureType.SubkeyRevocation ||
                sig.SignatureType == PgpSignatureType.PrimaryKeyBinding)
            {
                subkeySigs.Add(sig);
            }
            else if (sig.SignatureType == PgpSignatureType.GenericCertification ||
                     sig.SignatureType == PgpSignatureType.PersonaCertification ||
                     sig.SignatureType == PgpSignatureType.CasualCertification ||
                     sig.SignatureType == PgpSignatureType.PositiveCertification ||
                     sig.SignatureType == PgpSignatureType.CertificationRevocation)
            {
                certSigs.Add(sig);
            }
            else
            {
                otherSigs.Add(sig);
            }
        }

        // Write certification signatures
        foreach (var sig in certSigs)
        {
            sig.WriteTo(writer, format);
        }

        // Write other signatures
        foreach (var sig in otherSigs)
        {
            sig.WriteTo(writer, format);
        }

        // Write subkeys with binding signatures
        foreach (var subkey in Subkeys)
        {
            subkey.WriteTo(writer, format);

            foreach (var sig in subkeySigs)
            {
                sig.WriteTo(writer, format);
            }
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpSecretKeyRing other)
    {
        return MasterKey.ComputeFingerprint().AsSpan().SequenceEqual(other.MasterKey.ComputeFingerprint());
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpSecretKeyRing other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var fp = MasterKey.ComputeFingerprint();
        return fp.Length >= 4 ? BinaryPrimitives.ReadInt32BigEndian(fp) : 0;
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpSecretKeyRing left, PgpSecretKeyRing right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpSecretKeyRing left, PgpSecretKeyRing right) => !left.Equals(right);

    /// <summary>
    /// Returns a string representation of this key ring.
    /// </summary>
    public override string ToString()
    {
        var keyId = Convert.ToHexString(MasterKeyId);
        var userId = UserIds.Count > 0 ? UserIds[0].UserId : "(no user ID)";
        var encStatus = IsEncrypted ? "encrypted" : "unencrypted";
        return $"SecretKeyRing(v{Version}, {KeyCount} keys, {encStatus}, ID:{keyId}, {userId})";
    }

    private static Dictionary<ulong, int> BuildKeyIdIndex(
        PgpSecretKeyPacket masterKey,
        IReadOnlyList<PgpSecretKeyPacket> subkeys)
    {
        var index = new Dictionary<ulong, int>();

        ulong masterKeyId = BinaryPrimitives.ReadUInt64BigEndian(masterKey.GetKeyId());
        index[masterKeyId] = -1;

        for (int i = 0; i < subkeys.Count; i++)
        {
            ulong subkeyId = BinaryPrimitives.ReadUInt64BigEndian(subkeys[i].GetKeyId());
            index[subkeyId] = i;
        }

        return index;
    }

    private static int GetPacketEncodedLength(int bodyLength)
    {
        if (bodyLength < 192)
        {
            return 1 + 1 + bodyLength;
        }
        else if (bodyLength < 8384)
        {
            return 1 + 2 + bodyLength;
        }
        else
        {
            return 1 + 5 + bodyLength;
        }
    }
}
