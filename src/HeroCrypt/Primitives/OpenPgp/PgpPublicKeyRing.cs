using System.Buffers.Binary;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents an OpenPGP public key ring containing a master key, subkeys,
/// user IDs, user attributes, and associated signatures.
/// </summary>
/// <remarks>
/// <para>
/// A public key ring is the standard format for distributing OpenPGP public keys.
/// It contains all the components needed to use a key for encryption and signature verification.
/// </para>
/// <para>
/// <b>Structure (RFC 4880 Section 11.1):</b>
/// <code>
/// - One Public-Key packet (master)
/// - Zero or more revocation signatures
/// - Zero or more Direct Key signatures
/// - One or more User ID packets
///   - Zero or more Signature packets (certifications)
/// - Zero or more User Attribute packets
///   - Zero or more Signature packets
/// - Zero or more Subkey packets
///   - Zero or more Signature packets (binding)
/// </code>
/// </para>
/// <para>
/// This type is immutable. All modification methods return new instances.
/// </para>
/// </remarks>
public readonly struct PgpPublicKeyRing : IEquatable<PgpPublicKeyRing>
{
    private readonly Dictionary<ulong, int>? keyIdIndex;

    /// <summary>
    /// Gets the master (primary) public key.
    /// </summary>
    public PgpPublicKeyPacket MasterKey { get; }

    /// <summary>
    /// Gets the subkeys bound to this key ring.
    /// </summary>
    public IReadOnlyList<PgpPublicKeyPacket> Subkeys { get; }

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
    /// Gets the total number of keys (master + subkeys).
    /// </summary>
    public int KeyCount => 1 + Subkeys.Count;

    /// <summary>
    /// Initializes a new public key ring with the specified components.
    /// </summary>
    /// <param name="masterKey">The master public key.</param>
    /// <param name="subkeys">The subkeys (optional).</param>
    /// <param name="userIds">The user IDs (optional).</param>
    /// <param name="userAttributes">The user attributes (optional).</param>
    /// <param name="signatures">The signatures (optional).</param>
    public PgpPublicKeyRing(
        PgpPublicKeyPacket masterKey,
        IReadOnlyList<PgpPublicKeyPacket>? subkeys = null,
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
    /// Creates a public key ring with a master key and optional components.
    /// </summary>
    /// <param name="masterKey">The master public key.</param>
    /// <param name="userIds">The user IDs (optional).</param>
    /// <param name="signatures">The signatures (optional).</param>
    /// <returns>A new public key ring.</returns>
    public static PgpPublicKeyRing Create(
        PgpPublicKeyPacket masterKey,
        IEnumerable<PgpUserIdPacket>? userIds = null,
        IEnumerable<PgpSignaturePacket>? signatures = null)
    {
        return new PgpPublicKeyRing(
            masterKey,
            subkeys: null,
            userIds: userIds?.ToList(),
            userAttributes: null,
            signatures: signatures?.ToList());
    }

    /// <summary>
    /// Creates a public key ring with all components.
    /// </summary>
    /// <param name="masterKey">The master public key.</param>
    /// <param name="subkeys">The subkeys.</param>
    /// <param name="userIds">The user IDs.</param>
    /// <param name="userAttributes">The user attributes.</param>
    /// <param name="signatures">The signatures.</param>
    /// <returns>A new public key ring.</returns>
    public static PgpPublicKeyRing Create(
        PgpPublicKeyPacket masterKey,
        IEnumerable<PgpPublicKeyPacket>? subkeys,
        IEnumerable<PgpUserIdPacket>? userIds,
        IEnumerable<PgpUserAttributePacket>? userAttributes,
        IEnumerable<PgpSignaturePacket>? signatures)
    {
        return new PgpPublicKeyRing(
            masterKey,
            subkeys?.ToList(),
            userIds?.ToList(),
            userAttributes?.ToList(),
            signatures?.ToList());
    }

    /// <summary>
    /// Reads a public key ring from a span.
    /// </summary>
    /// <param name="source">The source span containing the key ring data.</param>
    /// <returns>The parsed public key ring.</returns>
    /// <exception cref="ArgumentException">If the data is malformed.</exception>
    public static PgpPublicKeyRing Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var keyRing, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return keyRing;
    }

    /// <summary>
    /// Reads a public key ring from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the key ring data.</param>
    /// <returns>The parsed public key ring.</returns>
    /// <exception cref="InvalidDataException">If the data is malformed.</exception>
    public static PgpPublicKeyRing Read(Stream stream)
    {
        if (!TryRead(stream, out var keyRing, out var error))
        {
            throw new InvalidDataException(error);
        }

        return keyRing;
    }

    /// <summary>
    /// Tries to read a public key ring from a span.
    /// </summary>
    /// <param name="source">The source span containing the key ring data.</param>
    /// <param name="keyRing">The parsed key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the key ring was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpPublicKeyRing keyRing, out string? error)
    {
        keyRing = default;
        error = null;

        using var stream = new MemoryStream(source.ToArray());
        return TryRead(stream, out keyRing, out error);
    }

    /// <summary>
    /// Tries to read a public key ring from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the key ring data.</param>
    /// <param name="keyRing">The parsed key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the key ring was parsed successfully.</returns>
    public static bool TryRead(Stream stream, out PgpPublicKeyRing keyRing, out string? error)
    {
        keyRing = default;
        error = null;

        using var reader = new PgpPacketReader(stream, leaveOpen: true);

        // First packet must be a PublicKey (Tag 6)
        if (!reader.ReadNextPacket(out var tag, out var body))
        {
            error = "Empty stream - no packets found.";
            return false;
        }

        if (tag != PgpPacketTag.PublicKey)
        {
            error = $"Expected PublicKey packet (Tag 6), got {tag}.";
            return false;
        }

        if (!PgpPublicKeyPacket.TryRead(body.Span, isSubkey: false, out var masterKey, out var packetError))
        {
            error = $"Failed to parse master key: {packetError}";
            return false;
        }

        List<PgpPublicKeyPacket> subkeys = [];
        List<PgpUserIdPacket> userIds = [];
        List<PgpUserAttributePacket> userAttributes = [];
        List<PgpSignaturePacket> signatures = [];

        // Read remaining packets
        while (reader.ReadNextPacket(out tag, out body))
        {
#pragma warning disable IDE0010 // PgpPacketTag has many values; we only handle relevant ones
            switch (tag)
            {
                case PgpPacketTag.PublicKey:
                    // Next key ring starts - we're done with this one
                    // Note: In a full implementation, we'd need to "unread" this packet
                    // For now, this method only reads a single key ring
                    goto done;

                case PgpPacketTag.PublicSubkey:
                    if (!PgpPublicKeyPacket.TryRead(body.Span, isSubkey: true, out var subkey, out packetError))
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
        keyRing = new PgpPublicKeyRing(masterKey, subkeys, userIds, userAttributes, signatures);
        return true;
    }

    /// <summary>
    /// Gets a public key by its key ID.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <returns>The public key, or null if not found.</returns>
    public PgpPublicKeyPacket? GetPublicKey(ReadOnlySpan<byte> keyId)
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
    /// Gets a public key by its fingerprint.
    /// </summary>
    /// <param name="fingerprint">The key fingerprint (20 bytes for V4, 32 bytes for V6).</param>
    /// <returns>The public key, or null if not found.</returns>
    public PgpPublicKeyPacket? GetPublicKeyByFingerprint(ReadOnlySpan<byte> fingerprint)
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
        return GetPublicKey(keyId) != null;
    }

    /// <summary>
    /// Gets all signatures for a specific user ID by index.
    /// </summary>
    /// <param name="userIdIndex">The index of the user ID in the UserIds collection.</param>
    /// <returns>The signatures for the user ID.</returns>
    /// <remarks>
    /// This method returns signatures that appear to certify the specified user ID
    /// based on signature type (0x10-0x13 certifications, 0x30 revocations).
    /// </remarks>
    public IEnumerable<PgpSignaturePacket> GetSignaturesForUserId(int userIdIndex)
    {
        if (userIdIndex < 0 || userIdIndex >= UserIds.Count)
        {
            yield break;
        }

        // Filter signatures that are certification types
        foreach (var sig in Signatures)
        {
            var sigType = sig.SignatureType;
            if (sigType == PgpSignatureType.GenericCertification ||
                sigType == PgpSignatureType.PersonaCertification ||
                sigType == PgpSignatureType.CasualCertification ||
                sigType == PgpSignatureType.PositiveCertification ||
                sigType == PgpSignatureType.CertificationRevocation)
            {
                // Note: In a full implementation, we'd need to track which signature
                // follows which user ID in the packet stream. For now, return all certifications.
                yield return sig;
            }
        }
    }

    /// <summary>
    /// Gets the binding signatures for a subkey.
    /// </summary>
    /// <param name="subkeyId">The 8-byte key ID of the subkey.</param>
    /// <returns>The binding signatures for the subkey.</returns>
    public IEnumerable<PgpSignaturePacket> GetSubkeyBindingSignatures(byte[] subkeyId)
    {
        // Find if subkey exists
        var subkey = GetPublicKey(subkeyId);
        if (subkey == null || !subkey.Value.IsSubkey)
        {
            yield break;
        }

        // Return subkey binding signatures
        foreach (var sig in Signatures)
        {
            if (sig.SignatureType == PgpSignatureType.SubkeyBinding ||
                sig.SignatureType == PgpSignatureType.SubkeyRevocation)
            {
                yield return sig;
            }
        }
    }

    /// <summary>
    /// Gets the primary user ID (the first one or the one marked as primary).
    /// </summary>
    /// <returns>The primary user ID, or null if no user IDs exist.</returns>
    /// <remarks>
    /// <para>
    /// This method looks for a signature containing the PrimaryUserId subpacket.
    /// If not found, it returns the first user ID.
    /// </para>
    /// </remarks>
    public PgpUserIdPacket? GetPrimaryUserId()
    {
        if (UserIds.Count == 0)
        {
            return null;
        }

        // Look for a signature with the PrimaryUserId subpacket
        foreach (var sig in Signatures)
        {
            // Check if any subpacket indicates this is the primary user ID
            foreach (var subpacket in sig.HashedSubpackets)
            {
                if (subpacket.Type == PgpSignatureSubpacketType.PrimaryUserId)
                {
                    // Found primary user ID marker - return first user ID
                    // (In a full implementation, we'd track which user ID this signature certifies)
                    return UserIds[0];
                }
            }
        }

        // Default to first user ID
        return UserIds[0];
    }

    /// <summary>
    /// Adds a subkey to this key ring.
    /// </summary>
    /// <param name="subkey">The subkey to add.</param>
    /// <param name="bindingSignature">The subkey binding signature.</param>
    /// <returns>A new key ring with the added subkey.</returns>
    public PgpPublicKeyRing AddSubkey(PgpPublicKeyPacket subkey, PgpSignaturePacket bindingSignature)
    {
        if (!subkey.IsSubkey)
        {
            throw new ArgumentException("Subkey must have IsSubkey = true.", nameof(subkey));
        }

        if (bindingSignature.SignatureType != PgpSignatureType.SubkeyBinding)
        {
            throw new ArgumentException("Binding signature must be of type SubkeyBinding (0x18).", nameof(bindingSignature));
        }

        List<PgpPublicKeyPacket> newSubkeys = [.. Subkeys, subkey];
        List<PgpSignaturePacket> newSignatures = [.. Signatures, bindingSignature];

        return new PgpPublicKeyRing(MasterKey, newSubkeys, UserIds, UserAttributes, newSignatures);
    }

    /// <summary>
    /// Removes a subkey from this key ring.
    /// </summary>
    /// <param name="keyId">The key ID of the subkey to remove.</param>
    /// <returns>A new key ring without the specified subkey.</returns>
    public PgpPublicKeyRing RemoveSubkey(ReadOnlySpan<byte> keyId)
    {
        var targetKeyId = keyId.ToArray();
        var newSubkeys = Subkeys.Where(sk => !sk.GetKeyId().AsSpan().SequenceEqual(targetKeyId)).ToList();

        if (newSubkeys.Count == Subkeys.Count)
        {
            // Key not found - return unchanged
            return this;
        }

        return new PgpPublicKeyRing(MasterKey, newSubkeys, UserIds, UserAttributes, Signatures);
    }

    /// <summary>
    /// Adds a user ID to this key ring.
    /// </summary>
    /// <param name="userId">The user ID to add.</param>
    /// <param name="certification">Optional certification signature.</param>
    /// <returns>A new key ring with the added user ID.</returns>
    public PgpPublicKeyRing AddUserId(PgpUserIdPacket userId, PgpSignaturePacket? certification = null)
    {
        List<PgpUserIdPacket> newUserIds = [.. UserIds, userId];
        List<PgpSignaturePacket> newSignatures = certification.HasValue
            ? [.. Signatures, certification.Value]
            : [.. Signatures];

        return new PgpPublicKeyRing(MasterKey, Subkeys, newUserIds, UserAttributes, newSignatures);
    }

    /// <summary>
    /// Adds a signature to this key ring.
    /// </summary>
    /// <param name="signature">The signature to add.</param>
    /// <returns>A new key ring with the added signature.</returns>
    public PgpPublicKeyRing AddSignature(PgpSignaturePacket signature)
    {
        List<PgpSignaturePacket> newSignatures = [.. Signatures, signature];
        return new PgpPublicKeyRing(MasterKey, Subkeys, UserIds, UserAttributes, newSignatures);
    }

    /// <summary>
    /// Adds a key revocation signature (type 0x20) to this key ring.
    /// </summary>
    /// <param name="revocation">The revocation signature to add.</param>
    /// <returns>A new key ring with the added revocation signature.</returns>
    /// <exception cref="ArgumentException">If the signature is not a key revocation type.</exception>
    /// <remarks>
    /// <para>
    /// A key revocation signature permanently invalidates the key. For "hard" revocations
    /// (KeyCompromised), all prior signatures become suspect. For "soft" revocations,
    /// prior signatures remain valid.
    /// </para>
    /// </remarks>
    public PgpPublicKeyRing AddRevocationSignature(PgpSignaturePacket revocation)
    {
        if (revocation.SignatureType != PgpSignatureType.KeyRevocation)
        {
            throw new ArgumentException(
                $"Expected KeyRevocation signature (0x20), got {revocation.SignatureType}.",
                nameof(revocation));
        }

        return AddSignature(revocation);
    }

    /// <summary>
    /// Adds a subkey revocation signature (type 0x28) for the specified subkey.
    /// </summary>
    /// <param name="subkeyId">The key ID of the subkey being revoked.</param>
    /// <param name="revocation">The subkey revocation signature.</param>
    /// <returns>A new key ring with the added revocation signature.</returns>
    /// <exception cref="ArgumentException">If the signature is not a subkey revocation type or subkey is not found.</exception>
    public PgpPublicKeyRing AddSubkeyRevocationSignature(ReadOnlySpan<byte> subkeyId, PgpSignaturePacket revocation)
    {
        if (revocation.SignatureType != PgpSignatureType.SubkeyRevocation)
        {
            throw new ArgumentException(
                $"Expected SubkeyRevocation signature (0x28), got {revocation.SignatureType}.",
                nameof(revocation));
        }

        var subkey = GetPublicKey(subkeyId);
        if (subkey == null)
        {
            throw new ArgumentException("Subkey not found in key ring.", nameof(subkeyId));
        }

        return AddSignature(revocation);
    }

    /// <summary>
    /// Adds a certification signature for a User ID.
    /// </summary>
    /// <param name="userId">The User ID being certified.</param>
    /// <param name="certification">The certification signature (type 0x10-0x13).</param>
    /// <returns>A new key ring with the certification added.</returns>
    /// <exception cref="ArgumentException">User ID not found or invalid signature type.</exception>
    /// <remarks>
    /// <para>
    /// Certifications are used in the Web of Trust model to indicate that someone
    /// has verified the binding between this key and a User ID.
    /// </para>
    /// <para>
    /// The User ID must already exist in this key ring.
    /// </para>
    /// </remarks>
    public PgpPublicKeyRing AddCertification(PgpUserIdPacket userId, PgpSignaturePacket certification)
    {
        // Validate signature type
        if (certification.SignatureType != PgpSignatureType.GenericCertification &&
            certification.SignatureType != PgpSignatureType.PersonaCertification &&
            certification.SignatureType != PgpSignatureType.CasualCertification &&
            certification.SignatureType != PgpSignatureType.PositiveCertification)
        {
            throw new ArgumentException(
                $"Expected certification signature (0x10-0x13), got {certification.SignatureType}.",
                nameof(certification));
        }

        // Verify the User ID exists in this key ring
        bool userIdExists = UserIds.Any(u => u.UserId == userId.UserId);
        if (!userIdExists)
        {
            throw new ArgumentException(
                $"User ID '{userId.UserId}' not found in this key ring.",
                nameof(userId));
        }

        return AddSignature(certification);
    }

    /// <summary>
    /// Gets all certification signatures for the specified User ID.
    /// </summary>
    /// <param name="userId">The User ID to get certifications for.</param>
    /// <returns>The certification signatures.</returns>
    /// <remarks>
    /// Note: This returns all certifications in the key ring. Proper verification
    /// that a certification applies to a specific User ID requires signature verification.
    /// </remarks>
    public IEnumerable<PgpSignaturePacket> GetCertifications(PgpUserIdPacket userId)
    {
        // Accept the parameter for future use when we can properly filter by User ID
        _ = userId;

        // Return certifications (0x10-0x13)
        // Note: Proper verification requires checking the signature's hash matches the user ID
        return Signatures.Where(s =>
            s.SignatureType == PgpSignatureType.GenericCertification ||
            s.SignatureType == PgpSignatureType.PersonaCertification ||
            s.SignatureType == PgpSignatureType.CasualCertification ||
            s.SignatureType == PgpSignatureType.PositiveCertification);
    }

    /// <summary>
    /// Gets all certification signatures (types 0x10-0x13) in this key ring.
    /// </summary>
    /// <returns>All certification signatures.</returns>
    public IEnumerable<PgpSignaturePacket> GetAllCertifications()
    {
        return Signatures.Where(s =>
            s.SignatureType == PgpSignatureType.GenericCertification ||
            s.SignatureType == PgpSignatureType.PersonaCertification ||
            s.SignatureType == PgpSignatureType.CasualCertification ||
            s.SignatureType == PgpSignatureType.PositiveCertification);
    }

    /// <summary>
    /// Gets all key revocation signatures (type 0x20) for the master key.
    /// </summary>
    /// <returns>The key revocation signatures.</returns>
    public IEnumerable<PgpSignaturePacket> GetRevocationSignatures()
    {
        return Signatures.Where(s => s.SignatureType == PgpSignatureType.KeyRevocation);
    }

    /// <summary>
    /// Gets all subkey revocation signatures (type 0x28).
    /// </summary>
    /// <returns>The subkey revocation signatures.</returns>
    public IEnumerable<PgpSignaturePacket> GetSubkeyRevocationSignatures()
    {
        return Signatures.Where(s => s.SignatureType == PgpSignatureType.SubkeyRevocation);
    }

    /// <summary>
    /// Gets whether the master key has been revoked.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This checks for the presence of a key revocation signature (type 0x20).
    /// Note that this does not verify the signature - use a signature verifier
    /// to validate the revocation.
    /// </para>
    /// </remarks>
    public bool IsRevoked => Signatures.Any(s => s.SignatureType == PgpSignatureType.KeyRevocation);

    /// <summary>
    /// Gets the key expiration date, if any expiration is set.
    /// </summary>
    /// <returns>The expiration date, or null if the key never expires.</returns>
    /// <remarks>
    /// <para>
    /// The expiration time is stored as a relative offset from the key creation time
    /// in the KeyExpirationTime subpacket of the self-signature.
    /// </para>
    /// </remarks>
    public DateTimeOffset? GetExpirationTime()
    {
        var lifetime = GetKeyLifetime();
        if (lifetime == null)
        {
            return null;
        }

        return CreationTime + lifetime.Value;
    }

    /// <summary>
    /// Gets the key lifetime (duration from creation to expiration), if set.
    /// </summary>
    /// <returns>The key lifetime, or null if the key never expires.</returns>
    public TimeSpan? GetKeyLifetime()
    {
        // Look for a self-signature with the KeyExpirationTime subpacket
        foreach (var sig in Signatures)
        {
            // Look for self-certification signatures
            if (sig.SignatureType != PgpSignatureType.GenericCertification &&
                sig.SignatureType != PgpSignatureType.PersonaCertification &&
                sig.SignatureType != PgpSignatureType.CasualCertification &&
                sig.SignatureType != PgpSignatureType.PositiveCertification)
            {
                continue;
            }

            foreach (var subpacket in sig.HashedSubpackets)
            {
                if (subpacket.Type == PgpSignatureSubpacketType.KeyExpirationTime)
                {
                    var seconds = subpacket.GetKeyExpirationTime();
                    if (seconds == 0)
                    {
                        return null; // 0 means never expires
                    }
                    return TimeSpan.FromSeconds(seconds);
                }
            }
        }

        return null; // No expiration subpacket found
    }

    /// <summary>
    /// Gets whether the key has expired.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This checks the current time against the key expiration time.
    /// A key with no expiration time is never expired.
    /// </para>
    /// </remarks>
    public bool IsExpired => IsExpiredAt(DateTimeOffset.UtcNow);

    /// <summary>
    /// Gets whether the key was expired at a specific point in time.
    /// </summary>
    /// <param name="atTime">The time to check.</param>
    /// <returns>True if the key was expired at the specified time.</returns>
    public bool IsExpiredAt(DateTimeOffset atTime)
    {
        var expirationTime = GetExpirationTime();
        if (expirationTime == null)
        {
            return false; // Never expires
        }

        return atTime >= expirationTime.Value;
    }

    /// <summary>
    /// Gets the revocation reason if the key has been revoked.
    /// </summary>
    /// <returns>The revocation reason and text, or null if not revoked.</returns>
    public (PgpRevocationReason Reason, string? ReasonText)? GetRevocationReason()
    {
        var revocation = Signatures.FirstOrDefault(s => s.SignatureType == PgpSignatureType.KeyRevocation);
        if (revocation.SignatureType != PgpSignatureType.KeyRevocation)
        {
            return null;
        }

        foreach (var subpacket in revocation.HashedSubpackets)
        {
            if (subpacket.Type == PgpSignatureSubpacketType.ReasonForRevocation)
            {
                return subpacket.GetRevocationReason();
            }
        }

        return (PgpRevocationReason.NoReason, null);
    }

    /// <summary>
    /// Gets the preferred symmetric algorithms from the key's self-signature.
    /// </summary>
    /// <returns>The array of algorithm IDs in preference order, or null if not set.</returns>
    /// <remarks>
    /// <para>
    /// Common values:
    /// <list type="bullet">
    ///   <item>9 = AES-256</item>
    ///   <item>8 = AES-192</item>
    ///   <item>7 = AES-128</item>
    /// </list>
    /// </para>
    /// </remarks>
    public byte[]? GetPreferredSymmetricAlgorithms()
    {
        return GetPreferredAlgorithmsOfType(PgpSignatureSubpacketType.PreferredSymmetricAlgorithms);
    }

    /// <summary>
    /// Gets the preferred hash algorithms from the key's self-signature.
    /// </summary>
    /// <returns>The array of algorithm IDs in preference order, or null if not set.</returns>
    /// <remarks>
    /// <para>
    /// Common values:
    /// <list type="bullet">
    ///   <item>10 = SHA-512</item>
    ///   <item>9 = SHA-384</item>
    ///   <item>8 = SHA-256</item>
    /// </list>
    /// </para>
    /// </remarks>
    public byte[]? GetPreferredHashAlgorithms()
    {
        return GetPreferredAlgorithmsOfType(PgpSignatureSubpacketType.PreferredHashAlgorithms);
    }

    /// <summary>
    /// Gets the preferred compression algorithms from the key's self-signature.
    /// </summary>
    /// <returns>The array of algorithm IDs in preference order, or null if not set.</returns>
    /// <remarks>
    /// <para>
    /// Common values:
    /// <list type="bullet">
    ///   <item>0 = Uncompressed</item>
    ///   <item>1 = ZIP</item>
    ///   <item>2 = ZLIB</item>
    ///   <item>3 = BZip2</item>
    /// </list>
    /// </para>
    /// </remarks>
    public byte[]? GetPreferredCompressionAlgorithms()
    {
        return GetPreferredAlgorithmsOfType(PgpSignatureSubpacketType.PreferredCompressionAlgorithms);
    }

    /// <summary>
    /// Gets the preferred AEAD algorithms from the key's self-signature.
    /// </summary>
    /// <returns>The array of (cipher, aead) pairs in preference order, or null if not set.</returns>
    /// <remarks>
    /// <para>
    /// Per RFC 9580, this contains pairs of bytes: (symmetric cipher algorithm, AEAD algorithm).
    /// Common AEAD values:
    /// <list type="bullet">
    ///   <item>1 = EAX</item>
    ///   <item>2 = OCB</item>
    ///   <item>3 = GCM</item>
    /// </list>
    /// </para>
    /// </remarks>
    public byte[]? GetPreferredAeadAlgorithms()
    {
        return GetPreferredAlgorithmsOfType(PgpSignatureSubpacketType.PreferredAeadAlgorithms);
    }

    private byte[]? GetPreferredAlgorithmsOfType(PgpSignatureSubpacketType subpacketType)
    {
        // Look for a self-signature with the preferred algorithms subpacket
        foreach (var sig in Signatures)
        {
            // Look for self-certification signatures
            if (sig.SignatureType != PgpSignatureType.GenericCertification &&
                sig.SignatureType != PgpSignatureType.PersonaCertification &&
                sig.SignatureType != PgpSignatureType.CasualCertification &&
                sig.SignatureType != PgpSignatureType.PositiveCertification)
            {
                continue;
            }

            foreach (var subpacket in sig.HashedSubpackets)
            {
                if (subpacket.Type == subpacketType)
                {
                    return subpacket.Data.ToArray();
                }
            }
        }

        return null; // Not found
    }

    /// <summary>
    /// Adds a user attribute to this key ring.
    /// </summary>
    /// <param name="userAttribute">The user attribute to add.</param>
    /// <param name="certification">Optional certification signature.</param>
    /// <returns>A new key ring with the added user attribute.</returns>
    public PgpPublicKeyRing AddUserAttribute(PgpUserAttributePacket userAttribute, PgpSignaturePacket? certification = null)
    {
        List<PgpUserAttributePacket> newUserAttributes = [.. UserAttributes, userAttribute];
        List<PgpSignaturePacket> newSignatures = certification.HasValue
            ? [.. Signatures, certification.Value]
            : [.. Signatures];

        return new PgpPublicKeyRing(MasterKey, Subkeys, UserIds, newUserAttributes, newSignatures);
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

        // User IDs and their signatures
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

        // Write user IDs with their signatures
        // Note: In a proper implementation, we'd track which signatures belong to which user IDs
        foreach (var userId in UserIds)
        {
            userId.WriteTo(writer, format);
        }

        // Write user attributes
        foreach (var userAttr in UserAttributes)
        {
            userAttr.WriteTo(writer, format);
        }

        // Write all signatures (certifications, direct key, etc.)
        // In a proper implementation, we'd interleave these with user IDs/subkeys appropriately
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

        // Write certification signatures (after user IDs)
        foreach (var sig in certSigs)
        {
            sig.WriteTo(writer, format);
        }

        // Write other signatures (direct key, etc.)
        foreach (var sig in otherSigs)
        {
            sig.WriteTo(writer, format);
        }

        // Write subkeys with their binding signatures
        foreach (var subkey in Subkeys)
        {
            subkey.WriteTo(writer, format);

            // Write binding signatures for this subkey
            foreach (var sig in subkeySigs)
            {
                sig.WriteTo(writer, format);
            }
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpPublicKeyRing other)
    {
        // Compare fingerprints for equality
        return MasterKey.ComputeFingerprint().AsSpan().SequenceEqual(other.MasterKey.ComputeFingerprint());
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpPublicKeyRing other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var fp = MasterKey.ComputeFingerprint();
        return fp.Length >= 4 ? BinaryPrimitives.ReadInt32BigEndian(fp) : 0;
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpPublicKeyRing left, PgpPublicKeyRing right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpPublicKeyRing left, PgpPublicKeyRing right) => !left.Equals(right);

    /// <summary>
    /// Returns a string representation of this key ring.
    /// </summary>
    public override string ToString()
    {
        var keyId = Convert.ToHexString(MasterKeyId);
        var userId = UserIds.Count > 0 ? UserIds[0].UserId : "(no user ID)";
        return $"PublicKeyRing(v{Version}, {KeyCount} keys, ID:{keyId}, {userId})";
    }

    private static Dictionary<ulong, int> BuildKeyIdIndex(
        PgpPublicKeyPacket masterKey,
        IReadOnlyList<PgpPublicKeyPacket> subkeys)
    {
        var index = new Dictionary<ulong, int>();

        // Master key at index -1
        ulong masterKeyId = BinaryPrimitives.ReadUInt64BigEndian(masterKey.GetKeyId());
        index[masterKeyId] = -1;

        // Subkeys at their respective indices
        for (int i = 0; i < subkeys.Count; i++)
        {
            ulong subkeyId = BinaryPrimitives.ReadUInt64BigEndian(subkeys[i].GetKeyId());
            index[subkeyId] = i;
        }

        return index;
    }

    private static int GetPacketEncodedLength(int bodyLength)
    {
        // New format packet header: 1 byte tag + variable length
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
