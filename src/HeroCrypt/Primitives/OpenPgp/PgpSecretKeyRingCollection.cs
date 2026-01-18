using System.Buffers.Binary;
using System.Collections;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a collection of OpenPGP secret key rings with efficient lookup capabilities.
/// </summary>
/// <remarks>
/// <para>
/// A secret key ring collection is used to manage multiple secret key rings, such as a keyring file
/// containing the user's private keys. It provides efficient lookup by key ID or fingerprint.
/// </para>
/// <para>
/// This type is immutable. All modification methods return new instances.
/// </para>
/// </remarks>
public readonly struct PgpSecretKeyRingCollection : IEquatable<PgpSecretKeyRingCollection>, IEnumerable<PgpSecretKeyRing>
{
    private readonly IReadOnlyList<PgpSecretKeyRing> keyRings;
    private readonly Dictionary<ulong, int>? keyIdIndex;

    /// <summary>
    /// Gets the key rings in this collection.
    /// </summary>
    public IReadOnlyList<PgpSecretKeyRing> KeyRings => keyRings ?? [];

    /// <summary>
    /// Gets the number of key rings in this collection.
    /// </summary>
    public int Count => KeyRings.Count;

    /// <summary>
    /// Gets an empty key ring collection.
    /// </summary>
    public static PgpSecretKeyRingCollection Empty => new([]);

    /// <summary>
    /// Initializes a new key ring collection with the specified key rings.
    /// </summary>
    /// <param name="keyRings">The key rings to include.</param>
    public PgpSecretKeyRingCollection(IEnumerable<PgpSecretKeyRing> keyRings)
    {
        this.keyRings = keyRings?.ToList() ?? [];
        keyIdIndex = BuildKeyIdIndex(this.keyRings);
    }

    /// <summary>
    /// Initializes a new key ring collection with a single key ring.
    /// </summary>
    /// <param name="keyRing">The key ring to include.</param>
    public PgpSecretKeyRingCollection(PgpSecretKeyRing keyRing)
        : this([keyRing])
    {
    }

    /// <summary>
    /// Reads a key ring collection from a span.
    /// </summary>
    /// <param name="source">The source span containing the key ring data.</param>
    /// <returns>The parsed key ring collection.</returns>
    /// <exception cref="ArgumentException">If the data is malformed.</exception>
    public static PgpSecretKeyRingCollection Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var collection, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return collection;
    }

    /// <summary>
    /// Reads a key ring collection from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the key ring data.</param>
    /// <returns>The parsed key ring collection.</returns>
    /// <exception cref="InvalidDataException">If the data is malformed.</exception>
    public static PgpSecretKeyRingCollection Read(Stream stream)
    {
        if (!TryRead(stream, out var collection, out var error))
        {
            throw new InvalidDataException(error);
        }

        return collection;
    }

    /// <summary>
    /// Tries to read a key ring collection from a span.
    /// </summary>
    /// <param name="source">The source span containing the key ring data.</param>
    /// <param name="collection">The parsed collection if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the collection was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSecretKeyRingCollection collection, out string? error)
    {
        collection = Empty;
        error = null;

        using var stream = new MemoryStream(source.ToArray());
        return TryRead(stream, out collection, out error);
    }

    /// <summary>
    /// Tries to read a key ring collection from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the key ring data.</param>
    /// <param name="collection">The parsed collection if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the collection was parsed successfully.</returns>
    public static bool TryRead(Stream stream, out PgpSecretKeyRingCollection collection, out string? error)
    {
        collection = Empty;
        error = null;

        List<PgpSecretKeyRing> keyRingsList = [];

        while (stream.Position < stream.Length)
        {
            if (!TryReadSingleKeyRing(stream, out var keyRing, out error))
            {
                if (keyRingsList.Count == 0)
                {
                    return false;
                }

                break;
            }

            keyRingsList.Add(keyRing);
        }

        collection = new PgpSecretKeyRingCollection(keyRingsList);
        return true;
    }

    /// <summary>
    /// Gets the key ring containing the specified key ID.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <returns>The key ring containing the key, or null if not found.</returns>
    public PgpSecretKeyRing? GetKeyRing(ReadOnlySpan<byte> keyId)
    {
        if (keyId.Length != 8 || keyIdIndex == null)
        {
            return null;
        }

        ulong keyIdValue = BinaryPrimitives.ReadUInt64BigEndian(keyId);

        if (keyIdIndex.TryGetValue(keyIdValue, out int index) && index >= 0 && index < keyRings.Count)
        {
            return keyRings[index];
        }

        return null;
    }

    /// <summary>
    /// Gets the key ring containing the specified fingerprint.
    /// </summary>
    /// <param name="fingerprint">The key fingerprint.</param>
    /// <returns>The key ring containing the key, or null if not found.</returns>
    public PgpSecretKeyRing? GetKeyRingByFingerprint(ReadOnlySpan<byte> fingerprint)
    {
        foreach (var keyRing in KeyRings)
        {
            if (keyRing.GetSecretKeyByFingerprint(fingerprint) != null)
            {
                return keyRing;
            }
        }

        return null;
    }

    /// <summary>
    /// Gets a secret key by its key ID from any key ring in the collection.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <returns>The secret key, or null if not found.</returns>
    public PgpSecretKeyPacket? GetSecretKey(ReadOnlySpan<byte> keyId)
    {
        var keyRing = GetKeyRing(keyId);
        return keyRing?.GetSecretKey(keyId);
    }

    /// <summary>
    /// Gets all key rings matching a user ID substring (case-insensitive).
    /// </summary>
    /// <param name="userIdSubstring">The substring to match.</param>
    /// <returns>The matching key rings.</returns>
    public IEnumerable<PgpSecretKeyRing> GetKeyRingsByUserId(string userIdSubstring)
    {
        if (string.IsNullOrEmpty(userIdSubstring))
        {
            yield break;
        }

        foreach (var keyRing in KeyRings)
        {
            foreach (var userId in keyRing.UserIds)
            {
                if (userId.UserId.Contains(userIdSubstring, StringComparison.OrdinalIgnoreCase))
                {
                    yield return keyRing;
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Checks if this collection contains a key with the specified key ID.
    /// </summary>
    /// <param name="keyId">The 8-byte key ID.</param>
    /// <returns>True if the collection contains the key.</returns>
    public bool ContainsKey(ReadOnlySpan<byte> keyId)
    {
        return GetKeyRing(keyId) != null;
    }

    /// <summary>
    /// Extracts a public key ring collection from this secret key ring collection.
    /// </summary>
    /// <returns>A new public key ring collection containing only the public key material.</returns>
    public PgpPublicKeyRingCollection ExtractPublicKeyRingCollection()
    {
        var publicKeyRings = KeyRings.Select(skr => skr.ExtractPublicKeyRing());
        return new PgpPublicKeyRingCollection(publicKeyRings);
    }

    /// <summary>
    /// Adds a key ring to this collection.
    /// </summary>
    /// <param name="keyRing">The key ring to add.</param>
    /// <returns>A new collection with the added key ring.</returns>
    public PgpSecretKeyRingCollection Add(PgpSecretKeyRing keyRing)
    {
        List<PgpSecretKeyRing> newKeyRings = [.. KeyRings, keyRing];
        return new PgpSecretKeyRingCollection(newKeyRings);
    }

    /// <summary>
    /// Removes a key ring from this collection by its master key ID.
    /// </summary>
    /// <param name="masterKeyId">The master key ID of the key ring to remove.</param>
    /// <returns>A new collection without the specified key ring.</returns>
    public PgpSecretKeyRingCollection Remove(ReadOnlySpan<byte> masterKeyId)
    {
        var targetKeyId = masterKeyId.ToArray();
        var newKeyRings = KeyRings
            .Where(kr => !kr.MasterKeyId.AsSpan().SequenceEqual(targetKeyId))
            .ToList();

        return new PgpSecretKeyRingCollection(newKeyRings);
    }

    /// <summary>
    /// Securely clears all sensitive key material from all key rings in this collection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method zeros out the secret key material in all key rings.
    /// Call this when you no longer need the collection to minimize the window during which
    /// sensitive data resides in memory.
    /// </para>
    /// </remarks>
    public void ClearAllSensitiveData()
    {
        foreach (var keyRing in KeyRings)
        {
            keyRing.ClearSensitiveData();
        }
    }

    /// <summary>
    /// Gets the total encoded length of this collection.
    /// </summary>
    /// <returns>The number of bytes needed to encode the collection.</returns>
    public int GetEncodedLength()
    {
        int length = 0;
        foreach (var keyRing in KeyRings)
        {
            length += keyRing.GetEncodedLength();
        }
        return length;
    }

    /// <summary>
    /// Writes the collection to a byte array.
    /// </summary>
    /// <returns>The encoded collection.</returns>
    public byte[] ToArray()
    {
        using var ms = new MemoryStream();
        using var writer = new PgpPacketWriter(ms);

        WriteTo(writer);

        return ms.ToArray();
    }

    /// <summary>
    /// Writes the collection using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        foreach (var keyRing in KeyRings)
        {
            keyRing.WriteTo(writer, format);
        }
    }

    /// <inheritdoc />
    public IEnumerator<PgpSecretKeyRing> GetEnumerator() => KeyRings.GetEnumerator();

    /// <inheritdoc />
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <inheritdoc />
    public bool Equals(PgpSecretKeyRingCollection other)
    {
        if (Count != other.Count)
        {
            return false;
        }

        var thisIds = KeyRings.Select(kr => Convert.ToHexString(kr.MasterKeyId)).OrderBy(x => x);
        var otherIds = other.KeyRings.Select(kr => Convert.ToHexString(kr.MasterKeyId)).OrderBy(x => x);

        return thisIds.SequenceEqual(otherIds);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpSecretKeyRingCollection other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            foreach (var keyRing in KeyRings.OrderBy(kr => Convert.ToHexString(kr.MasterKeyId)))
            {
                hash = hash * 31 + keyRing.GetHashCode();
            }
            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpSecretKeyRingCollection left, PgpSecretKeyRingCollection right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpSecretKeyRingCollection left, PgpSecretKeyRingCollection right) => !left.Equals(right);

    /// <summary>
    /// Returns a string representation of this collection.
    /// </summary>
    public override string ToString()
    {
        return $"SecretKeyRingCollection({Count} key rings)";
    }

    private static bool TryReadSingleKeyRing(Stream stream, out PgpSecretKeyRing keyRing, out string? error)
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

        while (reader.ReadNextPacket(out tag, out body))
        {
#pragma warning disable IDE0010 // PgpPacketTag has many values; we only handle relevant ones
            switch (tag)
            {
                case PgpPacketTag.SecretKey:
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
                    break;

                default:
                    break;
            }
#pragma warning restore IDE0010
        }

    done:
        keyRing = new PgpSecretKeyRing(masterKey, subkeys, userIds, userAttributes, signatures);
        return true;
    }

    private static Dictionary<ulong, int> BuildKeyIdIndex(IReadOnlyList<PgpSecretKeyRing> keyRings)
    {
        var index = new Dictionary<ulong, int>();

        for (int ringIndex = 0; ringIndex < keyRings.Count; ringIndex++)
        {
            var keyRing = keyRings[ringIndex];

            ulong masterKeyId = BinaryPrimitives.ReadUInt64BigEndian(keyRing.MasterKeyId);
            index[masterKeyId] = ringIndex;

            foreach (var subkey in keyRing.Subkeys)
            {
                ulong subkeyId = BinaryPrimitives.ReadUInt64BigEndian(subkey.GetKeyId());
                index[subkeyId] = ringIndex;
            }
        }

        return index;
    }
}
