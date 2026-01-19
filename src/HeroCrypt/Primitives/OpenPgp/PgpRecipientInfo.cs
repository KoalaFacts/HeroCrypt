namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents information about a recipient in an encrypted message.
/// </summary>
/// <remarks>
/// <para>
/// This struct contains the key identification data extracted from a
/// Public-Key Encrypted Session Key (PKESK) packet.
/// </para>
/// <para>
/// For v3 PKESK packets, the <see cref="KeyId"/> property contains the 8-byte key ID.
/// For v6 PKESK packets, the <see cref="Fingerprint"/> property contains the full fingerprint.
/// </para>
/// </remarks>
public readonly struct PgpRecipientInfo : IEquatable<PgpRecipientInfo>
{
    /// <summary>
    /// Gets the PKESK packet version (3 or 6).
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the 8-byte key ID (v3 PKESK only).
    /// </summary>
    /// <remarks>
    /// <para>For v6 PKESK packets, this returns the last 8 bytes of the fingerprint.</para>
    /// </remarks>
    public ReadOnlyMemory<byte> KeyId { get; }

    /// <summary>
    /// Gets the full key fingerprint (v6 PKESK only).
    /// </summary>
    /// <remarks>
    /// <para>For v3 PKESK packets, this is empty.</para>
    /// </remarks>
    public ReadOnlyMemory<byte> Fingerprint { get; }

    /// <summary>
    /// Gets the key version (v6 PKESK only).
    /// </summary>
    public int KeyVersion { get; }

    /// <summary>
    /// Gets the public-key algorithm used for encryption.
    /// </summary>
    public PgpPublicKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// Initializes a new recipient info from a v3 PKESK packet.
    /// </summary>
    internal PgpRecipientInfo(ReadOnlyMemory<byte> keyId, PgpPublicKeyAlgorithm algorithm)
    {
        Version = 3;
        KeyId = keyId;
        Fingerprint = ReadOnlyMemory<byte>.Empty;
        KeyVersion = 0;
        Algorithm = algorithm;
    }

    /// <summary>
    /// Initializes a new recipient info from a v6 PKESK packet.
    /// </summary>
    internal PgpRecipientInfo(int keyVersion, ReadOnlyMemory<byte> fingerprint, PgpPublicKeyAlgorithm algorithm)
    {
        Version = 6;
        KeyVersion = keyVersion;
        Fingerprint = fingerprint;
        // For v6, derive key ID from fingerprint (last 8 bytes)
        KeyId = fingerprint.Length >= 8
            ? fingerprint.Slice(fingerprint.Length - 8)
            : fingerprint;
        Algorithm = algorithm;
    }

    /// <summary>
    /// Creates a recipient info from a PKESK packet.
    /// </summary>
    internal static PgpRecipientInfo FromPacket(PgpPublicKeyEncryptedSessionKeyPacket packet)
    {
        if (packet.Version == PgpPublicKeyEncryptedSessionKeyPacket.Version3)
        {
            return new PgpRecipientInfo(packet.KeyId, packet.Algorithm);
        }
        else
        {
            return new PgpRecipientInfo(packet.KeyVersion, packet.Fingerprint, packet.Algorithm);
        }
    }

    /// <summary>
    /// Creates a recipient info from a public key packet.
    /// </summary>
    /// <param name="publicKey">The recipient's public key.</param>
    internal static PgpRecipientInfo FromPublicKey(PgpPublicKeyPacket publicKey)
    {
        var fingerprint = publicKey.ComputeFingerprint();
        if (publicKey.Version == 6)
        {
            return new PgpRecipientInfo(publicKey.Version, fingerprint, publicKey.Algorithm);
        }
        else
        {
            // V4: use last 8 bytes of fingerprint as key ID
            var keyId = fingerprint.Length >= 8
                ? fingerprint.AsMemory(fingerprint.Length - 8)
                : fingerprint.AsMemory();
            return new PgpRecipientInfo(keyId, publicKey.Algorithm);
        }
    }

    /// <summary>
    /// Gets the key ID as a hexadecimal string.
    /// </summary>
    public string KeyIdHex => Convert.ToHexString(KeyId.Span);

    /// <summary>
    /// Gets the fingerprint as a hexadecimal string.
    /// </summary>
    public string FingerprintHex => Fingerprint.Length > 0
        ? Convert.ToHexString(Fingerprint.Span)
        : string.Empty;

    /// <summary>
    /// Checks if this recipient matches the specified key.
    /// </summary>
    /// <param name="publicKey">The public key to check.</param>
    /// <returns>True if the key matches this recipient.</returns>
    public bool MatchesKey(PgpPublicKeyPacket publicKey)
    {
        var keyFingerprint = publicKey.ComputeFingerprint();
        if (Version == 6 && Fingerprint.Length > 0)
        {
            // V6: Compare full fingerprint
            return Fingerprint.Span.SequenceEqual(keyFingerprint);
        }
        else
        {
            // V3: Compare key ID (last 8 bytes of fingerprint)
            if (keyFingerprint.Length >= 8)
            {
                var keyId = keyFingerprint.AsSpan(keyFingerprint.Length - 8);
                return KeyId.Span.SequenceEqual(keyId);
            }

            return false;
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpRecipientInfo other)
    {
        return Version == other.Version
            && KeyVersion == other.KeyVersion
            && Algorithm == other.Algorithm
            && KeyId.Span.SequenceEqual(other.KeyId.Span)
            && Fingerprint.Span.SequenceEqual(other.Fingerprint.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpRecipientInfo other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Version;
            hash = hash * 31 + KeyVersion;
            hash = hash * 31 + (int)Algorithm;
            foreach (var b in KeyId.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <inheritdoc />
    public override string ToString()
    {
        if (Version == 6)
        {
            return $"Recipient(v{KeyVersion}, {Algorithm}, FP={FingerprintHex})";
        }
        else
        {
            return $"Recipient({Algorithm}, KeyId={KeyIdHex})";
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpRecipientInfo left, PgpRecipientInfo right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpRecipientInfo left, PgpRecipientInfo right) => !left.Equals(right);
}
