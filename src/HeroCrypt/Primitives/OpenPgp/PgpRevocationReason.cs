namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Revocation reason codes as defined in RFC 4880 Section 5.2.3.23.
/// </summary>
/// <remarks>
/// <para>
/// These codes indicate why a key or certification was revoked. They are used
/// in the "Reason for Revocation" signature subpacket (type 29).
/// </para>
/// </remarks>
public enum PgpRevocationReason : byte
{
    /// <summary>
    /// No reason specified (0x00).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used when the issuer prefers not to disclose the reason for revocation.
    /// This is the default value.
    /// </para>
    /// </remarks>
    NoReason = 0x00,

    /// <summary>
    /// Key is superseded (0x01).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The key has been replaced by a newer key. The old key should no longer
    /// be used for new signatures or encryption, but existing signatures remain valid.
    /// </para>
    /// </remarks>
    KeySuperseded = 0x01,

    /// <summary>
    /// Key material has been compromised (0x02).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The private key has been compromised or is suspected to be compromised.
    /// All signatures made with this key should be considered suspect.
    /// This is a "hard" revocation - the key should never be trusted again.
    /// </para>
    /// </remarks>
    KeyCompromised = 0x02,

    /// <summary>
    /// Key is retired and no longer used (0x03).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The key is no longer being used but has not been compromised.
    /// Existing signatures remain valid.
    /// </para>
    /// </remarks>
    KeyRetired = 0x03,

    /// <summary>
    /// User ID information is no longer valid (0x20).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used for certification revocations. Indicates that the user ID
    /// is no longer valid (e.g., email address changed, name changed).
    /// </para>
    /// </remarks>
    UserIdNoLongerValid = 0x20,
}

/// <summary>
/// Extension methods for <see cref="PgpRevocationReason"/>.
/// </summary>
public static class ExtensionsToPgpRevocationReason
{
    /// <summary>
    /// Gets whether this revocation reason indicates the key should never be trusted again.
    /// </summary>
    /// <param name="reason">The revocation reason.</param>
    /// <returns>True if this is a "hard" revocation (compromised key).</returns>
    /// <remarks>
    /// <para>
    /// A "hard" revocation (KeyCompromised) means all signatures made with the key
    /// should be considered suspect, even those made before the revocation.
    /// </para>
    /// <para>
    /// "Soft" revocations (KeySuperseded, KeyRetired) mean the key should not be
    /// used for new operations, but existing signatures remain valid.
    /// </para>
    /// </remarks>
    public static bool IsHardRevocation(this PgpRevocationReason reason)
    {
        return reason == PgpRevocationReason.KeyCompromised;
    }

    /// <summary>
    /// Gets a human-readable description of the revocation reason.
    /// </summary>
    /// <param name="reason">The revocation reason.</param>
    /// <returns>A description of the reason.</returns>
    public static string GetDescription(this PgpRevocationReason reason)
    {
        return reason switch
        {
            PgpRevocationReason.NoReason => "No reason specified",
            PgpRevocationReason.KeySuperseded => "Key is superseded",
            PgpRevocationReason.KeyCompromised => "Key material has been compromised",
            PgpRevocationReason.KeyRetired => "Key is retired and no longer used",
            PgpRevocationReason.UserIdNoLongerValid => "User ID information is no longer valid",
            _ => $"Unknown reason (0x{(byte)reason:X2})"
        };
    }
}
