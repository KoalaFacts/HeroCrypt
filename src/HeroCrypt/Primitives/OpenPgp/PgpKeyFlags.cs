namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP key capability flags as defined in RFC 4880 Section 5.2.3.21 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// Key capability flags indicate what operations a key can perform. They appear in the Key Flags
/// signature subpacket on self-signatures and certifications.
/// </para>
/// <para>
/// A key should only be used for operations indicated by its flags.
/// Multiple flags can be combined.
/// </para>
/// </remarks>
[Flags]
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix - 'Flags' is the RFC 4880 name
public enum PgpKeyCapability : byte
#pragma warning restore CA1711
{
    /// <summary>
    /// No capabilities set.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// This key may be used to certify other keys (0x01).
    /// </summary>
    /// <remarks>
    /// <para>Primary keys typically have this flag.</para>
    /// <para>Allows creating key certifications (0x10-0x13) and revocations.</para>
    /// </remarks>
    Certify = 0x01,

    /// <summary>
    /// This key may be used to sign data (0x02).
    /// </summary>
    /// <remarks>
    /// <para>Allows creating document signatures (0x00, 0x01).</para>
    /// <para>Often combined with Certify on primary keys.</para>
    /// </remarks>
    Sign = 0x02,

    /// <summary>
    /// This key may be used to encrypt communications (0x04).
    /// </summary>
    /// <remarks>
    /// <para>For encrypting messages to this key.</para>
    /// <para>Typically on encryption subkeys.</para>
    /// </remarks>
    EncryptCommunications = 0x04,

    /// <summary>
    /// This key may be used to encrypt storage (0x08).
    /// </summary>
    /// <remarks>
    /// <para>For encrypting data at rest.</para>
    /// <para>Often combined with EncryptCommunications.</para>
    /// </remarks>
    EncryptStorage = 0x08,

    /// <summary>
    /// The private component of this key may have been split (0x10).
    /// </summary>
    /// <remarks>
    /// <para>Indicates the secret key was split using secret sharing.</para>
    /// <para>Requires multiple parties to reconstruct.</para>
    /// </remarks>
    SplitKey = 0x10,

    /// <summary>
    /// This key may be used for authentication (0x20).
    /// </summary>
    /// <remarks>
    /// <para>For SSH authentication, TLS client certificates, etc.</para>
    /// <para>Distinct from signing documents.</para>
    /// </remarks>
    Authentication = 0x20,

    /// <summary>
    /// The private component of this key may be in possession of more than one person (0x80).
    /// </summary>
    /// <remarks>
    /// <para>Indicates multiple parties hold copies of the secret key.</para>
    /// <para>Used for group/shared keys.</para>
    /// </remarks>
    GroupKey = 0x80,

    // ─────────────────────────────────────────────────────────────────────────
    // Common Combinations
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Typical primary key capabilities: Certify + Sign.
    /// </summary>
    CertifyAndSign = Certify | Sign,

    /// <summary>
    /// Typical encryption subkey capabilities: Encrypt Communications + Storage.
    /// </summary>
    EncryptAll = EncryptCommunications | EncryptStorage,

    /// <summary>
    /// All standard usage capabilities.
    /// </summary>
    AllUsage = Certify | Sign | EncryptCommunications | EncryptStorage | Authentication,
}
