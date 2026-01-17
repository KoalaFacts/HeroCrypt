using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP signature subpacket types as defined in RFC 4880 Section 5.2.3.1 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// Signature subpackets contain additional information about a signature.
/// They appear in two areas:
/// <list type="bullet">
///   <item>Hashed subpackets - included in signature hash (tamper-evident)</item>
///   <item>Unhashed subpackets - not included in hash (can be modified)</item>
/// </list>
/// </para>
/// <para>
/// Critical subpackets (bit 7 set) MUST be understood or the signature is invalid.
/// </para>
/// </remarks>
public enum PgpSignatureSubpacketType : byte
{
    // ─────────────────────────────────────────────────────────────────────────
    // Reserved (Type 0-1)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reserved (Type 0).
    /// </summary>
    Reserved0 = 0,

    /// <summary>
    /// Reserved (Type 1).
    /// </summary>
    Reserved1 = 1,

    // ─────────────────────────────────────────────────────────────────────────
    // Timestamp Subpackets
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Signature Creation Time (Type 2) - REQUIRED.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.4</para>
    /// <para>4-byte Unix timestamp of when the signature was created.</para>
    /// <para>MUST be present in the hashed area.</para>
    /// </remarks>
    [NotImplemented("Signature creation time - REQUIRED", Priority = 1)]
    SignatureCreationTime = 2,

    /// <summary>
    /// Signature Expiration Time (Type 3).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.10</para>
    /// <para>4-byte time delta from creation time. 0 = never expires.</para>
    /// </remarks>
    [NotImplemented("Signature expiration time", Priority = 2)]
    SignatureExpirationTime = 3,

    // ─────────────────────────────────────────────────────────────────────────
    // Trust and Exportability
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Exportable Certification (Type 4).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.11</para>
    /// <para>1-byte flag. 0 = local signature only, 1 = exportable.</para>
    /// </remarks>
    [NotImplemented("Exportable certification flag", Priority = 3)]
    ExportableCertification = 4,

    /// <summary>
    /// Trust Signature (Type 5).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.13</para>
    /// <para>Level and amount of trust. Used for web of trust.</para>
    /// </remarks>
    [NotImplemented("Trust signature - web of trust level", Priority = 3)]
    TrustSignature = 5,

    /// <summary>
    /// Regular Expression (Type 6).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.14</para>
    /// <para>Limits trust to User IDs matching the regex.</para>
    /// </remarks>
    [NotImplemented("Regular expression - trust constraint", Priority = 4)]
    RegularExpression = 6,

    // ─────────────────────────────────────────────────────────────────────────
    // Revocation
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Revocable (Type 7).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.12</para>
    /// <para>1-byte flag. 0 = signature is irrevocable.</para>
    /// </remarks>
    [NotImplemented("Revocable flag", Priority = 3)]
    Revocable = 7,

    // ─────────────────────────────────────────────────────────────────────────
    // Key Expiration
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Key Expiration Time (Type 9).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.6</para>
    /// <para>4-byte time delta from key creation. 0 = never expires.</para>
    /// </remarks>
    [NotImplemented("Key expiration time", Priority = 2)]
    KeyExpirationTime = 9,

    // ─────────────────────────────────────────────────────────────────────────
    // Placeholder for Backward Compatibility (Type 10)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Placeholder for backward compatibility (Type 10).
    /// </summary>
    [NotImplemented("Placeholder - backward compatibility", Priority = 5)]
    PlaceholderBackwardCompatibility = 10,

    // ─────────────────────────────────────────────────────────────────────────
    // Algorithm Preferences
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Preferred Symmetric Algorithms (Type 11).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.7</para>
    /// <para>List of symmetric algorithm IDs in preference order.</para>
    /// </remarks>
    [NotImplemented("Preferred symmetric algorithms", Priority = 2)]
    PreferredSymmetricAlgorithms = 11,

    /// <summary>
    /// Revocation Key (Type 12).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.15</para>
    /// <para>Designates a key that can revoke this key.</para>
    /// </remarks>
    [NotImplemented("Revocation key designation", Priority = 3)]
    RevocationKey = 12,

    // ─────────────────────────────────────────────────────────────────────────
    // Issuer Identification
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Issuer Key ID (Type 16).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.5</para>
    /// <para>8-byte key ID of the signing key.</para>
    /// <para>Typically in unhashed area (for efficiency).</para>
    /// </remarks>
    [NotImplemented("Issuer key ID", Priority = 1)]
    IssuerKeyId = 16,

    // ─────────────────────────────────────────────────────────────────────────
    // Notation Data
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Notation Data (Type 20).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.16</para>
    /// <para>Name-value pairs for arbitrary data.</para>
    /// <para>Used for application-specific extensions.</para>
    /// </remarks>
    [NotImplemented("Notation data - name-value pairs", Priority = 3)]
    NotationData = 20,

    // ─────────────────────────────────────────────────────────────────────────
    // More Algorithm Preferences
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Preferred Hash Algorithms (Type 21).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.8</para>
    /// <para>List of hash algorithm IDs in preference order.</para>
    /// </remarks>
    [NotImplemented("Preferred hash algorithms", Priority = 2)]
    PreferredHashAlgorithms = 21,

    /// <summary>
    /// Preferred Compression Algorithms (Type 22).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.9</para>
    /// <para>List of compression algorithm IDs in preference order.</para>
    /// </remarks>
    [NotImplemented("Preferred compression algorithms", Priority = 2)]
    PreferredCompressionAlgorithms = 22,

    /// <summary>
    /// Key Server Preferences (Type 23).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.17</para>
    /// <para>Flags indicating key server behavior preferences.</para>
    /// </remarks>
    [NotImplemented("Key server preferences", Priority = 3)]
    KeyServerPreferences = 23,

    /// <summary>
    /// Preferred Key Server (Type 24).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.18</para>
    /// <para>URI of preferred key server for updates.</para>
    /// </remarks>
    [NotImplemented("Preferred key server URI", Priority = 3)]
    PreferredKeyServer = 24,

    /// <summary>
    /// Primary User ID (Type 25).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.19</para>
    /// <para>1-byte flag. Non-zero = this is the primary User ID.</para>
    /// </remarks>
    [NotImplemented("Primary User ID flag", Priority = 2)]
    PrimaryUserId = 25,

    /// <summary>
    /// Policy URI (Type 26).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.20</para>
    /// <para>URI of signing policy document.</para>
    /// </remarks>
    [NotImplemented("Policy URI", Priority = 4)]
    PolicyUri = 26,

    /// <summary>
    /// Key Flags (Type 27).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.21</para>
    /// <para>Flags indicating key capabilities (certify, sign, encrypt, etc.).</para>
    /// </remarks>
    [NotImplemented("Key flags - capabilities", Priority = 1)]
    KeyFlags = 27,

    /// <summary>
    /// Signer's User ID (Type 28).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.22</para>
    /// <para>User ID under which the signature was made.</para>
    /// </remarks>
    [NotImplemented("Signer's User ID", Priority = 3)]
    SignersUserId = 28,

    /// <summary>
    /// Reason for Revocation (Type 29).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.23</para>
    /// <para>Revocation reason code and optional text.</para>
    /// </remarks>
    [NotImplemented("Reason for revocation", Priority = 2)]
    ReasonForRevocation = 29,

    /// <summary>
    /// Features (Type 30).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.24</para>
    /// <para>Flags indicating supported features (MDC, AEAD, etc.).</para>
    /// </remarks>
    [NotImplemented("Features flags", Priority = 2)]
    Features = 30,

    /// <summary>
    /// Signature Target (Type 31).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.25</para>
    /// <para>Identifies another signature being signed over.</para>
    /// </remarks>
    [NotImplemented("Signature target", Priority = 3)]
    SignatureTarget = 31,

    /// <summary>
    /// Embedded Signature (Type 32).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.3.26</para>
    /// <para>Complete signature packet embedded as subpacket.</para>
    /// <para>Used for primary key binding in subkey binding signatures.</para>
    /// </remarks>
    [NotImplemented("Embedded signature", Priority = 2)]
    EmbeddedSignature = 32,

    // ─────────────────────────────────────────────────────────────────────────
    // RFC 9580 Additions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Issuer Fingerprint (Type 33) - RFC 9580.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Version byte followed by full key fingerprint.</para>
    /// <para>More reliable than Key ID for key lookup.</para>
    /// </remarks>
    [NotImplemented("Issuer fingerprint - RFC 9580", Priority = 1)]
    IssuerFingerprint = 33,

    /// <summary>
    /// Preferred AEAD Algorithms (Type 34) - RFC 9580.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>List of AEAD algorithm IDs in preference order.</para>
    /// </remarks>
    [NotImplemented("Preferred AEAD algorithms - RFC 9580", Priority = 2)]
    PreferredAeadAlgorithms = 34,

    /// <summary>
    /// Intended Recipient Fingerprint (Type 35) - RFC 9580.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Fingerprint of intended recipient (surreptitious forwarding protection).</para>
    /// </remarks>
    [NotImplemented("Intended recipient fingerprint - RFC 9580", Priority = 3)]
    IntendedRecipientFingerprint = 35,

    /// <summary>
    /// Attestation Key Signature (Type 37) - RFC 9580.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>For attested key signatures.</para>
    /// </remarks>
    [NotImplemented("Attestation key signature - RFC 9580", Priority = 4)]
    AttestationKeySignature = 37,

    // ─────────────────────────────────────────────────────────────────────────
    // Private/Experimental (Types 100-110)
    // ─────────────────────────────────────────────────────────────────────────

    // Types 100-110 are reserved for private/experimental use
}
