using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP signature types as defined in RFC 4880 Section 5.2.1.
/// </summary>
/// <remarks>
/// <para>
/// The signature type indicates what the signature certifies and how it was computed.
/// Different signature types have different meanings for the hashed data.
/// </para>
/// </remarks>
public enum PgpSignatureType : byte
{
    // ─────────────────────────────────────────────────────────────────────────
    // Document Signatures (0x00-0x01)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Binary Document Signature (0x00).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Signature of a binary document. The document data is hashed directly
    /// without any canonicalization.
    /// </para>
    /// </remarks>
    [NotImplemented("Binary document signature", Priority = 1)]
    BinaryDocument = 0x00,

    /// <summary>
    /// Canonical Text Document Signature (0x01).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Signature of a text document. Line endings are canonicalized to CRLF
    /// and trailing whitespace is removed before hashing.
    /// </para>
    /// </remarks>
    [NotImplemented("Canonical text document signature", Priority = 1)]
    CanonicalTextDocument = 0x01,

    // ─────────────────────────────────────────────────────────────────────────
    // Standalone Signature (0x02)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Standalone Signature (0x02).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Signature that is not bound to any particular document.
    /// Meaning is determined by subpackets only.
    /// </para>
    /// </remarks>
    [NotImplemented("Standalone signature", Priority = 3)]
    Standalone = 0x02,

    // ─────────────────────────────────────────────────────────────────────────
    // Key Certifications (0x10-0x13)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Generic Certification (0x10).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Generic certification of a User ID and public key.
    /// No particular assurance about the identity claim.
    /// </para>
    /// </remarks>
    [NotImplemented("Generic key certification", Priority = 1)]
    GenericCertification = 0x10,

    /// <summary>
    /// Persona Certification (0x11).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Persona certification - signer has not verified the identity claim.
    /// "I have not checked whether this person is who they claim to be."
    /// </para>
    /// </remarks>
    [NotImplemented("Persona certification - no identity verification", Priority = 2)]
    PersonaCertification = 0x11,

    /// <summary>
    /// Casual Certification (0x12).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Casual certification - signer has done some casual checking.
    /// "I have done some checking that this person is who they claim to be."
    /// </para>
    /// </remarks>
    [NotImplemented("Casual certification - some identity verification", Priority = 2)]
    CasualCertification = 0x12,

    /// <summary>
    /// Positive Certification (0x13).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Positive certification - signer has done substantial verification.
    /// "I have done substantial verification that this person is who they claim to be."
    /// </para>
    /// </remarks>
    [NotImplemented("Positive certification - substantial identity verification", Priority = 2)]
    PositiveCertification = 0x13,

    // ─────────────────────────────────────────────────────────────────────────
    // Subkey Binding (0x18-0x19)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Subkey Binding Signature (0x18).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Made by the primary key over the primary key and subkey.
    /// Binds a subkey to the primary key.
    /// </para>
    /// </remarks>
    [NotImplemented("Subkey binding - binds subkey to primary key", Priority = 1)]
    SubkeyBinding = 0x18,

    /// <summary>
    /// Primary Key Binding Signature (0x19).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Made by a signing subkey over the primary key and itself.
    /// Proves the subkey belongs to the primary key owner.
    /// Required for signing-capable subkeys.
    /// </para>
    /// </remarks>
    [NotImplemented("Primary key binding - embedded in subkey binding", Priority = 2)]
    PrimaryKeyBinding = 0x19,

    // ─────────────────────────────────────────────────────────────────────────
    // Direct Key Signature (0x1F)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Direct Key Signature (0x1F).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Signature directly on a key (not on a User ID).
    /// Used for key preferences, features, and revocation keys.
    /// </para>
    /// </remarks>
    [NotImplemented("Direct key signature - key-level attributes", Priority = 2)]
    DirectKey = 0x1F,

    // ─────────────────────────────────────────────────────────────────────────
    // Key Revocation (0x20)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Key Revocation Signature (0x20).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Revokes a key. Made by the key being revoked or a designated revoker.
    /// Implementations MUST check for this signature type.
    /// </para>
    /// </remarks>
    [NotImplemented("Key revocation - invalidates entire key", Priority = 1)]
    KeyRevocation = 0x20,

    // ─────────────────────────────────────────────────────────────────────────
    // Subkey Revocation (0x28)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Subkey Revocation Signature (0x28).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Revokes a subkey. Made by the primary key.
    /// </para>
    /// </remarks>
    [NotImplemented("Subkey revocation - invalidates specific subkey", Priority = 2)]
    SubkeyRevocation = 0x28,

    // ─────────────────────────────────────────────────────────────────────────
    // Certification Revocation (0x30)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Certification Revocation Signature (0x30).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Revokes a prior certification. Can only revoke certifications
    /// made by the same key.
    /// </para>
    /// </remarks>
    [NotImplemented("Certification revocation - revokes prior certification", Priority = 2)]
    CertificationRevocation = 0x30,

    // ─────────────────────────────────────────────────────────────────────────
    // Timestamp Signature (0x40)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Timestamp Signature (0x40).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Signature over only the signature creation time subpacket.
    /// Used by timestamping services.
    /// </para>
    /// </remarks>
    [NotImplemented("Timestamp signature - timestamping services", Priority = 3)]
    Timestamp = 0x40,

    // ─────────────────────────────────────────────────────────────────────────
    // Third-Party Confirmation (0x50)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Third-Party Confirmation Signature (0x50).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2.1</para>
    /// <para>
    /// Signature over another signature, confirming it.
    /// Used to add additional certifications to existing signatures.
    /// </para>
    /// </remarks>
    [NotImplemented("Third-party confirmation - confirms another signature", Priority = 3)]
    ThirdPartyConfirmation = 0x50,
}
