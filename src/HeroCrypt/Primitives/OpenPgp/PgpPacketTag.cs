using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP packet tags as defined in RFC 4880 Section 4.3 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// The packet tag identifies the type of packet. In OpenPGP, packets are the fundamental
/// units of data. Each packet has a header indicating its type and length.
/// </para>
/// <para>
/// <b>Packet Format:</b>
/// <list type="bullet">
///   <item>Old format (bit 7=1, bit 6=0): Tags 0-15 only, fixed length types</item>
///   <item>New format (bit 7=1, bit 6=1): Tags 0-63, variable length encoding</item>
/// </list>
/// </para>
/// </remarks>
public enum PgpPacketTag : byte
{
    // ─────────────────────────────────────────────────────────────────────────
    // Reserved (Tag 0)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reserved - must not be used (Tag 0).
    /// </summary>
    Reserved = 0,

    // ─────────────────────────────────────────────────────────────────────────
    // Encrypted Session Key Packets
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Public-Key Encrypted Session Key (PKESK) Packet (Tag 1).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.1</para>
    /// <para>Contains a session key encrypted to a public key.</para>
    /// <para>Precedes Symmetrically Encrypted Data packets.</para>
    /// </remarks>
    [NotImplemented("PKESK packet - session key encrypted to public key", Priority = 2)]
    PublicKeyEncryptedSessionKey = 1,

    /// <summary>
    /// Symmetric-Key Encrypted Session Key (SKESK) Packet (Tag 3).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.3</para>
    /// <para>Contains a session key encrypted with a passphrase-derived key (S2K).</para>
    /// <para>Used for password-based encryption.</para>
    /// </remarks>
    [NotImplemented("SKESK packet - session key encrypted with S2K", Priority = 2)]
    SymmetricKeyEncryptedSessionKey = 3,

    // ─────────────────────────────────────────────────────────────────────────
    // Signature Packet
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Signature Packet (Tag 2).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.2</para>
    /// <para>
    /// Contains a digital signature. Used for:
    /// <list type="bullet">
    ///   <item>Document signatures</item>
    ///   <item>Key certifications</item>
    ///   <item>Key revocations</item>
    ///   <item>Timestamp signatures</item>
    /// </list>
    /// </para>
    /// </remarks>
    [NotImplemented("Signature packet - digital signatures and certifications", Priority = 1)]
    Signature = 2,

    // ─────────────────────────────────────────────────────────────────────────
    // One-Pass Signature Packet
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// One-Pass Signature Packet (Tag 4).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.4</para>
    /// <para>
    /// Placed before signed data to enable one-pass signature verification.
    /// Contains signing key ID and hash algorithm to allow streaming verification.
    /// </para>
    /// </remarks>
    [NotImplemented("One-pass signature - enables streaming verification", Priority = 2)]
    OnePassSignature = 4,

    // ─────────────────────────────────────────────────────────────────────────
    // Key Packets
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Secret Key Packet (Tag 5).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.5.3</para>
    /// <para>Contains the primary secret (private) key.</para>
    /// <para>Secret key material may be encrypted with S2K.</para>
    /// </remarks>
    [NotImplemented("Secret key packet - primary private key", Priority = 1)]
    SecretKey = 5,

    /// <summary>
    /// Public Key Packet (Tag 6).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.5.2</para>
    /// <para>Contains the primary public key.</para>
    /// <para>First packet in a public key block.</para>
    /// </remarks>
    [NotImplemented("Public key packet - primary public key", Priority = 1)]
    PublicKey = 6,

    /// <summary>
    /// Secret Subkey Packet (Tag 7).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.5.3</para>
    /// <para>Contains a secret subkey bound to the primary key.</para>
    /// <para>Typically used for encryption subkeys.</para>
    /// </remarks>
    [NotImplemented("Secret subkey packet - bound to primary key", Priority = 2)]
    SecretSubkey = 7,

    /// <summary>
    /// Compressed Data Packet (Tag 8).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.6</para>
    /// <para>Contains compressed data (ZIP, ZLIB, or BZIP2).</para>
    /// <para>Usually contains literal data or signed data.</para>
    /// </remarks>
    [NotImplemented("Compressed data packet - contains compressed payload", Priority = 2)]
    CompressedData = 8,

    /// <summary>
    /// Symmetrically Encrypted Data Packet (Tag 9).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.7</para>
    /// <para><b>Status:</b> DEPRECATED - Use SEIPD (Tag 18) instead.</para>
    /// <para>Legacy packet without integrity protection (vulnerable to attacks).</para>
    /// </remarks>
    [NotImplemented("DEPRECATED - use SEIPD (Tag 18) instead", Priority = 5)]
    SymmetricallyEncryptedData = 9,

    /// <summary>
    /// Marker Packet (Tag 10).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.8</para>
    /// <para>Obsolete literal packet. Contains "PGP" string for legacy compatibility.</para>
    /// <para>Implementations SHOULD ignore this packet.</para>
    /// </remarks>
    [NotImplemented("Obsolete marker packet - should be ignored", Priority = 5)]
    Marker = 10,

    /// <summary>
    /// Literal Data Packet (Tag 11).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.9</para>
    /// <para>
    /// Contains the actual message data with metadata:
    /// <list type="bullet">
    ///   <item>Data format (binary 'b', text 't', UTF-8 'u')</item>
    ///   <item>Filename (optional)</item>
    ///   <item>Modification time</item>
    /// </list>
    /// </para>
    /// </remarks>
    [NotImplemented("Literal data packet - actual message payload", Priority = 1)]
    LiteralData = 11,

    /// <summary>
    /// Trust Packet (Tag 12).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.10</para>
    /// <para>Contains trust information. Implementation-specific.</para>
    /// <para>Used in keyrings to store computed trust values.</para>
    /// </remarks>
    [NotImplemented("Trust packet - keyring trust data", Priority = 4)]
    Trust = 12,

    /// <summary>
    /// User ID Packet (Tag 13).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.11</para>
    /// <para>Contains a UTF-8 text string identifying the key owner.</para>
    /// <para>Typically in the format: "Name (Comment) &lt;email@example.com&gt;"</para>
    /// </remarks>
    [NotImplemented("User ID packet - key owner identification", Priority = 1)]
    UserId = 13,

    /// <summary>
    /// Public Subkey Packet (Tag 14).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.5.2</para>
    /// <para>Contains a public subkey bound to the primary key.</para>
    /// <para>Typically used for encryption subkeys.</para>
    /// </remarks>
    [NotImplemented("Public subkey packet - bound to primary key", Priority = 2)]
    PublicSubkey = 14,

    // ─────────────────────────────────────────────────────────────────────────
    // User Attribute Packet
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// User Attribute Packet (Tag 17).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.12</para>
    /// <para>Contains user attributes (e.g., photo ID images).</para>
    /// <para>Similar to User ID but with structured binary data.</para>
    /// </remarks>
    [NotImplemented("User attribute packet - photo ID and other attributes", Priority = 3)]
    UserAttribute = 17,

    // ─────────────────────────────────────────────────────────────────────────
    // Integrity Protected Data
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Symmetrically Encrypted Integrity Protected Data (SEIPD) Packet (Tag 18).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.13, RFC 9580</para>
    /// <para>
    /// Encrypted data with integrity protection.
    /// <list type="bullet">
    ///   <item>Version 1: CFB mode with MDC (SHA-1 hash)</item>
    ///   <item>Version 2: AEAD mode (RFC 9580) - recommended</item>
    /// </list>
    /// </para>
    /// </remarks>
    [NotImplemented("SEIPD packet - integrity-protected encrypted data", Priority = 1)]
    SymmetricallyEncryptedIntegrityProtectedData = 18,

    /// <summary>
    /// Modification Detection Code (MDC) Packet (Tag 19).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 4880 Section 5.14</para>
    /// <para>Contains SHA-1 hash of preceding plaintext for integrity check.</para>
    /// <para>Only used inside SEIPD v1 packets.</para>
    /// </remarks>
    [NotImplemented("MDC packet - SHA-1 integrity check for SEIPD v1", Priority = 2)]
    ModificationDetectionCode = 19,

    // ─────────────────────────────────────────────────────────────────────────
    // RFC 9580 Additions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// AEAD Encrypted Data Packet (Tag 20) - RFC 9580.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Alternative to SEIPD v2 for AEAD-encrypted data.</para>
    /// <para>Used for AEAD-encrypted secret key material.</para>
    /// </remarks>
    [NotImplemented("AEAD encrypted data - RFC 9580", Priority = 2)]
    AeadEncryptedData = 20,

    /// <summary>
    /// Padding Packet (Tag 21) - RFC 9580.
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Contains random padding data to obscure message size.</para>
    /// <para>Implementations SHOULD ignore the contents.</para>
    /// </remarks>
    [NotImplemented("Padding packet - traffic analysis protection", Priority = 4)]
    Padding = 21,

    // ─────────────────────────────────────────────────────────────────────────
    // Private/Experimental (Tags 60-63)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Private/Experimental Use (Tag 60).
    /// </summary>
    [NotImplemented("Private/experimental use", Priority = 5)]
    Private60 = 60,

    /// <summary>
    /// Private/Experimental Use (Tag 61).
    /// </summary>
    [NotImplemented("Private/experimental use", Priority = 5)]
    Private61 = 61,

    /// <summary>
    /// Private/Experimental Use (Tag 62).
    /// </summary>
    [NotImplemented("Private/experimental use", Priority = 5)]
    Private62 = 62,

    /// <summary>
    /// Private/Experimental Use (Tag 63).
    /// </summary>
    [NotImplemented("Private/experimental use", Priority = 5)]
    Private63 = 63,
}
