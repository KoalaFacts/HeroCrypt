namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// OpenPGP packet format types as defined in RFC 4880 Section 4.2.
/// </summary>
/// <remarks>
/// <para>
/// OpenPGP supports two packet header formats:
/// <list type="bullet">
///   <item><b>Old format (legacy):</b> Bit 6 = 0, supports tags 0-15, limited length encoding</item>
///   <item><b>New format:</b> Bit 6 = 1, supports tags 0-63, flexible length encoding</item>
/// </list>
/// </para>
/// <para>
/// RFC 9580 recommends using new format packets exclusively for new implementations.
/// Old format should only be used for backward compatibility with legacy systems.
/// </para>
/// </remarks>
public enum PgpPacketFormat : byte
{
    /// <summary>
    /// Old format packet header (RFC 4880 Section 4.2.1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Header byte format: 10TTLLLL
    /// <list type="bullet">
    ///   <item>Bit 7: Always 1 (packet tag bit)</item>
    ///   <item>Bit 6: 0 (old format)</item>
    ///   <item>Bits 5-2: Packet tag (0-15)</item>
    ///   <item>Bits 1-0: Length type (0=1 byte, 1=2 bytes, 2=4 bytes, 3=indeterminate)</item>
    /// </list>
    /// </para>
    /// </remarks>
    Old = 0,

    /// <summary>
    /// New format packet header (RFC 4880 Section 4.2.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Header byte format: 11TTTTTT
    /// <list type="bullet">
    ///   <item>Bit 7: Always 1 (packet tag bit)</item>
    ///   <item>Bit 6: 1 (new format)</item>
    ///   <item>Bits 5-0: Packet tag (0-63)</item>
    /// </list>
    /// </para>
    /// <para>
    /// Length encoding follows the header byte with variable-length encoding.
    /// </para>
    /// </remarks>
    New = 1,
}
