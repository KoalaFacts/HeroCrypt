namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Image encoding types for User Attribute Image subpackets as defined in RFC 4880 Section 5.12.1.
/// </summary>
public enum PgpImageEncoding : byte
{
    /// <summary>
    /// JPEG image format (encoding 1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the only encoding defined by RFC 4880.
    /// Images should be small (typically under 5KB) for compatibility.
    /// </para>
    /// </remarks>
    Jpeg = 1,

    /// <summary>
    /// Reserved for private/experimental use (encodings 100-110).
    /// </summary>
    PrivateExperimental100 = 100,

    /// <summary>
    /// Reserved for private/experimental use.
    /// </summary>
    PrivateExperimental101 = 101,

    /// <summary>
    /// Reserved for private/experimental use.
    /// </summary>
    PrivateExperimental110 = 110,
}
