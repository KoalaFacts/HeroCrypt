namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// User Attribute subpacket types as defined in RFC 4880 Section 5.12.
/// </summary>
public enum PgpUserAttributeSubpacketType : byte
{
    /// <summary>
    /// Image Attribute subpacket (type 1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Contains an image of the key holder, typically a JPEG photo.
    /// </para>
    /// </remarks>
    Image = 1,

    /// <summary>
    /// Reserved for private/experimental use (types 100-110).
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
