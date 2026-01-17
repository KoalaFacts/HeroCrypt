namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Literal data format types as defined in RFC 4880 Section 5.9.
/// </summary>
/// <remarks>
/// <para>
/// The format byte indicates how the literal data should be interpreted.
/// This affects text processing and line ending conversion.
/// </para>
/// </remarks>
public enum PgpLiteralDataFormat : byte
{
    /// <summary>
    /// Binary data format ('b' = 0x62).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Data is stored as-is without any conversion.
    /// Use for non-text files (images, executables, archives, etc.).
    /// </para>
    /// </remarks>
    Binary = (byte)'b',

    /// <summary>
    /// Text data format ('t' = 0x74).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Data represents text. Implementations may convert line endings.
    /// Canonical text uses &lt;CR&gt;&lt;LF&gt; line endings.
    /// </para>
    /// </remarks>
    Text = (byte)'t',

    /// <summary>
    /// UTF-8 text data format ('u' = 0x75).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Data is UTF-8 encoded text. Similar to Text format but
    /// explicitly indicates UTF-8 encoding.
    /// </para>
    /// </remarks>
    Utf8 = (byte)'u',
}
