namespace HeroCrypt.Operations;

/// <summary>
/// Compression algorithms.
/// </summary>
/// <remarks>
/// <para>
/// OpenPGP (RFC 4880) uses compression to reduce message size and
/// remove patterns that could aid cryptanalysis.
/// </para>
/// <para>
/// Note: HeroCrypt does not include compression libraries directly.
/// Use System.IO.Compression for ZIP/ZLIB support.
/// </para>
/// </remarks>
public enum CompressionAlgorithm : byte
{
    /// <summary>
    /// Uncompressed - no compression applied.
    /// </summary>
    /// <remarks>
    /// <para>Used when compression is disabled or data is already compressed.</para>
    /// </remarks>
    [PgpAlgorithmId(0, Rfc = "RFC 4880")]
    Uncompressed = 0,

    /// <summary>
    /// ZIP - DEFLATE without zlib header (RFC 1951).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 1951 (raw DEFLATE)</para>
    /// <para><b>Implementation:</b> Use System.IO.Compression.DeflateStream</para>
    /// <para>Most widely supported compression in OpenPGP.</para>
    /// </remarks>
    [PgpAlgorithmId(1, Rfc = "RFC 4880")]
    [NotImplemented("Use System.IO.Compression.DeflateStream", Priority = 2)]
    Zip = 1,

    /// <summary>
    /// ZLIB - DEFLATE with zlib header (RFC 1950).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 1950</para>
    /// <para><b>Implementation:</b> Use System.IO.Compression.ZLibStream (.NET 6+)</para>
    /// <para>Recommended over ZIP for better error detection (includes Adler-32 checksum).</para>
    /// </remarks>
    [PgpAlgorithmId(2, Rfc = "RFC 4880")]
    [NotImplemented("Use System.IO.Compression.ZLibStream (.NET 6+)", Priority = 2)]
    Zlib = 2,

    /// <summary>
    /// BZIP2 - Burrows-Wheeler compression.
    /// </summary>
    /// <remarks>
    /// <para><b>Implementation:</b> Requires third-party library (SharpZipLib or similar)</para>
    /// <para>Better compression ratio than DEFLATE but slower.</para>
    /// </remarks>
    [PgpAlgorithmId(3, Rfc = "RFC 4880")]
    [NotImplemented("Requires third-party library", Priority = 4)]
    Bzip2 = 3,
}
