namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Compression algorithms as defined in RFC 4880 Section 9.3.
/// </summary>
/// <remarks>
/// <para>
/// OpenPGP supports several compression algorithms for reducing message size.
/// The choice of algorithm affects compatibility and compression ratio.
/// </para>
/// </remarks>
public enum PgpCompressionAlgorithm : byte
{
    /// <summary>
    /// Uncompressed data (ID 0).
    /// </summary>
    /// <remarks>
    /// Data is stored without compression. Use when compression
    /// is not beneficial (e.g., already-compressed data).
    /// </remarks>
    Uncompressed = 0,

    /// <summary>
    /// ZIP compression without header (ID 1) - RFC 1951 DEFLATE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Raw DEFLATE compressed data without the zlib wrapper.
    /// This is the most widely supported compression algorithm.
    /// </para>
    /// </remarks>
    Zip = 1,

    /// <summary>
    /// ZLIB compression (ID 2) - RFC 1950.
    /// </summary>
    /// <remarks>
    /// <para>
    /// DEFLATE compressed data with zlib header and checksum.
    /// Provides slightly better error detection than raw DEFLATE.
    /// </para>
    /// </remarks>
    Zlib = 2,

    /// <summary>
    /// BZip2 compression (ID 3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// BZip2 provides better compression ratios for text data
    /// but is slower and less widely supported than DEFLATE.
    /// </para>
    /// </remarks>
    BZip2 = 3,
}
