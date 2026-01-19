using System.Text;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a decrypted OpenPGP message with metadata from the literal data packet.
/// </summary>
/// <remarks>
/// <para>
/// A decrypted message contains the original plaintext along with metadata that was
/// embedded in the literal data packet, including filename, modification date, and
/// data format (binary, text, or UTF-8).
/// </para>
/// <para>
/// Use PgpMessageDecryptor to decrypt messages and obtain this result.
/// </para>
/// </remarks>
public readonly struct PgpDecryptedMessage : IEquatable<PgpDecryptedMessage>
{
    private readonly byte[] data;

    /// <summary>
    /// Gets the decrypted plaintext data.
    /// </summary>
    public ReadOnlyMemory<byte> Data => data ?? [];

    /// <summary>
    /// Gets the filename from the literal data packet (may be empty).
    /// </summary>
    public string FileName { get; }

    /// <summary>
    /// Gets the date/time from the literal data packet.
    /// </summary>
    public DateTimeOffset Date { get; }

    /// <summary>
    /// Gets the data format (Binary, Text, or Utf8).
    /// </summary>
    public PgpLiteralDataFormat Format { get; }

    /// <summary>
    /// Gets the key ID that was used for decryption.
    /// </summary>
    public ReadOnlyMemory<byte> DecryptionKeyId { get; }

    /// <summary>
    /// Gets whether the message was compressed.
    /// </summary>
    public bool WasCompressed { get; }

    /// <summary>
    /// Gets the compression algorithm that was used (if any).
    /// </summary>
    public PgpCompressionAlgorithm CompressionAlgorithm { get; }

    /// <summary>
    /// Gets the SEIPD version that was used (1 or 2).
    /// </summary>
    public int SeipdVersion { get; }

    /// <summary>
    /// Initializes a new decrypted message.
    /// </summary>
    /// <param name="data">The decrypted plaintext data.</param>
    /// <param name="fileName">The filename from the literal data packet.</param>
    /// <param name="date">The date from the literal data packet.</param>
    /// <param name="format">The data format.</param>
    /// <param name="decryptionKeyId">The key ID used for decryption.</param>
    /// <param name="wasCompressed">Whether the message was compressed.</param>
    /// <param name="compressionAlgorithm">The compression algorithm used.</param>
    /// <param name="seipdVersion">The SEIPD version used.</param>
    public PgpDecryptedMessage(
        byte[] data,
        string fileName,
        DateTimeOffset date,
        PgpLiteralDataFormat format,
        byte[] decryptionKeyId,
        bool wasCompressed = false,
        PgpCompressionAlgorithm compressionAlgorithm = PgpCompressionAlgorithm.Uncompressed,
        int seipdVersion = 1)
    {
        this.data = data ?? throw new ArgumentNullException(nameof(data));
        FileName = fileName ?? string.Empty;
        Date = date;
        Format = format;
        DecryptionKeyId = decryptionKeyId ?? [];
        WasCompressed = wasCompressed;
        CompressionAlgorithm = compressionAlgorithm;
        SeipdVersion = seipdVersion;
    }

    /// <summary>
    /// Gets the data as a UTF-8 string.
    /// </summary>
    /// <returns>The plaintext as a string.</returns>
    /// <exception cref="DecoderFallbackException">If the data is not valid UTF-8.</exception>
    public string GetDataAsString()
    {
        return Encoding.UTF8.GetString(Data.Span);
    }

    /// <summary>
    /// Tries to get the data as a UTF-8 string.
    /// </summary>
    /// <param name="result">The string if successful.</param>
    /// <returns>True if the data was valid UTF-8.</returns>
    public bool TryGetDataAsString(out string result)
    {
        try
        {
            result = Encoding.UTF8.GetString(Data.Span);
            return true;
        }
        catch
        {
            result = string.Empty;
            return false;
        }
    }

    /// <summary>
    /// Returns the decrypted data as a byte array.
    /// </summary>
    /// <returns>A copy of the plaintext data.</returns>
    public byte[] ToArray() => Data.ToArray();

    /// <summary>
    /// Writes the decrypted data to a stream.
    /// </summary>
    /// <param name="stream">The destination stream.</param>
    public void WriteTo(Stream stream)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(stream);
        stream.Write(Data.Span);
#else
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        var bytes = Data.ToArray();
        stream.Write(bytes, 0, bytes.Length);
#endif
    }

    /// <summary>
    /// Asynchronously writes the decrypted data to a stream.
    /// </summary>
    /// <param name="stream">The destination stream.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask WriteToAsync(Stream stream, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(stream);
        await stream.WriteAsync(Data, cancellationToken).ConfigureAwait(false);
#else
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        var bytes = Data.ToArray();
        await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken).ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Creates a decrypted message from a literal data packet.
    /// </summary>
    /// <param name="literalPacket">The literal data packet.</param>
    /// <param name="decryptionKeyId">The key ID used for decryption.</param>
    /// <param name="wasCompressed">Whether the message was compressed.</param>
    /// <param name="compressionAlgorithm">The compression algorithm.</param>
    /// <param name="seipdVersion">The SEIPD version.</param>
    /// <returns>A new decrypted message.</returns>
    internal static PgpDecryptedMessage FromLiteralPacket(
        PgpLiteralDataPacket literalPacket,
        byte[] decryptionKeyId,
        bool wasCompressed = false,
        PgpCompressionAlgorithm compressionAlgorithm = PgpCompressionAlgorithm.Uncompressed,
        int seipdVersion = 1)
    {
        return new PgpDecryptedMessage(
            literalPacket.Data.ToArray(),
            literalPacket.FileName,
            literalPacket.Date,
            literalPacket.Format,
            decryptionKeyId,
            wasCompressed,
            compressionAlgorithm,
            seipdVersion);
    }

    /// <inheritdoc />
    public bool Equals(PgpDecryptedMessage other)
    {
        return Data.Span.SequenceEqual(other.Data.Span)
            && FileName == other.FileName
            && Date == other.Date
            && Format == other.Format;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpDecryptedMessage other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
#if !NETSTANDARD2_0
        return HashCode.Combine(FileName, Date, Format, Data.Length);
#else
        unchecked
        {
            int hash = 17;
            hash = (hash * 31) + (FileName?.GetHashCode() ?? 0);
            hash = (hash * 31) + Date.GetHashCode();
            hash = (hash * 31) + (int)Format;
            hash = (hash * 31) + Data.Length;
            return hash;
        }
#endif
    }

    /// <summary>
    /// Returns a string representation of this decrypted message.
    /// </summary>
    public override string ToString()
    {
        var fileInfo = string.IsNullOrEmpty(FileName) ? "" : $", \"{FileName}\"";
        var compressionInfo = WasCompressed ? $", {CompressionAlgorithm}" : "";
        return $"PgpDecryptedMessage({Data.Length} bytes, {Format}{fileInfo}{compressionInfo})";
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpDecryptedMessage left, PgpDecryptedMessage right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpDecryptedMessage left, PgpDecryptedMessage right) => !left.Equals(right);
}
