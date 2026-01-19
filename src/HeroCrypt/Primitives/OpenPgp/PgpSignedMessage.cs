namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a signed OpenPGP message containing the original data and signature.
/// </summary>
/// <remarks>
/// <para>
/// A signed message consists of:
/// <list type="bullet">
///   <item>One-Pass Signature packet (optional, for streaming verification)</item>
///   <item>Literal Data packet (the signed data)</item>
///   <item>Signature packet (the actual signature)</item>
/// </list>
/// </para>
/// </remarks>
public readonly struct PgpSignedMessage
{
    /// <summary>
    /// Gets the signed data.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// Gets the signature packet.
    /// </summary>
    public PgpSignaturePacket Signature { get; }

    /// <summary>
    /// Gets the One-Pass Signature packet (if present).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The One-Pass Signature packet is used for streaming verification,
    /// allowing the verifier to begin hashing before reading the signature.
    /// </para>
    /// </remarks>
    public PgpOnePassSignaturePacket? OnePassSignature { get; }

    /// <summary>
    /// Gets the literal data format.
    /// </summary>
    public PgpLiteralDataFormat DataFormat { get; }

    /// <summary>
    /// Gets the filename from the literal data packet.
    /// </summary>
    public string FileName { get; }

    /// <summary>
    /// Gets the file modification time from the literal data packet.
    /// </summary>
    public DateTimeOffset FileDate { get; }

    /// <summary>
    /// Initializes a new signed message.
    /// </summary>
    /// <param name="data">The signed data.</param>
    /// <param name="signature">The signature packet.</param>
    /// <param name="onePassSignature">The optional One-Pass Signature packet.</param>
    /// <param name="dataFormat">The literal data format.</param>
    /// <param name="fileName">The filename.</param>
    /// <param name="fileDate">The file modification time.</param>
    public PgpSignedMessage(
        ReadOnlyMemory<byte> data,
        PgpSignaturePacket signature,
        PgpOnePassSignaturePacket? onePassSignature = null,
        PgpLiteralDataFormat dataFormat = PgpLiteralDataFormat.Binary,
        string fileName = "",
        DateTimeOffset fileDate = default)
    {
        Data = data;
        Signature = signature;
        OnePassSignature = onePassSignature;
        DataFormat = dataFormat;
        FileName = fileName ?? string.Empty;
        FileDate = fileDate == default ? DateTimeOffset.UtcNow : fileDate;
    }

    /// <summary>
    /// Gets the full serialized message as a byte array.
    /// </summary>
    /// <returns>The serialized message bytes.</returns>
    /// <remarks>
    /// <para>
    /// The message format is:
    /// <code>
    /// [OnePassSignature] [LiteralData] [Signature]
    /// </code>
    /// </para>
    /// </remarks>
    public byte[] ToArray()
    {
        using var ms = new MemoryStream();
        WriteTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Writes the message to a stream.
    /// </summary>
    /// <param name="stream">The destination stream.</param>
    public void WriteTo(Stream stream)
    {
        using var writer = new PgpPacketWriter(stream);

        // Write One-Pass Signature packet if present
        if (OnePassSignature.HasValue)
        {
            OnePassSignature.Value.WriteTo(writer);
        }

        // Write Literal Data packet
        var literalPacket = new PgpLiteralDataPacket(DataFormat, FileName, FileDate, Data.ToArray());
        literalPacket.WriteTo(writer);

        // Write Signature packet
        Signature.WriteTo(writer);
    }

    /// <summary>
    /// Creates a detached signature (signature only, without the signed data).
    /// </summary>
    /// <returns>The signature packet bytes.</returns>
    public byte[] GetDetachedSignature()
    {
        using var ms = new MemoryStream();
        using var writer = new PgpPacketWriter(ms);
        Signature.WriteTo(writer);
        return ms.ToArray();
    }

    /// <summary>
    /// Gets the signed data as a UTF-8 string.
    /// </summary>
    /// <returns>The data as a string.</returns>
    /// <exception cref="InvalidOperationException">If the data is not valid UTF-8.</exception>
    public string GetDataAsString()
    {
        return System.Text.Encoding.UTF8.GetString(Data.Span);
    }

    /// <summary>
    /// Tries to get the signed data as a UTF-8 string.
    /// </summary>
    /// <param name="result">The data as a string if successful.</param>
    /// <returns>True if the data could be decoded as UTF-8.</returns>
    public bool TryGetDataAsString(out string result)
    {
        try
        {
            result = System.Text.Encoding.UTF8.GetString(Data.Span);
            return true;
        }
        catch
        {
            result = string.Empty;
            return false;
        }
    }

    /// <summary>
    /// Reads a signed message from serialized data.
    /// </summary>
    /// <param name="data">The serialized message data.</param>
    /// <returns>The parsed signed message.</returns>
    /// <exception cref="ArgumentException">If the data is malformed.</exception>
    public static PgpSignedMessage Read(ReadOnlySpan<byte> data)
    {
        if (!TryRead(data, out var message, out var error))
        {
            throw new ArgumentException(error, nameof(data));
        }

        return message;
    }

    /// <summary>
    /// Tries to read a signed message from serialized data.
    /// </summary>
    /// <param name="data">The serialized message data.</param>
    /// <param name="message">The parsed message if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the message was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> data, out PgpSignedMessage message, out string error)
    {
        message = default;
        error = string.Empty;

        using var ms = new MemoryStream(data.ToArray());
        var reader = new PgpPacketReader(ms);

        PgpOnePassSignaturePacket? onePassSig = null;
        PgpLiteralDataPacket? literalData = null;
        PgpSignaturePacket? signature = null;

        while (reader.ReadNextPacket(out var tag, out var body))
        {
#pragma warning disable IDE0010 // Populate switch - we intentionally only handle specific packet types
            switch (tag)
#pragma warning restore IDE0010
            {
                case PgpPacketTag.OnePassSignature:
                    if (!PgpOnePassSignaturePacket.TryRead(body.Span, out var ops, out var opsError))
                    {
                        error = $"Failed to parse One-Pass Signature: {opsError}";
                        return false;
                    }
                    onePassSig = ops;
                    break;

                case PgpPacketTag.LiteralData:
                    if (!PgpLiteralDataPacket.TryRead(body.Span, out var lit, out var litError))
                    {
                        error = $"Failed to parse Literal Data: {litError}";
                        return false;
                    }
                    literalData = lit;
                    break;

                case PgpPacketTag.Signature:
                    if (!PgpSignaturePacket.TryRead(body.Span, out var sig, out var sigError))
                    {
                        error = $"Failed to parse Signature: {sigError}";
                        return false;
                    }
                    signature = sig;
                    break;

                default:
                    // Ignore unknown packets
                    break;
            }
        }

        if (!literalData.HasValue)
        {
            error = "Signed message missing Literal Data packet.";
            return false;
        }

        if (!signature.HasValue)
        {
            error = "Signed message missing Signature packet.";
            return false;
        }

        message = new PgpSignedMessage(
            literalData.Value.Data,
            signature.Value,
            onePassSig,
            literalData.Value.Format,
            literalData.Value.FileName,
            literalData.Value.Date);

        return true;
    }

    /// <summary>
    /// Returns a string representation of this signed message.
    /// </summary>
    public override string ToString()
    {
        var sigTime = Signature.GetCreationTime();
        var timeStr = sigTime.HasValue ? sigTime.Value.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) : "unknown";
        return $"SignedMessage({Data.Length} bytes, signed {timeStr})";
    }
}
