using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents an encrypted OpenPGP message containing PKESK and SEIPD packets.
/// </summary>
/// <remarks>
/// <para>
/// An encrypted message consists of one or more Public-Key Encrypted Session Key (PKESK) packets
/// followed by a Symmetrically Encrypted Integrity Protected Data (SEIPD) packet.
/// </para>
/// <para>
/// Use PgpMessageEncryptor to create encrypted messages, and
/// PgpMessageDecryptor to decrypt them.
/// </para>
/// </remarks>
public readonly struct PgpEncryptedMessage : IEquatable<PgpEncryptedMessage>
{
    private readonly byte[] data;
    private readonly PgpRecipientInfo[] recipients;

    /// <summary>
    /// Gets the complete encrypted message as bytes (ready for transmission/storage).
    /// </summary>
    public ReadOnlyMemory<byte> Data => data ?? [];

    /// <summary>
    /// Gets the recipients of this encrypted message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each recipient corresponds to a PKESK packet in the message. The recipient info
    /// contains the key ID (v3) or fingerprint (v6) that can be used to identify which
    /// secret key is needed for decryption.
    /// </para>
    /// </remarks>
    public ReadOnlySpan<PgpRecipientInfo> Recipients => recipients ?? [];

    /// <summary>
    /// Gets the number of recipients (PKESK packets).
    /// </summary>
    public int RecipientCount => recipients?.Length ?? 0;

    /// <summary>
    /// Gets the SEIPD version used (1 = CFB+MDC, 2 = AEAD).
    /// </summary>
    public int SeipdVersion { get; }

    /// <summary>
    /// Gets the symmetric cipher used for the session key.
    /// </summary>
    public SymmetricCipherAlgorithm SymmetricAlgorithm { get; }

    /// <summary>
    /// Gets the AEAD algorithm if SEIPD v2 was used.
    /// </summary>
    public AeadAlgorithm AeadAlgorithm { get; }

    /// <summary>
    /// Gets whether compression was applied.
    /// </summary>
    public bool IsCompressed { get; }

    /// <summary>
    /// Initializes a new encrypted message.
    /// </summary>
    /// <param name="data">The complete encrypted message data.</param>
    /// <param name="recipients">The recipients of the message.</param>
    /// <param name="seipdVersion">SEIPD version (1 or 2).</param>
    /// <param name="symmetricAlgorithm">Symmetric cipher used.</param>
    /// <param name="aeadAlgorithm">AEAD algorithm (for v2).</param>
    /// <param name="isCompressed">Whether compression was applied.</param>
    public PgpEncryptedMessage(
        byte[] data,
        PgpRecipientInfo[] recipients,
        int seipdVersion,
        SymmetricCipherAlgorithm symmetricAlgorithm,
        AeadAlgorithm aeadAlgorithm = AeadAlgorithm.None,
        bool isCompressed = false)
    {
        this.data = data ?? throw new ArgumentNullException(nameof(data));
        this.recipients = recipients ?? [];
        SeipdVersion = seipdVersion;
        SymmetricAlgorithm = symmetricAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        IsCompressed = isCompressed;
    }

    /// <summary>
    /// Initializes a new encrypted message (legacy overload for backwards compatibility).
    /// </summary>
    /// <param name="data">The complete encrypted message data.</param>
    /// <param name="recipientCount">Number of recipients (recipients will be empty).</param>
    /// <param name="seipdVersion">SEIPD version (1 or 2).</param>
    /// <param name="symmetricAlgorithm">Symmetric cipher used.</param>
    /// <param name="aeadAlgorithm">AEAD algorithm (for v2).</param>
    /// <param name="isCompressed">Whether compression was applied.</param>
    [Obsolete("Use the constructor that takes PgpRecipientInfo[] instead.")]
    public PgpEncryptedMessage(
        byte[] data,
        int recipientCount,
        int seipdVersion,
        SymmetricCipherAlgorithm symmetricAlgorithm,
        AeadAlgorithm aeadAlgorithm = AeadAlgorithm.None,
        bool isCompressed = false)
    {
        this.data = data ?? throw new ArgumentNullException(nameof(data));
        recipients = new PgpRecipientInfo[recipientCount];
        SeipdVersion = seipdVersion;
        SymmetricAlgorithm = symmetricAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        IsCompressed = isCompressed;
    }

    /// <summary>
    /// Writes the encrypted message to a stream.
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
    /// Asynchronously writes the encrypted message to a stream.
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
    /// Returns the message as a byte array.
    /// </summary>
    /// <returns>A copy of the encrypted message data.</returns>
    public byte[] ToArray() => Data.ToArray();

    /// <summary>
    /// Reads an encrypted message from bytes.
    /// </summary>
    /// <param name="source">The source data.</param>
    /// <returns>The parsed encrypted message.</returns>
    /// <exception cref="ArgumentException">If the data is malformed.</exception>
    public static PgpEncryptedMessage Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var message, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return message;
    }

    /// <summary>
    /// Tries to read an encrypted message from bytes.
    /// </summary>
    /// <param name="source">The source data.</param>
    /// <param name="message">The parsed message if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the message was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpEncryptedMessage message, out string? error)
    {
        message = default;
        error = null;

        using var stream = new MemoryStream(source.ToArray());
        using var reader = new PgpPacketReader(stream);

        var recipientList = new List<PgpRecipientInfo>();
        int seipdVersion = 0;
        var symmetricAlgorithm = SymmetricCipherAlgorithm.Aes256;
        var aeadAlgorithm = AeadAlgorithm.None;

        while (reader.ReadNextPacket(out var tag, out var body))
        {
            // We only need PKESK and SEIPD packets - ignore all other packet types
            if (tag == PgpPacketTag.PublicKeyEncryptedSessionKey)
            {
                if (PgpPublicKeyEncryptedSessionKeyPacket.TryRead(body.Span, out var pkesk, out _))
                {
                    recipientList.Add(PgpRecipientInfo.FromPacket(pkesk));
                }
                else
                {
                    // If we can't parse the PKESK, still count it but without details
                    recipientList.Add(default);
                }
            }
            else if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData)
            {
                if (PgpSymEncryptedIntegrityProtectedDataPacket.TryRead(body.Span, out var seipd, out _))
                {
                    seipdVersion = seipd.Version;
                    symmetricAlgorithm = seipd.CipherAlgorithm;
                    aeadAlgorithm = seipd.AeadAlgorithm;
                }
            }
        }

        if (recipientList.Count == 0)
        {
            error = "No PKESK packets found in encrypted message.";
            return false;
        }

        if (seipdVersion == 0)
        {
            error = "No SEIPD packet found in encrypted message.";
            return false;
        }

        message = new PgpEncryptedMessage(
            source.ToArray(),
            [.. recipientList],
            seipdVersion,
            symmetricAlgorithm,
            aeadAlgorithm);

        return true;
    }

    /// <summary>
    /// Reads an encrypted message from a stream.
    /// </summary>
    /// <param name="stream">The source stream.</param>
    /// <returns>The parsed encrypted message.</returns>
    public static PgpEncryptedMessage Read(Stream stream)
    {
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Read(ms.ToArray());
    }

    /// <inheritdoc />
    public bool Equals(PgpEncryptedMessage other)
    {
        return Data.Span.SequenceEqual(other.Data.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpEncryptedMessage other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
#if !NETSTANDARD2_0
        var hash = new HashCode();
        foreach (var b in Data.Span)
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
#else
        unchecked
        {
            int hash = 17;
            foreach (var b in Data.ToArray())
            {
                hash = (hash * 31) + b;
            }
            return hash;
        }
#endif
    }

    /// <summary>
    /// Returns a string representation of this encrypted message.
    /// </summary>
    public override string ToString()
    {
        var aeadInfo = AeadAlgorithm != AeadAlgorithm.None ? $", {AeadAlgorithm}" : "";
        return $"PgpEncryptedMessage({RecipientCount} recipient(s), SEIPD v{SeipdVersion}, {SymmetricAlgorithm}{aeadInfo}, {Data.Length} bytes)";
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpEncryptedMessage left, PgpEncryptedMessage right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpEncryptedMessage left, PgpEncryptedMessage right) => !left.Equals(right);
}
