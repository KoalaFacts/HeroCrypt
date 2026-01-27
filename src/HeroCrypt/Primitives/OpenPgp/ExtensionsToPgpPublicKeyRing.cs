using HeroCrypt.Primitives.Armor;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace HeroCrypt.Primitives.OpenPgp;
#pragma warning restore IDE0130

/// <summary>
/// Extension methods for <see cref="PgpPublicKeyRing"/> to support ASCII Armor import/export.
/// </summary>
public static class ExtensionsToPgpPublicKeyRing
{
    /// <summary>
    /// Exports the public key ring to ASCII Armor format.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <returns>The ASCII Armored string representation.</returns>
    /// <remarks>
    /// <para>
    /// The output follows RFC 4880 Section 6 with:
    /// <list type="bullet">
    ///   <item>Header: -----BEGIN PGP PUBLIC KEY BLOCK-----</item>
    ///   <item>Base64-encoded key ring data with 76-character line wrapping</item>
    ///   <item>CRC24 checksum</item>
    ///   <item>Footer: -----END PGP PUBLIC KEY BLOCK-----</item>
    /// </list>
    /// </para>
    /// </remarks>
    public static string ToArmor(this PgpPublicKeyRing keyRing)
    {
        var binaryData = keyRing.ToArray();
        return ArmorCore.Encode(binaryData, ArmorType.PublicKey);
    }

    /// <summary>
    /// Exports the public key ring to ASCII Armor format with custom headers.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <param name="headers">Optional armor headers (e.g., "Version", "Comment").</param>
    /// <returns>The ASCII Armored string representation.</returns>
    public static string ToArmor(this PgpPublicKeyRing keyRing, IDictionary<string, string>? headers)
    {
        var binaryData = keyRing.ToArray();
        return ArmorCore.Encode(binaryData, ArmorType.PublicKey, headers);
    }

    /// <summary>
    /// Exports the public key ring to ASCII Armor format as UTF-8 bytes.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <returns>The ASCII Armored representation as UTF-8 bytes.</returns>
    public static byte[] ToArmorBytes(this PgpPublicKeyRing keyRing)
    {
        var armored = keyRing.ToArmor();
        return System.Text.Encoding.UTF8.GetBytes(armored);
    }

    /// <summary>
    /// Writes the public key ring to a stream in ASCII Armor format.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <param name="stream">The stream to write to.</param>
    public static void WriteArmor(this PgpPublicKeyRing keyRing, Stream stream)
    {
        var armorBytes = keyRing.ToArmorBytes();
        stream.Write(armorBytes, 0, armorBytes.Length);
    }

    /// <summary>
    /// Writes the public key ring to a stream in ASCII Armor format asynchronously.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <param name="stream">The stream to write to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    public static async Task WriteArmorAsync(this PgpPublicKeyRing keyRing, Stream stream, CancellationToken cancellationToken = default)
    {
        var armorBytes = keyRing.ToArmorBytes();
#if NET8_0_OR_GREATER
        await stream.WriteAsync(armorBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
#else
        await stream.WriteAsync(armorBytes, 0, armorBytes.Length, cancellationToken).ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Saves the public key ring to a file in ASCII Armor format.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <param name="filePath">The file path to write to.</param>
    public static void SaveToArmorFile(this PgpPublicKeyRing keyRing, string filePath)
    {
        var armored = keyRing.ToArmor();
        File.WriteAllText(filePath, armored);
    }

    /// <summary>
    /// Saves the public key ring to a file in ASCII Armor format asynchronously.
    /// </summary>
    /// <param name="keyRing">The public key ring to export.</param>
    /// <param name="filePath">The file path to write to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    public static async Task SaveToArmorFileAsync(this PgpPublicKeyRing keyRing, string filePath, CancellationToken cancellationToken = default)
    {
        var armored = keyRing.ToArmor();
#if NET8_0_OR_GREATER
        await File.WriteAllTextAsync(filePath, armored, cancellationToken).ConfigureAwait(false);
#else
        using var writer = new StreamWriter(filePath);
        await writer.WriteAsync(armored).ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Parses a public key ring from ASCII Armor format.
    /// </summary>
    /// <param name="armoredKey">The ASCII Armored public key.</param>
    /// <returns>The parsed public key ring.</returns>
    /// <exception cref="FormatException">If the armor format is invalid.</exception>
    /// <exception cref="ArgumentException">If the data is not a valid public key ring.</exception>
    public static PgpPublicKeyRing FromArmor(string armoredKey)
    {
        var decoded = ArmorCore.Decode(armoredKey);

        if (decoded.Type != ArmorType.PublicKey)
        {
            throw new ArgumentException($"Expected PUBLIC KEY BLOCK but got {decoded.Type}.", nameof(armoredKey));
        }

        return PgpPublicKeyRing.Read(decoded.Data);
    }

    /// <summary>
    /// Tries to parse a public key ring from ASCII Armor format.
    /// </summary>
    /// <param name="armoredKey">The ASCII Armored public key.</param>
    /// <param name="keyRing">The parsed public key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if parsing succeeded, false otherwise.</returns>
    public static bool TryFromArmor(string armoredKey, out PgpPublicKeyRing keyRing, out string? error)
    {
        keyRing = default;

        try
        {
            var decoded = ArmorCore.Decode(armoredKey);

            if (decoded.Type != ArmorType.PublicKey)
            {
                error = $"Expected PUBLIC KEY BLOCK but got {decoded.Type}.";
                return false;
            }

            return PgpPublicKeyRing.TryRead(decoded.Data, out keyRing, out error);
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Parses a public key ring from ASCII Armor format with metadata.
    /// </summary>
    /// <param name="armoredKey">The ASCII Armored public key.</param>
    /// <returns>The parsed result including key ring and armor headers.</returns>
    public static ArmoredPublicKeyRingResult FromArmorWithMetadata(string armoredKey)
    {
        var decoded = ArmorCore.Decode(armoredKey);

        if (decoded.Type != ArmorType.PublicKey)
        {
            throw new ArgumentException($"Expected PUBLIC KEY BLOCK but got {decoded.Type}.", nameof(armoredKey));
        }

        var keyRing = PgpPublicKeyRing.Read(decoded.Data);
        return new ArmoredPublicKeyRingResult(keyRing, decoded.Headers);
    }

    /// <summary>
    /// Reads a public key ring from a stream containing ASCII Armor data.
    /// </summary>
    /// <param name="stream">The stream to read from.</param>
    /// <returns>The parsed public key ring.</returns>
    public static PgpPublicKeyRing ReadFromArmorStream(Stream stream)
    {
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true);
        var armoredText = reader.ReadToEnd();
        return FromArmor(armoredText);
    }

    /// <summary>
    /// Reads a public key ring from a stream containing ASCII Armor data asynchronously.
    /// </summary>
    /// <param name="stream">The stream to read from.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The parsed public key ring.</returns>
    public static async Task<PgpPublicKeyRing> ReadFromArmorStreamAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true);
#if NET8_0_OR_GREATER
        var armoredText = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
#else
        var armoredText = await reader.ReadToEndAsync().ConfigureAwait(false);
#endif
        return FromArmor(armoredText);
    }

    /// <summary>
    /// Loads a public key ring from an ASCII Armored file.
    /// </summary>
    /// <param name="filePath">The file path to read from.</param>
    /// <returns>The parsed public key ring.</returns>
    public static PgpPublicKeyRing LoadFromArmorFile(string filePath)
    {
        var armoredText = File.ReadAllText(filePath);
        return FromArmor(armoredText);
    }

    /// <summary>
    /// Loads a public key ring from an ASCII Armored file asynchronously.
    /// </summary>
    /// <param name="filePath">The file path to read from.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The parsed public key ring.</returns>
    public static async Task<PgpPublicKeyRing> LoadFromArmorFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        var armoredText = await File.ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);
#else
        using var reader = new StreamReader(filePath);
        var armoredText = await reader.ReadToEndAsync().ConfigureAwait(false);
#endif
        return FromArmor(armoredText);
    }

    /// <summary>
    /// Tries to load a public key ring from an ASCII Armored file.
    /// </summary>
    /// <param name="filePath">The file path to read from.</param>
    /// <param name="keyRing">The parsed public key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if parsing succeeded, false otherwise.</returns>
    public static bool TryLoadFromArmorFile(string filePath, out PgpPublicKeyRing keyRing, out string? error)
    {
        keyRing = default;

        try
        {
            if (!File.Exists(filePath))
            {
                error = $"File not found: {filePath}";
                return false;
            }

            var armoredText = File.ReadAllText(filePath);
            return TryFromArmor(armoredText, out keyRing, out error);
        }
        catch (IOException ex)
        {
            error = $"Failed to read file: {ex.Message}";
            return false;
        }
    }
}

/// <summary>
/// Result of parsing an armored public key ring, including metadata.
/// </summary>
public readonly struct ArmoredPublicKeyRingResult
{
    /// <summary>
    /// Creates a new armored key ring result.
    /// </summary>
    internal ArmoredPublicKeyRingResult(PgpPublicKeyRing keyRing, IDictionary<string, string> headers)
    {
        KeyRing = keyRing;
        Headers = headers;
    }

    /// <summary>
    /// Gets the parsed public key ring.
    /// </summary>
    public PgpPublicKeyRing KeyRing { get; }

    /// <summary>
    /// Gets the armor headers (e.g., "Version", "Comment").
    /// </summary>
    public IDictionary<string, string> Headers { get; }
}
