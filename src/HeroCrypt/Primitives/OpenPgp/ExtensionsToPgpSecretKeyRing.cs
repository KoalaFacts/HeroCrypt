using HeroCrypt.Primitives.Armor;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace HeroCrypt.Primitives.OpenPgp;
#pragma warning restore IDE0130

/// <summary>
/// Extension methods for <see cref="PgpSecretKeyRing"/> to support ASCII Armor import/export.
/// </summary>
public static class ExtensionsToPgpSecretKeyRing
{
    #region Export (ToArmor)

    /// <summary>
    /// Exports the secret key ring to ASCII Armor format.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <returns>The ASCII Armored string representation.</returns>
    /// <remarks>
    /// <para>
    /// <b>Security Warning:</b> The exported data contains secret key material.
    /// Handle with care and consider encrypting the key ring with a passphrase
    /// before exporting.
    /// </para>
    /// <para>
    /// The output follows RFC 4880 Section 6 with:
    /// <list type="bullet">
    ///   <item>Header: -----BEGIN PGP PRIVATE KEY BLOCK-----</item>
    ///   <item>Base64-encoded key ring data with 76-character line wrapping</item>
    ///   <item>CRC24 checksum</item>
    ///   <item>Footer: -----END PGP PRIVATE KEY BLOCK-----</item>
    /// </list>
    /// </para>
    /// </remarks>
    public static string ToArmor(this PgpSecretKeyRing keyRing)
    {
        var binaryData = keyRing.ToArray();
        return ArmorCore.Encode(binaryData, ArmorType.PrivateKey);
    }

    /// <summary>
    /// Exports the secret key ring to ASCII Armor format with custom headers.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <param name="headers">Optional armor headers (e.g., "Version", "Comment").</param>
    /// <returns>The ASCII Armored string representation.</returns>
    public static string ToArmor(this PgpSecretKeyRing keyRing, IDictionary<string, string>? headers)
    {
        var binaryData = keyRing.ToArray();
        return ArmorCore.Encode(binaryData, ArmorType.PrivateKey, headers);
    }

    /// <summary>
    /// Exports the secret key ring to ASCII Armor format as UTF-8 bytes.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <returns>The ASCII Armored representation as UTF-8 bytes.</returns>
    public static byte[] ToArmorBytes(this PgpSecretKeyRing keyRing)
    {
        var armored = keyRing.ToArmor();
        return System.Text.Encoding.UTF8.GetBytes(armored);
    }

    /// <summary>
    /// Writes the secret key ring to a stream in ASCII Armor format.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <param name="stream">The stream to write to.</param>
    public static void WriteArmor(this PgpSecretKeyRing keyRing, Stream stream)
    {
        var armorBytes = keyRing.ToArmorBytes();
        stream.Write(armorBytes, 0, armorBytes.Length);
    }

    /// <summary>
    /// Writes the secret key ring to a stream in ASCII Armor format asynchronously.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <param name="stream">The stream to write to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    public static async Task WriteArmorAsync(this PgpSecretKeyRing keyRing, Stream stream, CancellationToken cancellationToken = default)
    {
        var armorBytes = keyRing.ToArmorBytes();
#if NET8_0_OR_GREATER
        await stream.WriteAsync(armorBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
#else
        await stream.WriteAsync(armorBytes, 0, armorBytes.Length, cancellationToken).ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// Saves the secret key ring to a file in ASCII Armor format.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <param name="filePath">The file path to write to.</param>
    /// <remarks>
    /// <para>
    /// <b>Security Warning:</b> The file will contain secret key material.
    /// Ensure the file is stored securely with appropriate permissions.
    /// </para>
    /// </remarks>
    public static void SaveToArmorFile(this PgpSecretKeyRing keyRing, string filePath)
    {
        var armored = keyRing.ToArmor();
        File.WriteAllText(filePath, armored);
    }

    /// <summary>
    /// Saves the secret key ring to a file in ASCII Armor format asynchronously.
    /// </summary>
    /// <param name="keyRing">The secret key ring to export.</param>
    /// <param name="filePath">The file path to write to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    public static async Task SaveToArmorFileAsync(this PgpSecretKeyRing keyRing, string filePath, CancellationToken cancellationToken = default)
    {
        var armored = keyRing.ToArmor();
#if NET8_0_OR_GREATER
        await File.WriteAllTextAsync(filePath, armored, cancellationToken).ConfigureAwait(false);
#else
        using var writer = new StreamWriter(filePath);
        await writer.WriteAsync(armored).ConfigureAwait(false);
#endif
    }

    #endregion

    #region Import (FromArmor)

    /// <summary>
    /// Parses a secret key ring from ASCII Armor format.
    /// </summary>
    /// <param name="armoredKey">The ASCII Armored secret key.</param>
    /// <returns>The parsed secret key ring.</returns>
    /// <exception cref="FormatException">If the armor format is invalid.</exception>
    /// <exception cref="ArgumentException">If the data is not a valid secret key ring.</exception>
    public static PgpSecretKeyRing FromArmor(string armoredKey)
    {
        var decoded = ArmorCore.Decode(armoredKey);

        if (decoded.Type != ArmorType.PrivateKey)
        {
            throw new ArgumentException($"Expected PRIVATE KEY BLOCK but got {decoded.Type}.", nameof(armoredKey));
        }

        return PgpSecretKeyRing.Read(decoded.Data);
    }

    /// <summary>
    /// Tries to parse a secret key ring from ASCII Armor format.
    /// </summary>
    /// <param name="armoredKey">The ASCII Armored secret key.</param>
    /// <param name="keyRing">The parsed secret key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if parsing succeeded, false otherwise.</returns>
    public static bool TryFromArmor(string armoredKey, out PgpSecretKeyRing keyRing, out string? error)
    {
        keyRing = default;

        try
        {
            var decoded = ArmorCore.Decode(armoredKey);

            if (decoded.Type != ArmorType.PrivateKey)
            {
                error = $"Expected PRIVATE KEY BLOCK but got {decoded.Type}.";
                return false;
            }

            return PgpSecretKeyRing.TryRead(decoded.Data, out keyRing, out error);
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Parses a secret key ring from ASCII Armor format with metadata.
    /// </summary>
    /// <param name="armoredKey">The ASCII Armored secret key.</param>
    /// <returns>The parsed result including key ring and armor headers.</returns>
    public static ArmoredSecretKeyRingResult FromArmorWithMetadata(string armoredKey)
    {
        var decoded = ArmorCore.Decode(armoredKey);

        if (decoded.Type != ArmorType.PrivateKey)
        {
            throw new ArgumentException($"Expected PRIVATE KEY BLOCK but got {decoded.Type}.", nameof(armoredKey));
        }

        var keyRing = PgpSecretKeyRing.Read(decoded.Data);
        return new ArmoredSecretKeyRingResult(keyRing, decoded.Headers);
    }

    /// <summary>
    /// Reads a secret key ring from a stream containing ASCII Armor data.
    /// </summary>
    /// <param name="stream">The stream to read from.</param>
    /// <returns>The parsed secret key ring.</returns>
    public static PgpSecretKeyRing ReadFromArmorStream(Stream stream)
    {
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 1024, leaveOpen: true);
        var armoredText = reader.ReadToEnd();
        return FromArmor(armoredText);
    }

    /// <summary>
    /// Reads a secret key ring from a stream containing ASCII Armor data asynchronously.
    /// </summary>
    /// <param name="stream">The stream to read from.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The parsed secret key ring.</returns>
    public static async Task<PgpSecretKeyRing> ReadFromArmorStreamAsync(Stream stream, CancellationToken cancellationToken = default)
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
    /// Loads a secret key ring from an ASCII Armored file.
    /// </summary>
    /// <param name="filePath">The file path to read from.</param>
    /// <returns>The parsed secret key ring.</returns>
    public static PgpSecretKeyRing LoadFromArmorFile(string filePath)
    {
        var armoredText = File.ReadAllText(filePath);
        return FromArmor(armoredText);
    }

    /// <summary>
    /// Loads a secret key ring from an ASCII Armored file asynchronously.
    /// </summary>
    /// <param name="filePath">The file path to read from.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The parsed secret key ring.</returns>
    public static async Task<PgpSecretKeyRing> LoadFromArmorFileAsync(string filePath, CancellationToken cancellationToken = default)
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
    /// Tries to load a secret key ring from an ASCII Armored file.
    /// </summary>
    /// <param name="filePath">The file path to read from.</param>
    /// <param name="keyRing">The parsed secret key ring if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if parsing succeeded, false otherwise.</returns>
    public static bool TryLoadFromArmorFile(string filePath, out PgpSecretKeyRing keyRing, out string? error)
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

    #endregion
}

/// <summary>
/// Result of parsing an armored secret key ring, including metadata.
/// </summary>
public readonly struct ArmoredSecretKeyRingResult
{
    /// <summary>
    /// Creates a new armored key ring result.
    /// </summary>
    internal ArmoredSecretKeyRingResult(PgpSecretKeyRing keyRing, IDictionary<string, string> headers)
    {
        KeyRing = keyRing;
        Headers = headers;
    }

    /// <summary>
    /// Gets the parsed secret key ring.
    /// </summary>
    public PgpSecretKeyRing KeyRing { get; }

    /// <summary>
    /// Gets the armor headers (e.g., "Version", "Comment").
    /// </summary>
    public IDictionary<string, string> Headers { get; }
}
