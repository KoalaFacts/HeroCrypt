using System.Text;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.Crc24;

namespace HeroCrypt.Primitives.Armor;

/// <summary>
/// OpenPGP ASCII Armor encoding implementation as specified in RFC 4880 Section 6.
/// </summary>
/// <remarks>
/// ASCII Armor is used to convert binary OpenPGP data into a printable ASCII format
/// suitable for transmission via email or other text-based channels.
/// </remarks>
internal static class ArmorCore
{
    /// <summary>
    /// Maximum line length for Base64 data (RFC 4880 recommends 76 characters).
    /// </summary>
    public const int MAX_LINE_LENGTH = 76;

    private const string ARMOR_BEGIN = "-----BEGIN PGP ";
    private const string ARMOR_END = "-----END PGP ";
    private const string ARMOR_SUFFIX = "-----";

    private static readonly string[] LineSeparators = ["\r\n", "\n", "\r"];

    /// <summary>
    /// Encodes binary data into ASCII Armor format.
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <param name="armorType">The type of armor (e.g., MESSAGE, PUBLIC KEY BLOCK).</param>
    /// <param name="headers">Optional armor headers (key-value pairs).</param>
    /// <returns>The ASCII Armored string.</returns>
    public static string Encode(ReadOnlySpan<byte> data, ArmorType armorType, IDictionary<string, string>? headers = null)
    {
        var sb = new StringBuilder();
        var typeName = GetArmorTypeName(armorType);

        // Header line
        sb.Append(ARMOR_BEGIN).Append(typeName).AppendLine(ARMOR_SUFFIX);

        // Optional headers
        if (headers != null && headers.Count > 0)
        {
            foreach (var kvp in headers)
            {
                sb.Append(kvp.Key).Append(": ").AppendLine(kvp.Value);
            }
        }

        // Blank line separating headers from data
        sb.AppendLine();

        // Base64-encoded data with line wrapping
        var base64 = Convert.ToBase64String(data.ToArray());
        for (var i = 0; i < base64.Length; i += MAX_LINE_LENGTH)
        {
            var lineLength = Math.Min(MAX_LINE_LENGTH, base64.Length - i);
            sb.AppendLine(base64.Substring(i, lineLength));
        }

        // CRC24 checksum
        var crc = Crc24Core.Compute(data);
        var crcBytes = new byte[3];
        crcBytes[0] = (byte)((crc >> 16) & 0xFF);
        crcBytes[1] = (byte)((crc >> 8) & 0xFF);
        crcBytes[2] = (byte)(crc & 0xFF);
        sb.Append('=').AppendLine(Convert.ToBase64String(crcBytes));

        // Tail line
        sb.Append(ARMOR_END).Append(typeName).Append(ARMOR_SUFFIX);

        return sb.ToString();
    }

    /// <summary>
    /// Decodes ASCII Armor format back to binary data.
    /// </summary>
    /// <param name="armoredText">The ASCII Armored text.</param>
    /// <returns>The decoded result including data, type, and headers.</returns>
    /// <exception cref="FormatException">If the armor format is invalid.</exception>
    public static ArmorDecodeResult Decode(string armoredText)
    {
        ArgumentHelper.ThrowIfNull(armoredText);

        var lines = armoredText.Split(LineSeparators, StringSplitOptions.None);
        var lineIndex = 0;

        // Skip leading empty lines
        while (lineIndex < lines.Length && string.IsNullOrWhiteSpace(lines[lineIndex]))
        {
            lineIndex++;
        }

        if (lineIndex >= lines.Length)
        {
            throw new FormatException("No armor header found.");
        }

        // Parse header line
        var headerLine = lines[lineIndex].Trim();
        if (!headerLine.StartsWith(ARMOR_BEGIN, StringComparison.Ordinal) || !headerLine.EndsWith(ARMOR_SUFFIX, StringComparison.Ordinal))
        {
            throw new FormatException($"Invalid armor header: {headerLine}");
        }

        var typeName = headerLine.Substring(ARMOR_BEGIN.Length, headerLine.Length - ARMOR_BEGIN.Length - ARMOR_SUFFIX.Length);
        var armorType = ParseArmorType(typeName);
        lineIndex++;

        // Parse optional headers
        var headers = new Dictionary<string, string>();
        while (lineIndex < lines.Length)
        {
            var line = lines[lineIndex].Trim();
            if (string.IsNullOrEmpty(line))
            {
                lineIndex++;
                break;
            }

            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var key = line.Substring(0, colonIndex).Trim();
                var value = line.Substring(colonIndex + 1).Trim();
                headers[key] = value;
            }
            lineIndex++;
        }

        // Parse Base64 data and CRC
        var base64Builder = new StringBuilder();
        byte[]? crcBytes = null;

        while (lineIndex < lines.Length)
        {
            var line = lines[lineIndex].Trim();

            // Check for tail line
            if (line.StartsWith(ARMOR_END, StringComparison.Ordinal))
            {
                break;
            }

            // Check for CRC line
            if (line.StartsWith('=') && line.Length == 5)
            {
                try
                {
                    crcBytes = Convert.FromBase64String(line.Substring(1));
                }
                catch (FormatException)
                {
                    throw new FormatException($"Invalid CRC line: {line}");
                }
                lineIndex++;
                continue;
            }

            // Skip empty lines in data section
            if (!string.IsNullOrWhiteSpace(line))
            {
                base64Builder.Append(line);
            }
            lineIndex++;
        }

        // Decode Base64 data
        byte[] data;
        try
        {
            data = Convert.FromBase64String(base64Builder.ToString());
        }
        catch (FormatException ex)
        {
            throw new FormatException("Invalid Base64 data in armor.", ex);
        }

        // Verify CRC if present
        if (crcBytes != null)
        {
            if (!Crc24Core.Verify(crcBytes, data))
            {
                throw new FormatException("CRC24 checksum verification failed.");
            }
        }

        return new ArmorDecodeResult
        {
            Data = data,
            Type = armorType,
            Headers = headers
        };
    }

    /// <summary>
    /// Verifies the CRC24 checksum of armored text without fully decoding.
    /// </summary>
    /// <param name="armoredText">The ASCII Armored text.</param>
    /// <returns>True if the checksum is valid or not present, false if invalid.</returns>
    public static bool VerifyChecksum(string armoredText)
    {
        try
        {
            Decode(armoredText);
            return true;
        }
        catch (FormatException ex) when (ex.Message.Contains("CRC24", StringComparison.Ordinal))
        {
            return false;
        }
    }

    /// <summary>
    /// Gets the armor type name string for encoding.
    /// </summary>
    private static string GetArmorTypeName(ArmorType type) => type switch
    {
        ArmorType.Message => "MESSAGE",
        ArmorType.PublicKey => "PUBLIC KEY BLOCK",
        ArmorType.PrivateKey => "PRIVATE KEY BLOCK",
        ArmorType.Signature => "SIGNATURE",
        ArmorType.SignedMessage => "SIGNED MESSAGE",
        _ => throw new ArgumentException($"Unknown armor type: {type}", nameof(type))
    };

    /// <summary>
    /// Parses the armor type name string.
    /// </summary>
    private static ArmorType ParseArmorType(string typeName) => typeName.ToUpperInvariant() switch
    {
        "MESSAGE" => ArmorType.Message,
        "PUBLIC KEY BLOCK" => ArmorType.PublicKey,
        "PRIVATE KEY BLOCK" => ArmorType.PrivateKey,
        "SECRET KEY BLOCK" => ArmorType.PrivateKey, // Alias
        "SIGNATURE" => ArmorType.Signature,
        "SIGNED MESSAGE" => ArmorType.SignedMessage,
        _ => throw new FormatException($"Unknown armor type: {typeName}")
    };
}

/// <summary>
/// Types of OpenPGP ASCII Armor.
/// </summary>
public enum ArmorType
{
    /// <summary>Encrypted message.</summary>
    Message,

    /// <summary>Public key block.</summary>
    PublicKey,

    /// <summary>Private (secret) key block.</summary>
    PrivateKey,

    /// <summary>Detached signature.</summary>
    Signature,

    /// <summary>Cleartext signed message.</summary>
    SignedMessage
}

/// <summary>
/// Result of decoding ASCII Armor.
/// </summary>
public sealed class ArmorDecodeResult
{
    /// <summary>The decoded binary data.</summary>
    public required byte[] Data { get; init; }

    /// <summary>The armor type.</summary>
    public required ArmorType Type { get; init; }

    /// <summary>The armor headers (if any).</summary>
    public required IDictionary<string, string> Headers { get; init; }
}
