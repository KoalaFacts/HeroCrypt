using HeroCrypt.Polyfills;

namespace HeroCrypt.Primitives.Armor;

/// <summary>
/// Fluent builder for OpenPGP ASCII Armor encoding operations.
/// Implements RFC 4880 Section 6.
/// </summary>
/// <remarks>
/// ASCII Armor provides a portable text representation of binary OpenPGP data,
/// including Base64 encoding with CRC24 checksum for integrity verification.
/// </remarks>
/// <example>
/// <code>
/// // Encode data to ASCII Armor
/// var armored = ArmorBuilder.Create()
///     .WithType(ArmorType.Message)
///     .WithHeader("Version", "HeroCrypt 1.0")
///     .Encode(binaryData);
///
/// // Decode ASCII Armor
/// var result = ArmorBuilder.Create()
///     .Decode(armoredText);
/// </code>
/// </example>
public sealed class ArmorBuilder
{
    private ArmorType armorType = ArmorType.Message;
    private readonly Dictionary<string, string> armorHeaders = [];

    private ArmorBuilder() { }

    /// <summary>
    /// Creates a new ASCII Armor builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static ArmorBuilder Create() => new();

    /// <summary>
    /// Sets the armor type for encoding.
    /// </summary>
    /// <param name="type">The armor type.</param>
    /// <returns>The builder instance for method chaining.</returns>
    public ArmorBuilder WithType(ArmorType type)
    {
        armorType = type;
        return this;
    }

    /// <summary>
    /// Adds an armor header for encoding.
    /// </summary>
    /// <param name="key">The header key.</param>
    /// <param name="value">The header value.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If key or value is null.</exception>
    public ArmorBuilder WithHeader(string key, string value)
    {
        ArgumentHelper.ThrowIfNull(key);
        ArgumentHelper.ThrowIfNull(value);
        armorHeaders[key] = value;
        return this;
    }

    /// <summary>
    /// Adds multiple armor headers for encoding.
    /// </summary>
    /// <param name="headers">The headers to add.</param>
    /// <returns>The builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">If headers is null.</exception>
    public ArmorBuilder WithHeaders(IDictionary<string, string> headers)
    {
        ArgumentHelper.ThrowIfNull(headers);
        foreach (var kvp in headers)
        {
            armorHeaders[kvp.Key] = kvp.Value;
        }
        return this;
    }

    /// <summary>
    /// Clears all configured headers.
    /// </summary>
    /// <returns>The builder instance for method chaining.</returns>
    public ArmorBuilder ClearHeaders()
    {
        armorHeaders.Clear();
        return this;
    }

    /// <summary>
    /// Encodes binary data into ASCII Armor format.
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <returns>The ASCII Armored string.</returns>
    /// <exception cref="ArgumentNullException">If data is null.</exception>
    public string Encode(byte[] data)
    {
        ArgumentHelper.ThrowIfNull(data);
        return ArmorCore.Encode(data, armorType, armorHeaders.Count > 0 ? armorHeaders : null);
    }

    /// <summary>
    /// Encodes binary data into ASCII Armor format.
    /// </summary>
    /// <param name="data">The binary data to encode.</param>
    /// <returns>The ASCII Armored string.</returns>
    public string Encode(ReadOnlySpan<byte> data)
    {
        return ArmorCore.Encode(data, armorType, armorHeaders.Count > 0 ? armorHeaders : null);
    }

    /// <summary>
    /// Decodes ASCII Armor format back to binary data.
    /// </summary>
    /// <param name="armoredText">The ASCII Armored text.</param>
    /// <returns>The decoded result including data, type, and headers.</returns>
    /// <exception cref="ArgumentNullException">If armoredText is null.</exception>
    /// <exception cref="FormatException">If the armor format is invalid.</exception>
    public ArmorDecodeResult Decode(string armoredText)
    {
        ArgumentHelper.ThrowIfNull(armoredText);
        return ArmorCore.Decode(armoredText);
    }

    /// <summary>
    /// Decodes ASCII Armor format and returns only the binary data.
    /// </summary>
    /// <param name="armoredText">The ASCII Armored text.</param>
    /// <returns>The decoded binary data.</returns>
    /// <exception cref="ArgumentNullException">If armoredText is null.</exception>
    /// <exception cref="FormatException">If the armor format is invalid.</exception>
    public byte[] DecodeData(string armoredText)
    {
        return Decode(armoredText).Data;
    }

    /// <summary>
    /// Verifies the CRC24 checksum of armored text without fully decoding.
    /// </summary>
    /// <param name="armoredText">The ASCII Armored text.</param>
    /// <returns>True if the checksum is valid or not present, false if invalid.</returns>
    /// <exception cref="ArgumentNullException">If armoredText is null.</exception>
    public bool VerifyChecksum(string armoredText)
    {
        ArgumentHelper.ThrowIfNull(armoredText);
        return ArmorCore.VerifyChecksum(armoredText);
    }

    /// <summary>
    /// Attempts to decode ASCII Armor format without throwing on failure.
    /// </summary>
    /// <param name="armoredText">The ASCII Armored text.</param>
    /// <param name="result">The decoded result if successful, null otherwise.</param>
    /// <returns>True if decoding succeeded, false otherwise.</returns>
    public bool TryDecode(string armoredText, out ArmorDecodeResult? result)
    {
        if (string.IsNullOrEmpty(armoredText))
        {
            result = null;
            return false;
        }

        try
        {
            result = ArmorCore.Decode(armoredText);
            return true;
        }
        catch (FormatException)
        {
            result = null;
            return false;
        }
    }
}
