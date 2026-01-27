namespace HeroCrypt.Operations.Internal;

/// <summary>
/// Internal helper class for text encoding conversions used by builders.
/// Centralizes Base64Url and hex encoding logic to avoid code duplication.
/// </summary>
/// <remarks>
/// <para>
/// This class provides consistent text encoding across all HeroCrypt builders,
/// supporting three standard formats:
/// </para>
/// <list type="bullet">
///   <item><term>Hex</term><description>Lowercase hexadecimal (64 chars for 32 bytes)</description></item>
///   <item><term>Base64</term><description>Standard Base64 with padding (44 chars for 32 bytes)</description></item>
///   <item><term>Base64Url</term><description>URL-safe Base64 without padding (43 chars for 32 bytes)</description></item>
/// </list>
/// <para>
/// Base64Url is preferred for URLs, JWTs, and API payloads as it requires no escaping.
/// Hex is preferred for logging and debugging due to its readability.
/// </para>
/// </remarks>
internal static class TextEncodings
{
    /// <summary>
    /// Converts bytes to a URL-safe Base64 string (no padding).
    /// Replaces '+' with '-', '/' with '_', and removes '=' padding.
    /// </summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <returns>A URL-safe Base64 string without padding.</returns>
    /// <remarks>
    /// Output is compatible with RFC 4648 Section 5 (Base 64 Encoding with URL and Filename Safe Alphabet).
    /// The output can be safely used in URLs, filenames, and JSON without escaping.
    /// </remarks>
    public static string ToBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Converts a URL-safe Base64 string back to bytes.
    /// Handles both padded and unpadded input.
    /// </summary>
    /// <param name="base64Url">The URL-safe Base64 string to decode.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="FormatException">Thrown when the input is not valid Base64Url.</exception>
    /// <remarks>
    /// This method is lenient and accepts both padded and unpadded input.
    /// It converts URL-safe characters ('-', '_') back to standard Base64 ('+', '/')
    /// before decoding.
    /// </remarks>
    public static byte[] FromBase64Url(string base64Url)
    {
        // Convert URL-safe Base64 to standard Base64
        var base64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        // Add padding if needed
        switch (base64.Length % 4)
        {
            case 0:
                // No padding needed
                break;
            case 1:
                // Invalid Base64 length - let Convert.FromBase64String handle the error
                break;
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
            default:
                // Unreachable for % 4, but required for exhaustive switch
                break;
        }

        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Converts bytes to a lowercase hexadecimal string.
    /// Uses Convert.ToHexStringLower on .NET 9+ for efficiency.
    /// </summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <returns>A lowercase hexadecimal string (2 characters per byte).</returns>
    /// <remarks>
    /// <para>
    /// Lowercase hex is used consistently throughout HeroCrypt for readability
    /// and compatibility with common conventions (e.g., git hashes, SSL fingerprints).
    /// </para>
    /// <para>
    /// On .NET 9+, this uses the optimized <c>Convert.ToHexStringLower</c> method.
    /// On earlier frameworks, it falls back to <c>Convert.ToHexString().ToLowerInvariant()</c>.
    /// </para>
    /// </remarks>
    public static string ToHexLower(byte[] bytes)
    {
#if NET9_0_OR_GREATER
        return Convert.ToHexStringLower(bytes);
#else
        return Convert.ToHexString(bytes).ToLowerInvariant();
#endif
    }
}
