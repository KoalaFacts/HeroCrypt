namespace HeroCrypt.Operations.Internal;

/// <summary>
/// Internal helper class for text encoding conversions used by builders.
/// Centralizes Base64Url and hex encoding logic to avoid code duplication.
/// </summary>
internal static class TextEncodings
{
    /// <summary>
    /// Converts bytes to a URL-safe Base64 string (no padding).
    /// Replaces '+' with '-', '/' with '_', and removes '=' padding.
    /// </summary>
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
    public static string ToHexLower(byte[] bytes)
    {
#if NET9_0_OR_GREATER
        return Convert.ToHexStringLower(bytes);
#else
        return Convert.ToHexString(bytes).ToLowerInvariant();
#endif
    }
}
