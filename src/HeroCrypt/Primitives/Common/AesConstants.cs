namespace HeroCrypt.Primitives.Common;

/// <summary>
/// Shared constants for AES-based cryptographic operations
/// </summary>
internal static class AesConstants
{
    /// <summary>
    /// AES block size in bytes (128 bits)
    /// </summary>
    public const int BlockSize = 16;

    /// <summary>
    /// AES-128 key size in bytes
    /// </summary>
    public const int Aes128KeySize = 16;

    /// <summary>
    /// AES-192 key size in bytes
    /// </summary>
    public const int Aes192KeySize = 24;

    /// <summary>
    /// AES-256 key size in bytes
    /// </summary>
    public const int Aes256KeySize = 32;

    /// <summary>
    /// Supported key sizes for standard AES (AES-128, AES-192, AES-256)
    /// </summary>
    public static readonly int[] StandardKeySizes = [16, 24, 32];

    /// <summary>
    /// Supported key sizes for AES-SIV (doubled because SIV uses two keys)
    /// AES-SIV-128: 32 bytes (16+16)
    /// AES-SIV-192: 48 bytes (24+24)
    /// AES-SIV-256: 64 bytes (32+32)
    /// </summary>
    public static readonly int[] SivKeySizes = [32, 48, 64];

    /// <summary>
    /// Checks if a key size is valid for standard AES operations
    /// </summary>
    /// <param name="keySize">Key size in bytes</param>
    /// <returns>True if the key size is valid (16, 24, or 32 bytes)</returns>
    public static bool IsValidKeySize(int keySize)
    {
        return keySize is Aes128KeySize or Aes192KeySize or Aes256KeySize;
    }

    /// <summary>
    /// Checks if a key size is valid for AES-SIV operations
    /// </summary>
    /// <param name="keySize">Key size in bytes</param>
    /// <returns>True if the key size is valid (32, 48, or 64 bytes)</returns>
    public static bool IsValidSivKeySize(int keySize)
    {
        return keySize is 32 or 48 or 64;
    }
}
