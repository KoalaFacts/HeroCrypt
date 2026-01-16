using System.Security.Cryptography;

namespace HeroCrypt.Primitives.Common;

/// <summary>
/// Shared constants and utilities for Key Derivation Functions
/// </summary>
internal static class KdfConstants
{
    /// <summary>
    /// Minimum recommended salt length in bytes
    /// </summary>
    public const int MinSaltLength = 16;

    /// <summary>
    /// Default salt length in bytes
    /// </summary>
    public const int DefaultSaltLength = 32;

    /// <summary>
    /// Generates a cryptographically secure random salt
    /// </summary>
    /// <param name="length">Salt length in bytes (default: 32)</param>
    /// <returns>Random salt bytes</returns>
    /// <exception cref="ArgumentException">If length is less than minimum</exception>
    public static byte[] GenerateRandomSalt(int length = DefaultSaltLength)
    {
        if (length < MinSaltLength)
        {
            throw new ArgumentException(
                $"Salt length must be at least {MinSaltLength} bytes, but was {length} bytes",
                nameof(length));
        }

        var salt = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Validates that a salt meets minimum length requirements
    /// </summary>
    /// <param name="salt">Salt to validate</param>
    /// <param name="allowWeak">If true, skips minimum length validation</param>
    /// <exception cref="ArgumentException">If salt is too short and allowWeak is false</exception>
    public static void ValidateSalt(ReadOnlySpan<byte> salt, bool allowWeak = false)
    {
        if (!allowWeak && salt.Length < MinSaltLength)
        {
            throw new ArgumentException(
                $"Salt must be at least {MinSaltLength} bytes, but was {salt.Length} bytes",
                nameof(salt));
        }
    }
}
