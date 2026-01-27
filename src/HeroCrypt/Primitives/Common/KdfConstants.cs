using System.Security.Cryptography;

namespace HeroCrypt.Primitives.Common;

/// <summary>
/// Shared constants and utilities for Key Derivation Functions.
/// </summary>
/// <remarks>
/// <para>
/// This class provides common constants and salt generation utilities used across
/// all KDF implementations (Argon2, PBKDF2, Scrypt, HKDF, Balloon).
/// </para>
/// <para>
/// <b>Salt requirements:</b>
/// </para>
/// <list type="bullet">
///   <item>
///     <term>Minimum length</term>
///     <description>16 bytes (128 bits) per NIST SP 800-132 recommendations</description>
///   </item>
///   <item>
///     <term>Recommended length</term>
///     <description>32 bytes (256 bits) for maximum security margin</description>
///   </item>
///   <item>
///     <term>Uniqueness</term>
///     <description>Each password should have a unique, randomly generated salt</description>
///   </item>
/// </list>
/// <para>
/// Salts prevent rainbow table attacks and ensure that identical passwords
/// produce different derived keys across different users or contexts.
/// </para>
/// </remarks>
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
