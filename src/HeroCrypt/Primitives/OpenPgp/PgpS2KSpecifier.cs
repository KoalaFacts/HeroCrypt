using System.Runtime.InteropServices;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents an S2K (String-to-Key) specifier as used in secret key packets.
/// </summary>
/// <remarks>
/// <para>
/// S2K specifiers define how to derive a symmetric key from a passphrase.
/// Different types provide varying levels of protection against brute-force attacks.
/// </para>
/// </remarks>
public readonly struct PgpS2KSpecifier
{
    /// <summary>
    /// Minimum allowed memory exponent for Argon2 (2^16 KB = 64 MB).
    /// </summary>
    /// <remarks>
    /// RFC 9580 Section 3.7.1.4 requires the memory exponent to be within [3, 31].
    /// Values below 16 (64 MB) are considered too weak for modern security.
    /// </remarks>
    public const byte MinArgon2MemoryExponent = 3;

    /// <summary>
    /// Maximum allowed memory exponent for Argon2 (2^31 KB).
    /// </summary>
    public const byte MaxArgon2MemoryExponent = 31;

    /// <summary>
    /// Minimum allowed passes (iterations) for Argon2.
    /// </summary>
    public const byte MinArgon2Passes = 1;

    /// <summary>
    /// Maximum allowed passes (iterations) for Argon2.
    /// </summary>
    public const byte MaxArgon2Passes = 255;

    /// <summary>
    /// Minimum allowed parallelism for Argon2.
    /// </summary>
    public const byte MinArgon2Parallelism = 1;

    /// <summary>
    /// Maximum allowed parallelism for Argon2.
    /// </summary>
    public const byte MaxArgon2Parallelism = 255;

    /// <summary>
    /// Gets the S2K type.
    /// </summary>
    public S2KType Type { get; }

    /// <summary>
    /// Gets the hash algorithm ID.
    /// </summary>
    public byte HashAlgorithm { get; }

    /// <summary>
    /// Gets the salt (8 bytes for salted/iterated S2K).
    /// </summary>
    public ReadOnlyMemory<byte> Salt { get; }

    /// <summary>
    /// Gets the encoded iteration count byte (for iterated S2K).
    /// </summary>
    public byte EncodedCount { get; }

    /// <summary>
    /// Gets the Argon2 parameters (for Argon2 S2K).
    /// </summary>
    public (byte Passes, byte Parallelism, byte MemoryExponent)? Argon2Params { get; }

    /// <summary>
    /// Initializes a new S2K specifier.
    /// </summary>
    public PgpS2KSpecifier(
        S2KType type,
        byte hashAlgorithm,
        ReadOnlyMemory<byte> salt = default,
        byte encodedCount = 0,
        (byte, byte, byte)? argon2Params = null)
    {
        Type = type;
        HashAlgorithm = hashAlgorithm;
        Salt = salt;
        EncodedCount = encodedCount;
        Argon2Params = argon2Params;
    }

    /// <summary>
    /// Creates a simple S2K specifier (not recommended).
    /// </summary>
    public static PgpS2KSpecifier CreateSimple(byte hashAlgorithm)
    {
        return new PgpS2KSpecifier(S2KType.Simple, hashAlgorithm);
    }

    /// <summary>
    /// Creates a salted S2K specifier.
    /// </summary>
    public static PgpS2KSpecifier CreateSalted(byte hashAlgorithm, ReadOnlySpan<byte> salt)
    {
        if (salt.Length != 8)
        {
            throw new ArgumentException("Salt must be 8 bytes.", nameof(salt));
        }

        return new PgpS2KSpecifier(S2KType.Salted, hashAlgorithm, salt.ToArray());
    }

    /// <summary>
    /// Creates an iterated and salted S2K specifier (recommended for legacy).
    /// </summary>
    public static PgpS2KSpecifier CreateIterated(byte hashAlgorithm, ReadOnlySpan<byte> salt, byte encodedCount)
    {
        if (salt.Length != 8)
        {
            throw new ArgumentException("Salt must be 8 bytes.", nameof(salt));
        }

        return new PgpS2KSpecifier(S2KType.IteratedAndSalted, hashAlgorithm, salt.ToArray(), encodedCount);
    }

    /// <summary>
    /// Creates an Argon2 S2K specifier (recommended for modern use).
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm ID.</param>
    /// <param name="salt">The 16-byte salt.</param>
    /// <param name="passes">Number of passes (iterations). Must be at least 1.</param>
    /// <param name="parallelism">Degree of parallelism. Must be at least 1.</param>
    /// <param name="memoryExponent">Memory exponent (memory = 2^exponent KB). Must be in [3, 31].</param>
    /// <returns>A new Argon2 S2K specifier.</returns>
    /// <exception cref="ArgumentException">If parameters are invalid.</exception>
    public static PgpS2KSpecifier CreateArgon2(
        byte hashAlgorithm,
        ReadOnlySpan<byte> salt,
        byte passes,
        byte parallelism,
        byte memoryExponent)
    {
        if (salt.Length != 16)
        {
            throw new ArgumentException("Argon2 salt must be 16 bytes.", nameof(salt));
        }

        ValidateArgon2Parameters(passes, parallelism, memoryExponent);

        return new PgpS2KSpecifier(
            S2KType.Argon2,
            hashAlgorithm,
            salt.ToArray(),
            0,
            (passes, parallelism, memoryExponent));
    }

    /// <summary>
    /// Validates Argon2 parameters according to RFC 9580 Section 3.7.1.4.
    /// </summary>
    /// <param name="passes">Number of passes (iterations).</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="memoryExponent">Memory exponent.</param>
    /// <exception cref="ArgumentOutOfRangeException">If any parameter is out of valid range.</exception>
    public static void ValidateArgon2Parameters(byte passes, byte parallelism, byte memoryExponent)
    {
        if (memoryExponent < MinArgon2MemoryExponent || memoryExponent > MaxArgon2MemoryExponent)
        {
            throw new ArgumentOutOfRangeException(
                nameof(memoryExponent),
                $"Memory exponent must be between {MinArgon2MemoryExponent} and {MaxArgon2MemoryExponent}.");
        }

        if (passes < MinArgon2Passes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(passes),
                $"Passes must be at least {MinArgon2Passes}.");
        }

        if (parallelism < MinArgon2Parallelism)
        {
            throw new ArgumentOutOfRangeException(
                nameof(parallelism),
                $"Parallelism must be at least {MinArgon2Parallelism}.");
        }
    }

    /// <summary>
    /// Reads an S2K specifier from a span.
    /// </summary>
    /// <param name="source">The source span.</param>
    /// <param name="bytesConsumed">The number of bytes consumed.</param>
    /// <returns>The parsed S2K specifier.</returns>
    public static PgpS2KSpecifier Read(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        if (!TryRead(source, out var specifier, out bytesConsumed, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return specifier;
    }

    /// <summary>
    /// Tries to read an S2K specifier from a span.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpS2KSpecifier specifier, out int bytesConsumed, out string error)
    {
        specifier = default;
        bytesConsumed = 0;
        error = string.Empty;

        if (source.Length < 2)
        {
            error = "Source too short for S2K specifier.";
            return false;
        }

        var type = (S2KType)source[0];
        byte hashAlgorithm = source[1];

        switch (type)
        {
            case S2KType.Simple:
                bytesConsumed = 2;
                specifier = new PgpS2KSpecifier(type, hashAlgorithm);
                return true;

            case S2KType.Salted:
                if (source.Length < 10)
                {
                    error = "Source too short for salted S2K specifier.";
                    return false;
                }

                bytesConsumed = 10;
                specifier = new PgpS2KSpecifier(type, hashAlgorithm, source.Slice(2, 8).ToArray());
                return true;

            case S2KType.Reserved:
                error = "Reserved S2K type is not supported.";
                return false;

            case S2KType.IteratedAndSalted:
                if (source.Length < 11)
                {
                    error = "Source too short for iterated S2K specifier.";
                    return false;
                }

                bytesConsumed = 11;
                specifier = new PgpS2KSpecifier(type, hashAlgorithm, source.Slice(2, 8).ToArray(), source[10]);
                return true;

            case S2KType.Argon2:
                if (source.Length < 21)
                {
                    error = "Source too short for Argon2 S2K specifier.";
                    return false;
                }

                // Validate Argon2 parameters per RFC 9580 Section 3.7.1.4
                // Format: type(1) + hash(1) + salt(16) + memExp(1) + passes(1) + parallelism(1) = 21 bytes
                byte memoryExponent = source[18];
                byte passes = source[19];
                byte parallelism = source[20];

                if (memoryExponent < MinArgon2MemoryExponent || memoryExponent > MaxArgon2MemoryExponent)
                {
                    error = "Invalid Argon2 memory exponent.";
                    return false;
                }

                if (passes < MinArgon2Passes)
                {
                    error = "Invalid Argon2 passes parameter.";
                    return false;
                }

                if (parallelism < MinArgon2Parallelism)
                {
                    error = "Invalid Argon2 parallelism parameter.";
                    return false;
                }

                bytesConsumed = 21;
                specifier = new PgpS2KSpecifier(
                    type,
                    hashAlgorithm,
                    source.Slice(2, 16).ToArray(),
                    0,
                    (passes, parallelism, memoryExponent));
                return true;

            default:
                error = $"Unknown S2K type: {(byte)type}";
                return false;
        }
    }

    /// <summary>
    /// Gets the encoded length of this S2K specifier.
    /// </summary>
    public int GetEncodedLength()
    {
        return Type switch
        {
            S2KType.Simple => 2,
            S2KType.Salted => 10,
            S2KType.IteratedAndSalted => 11,
            S2KType.Argon2 => 21, // type(1) + hash(1) + salt(16) + memExp(1) + passes(1) + parallelism(1)
            _ => 2
        };
    }

    /// <summary>
    /// Writes this S2K specifier to a span.
    /// </summary>
    public int Write(Span<byte> destination)
    {
        int length = GetEncodedLength();
        if (destination.Length < length)
        {
            throw new ArgumentException($"Destination too small. Need {length} bytes.", nameof(destination));
        }

        destination[0] = (byte)Type;
        destination[1] = HashAlgorithm;

        switch (Type)
        {
            case S2KType.Simple:
                // No additional data to write
                break;

            case S2KType.Reserved:
                throw new InvalidOperationException("Cannot write reserved S2K type. This type is not valid for use.");

            case S2KType.Salted:
                Salt.Span.CopyTo(destination.Slice(2, 8));
                break;

            case S2KType.IteratedAndSalted:
                Salt.Span.CopyTo(destination.Slice(2, 8));
                destination[10] = EncodedCount;
                break;

            case S2KType.Argon2:
                if (Argon2Params.HasValue)
                {
                    Salt.Span.CopyTo(destination.Slice(2, 16));
                    destination[18] = Argon2Params.Value.MemoryExponent;
                    destination[19] = Argon2Params.Value.Passes;
                    destination[20] = Argon2Params.Value.Parallelism;
                }
                break;

            default:
                // Unknown type - already handled by GetEncodedLength returning 2
                break;
        }

        return length;
    }

    /// <summary>
    /// Gets the actual iteration count for iterated S2K.
    /// </summary>
    public long GetIterationCount()
    {
        if (Type != S2KType.IteratedAndSalted)
        {
            return 0;
        }

        return S2KCore.DecodeIterationCount(EncodedCount);
    }

    /// <summary>
    /// Securely clears the salt from memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method zeros out the S2K salt to prevent sensitive data from lingering in memory.
    /// </para>
    /// </remarks>
    public void ClearSensitiveData()
    {
        if (Salt.IsEmpty)
        {
            return;
        }

        if (MemoryMarshal.TryGetArray(Salt, out ArraySegment<byte> segment) && segment.Array != null)
        {
            SecureMemoryOperations.SecureClear(segment.Array.AsSpan(segment.Offset, segment.Count));
        }
    }
}
