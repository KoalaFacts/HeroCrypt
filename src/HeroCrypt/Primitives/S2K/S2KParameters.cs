using HeroCrypt.Operations;

namespace HeroCrypt.Primitives.S2K;

/// <summary>
/// Represents parsed S2K (String-to-Key) parameters from OpenPGP packet data.
/// </summary>
/// <remarks>
/// <para>
/// This struct holds all parameters needed to derive a key from a passphrase
/// according to RFC 4880 Section 3.7 and RFC 9580 Section 3.7.1.4.
/// </para>
/// <para>
/// Use <see cref="Parse(ReadOnlySpan{byte})"/> to read S2K data from packet bytes, and
/// <see cref="DeriveKey"/> to derive a symmetric key from a passphrase.
/// </para>
/// </remarks>
public readonly struct S2KParameters
{
    /// <summary>
    /// Gets the S2K type.
    /// </summary>
    public S2KType Type { get; init; }

    /// <summary>
    /// Gets the hash algorithm (for types 0-3).
    /// </summary>
    public HashingAlgorithm HashAlgorithm { get; init; }

    /// <summary>
    /// Gets the salt value (8 bytes for types 1-3, 16 bytes for type 4).
    /// </summary>
    public ReadOnlyMemory<byte> Salt { get; init; }

    /// <summary>
    /// Gets the encoded iteration count (for type 3).
    /// </summary>
    public byte EncodedCount { get; init; }

    /// <summary>
    /// Gets the Argon2 time passes parameter (for type 4).
    /// </summary>
    public byte Argon2TimePasses { get; init; }

    /// <summary>
    /// Gets the Argon2 parallelism parameter (for type 4).
    /// </summary>
    public byte Argon2Parallelism { get; init; }

    /// <summary>
    /// Gets the Argon2 memory exponent parameter (for type 4).
    /// Memory size = 2^m KiB.
    /// </summary>
    public byte Argon2MemoryExponent { get; init; }

    /// <summary>
    /// Parses S2K parameters from packet data.
    /// </summary>
    /// <param name="data">The packet data starting at the S2K specifier.</param>
    /// <returns>Parsed S2K parameters.</returns>
    /// <exception cref="ArgumentException">If the data is invalid or too short.</exception>
    public static S2KParameters Parse(ReadOnlySpan<byte> data)
    {
        return Parse(data, out _);
    }

    /// <summary>
    /// Parses S2K parameters from packet data.
    /// </summary>
    /// <param name="data">The packet data starting at the S2K specifier.</param>
    /// <param name="bytesRead">The number of bytes consumed.</param>
    /// <returns>Parsed S2K parameters.</returns>
    /// <exception cref="ArgumentException">If the data is invalid or too short.</exception>
    public static S2KParameters Parse(ReadOnlySpan<byte> data, out int bytesRead)
    {
        if (data.Length < 1)
        {
            throw new ArgumentException("S2K data too short", nameof(data));
        }

        var type = (S2KType)data[0];

        return type switch
        {
            S2KType.Simple => ParseSimple(data, out bytesRead),
            S2KType.Salted => ParseSalted(data, out bytesRead),
            S2KType.IteratedAndSalted => ParseIterated(data, out bytesRead),
            S2KType.Argon2 => ParseArgon2(data, out bytesRead),
            _ => throw new ArgumentException($"Unsupported S2K type: {type}", nameof(data))
        };
    }

    private static S2KParameters ParseSimple(ReadOnlySpan<byte> data, out int bytesRead)
    {
        // Simple S2K: type (1) + hash (1) = 2 bytes
        if (data.Length < 2)
        {
            throw new ArgumentException("Simple S2K data too short (need 2 bytes)", nameof(data));
        }

        bytesRead = 2;
        return new S2KParameters
        {
            Type = S2KType.Simple,
            HashAlgorithm = MapPgpHashAlgorithm(data[1])
        };
    }

    private static S2KParameters ParseSalted(ReadOnlySpan<byte> data, out int bytesRead)
    {
        // Salted S2K: type (1) + hash (1) + salt (8) = 10 bytes
        if (data.Length < 10)
        {
            throw new ArgumentException("Salted S2K data too short (need 10 bytes)", nameof(data));
        }

        bytesRead = 10;
        return new S2KParameters
        {
            Type = S2KType.Salted,
            HashAlgorithm = MapPgpHashAlgorithm(data[1]),
            Salt = data.Slice(2, 8).ToArray()
        };
    }

    private static S2KParameters ParseIterated(ReadOnlySpan<byte> data, out int bytesRead)
    {
        // Iterated S2K: type (1) + hash (1) + salt (8) + count (1) = 11 bytes
        if (data.Length < 11)
        {
            throw new ArgumentException("Iterated S2K data too short (need 11 bytes)", nameof(data));
        }

        bytesRead = 11;
        return new S2KParameters
        {
            Type = S2KType.IteratedAndSalted,
            HashAlgorithm = MapPgpHashAlgorithm(data[1]),
            Salt = data.Slice(2, 8).ToArray(),
            EncodedCount = data[10]
        };
    }

    private static S2KParameters ParseArgon2(ReadOnlySpan<byte> data, out int bytesRead)
    {
        // Argon2 S2K: type (1) + salt (16) + t (1) + p (1) + m (1) = 20 bytes
        if (data.Length < 20)
        {
            throw new ArgumentException("Argon2 S2K data too short (need 20 bytes)", nameof(data));
        }

        bytesRead = 20;
        return new S2KParameters
        {
            Type = S2KType.Argon2,
            Salt = data.Slice(1, 16).ToArray(),
            Argon2TimePasses = data[17],
            Argon2Parallelism = data[18],
            Argon2MemoryExponent = data[19]
        };
    }

    /// <summary>
    /// Serializes the S2K parameters to bytes.
    /// </summary>
    /// <returns>The serialized S2K specifier.</returns>
    public byte[] Serialize()
    {
        return Type switch
        {
            S2KType.Simple => SerializeSimple(),
            S2KType.Salted => SerializeSalted(),
            S2KType.IteratedAndSalted => SerializeIterated(),
            S2KType.Argon2 => SerializeArgon2(),
            _ => throw new InvalidOperationException($"Cannot serialize S2K type: {Type}")
        };
    }

    private byte[] SerializeSimple()
    {
        return [(byte)Type, GetPgpHashId(HashAlgorithm)];
    }

    private byte[] SerializeSalted()
    {
        var result = new byte[10];
        result[0] = (byte)Type;
        result[1] = GetPgpHashId(HashAlgorithm);
        Salt.Span.CopyTo(result.AsSpan(2));
        return result;
    }

    private byte[] SerializeIterated()
    {
        var result = new byte[11];
        result[0] = (byte)Type;
        result[1] = GetPgpHashId(HashAlgorithm);
        Salt.Span.CopyTo(result.AsSpan(2));
        result[10] = EncodedCount;
        return result;
    }

    private byte[] SerializeArgon2()
    {
        var result = new byte[20];
        result[0] = (byte)Type;
        Salt.Span.CopyTo(result.AsSpan(1));
        result[17] = Argon2TimePasses;
        result[18] = Argon2Parallelism;
        result[19] = Argon2MemoryExponent;
        return result;
    }

    /// <summary>
    /// Derives a symmetric key from a passphrase using these S2K parameters.
    /// </summary>
    /// <param name="passphrase">The passphrase bytes.</param>
    /// <param name="keyLength">Desired key length in bytes.</param>
    /// <returns>The derived key.</returns>
    public byte[] DeriveKey(ReadOnlySpan<byte> passphrase, int keyLength)
    {
        var hashAlg = S2KCore.MapHashAlgorithm(HashAlgorithm);

        return Type switch
        {
            S2KType.Simple => S2KCore.SimpleS2K(passphrase, keyLength, hashAlg),
            S2KType.Salted => S2KCore.SaltedS2K(passphrase, Salt.Span, keyLength, hashAlg),
            S2KType.IteratedAndSalted => S2KCore.IteratedS2K(
                passphrase,
                Salt.Span,
                S2KCore.DecodeIterationCount(EncodedCount),
                keyLength,
                hashAlg),
            S2KType.Argon2 => S2KCore.Argon2S2K(
                passphrase,
                Salt.Span,
                Argon2TimePasses,
                Argon2Parallelism,
                Argon2MemoryExponent,
                keyLength),
            _ => throw new InvalidOperationException($"Unsupported S2K type: {Type}")
        };
    }

    /// <summary>
    /// Creates Simple S2K parameters.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>New S2K parameters.</returns>
    [Obsolete("Simple S2K provides minimal security. Use CreateIterated or CreateArgon2 instead.")]
    public static S2KParameters CreateSimple(HashingAlgorithm hashAlgorithm = HashingAlgorithm.Sha256)
    {
        return new S2KParameters
        {
            Type = S2KType.Simple,
            HashAlgorithm = hashAlgorithm
        };
    }

    /// <summary>
    /// Creates Salted S2K parameters with a random salt.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>New S2K parameters.</returns>
    public static S2KParameters CreateSalted(HashingAlgorithm hashAlgorithm = HashingAlgorithm.Sha256)
    {
        return new S2KParameters
        {
            Type = S2KType.Salted,
            HashAlgorithm = hashAlgorithm,
            Salt = S2KCore.GenerateSalt()
        };
    }

    /// <summary>
    /// Creates Iterated and Salted S2K parameters with a random salt.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="encodedCount">The encoded iteration count (default: 0xC0 = ~1M iterations).</param>
    /// <returns>New S2K parameters.</returns>
    public static S2KParameters CreateIterated(
        HashingAlgorithm hashAlgorithm = HashingAlgorithm.Sha256,
        byte encodedCount = 0xC0)
    {
        return new S2KParameters
        {
            Type = S2KType.IteratedAndSalted,
            HashAlgorithm = hashAlgorithm,
            Salt = S2KCore.GenerateSalt(),
            EncodedCount = encodedCount
        };
    }

    /// <summary>
    /// Creates Argon2 S2K parameters with a random salt.
    /// </summary>
    /// <param name="timePasses">Time parameter (iterations). Default: 3.</param>
    /// <param name="parallelism">Parallelism degree. Default: 4.</param>
    /// <param name="memoryExponent">Memory exponent (memory = 2^m KiB). Default: 16 (64 MiB).</param>
    /// <returns>New S2K parameters.</returns>
    public static S2KParameters CreateArgon2(
        byte timePasses = 3,
        byte parallelism = 4,
        byte memoryExponent = 16)
    {
        return new S2KParameters
        {
            Type = S2KType.Argon2,
            Salt = S2KCore.GenerateArgon2Salt(),
            Argon2TimePasses = timePasses,
            Argon2Parallelism = parallelism,
            Argon2MemoryExponent = memoryExponent
        };
    }

    /// <summary>
    /// Gets the size of this S2K specifier in bytes when serialized.
    /// </summary>
    public int SerializedLength => Type switch
    {
        S2KType.Simple => 2,
        S2KType.Salted => 10,
        S2KType.IteratedAndSalted => 11,
        S2KType.Argon2 => 20,
        _ => throw new InvalidOperationException($"Unknown S2K type: {Type}")
    };

    /// <summary>
    /// Maps OpenPGP hash algorithm ID to HashingAlgorithm enum.
    /// </summary>
    private static HashingAlgorithm MapPgpHashAlgorithm(byte id)
    {
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
        return id switch
        {
            1 => HashingAlgorithm.Md5,
            2 => HashingAlgorithm.Sha1,
            8 => HashingAlgorithm.Sha256,
            9 => HashingAlgorithm.Sha384,
            10 => HashingAlgorithm.Sha512,
            _ => throw new ArgumentException($"Unsupported OpenPGP hash algorithm ID: {id}")
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Gets the OpenPGP hash algorithm ID.
    /// </summary>
    private static byte GetPgpHashId(HashingAlgorithm algorithm)
    {
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
        return algorithm switch
        {
            HashingAlgorithm.Md5 => 1,
            HashingAlgorithm.Sha1 => 2,
            HashingAlgorithm.Sha256 => 8,
            HashingAlgorithm.Sha384 => 9,
            HashingAlgorithm.Sha512 => 10,
            _ => throw new ArgumentException($"Unsupported hash algorithm for OpenPGP: {algorithm}")
        };
#pragma warning restore CS0618
    }
}
