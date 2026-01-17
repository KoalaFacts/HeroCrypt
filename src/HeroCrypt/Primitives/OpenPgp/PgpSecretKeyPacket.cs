using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using HeroCrypt.Primitives.S2K;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// S2K usage convention values for secret key packets.
/// </summary>
/// <remarks>
/// <para>
/// The S2K usage byte determines how the secret key material is protected:
/// <list type="bullet">
///   <item>0: Unencrypted (plaintext key material with 2-byte checksum)</item>
///   <item>254: Encrypted with S2K, SHA-1 hash of plaintext for integrity</item>
///   <item>255: Encrypted with S2K, 2-byte checksum (legacy)</item>
///   <item>253: AEAD encryption (RFC 9580)</item>
///   <item>1-252: Direct cipher algorithm ID (legacy, deprecated)</item>
/// </list>
/// </para>
/// </remarks>
public enum PgpS2KUsage : byte
{
    /// <summary>
    /// No encryption - plaintext secret key with 2-byte checksum.
    /// </summary>
    None = 0,

    /// <summary>
    /// Encrypted with S2K, 2-byte checksum of plaintext (legacy).
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Legacy format, prefer Sha1Hash for better security.</para>
    /// </remarks>
    Checksum = 255,

    /// <summary>
    /// Encrypted with S2K, SHA-1 hash of plaintext for integrity.
    /// </summary>
    /// <remarks>
    /// <para><b>Status:</b> Recommended for v4 keys.</para>
    /// </remarks>
    Sha1Hash = 254,

    /// <summary>
    /// AEAD encryption (RFC 9580).
    /// </summary>
    /// <remarks>
    /// <para><b>Standard:</b> RFC 9580</para>
    /// <para>Modern AEAD protection for v6 keys.</para>
    /// </remarks>
    Aead = 253,
}

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
                if (source.Length < 20)
                {
                    error = "Source too short for Argon2 S2K specifier.";
                    return false;
                }

                bytesConsumed = 20;
                specifier = new PgpS2KSpecifier(
                    type,
                    hashAlgorithm,
                    source.Slice(2, 16).ToArray(),
                    0,
                    (source[18], source[19], source[17]));
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
            S2KType.Argon2 => 20,
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
                    destination[17] = Argon2Params.Value.MemoryExponent;
                    destination[18] = Argon2Params.Value.Passes;
                    destination[19] = Argon2Params.Value.Parallelism;
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
}

/// <summary>
/// Represents a Secret Key Packet (Tag 5) or Secret Subkey Packet (Tag 7) as defined in RFC 4880 Section 5.5.3.
/// </summary>
/// <remarks>
/// <para>
/// Secret key packets extend public key packets with private key material.
/// The private key may be encrypted with a passphrase-derived key (S2K).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// <code>
/// [Public key fields] + S2K usage(1) + [S2K specifier] + [IV] + Secret MPIs + Checksum
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpSecretKeyPacket
{
    /// <summary>
    /// Gets the public key portion of this secret key.
    /// </summary>
    public PgpPublicKeyPacket PublicKey { get; }

    /// <summary>
    /// Gets the S2K usage convention.
    /// </summary>
    public PgpS2KUsage S2KUsage { get; }

    /// <summary>
    /// Gets the cipher algorithm used for encryption (when S2K is used).
    /// </summary>
    public byte CipherAlgorithm { get; }

    /// <summary>
    /// Gets the S2K specifier (when S2K is used).
    /// </summary>
    public PgpS2KSpecifier? S2KSpecifier { get; }

    /// <summary>
    /// Gets the initialization vector for encryption (when S2K is used).
    /// </summary>
    public ReadOnlyMemory<byte> IV { get; }

    /// <summary>
    /// Gets the secret key material (encrypted or plaintext).
    /// </summary>
    /// <remarks>
    /// <para>
    /// If <see cref="IsEncrypted"/> is true, this is encrypted data.
    /// Otherwise, it contains plaintext MPIs followed by a checksum.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> SecretKeyMaterial { get; }

    /// <summary>
    /// Gets whether this is a subkey packet (Tag 7) rather than a primary key packet (Tag 5).
    /// </summary>
    public bool IsSubkey => PublicKey.IsSubkey;

    /// <summary>
    /// Gets whether the secret key material is encrypted.
    /// </summary>
    public bool IsEncrypted => S2KUsage != PgpS2KUsage.None;

    /// <summary>
    /// Gets the key version (4 or 6).
    /// </summary>
    public byte Version => PublicKey.Version;

    /// <summary>
    /// Gets the key creation time.
    /// </summary>
    public DateTimeOffset CreationTime => PublicKey.CreationTime;

    /// <summary>
    /// Gets the public key algorithm.
    /// </summary>
    public PgpPublicKeyAlgorithm Algorithm => PublicKey.Algorithm;

    /// <summary>
    /// Initializes a new secret key packet.
    /// </summary>
    public PgpSecretKeyPacket(
        PgpPublicKeyPacket publicKey,
        PgpS2KUsage s2kUsage,
        byte cipherAlgorithm,
        PgpS2KSpecifier? s2kSpecifier,
        ReadOnlyMemory<byte> iv,
        ReadOnlyMemory<byte> secretKeyMaterial)
    {
        PublicKey = publicKey;
        S2KUsage = s2kUsage;
        CipherAlgorithm = cipherAlgorithm;
        S2KSpecifier = s2kSpecifier;
        IV = iv;
        SecretKeyMaterial = secretKeyMaterial;
    }

    /// <summary>
    /// Creates an unencrypted secret key packet.
    /// </summary>
    /// <param name="publicKey">The public key portion.</param>
    /// <param name="secretKeyMaterial">The plaintext secret key MPIs (checksum will be calculated automatically).</param>
    /// <returns>A new unencrypted secret key packet.</returns>
    public static PgpSecretKeyPacket CreateUnencrypted(
        PgpPublicKeyPacket publicKey,
        ReadOnlyMemory<byte> secretKeyMaterial)
    {
        // Calculate checksum: sum of all bytes mod 65536
        ushort checksum = 0;
        foreach (byte b in secretKeyMaterial.Span)
        {
            checksum = (ushort)((checksum + b) & 0xFFFF);
        }

        // Append checksum to secret key material
        var materialWithChecksum = new byte[secretKeyMaterial.Length + 2];
        secretKeyMaterial.Span.CopyTo(materialWithChecksum);
        BinaryPrimitives.WriteUInt16BigEndian(materialWithChecksum.AsSpan(secretKeyMaterial.Length), checksum);

        return new PgpSecretKeyPacket(
            publicKey,
            PgpS2KUsage.None,
            0,
            null,
            Array.Empty<byte>(),
            materialWithChecksum);
    }

    /// <summary>
    /// Creates an encrypted secret key packet.
    /// </summary>
    /// <param name="publicKey">The public key portion.</param>
    /// <param name="s2kUsage">The S2K usage convention.</param>
    /// <param name="cipherAlgorithm">The cipher algorithm ID.</param>
    /// <param name="s2kSpecifier">The S2K specifier.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="encryptedSecretKey">The encrypted secret key material.</param>
    /// <returns>A new encrypted secret key packet.</returns>
    public static PgpSecretKeyPacket CreateEncrypted(
        PgpPublicKeyPacket publicKey,
        PgpS2KUsage s2kUsage,
        byte cipherAlgorithm,
        PgpS2KSpecifier s2kSpecifier,
        ReadOnlyMemory<byte> iv,
        ReadOnlyMemory<byte> encryptedSecretKey)
    {
        if (s2kUsage == PgpS2KUsage.None)
        {
            throw new ArgumentException("Use CreateUnencrypted for unencrypted keys.", nameof(s2kUsage));
        }

        return new PgpSecretKeyPacket(
            publicKey,
            s2kUsage,
            cipherAlgorithm,
            s2kSpecifier,
            iv,
            encryptedSecretKey);
    }

    /// <summary>
    /// Reads a secret key packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="isSubkey">Whether this is a subkey packet (Tag 7).</param>
    /// <returns>The parsed secret key packet.</returns>
    public static PgpSecretKeyPacket Read(ReadOnlySpan<byte> source, bool isSubkey = false)
    {
        if (!TryRead(source, isSubkey, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a secret key packet from a span.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> source, bool isSubkey, out PgpSecretKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for secret key packet version.";
            return false;
        }

        byte version = source[0];
        if (version == 4)
        {
            return TryReadV4(source, isSubkey, out packet, out error);
        }

        if (version == 6)
        {
            return TryReadV6(source, isSubkey, out packet, out error);
        }

        error = $"Unsupported secret key version: {version}. Only versions 4 and 6 are supported.";
        return false;
    }

    private static bool TryReadV4(ReadOnlySpan<byte> source, bool isSubkey, out PgpSecretKeyPacket packet, out string error)
    {
        packet = default;

        // First, read the public key portion
        // V4 public: version(1) + creation(4) + algorithm(1) = 6 minimum
        if (source.Length < 7) // Need at least public header + s2k usage
        {
            error = "Source too short for v4 secret key packet.";
            return false;
        }

        // Read public key header
        int offset = 0;
        byte version = source[offset++];
        uint creationTimestamp = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;
        var algorithm = (PgpPublicKeyAlgorithm)source[offset++];

        var creationTime = DateTimeOffset.FromUnixTimeSeconds(creationTimestamp);

        // Find where secret key portion starts by parsing public key material
        int publicKeyMaterialStart = offset;
        if (!TrySkipPublicKeyMaterial(source.Slice(offset), algorithm, out int publicKeyMaterialLength, out error))
        {
            return false;
        }

        offset += publicKeyMaterialLength;

        var publicKeyMaterial = source.Slice(publicKeyMaterialStart, publicKeyMaterialLength).ToArray();
        var publicKey = new PgpPublicKeyPacket(version, creationTime, algorithm, publicKeyMaterial, isSubkey);

        // Read S2K usage
        if (source.Length <= offset)
        {
            error = "Source too short for S2K usage byte.";
            return false;
        }

        var s2kUsage = (PgpS2KUsage)source[offset++];

        if (s2kUsage == PgpS2KUsage.None)
        {
            // Unencrypted: remaining is MPIs + 2-byte checksum
            var remaining = source.Slice(offset);
            if (remaining.Length < 2)
            {
                error = "Source too short for unencrypted secret key checksum.";
                return false;
            }

            // Validate checksum: sum of all MPI bytes mod 65536
            var mpiData = remaining.Slice(0, remaining.Length - 2);
            var expectedChecksum = BinaryPrimitives.ReadUInt16BigEndian(remaining.Slice(remaining.Length - 2));
            ushort actualChecksum = 0;
            foreach (byte b in mpiData)
            {
                actualChecksum = (ushort)((actualChecksum + b) & 0xFFFF);
            }

            if (actualChecksum != expectedChecksum)
            {
                error = $"Secret key checksum mismatch. Expected {expectedChecksum:X4}, got {actualChecksum:X4}.";
                return false;
            }

            var secretMaterial = remaining.ToArray();
            packet = new PgpSecretKeyPacket(publicKey, s2kUsage, 0, null, Array.Empty<byte>(), secretMaterial);
            return true;
        }

        // Encrypted: need cipher algorithm
        if (source.Length <= offset)
        {
            error = "Source too short for cipher algorithm.";
            return false;
        }

        byte cipherAlgorithm = source[offset++];

        // Read S2K specifier
        if (!PgpS2KSpecifier.TryRead(source.Slice(offset), out var s2kSpec, out int s2kLength, out error))
        {
            return false;
        }

        offset += s2kLength;

        // Read IV (size depends on cipher algorithm)
        int ivSize = GetCipherBlockSize(cipherAlgorithm);
        if (source.Length < offset + ivSize)
        {
            error = "Source too short for IV.";
            return false;
        }

        var iv = source.Slice(offset, ivSize).ToArray();
        offset += ivSize;

        // Remaining is encrypted secret key material
        var encryptedMaterial = source.Slice(offset).ToArray();

        packet = new PgpSecretKeyPacket(publicKey, s2kUsage, cipherAlgorithm, s2kSpec, iv, encryptedMaterial);
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, bool isSubkey, out PgpSecretKeyPacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        // V6 public: version(1) + creation(4) + algorithm(1) + keylen(4) = 10 minimum
        if (source.Length < 11) // Need at least public header + s2k usage
        {
            error = "Source too short for v6 secret key packet.";
            return false;
        }

        // Read public key header
        int offset = 0;
        byte version = source[offset++];
        uint creationTimestamp = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;
        var algorithm = (PgpPublicKeyAlgorithm)source[offset++];
        uint publicKeyLength = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;

        if (publicKeyLength > int.MaxValue || source.Length < offset + (int)publicKeyLength + 1)
        {
            error = "Source too short for public key material and S2K usage.";
            return false;
        }

        var creationTime = DateTimeOffset.FromUnixTimeSeconds(creationTimestamp);
        var publicKeyMaterial = source.Slice(offset, (int)publicKeyLength).ToArray();
        offset += (int)publicKeyLength;

        var publicKey = new PgpPublicKeyPacket(version, creationTime, algorithm, publicKeyMaterial, isSubkey);

        // V6 has 1-byte scalar for secret key data count
        byte s2kUsage = source[offset++];

        if (s2kUsage == 0)
        {
            // V6 unencrypted: 1-byte count of optional S2K data (0), then plaintext + checksum
            var remaining = source.Slice(offset);
            if (remaining.Length < 2)
            {
                error = "Source too short for unencrypted secret key checksum.";
                return false;
            }

            // Validate checksum: sum of all MPI bytes mod 65536
            var mpiData = remaining.Slice(0, remaining.Length - 2);
            var expectedChecksum = BinaryPrimitives.ReadUInt16BigEndian(remaining.Slice(remaining.Length - 2));
            ushort actualChecksum = 0;
            foreach (byte b in mpiData)
            {
                actualChecksum = (ushort)((actualChecksum + b) & 0xFFFF);
            }

            if (actualChecksum != expectedChecksum)
            {
                error = $"Secret key checksum mismatch. Expected {expectedChecksum:X4}, got {actualChecksum:X4}.";
                return false;
            }

            var secretMaterial = remaining.ToArray();
            packet = new PgpSecretKeyPacket(publicKey, PgpS2KUsage.None, 0, null, Array.Empty<byte>(), secretMaterial);
            return true;
        }

        // V6 encrypted: scalar count includes cipher + S2K length
        // Read cipher algorithm
        if (source.Length <= offset)
        {
            error = "Source too short for cipher algorithm.";
            return false;
        }

        byte cipherAlgorithm = source[offset++];

        // For AEAD (253), there's an AEAD algorithm byte too
        byte aeadAlgorithm = 0;
        if (s2kUsage == (byte)PgpS2KUsage.Aead)
        {
            if (source.Length <= offset)
            {
                error = "Source too short for AEAD algorithm.";
                return false;
            }

            aeadAlgorithm = source[offset++];
        }

        // Read S2K specifier
        if (!PgpS2KSpecifier.TryRead(source.Slice(offset), out var s2kSpec, out int s2kLength, out error))
        {
            return false;
        }

        offset += s2kLength;

        // Read IV/nonce
        int ivSize = s2kUsage == (byte)PgpS2KUsage.Aead
            ? GetAeadNonceSize(aeadAlgorithm)
            : GetCipherBlockSize(cipherAlgorithm);

        if (source.Length < offset + ivSize)
        {
            error = "Source too short for IV/nonce.";
            return false;
        }

        var iv = source.Slice(offset, ivSize).ToArray();
        offset += ivSize;

        // Remaining is encrypted secret key material
        var encryptedMaterial = source.Slice(offset).ToArray();

        packet = new PgpSecretKeyPacket(publicKey, (PgpS2KUsage)s2kUsage, cipherAlgorithm, s2kSpec, iv, encryptedMaterial);
        return true;
    }

    private static bool TrySkipPublicKeyMaterial(ReadOnlySpan<byte> source, PgpPublicKeyAlgorithm algorithm, out int length, out string error)
    {
        length = 0;
        error = string.Empty;

        try
        {
            switch (algorithm)
            {
                case PgpPublicKeyAlgorithm.RsaEncryptOrSign:
#pragma warning disable CS0618 // Obsolete member
                case PgpPublicKeyAlgorithm.RsaEncryptOnly:
                case PgpPublicKeyAlgorithm.RsaSignOnly:
#pragma warning restore CS0618
                    // RSA: n + e (2 MPIs)
                    Mpi.Read(source, out int nLen);
                    Mpi.Read(source.Slice(nLen), out int eLen);
                    length = nLen + eLen;
                    return true;

                case PgpPublicKeyAlgorithm.Dsa:
                    // DSA: p + q + g + y (4 MPIs)
                    int offset = 0;
                    Mpi.Read(source, out int consumed);
                    offset += consumed;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    length = offset;
                    return true;

                case PgpPublicKeyAlgorithm.ElgamalEncryptOnly:
                    // Elgamal: p + g + y (3 MPIs)
                    offset = 0;
                    Mpi.Read(source, out consumed);
                    offset += consumed;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    length = offset;
                    return true;

                case PgpPublicKeyAlgorithm.Ecdsa:
#pragma warning disable CS0618 // Obsolete member
                case PgpPublicKeyAlgorithm.EdDsaLegacy:
#pragma warning restore CS0618
                    // ECDSA/EdDSA-legacy: OID length + OID + Q (MPI)
                    if (source.Length < 2)
                    {
                        error = "Source too short for EC OID.";
                        return false;
                    }

                    int oidLen = source[0];
                    offset = 1 + oidLen;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    length = offset;
                    return true;

                case PgpPublicKeyAlgorithm.Ecdh:
                    // ECDH: OID length + OID + Q (MPI) + KDF params (4 bytes)
                    if (source.Length < 2)
                    {
                        error = "Source too short for ECDH OID.";
                        return false;
                    }

                    oidLen = source[0];
                    offset = 1 + oidLen;
                    Mpi.Read(source.Slice(offset), out consumed);
                    offset += consumed;
                    offset += 4; // KDF params
                    length = offset;
                    return true;

                case PgpPublicKeyAlgorithm.Ed25519:
                case PgpPublicKeyAlgorithm.X25519:
                    length = 32;
                    return true;

                case PgpPublicKeyAlgorithm.Ed448:
                    length = 57;
                    return true;

                case PgpPublicKeyAlgorithm.X448:
                    length = 56;
                    return true;

                case PgpPublicKeyAlgorithm.Reserved20:
                case PgpPublicKeyAlgorithm.Reserved21:
                case PgpPublicKeyAlgorithm.Private100:
                case PgpPublicKeyAlgorithm.Private101:
                case PgpPublicKeyAlgorithm.Private110:
                default:
                    error = $"Unknown or unsupported public key algorithm: {algorithm}";
                    return false;
            }
        }
        catch (Exception ex)
        {
            error = $"Failed to parse public key material: {ex.Message}";
            return false;
        }
    }

    private static int GetCipherBlockSize(byte cipherAlgorithm)
    {
        // RFC 4880 symmetric cipher block sizes
        return cipherAlgorithm switch
        {
            1 => 8,  // IDEA
            2 => 8,  // 3DES
            3 => 8,  // CAST5
            4 => 8,  // Blowfish
            7 => 16, // AES-128
            8 => 16, // AES-192
            9 => 16, // AES-256
            10 => 16, // Twofish
            11 => 16, // Camellia-128
            12 => 16, // Camellia-192
            13 => 16, // Camellia-256
            _ => throw new ArgumentException($"Unknown cipher algorithm: {cipherAlgorithm}. Cannot determine block size.", nameof(cipherAlgorithm))
        };
    }

    private static int GetAeadNonceSize(byte aeadAlgorithm)
    {
        // RFC 9580 AEAD nonce sizes
        return aeadAlgorithm switch
        {
            1 => 15, // EAX
            2 => 12, // OCB
            3 => 12, // GCM
            _ => 12  // Default
        };
    }

    /// <summary>
    /// Gets the total encoded length of this packet's body.
    /// </summary>
    public int GetEncodedLength()
    {
        int length = PublicKey.GetEncodedLength();
        length += 1; // S2K usage

        if (S2KUsage != PgpS2KUsage.None)
        {
            length += 1; // Cipher algorithm
            if (S2KSpecifier.HasValue)
            {
                length += S2KSpecifier.Value.GetEncodedLength();
            }

            length += IV.Length;
        }

        length += SecretKeyMaterial.Length;
        return length;
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    public int Write(Span<byte> destination)
    {
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            throw new ArgumentException($"Destination too small. Need {encodedLength} bytes.", nameof(destination));
        }

        int offset = PublicKey.Write(destination);

        destination[offset++] = (byte)S2KUsage;

        if (S2KUsage != PgpS2KUsage.None)
        {
            destination[offset++] = CipherAlgorithm;
            if (S2KSpecifier.HasValue)
            {
                offset += S2KSpecifier.Value.Write(destination.Slice(offset));
            }

            IV.Span.CopyTo(destination.Slice(offset));
            offset += IV.Length;
        }

        SecretKeyMaterial.Span.CopyTo(destination.Slice(offset));
        offset += SecretKeyMaterial.Length;

        return offset;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    public byte[] ToArray()
    {
        byte[] result = new byte[GetEncodedLength()];
        Write(result);
        return result;
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        var tag = IsSubkey ? PgpPacketTag.SecretSubkey : PgpPacketTag.SecretKey;
        writer.WritePacket(tag, body, format);
    }

    /// <summary>
    /// Computes the key fingerprint (from the public key portion).
    /// </summary>
    public byte[] ComputeFingerprint() => PublicKey.ComputeFingerprint();

    /// <summary>
    /// Gets the key ID (from the public key portion).
    /// </summary>
    public byte[] GetKeyId() => PublicKey.GetKeyId();

    /// <summary>
    /// Reads unencrypted RSA secret key material.
    /// </summary>
    /// <returns>A tuple of RSA private parameters (d, p, q, u).</returns>
    /// <exception cref="InvalidOperationException">If encrypted or not RSA.</exception>
    public (BigInteger D, BigInteger P, BigInteger Q, BigInteger U) ReadRsaSecretKey()
    {
        if (IsEncrypted)
        {
            throw new InvalidOperationException("Cannot read encrypted secret key material. Decrypt first.");
        }

        if (Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOrSign &&
#pragma warning disable CS0618 // Obsolete member
            Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOnly &&
            Algorithm != PgpPublicKeyAlgorithm.RsaSignOnly)
#pragma warning restore CS0618
        {
            throw new InvalidOperationException($"Cannot read RSA secret key from algorithm {Algorithm}.");
        }

        var span = SecretKeyMaterial.Span;
        int offset = 0;

        var d = Mpi.Read(span.Slice(offset), out int consumed);
        offset += consumed;
        var p = Mpi.Read(span.Slice(offset), out consumed);
        offset += consumed;
        var q = Mpi.Read(span.Slice(offset), out consumed);
        offset += consumed;
        var u = Mpi.Read(span.Slice(offset), out _);

        return (d, p, q, u);
    }

    /// <summary>
    /// Reads unencrypted DSA/Elgamal secret key material.
    /// </summary>
    /// <returns>The secret exponent x.</returns>
    /// <exception cref="InvalidOperationException">If encrypted or incompatible algorithm.</exception>
    public BigInteger ReadDsaOrElgamalSecretKey()
    {
        if (IsEncrypted)
        {
            throw new InvalidOperationException("Cannot read encrypted secret key material. Decrypt first.");
        }

        if (Algorithm != PgpPublicKeyAlgorithm.Dsa && Algorithm != PgpPublicKeyAlgorithm.ElgamalEncryptOnly)
        {
            throw new InvalidOperationException($"Cannot read DSA/Elgamal secret key from algorithm {Algorithm}.");
        }

        return Mpi.Read(SecretKeyMaterial.Span, out _);
    }

    /// <summary>
    /// Reads unencrypted EC secret key material.
    /// </summary>
    /// <returns>The secret scalar d.</returns>
    /// <exception cref="InvalidOperationException">If encrypted or not an EC algorithm.</exception>
    public byte[] ReadEcSecretKey()
    {
        if (IsEncrypted)
        {
            throw new InvalidOperationException("Cannot read encrypted secret key material. Decrypt first.");
        }

        if (Algorithm.UsesNativeFormat())
        {
            // Native format: raw bytes
            int expectedSize = Algorithm.GetNativeSecretKeySize();
            if (SecretKeyMaterial.Length < expectedSize)
            {
                throw new InvalidOperationException($"Invalid secret key size. Expected at least {expectedSize} bytes.");
            }

            return SecretKeyMaterial.Span.Slice(0, expectedSize).ToArray();
        }

        if (Algorithm.UsesOidEncoding())
        {
            // OID format: MPI-encoded scalar
            return Mpi.ReadBytes(SecretKeyMaterial.Span, out _);
        }

        throw new InvalidOperationException($"Cannot read EC secret key from algorithm {Algorithm}.");
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        var keyType = IsSubkey ? "Subkey" : "Key";
        var encStatus = IsEncrypted ? "encrypted" : "unencrypted";
        var fingerprint = Convert.ToHexString(GetKeyId());
        return $"Secret{keyType}(v{Version}, {Algorithm}, {CreationTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}, {encStatus}, ID:{fingerprint})";
    }
}
