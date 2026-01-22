using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Symmetric-Key Encrypted Session Key (SKESK) Packet (Tag 3) as defined
/// in RFC 4880 Section 5.3 and RFC 9580.
/// </summary>
/// <remarks>
/// <para>
/// A Symmetric-Key Encrypted Session Key packet contains the session key used to
/// encrypt a message, encrypted with a passphrase-derived key using String-to-Key (S2K).
/// </para>
/// <para>
/// <b>Wire format (v4):</b>
/// <code>
/// +----------+-----------+----------------+----------------------+
/// | Version  | Algorithm | S2K Specifier  | Encrypted Session Key|
/// | 1 byte   |  1 byte   |   variable     |  optional/variable   |
/// +----------+-----------+----------------+----------------------+
/// </code>
/// </para>
/// <para>
/// <b>Wire format (v6 - RFC 9580):</b>
/// <code>
/// +----------+-------+-----------+------+-------+----------------+----+----------------------+
/// | Version  | Count | Algorithm | AEAD | S2KCnt| S2K Specifier  | IV | Encrypted SK + Tag   |
/// | 1 byte   |1 byte |  1 byte   |1 byte|1 byte |   variable     |var |      variable        |
/// +----------+-------+-----------+------+-------+----------------+----+----------------------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpSymmetricKeyEncryptedSessionKeyPacket : IEquatable<PgpSymmetricKeyEncryptedSessionKeyPacket>
{
    /// <summary>
    /// Version 4 packet (RFC 4880).
    /// </summary>
    public const int Version4 = 4;

    /// <summary>
    /// Version 6 packet (RFC 9580).
    /// </summary>
    public const int Version6 = 6;

    /// <summary>
    /// Minimum packet size for v4: version (1) + algorithm (1) + s2k type (1).
    /// </summary>
    public const int MinSizeV4 = 3;

    /// <summary>
    /// Minimum packet size for v6: version (1) + count (1) + algorithm (1) + aead (1) + s2k count (1).
    /// </summary>
    public const int MinSizeV6 = 5;

    /// <summary>
    /// Gets the version number.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Gets the symmetric cipher algorithm.
    /// </summary>
    public SymmetricCipherAlgorithm CipherAlgorithm { get; }

    /// <summary>
    /// Gets the AEAD algorithm (v6 only).
    /// </summary>
    public AeadAlgorithm AeadAlgorithm { get; }

    /// <summary>
    /// Gets the S2K specifier data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The S2K specifier defines how the passphrase is converted to a key.
    /// The format depends on the S2K type (first byte): Simple (0), Salted (1),
    /// Iterated and Salted (3), or Argon2 (4).
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> S2kSpecifier { get; }

    /// <summary>
    /// Gets the initialization vector (v6 only).
    /// </summary>
    public ReadOnlyMemory<byte> IV { get; }

    /// <summary>
    /// Gets the encrypted session key data.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For v4: Optional. If present, contains the encrypted session key.
    /// If absent, the S2K-derived key is used directly.
    /// </para>
    /// <para>
    /// For v6: Contains the AEAD-encrypted session key with authentication tag.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> EncryptedSessionKey { get; }

    /// <summary>
    /// Initializes a new v4 SKESK packet.
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="s2kSpecifier">The S2K specifier data.</param>
    /// <param name="encryptedSessionKey">The encrypted session key (optional).</param>
    public PgpSymmetricKeyEncryptedSessionKeyPacket(
        SymmetricCipherAlgorithm cipherAlgorithm,
        ReadOnlyMemory<byte> s2kSpecifier,
        ReadOnlyMemory<byte> encryptedSessionKey = default)
    {
        Version = Version4;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = AeadAlgorithm.None;
        S2kSpecifier = s2kSpecifier;
        IV = ReadOnlyMemory<byte>.Empty;
        EncryptedSessionKey = encryptedSessionKey;
    }

    /// <summary>
    /// Initializes a new v6 SKESK packet.
    /// </summary>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="aeadAlgorithm">The AEAD algorithm.</param>
    /// <param name="s2kSpecifier">The S2K specifier data.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <param name="encryptedSessionKey">The AEAD-encrypted session key with tag.</param>
    public PgpSymmetricKeyEncryptedSessionKeyPacket(
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        ReadOnlyMemory<byte> s2kSpecifier,
        ReadOnlyMemory<byte> iv,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        Version = Version6;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        S2kSpecifier = s2kSpecifier;
        IV = iv;
        EncryptedSessionKey = encryptedSessionKey;
    }

    // Internal constructor for reading
    private PgpSymmetricKeyEncryptedSessionKeyPacket(
        int version,
        SymmetricCipherAlgorithm cipherAlgorithm,
        AeadAlgorithm aeadAlgorithm,
        ReadOnlyMemory<byte> s2kSpecifier,
        ReadOnlyMemory<byte> iv,
        ReadOnlyMemory<byte> encryptedSessionKey)
    {
        Version = version;
        CipherAlgorithm = cipherAlgorithm;
        AeadAlgorithm = aeadAlgorithm;
        S2kSpecifier = s2kSpecifier;
        IV = iv;
        EncryptedSessionKey = encryptedSessionKey;
    }

    /// <summary>
    /// Reads a SKESK packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ArgumentException">If the source is invalid.</exception>
    public static PgpSymmetricKeyEncryptedSessionKeyPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a SKESK packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpSymmetricKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for SKESK packet.";
            return false;
        }

        int version = source[0];

        if (version == Version4)
        {
            return TryReadV4(source, out packet, out error);
        }
        else if (version == Version6)
        {
            return TryReadV6(source, out packet, out error);
        }
        else
        {
            error = $"Unsupported SKESK version {version}. Supported: 4, 6.";
            return false;
        }
    }

    private static bool TryReadV4(ReadOnlySpan<byte> source, out PgpSymmetricKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < MinSizeV4)
        {
            error = $"Source too short for v4 SKESK packet. Need at least {MinSizeV4} bytes.";
            return false;
        }

        var cipherAlgorithm = (SymmetricCipherAlgorithm)source[1];

        // Parse S2K specifier
        if (!TryGetS2kLength(source.Slice(2), out int s2kLength, out error))
        {
            return false;
        }

        if (source.Length < 2 + s2kLength)
        {
            error = "Source too short for v4 SKESK S2K specifier.";
            return false;
        }

        var s2kSpecifier = source.Slice(2, s2kLength).ToArray();
        var encryptedSessionKey = source.Slice(2 + s2kLength).ToArray();

        packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
            Version4,
            cipherAlgorithm,
            AeadAlgorithm.None,
            s2kSpecifier,
            ReadOnlyMemory<byte>.Empty,
            encryptedSessionKey);
        error = string.Empty;
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, out PgpSymmetricKeyEncryptedSessionKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < MinSizeV6)
        {
            error = $"Source too short for v6 SKESK packet. Need at least {MinSizeV6} bytes.";
            return false;
        }

        int count = source[1];
        if (source.Length < 2 + count)
        {
            error = "Source too short for v6 SKESK packet fields.";
            return false;
        }

        var cipherAlgorithm = (SymmetricCipherAlgorithm)source[2];
        var aeadAlgorithm = (AeadAlgorithm)source[3];

        // S2K count byte at offset 4
        // S2K specifier follows
        if (!TryGetS2kLength(source.Slice(5), out int s2kLength, out error))
        {
            return false;
        }

        int ivOffset = 5 + s2kLength;
        int ivLength = GetIvLength(aeadAlgorithm);

        if (source.Length < ivOffset + ivLength)
        {
            error = "Source too short for v6 SKESK IV.";
            return false;
        }

        var s2kSpecifier = source.Slice(5, s2kLength).ToArray();
        var iv = source.Slice(ivOffset, ivLength).ToArray();
        var encryptedSessionKey = source.Slice(ivOffset + ivLength).ToArray();

        packet = new PgpSymmetricKeyEncryptedSessionKeyPacket(
            Version6,
            cipherAlgorithm,
            aeadAlgorithm,
            s2kSpecifier,
            iv,
            encryptedSessionKey);
        error = string.Empty;
        return true;
    }

    private static bool TryGetS2kLength(ReadOnlySpan<byte> s2kData, out int length, out string error)
    {
        length = 0;
        error = string.Empty;

        if (s2kData.Length < 1)
        {
            error = "S2K data too short.";
            return false;
        }

        byte s2kType = s2kData[0];

        // S2K length depends on type (RFC 4880 Section 3.7, RFC 9580 Section 3.7.1.4)
        // Type 0 (Simple): 2 bytes (type + hash)
        // Type 1 (Salted): 10 bytes (type + hash + 8-byte salt)
        // Type 3 (Iterated): 11 bytes (type + hash + 8-byte salt + count)
        // Type 4 (Argon2): 20 bytes (type + 16-byte salt + t + p + m)
        length = s2kType switch
        {
            0 => 2,  // Simple S2K
            1 => 10, // Salted S2K
            3 => 11, // Iterated and Salted S2K
            4 => 20, // Argon2 S2K (RFC 9580)
            _ => 2   // Unknown, assume minimal
        };

        return true;
    }

    private static int GetIvLength(AeadAlgorithm aeadAlgorithm)
    {
        return aeadAlgorithm switch
        {
            AeadAlgorithm.Eax => 16,
            AeadAlgorithm.Ocb => 15,
            AeadAlgorithm.Gcm => 12,
            _ => 0
        };
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        if (Version == Version4)
        {
            return 1 + 1 + S2kSpecifier.Length + EncryptedSessionKey.Length;
        }
        else
        {
            // v6: version + count + algorithm + aead + s2k count (1) + s2k + iv + encrypted
            int fieldsLength = 1 + 1 + 1 + S2kSpecifier.Length + IV.Length;
            return 1 + 1 + fieldsLength + EncryptedSessionKey.Length;
        }
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            throw new ArgumentException($"Destination too small. Need {encodedLength} bytes.", nameof(destination));
        }

        int offset = 0;
        destination[offset++] = (byte)Version;

        if (Version == Version4)
        {
            destination[offset++] = (byte)CipherAlgorithm;
            S2kSpecifier.Span.CopyTo(destination.Slice(offset));
            offset += S2kSpecifier.Length;
        }
        else
        {
            // v6 format
            int fieldsLength = 1 + 1 + 1 + S2kSpecifier.Length + IV.Length;
            destination[offset++] = (byte)fieldsLength;
            destination[offset++] = (byte)CipherAlgorithm;
            destination[offset++] = (byte)AeadAlgorithm;
            destination[offset++] = 0; // S2K count byte (placeholder)
            S2kSpecifier.Span.CopyTo(destination.Slice(offset));
            offset += S2kSpecifier.Length;
            IV.Span.CopyTo(destination.Slice(offset));
            offset += IV.Length;
        }

        EncryptedSessionKey.Span.CopyTo(destination.Slice(offset));

        return encodedLength;
    }

    /// <summary>
    /// Tries to write the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <param name="bytesWritten">The number of bytes written if successful.</param>
    /// <returns>True if the write was successful; false if the destination is too small.</returns>
    public bool TryWrite(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            return false;
        }

        bytesWritten = Write(destination);
        return true;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The encoded packet body.</returns>
    public byte[] ToArray()
    {
        var result = new byte[GetEncodedLength()];
        Write(result);
        return result;
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.SymmetricKeyEncryptedSessionKey, body, format);
    }

    /// <summary>
    /// Decrypts the session key using the provided passphrase.
    /// </summary>
    /// <param name="passphrase">The passphrase bytes.</param>
    /// <returns>The decrypted session key.</returns>
    /// <exception cref="CryptographicException">If decryption fails.</exception>
    /// <remarks>
    /// <para>
    /// For v4 packets without an encrypted session key, the S2K-derived key is returned directly.
    /// For v4 packets with an encrypted session key, the S2K-derived key is used to decrypt it.
    /// For v6 packets, AEAD decryption is used.
    /// </para>
    /// </remarks>
    public byte[] DecryptSessionKey(ReadOnlySpan<byte> passphrase)
    {
        // Parse S2K parameters
        var s2kParams = S2KParameters.Parse(S2kSpecifier.Span);

        // Get the key size for this cipher
        int keySize = GetKeySize(CipherAlgorithm);

        // Derive the key encryption key (KEK) from the passphrase
        var kek = s2kParams.DeriveKey(passphrase, keySize);

        try
        {
            if (Version == Version4)
            {
                return DecryptSessionKeyV4(kek);
            }
            else
            {
                return DecryptSessionKeyV6(kek);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(kek);
        }
    }

    private byte[] DecryptSessionKeyV4(byte[] kek)
    {
        // If no encrypted session key, the KEK IS the session key
        if (EncryptedSessionKey.Length == 0)
        {
            // Return a copy since kek will be cleared
            var sessionKey = new byte[kek.Length];
            kek.CopyTo(sessionKey, 0);
            return sessionKey;
        }

        // Decrypt the session key using CFB mode with zero IV (OpenPGP style)
        // The encrypted data is: cipher_algorithm_byte || session_key || checksum
        var encryptedData = EncryptedSessionKey.Span;

        // Use CFB mode to decrypt
        var decrypted = DecryptCfb(encryptedData, kek, CipherAlgorithm);

        try
        {
            // First byte is the algorithm, followed by key, then 2-byte checksum
            if (decrypted.Length < 3)
            {
                throw new CryptographicException("Decrypted session key data too short.");
            }

            var algorithm = (SymmetricCipherAlgorithm)decrypted[0];
            int sessionKeySize = GetKeySize(algorithm);

            if (decrypted.Length < 1 + sessionKeySize + 2)
            {
                throw new CryptographicException($"Decrypted session key data too short for {algorithm}.");
            }

            var sessionKey = new byte[sessionKeySize];
            Array.Copy(decrypted, 1, sessionKey, 0, sessionKeySize);

            // Verify checksum (sum of all key bytes mod 65536)
            int checksum = 0;
            for (int i = 0; i < sessionKeySize; i++)
            {
                checksum += sessionKey[i];
            }
            checksum &= 0xFFFF;

            int storedChecksum = (decrypted[1 + sessionKeySize] << 8) | decrypted[1 + sessionKeySize + 1];

            if (checksum != storedChecksum)
            {
                SecureMemoryOperations.SecureClear(sessionKey);
                throw new CryptographicException("Session key checksum verification failed. Incorrect passphrase?");
            }

            return sessionKey;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(decrypted);
        }
    }

    private byte[] DecryptSessionKeyV6(byte[] kek)
    {
#if NETSTANDARD2_0
        throw new PlatformNotSupportedException("AEAD decryption requires .NET Core 3.0 or later.");
#else
        if (AeadAlgorithm != AeadAlgorithm.Gcm)
        {
            throw new NotSupportedException($"AEAD algorithm {AeadAlgorithm} is not yet supported for SKESK v6. Only GCM is currently implemented.");
        }

        const int tagSize = 16;
        var encryptedData = EncryptedSessionKey.Span;

        if (encryptedData.Length <= tagSize)
        {
            throw new CryptographicException("Encrypted session key data too short.");
        }

        int ciphertextLength = encryptedData.Length - tagSize;
        var ciphertext = encryptedData[..ciphertextLength];
        var tag = encryptedData[ciphertextLength..];

        byte[] plaintext = new byte[ciphertextLength];

        using var aesGcm = new System.Security.Cryptography.AesGcm(kek, tagSize);
        // IDE0301 suppressed: using [] causes ambiguity between byte[] and Span<byte> overloads
#pragma warning disable IDE0301
        aesGcm.Decrypt(
            nonce: IV.Span,
            ciphertext: ciphertext,
            tag: tag,
            plaintext: plaintext,
            associatedData: ReadOnlySpan<byte>.Empty);
#pragma warning restore IDE0301

        return plaintext;
#endif
    }

    private static byte[] DecryptCfb(ReadOnlySpan<byte> ciphertext, byte[] key, SymmetricCipherAlgorithm algorithm)
    {
        // OpenPGP CFB decryption with zero IV
        // Implemented manually to handle non-block-aligned input
        int blockSize = GetBlockSize(algorithm);
        var feedback = new byte[blockSize]; // Start with zero IV
        var plaintext = new byte[ciphertext.Length];

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        var keystreamBlock = new byte[blockSize];

        int offset = 0;
        while (offset < ciphertext.Length)
        {
            // Encrypt the feedback to get keystream
            encryptor.TransformBlock(feedback, 0, blockSize, keystreamBlock, 0);

            // Process up to one block
            int bytesToProcess = Math.Min(blockSize, ciphertext.Length - offset);
            for (int i = 0; i < bytesToProcess; i++)
            {
                plaintext[offset + i] = (byte)(ciphertext[offset + i] ^ keystreamBlock[i]);
            }

            // Update feedback with ciphertext (for full-block CFB)
            if (bytesToProcess == blockSize)
            {
                ciphertext.Slice(offset, blockSize).CopyTo(feedback);
            }
            else
            {
                // Partial block: shift feedback left and append ciphertext bytes
                Array.Copy(feedback, bytesToProcess, feedback, 0, blockSize - bytesToProcess);
                ciphertext.Slice(offset, bytesToProcess).CopyTo(feedback.AsSpan(blockSize - bytesToProcess));
            }

            offset += bytesToProcess;
        }

        return plaintext;
    }

    /// <summary>
    /// Creates a new v4 SKESK packet for password-based encryption.
    /// </summary>
    /// <param name="passphrase">The passphrase to derive the key from.</param>
    /// <param name="sessionKey">The session key to encrypt (or null to use derived key directly).</param>
    /// <param name="cipherAlgorithm">The symmetric cipher algorithm.</param>
    /// <param name="s2kType">The S2K type to use.</param>
    /// <param name="hashAlgorithm">The hash algorithm for S2K.</param>
    /// <returns>A new SKESK packet.</returns>
    public static PgpSymmetricKeyEncryptedSessionKeyPacket Create(
        ReadOnlySpan<byte> passphrase,
        byte[]? sessionKey,
        SymmetricCipherAlgorithm cipherAlgorithm = SymmetricCipherAlgorithm.Aes256,
        S2KType s2kType = S2KType.IteratedAndSalted,
        HashingAlgorithm hashAlgorithm = HashingAlgorithm.Sha256)
    {
        // Create S2K parameters
        S2KParameters s2kParams;
        if (s2kType == S2KType.Argon2)
        {
            s2kParams = S2KParameters.CreateArgon2();
        }
        else
        {
            byte encodedCount = s2kType == S2KType.IteratedAndSalted ? (byte)0xC0 : (byte)0;
#pragma warning disable CS0618 // Simple S2K needed for OpenPGP compatibility
            s2kParams = s2kType switch
            {
                S2KType.Simple => S2KParameters.CreateSimple(hashAlgorithm),
                S2KType.Salted => S2KParameters.CreateSalted(hashAlgorithm),
                S2KType.IteratedAndSalted => S2KParameters.CreateIterated(hashAlgorithm, encodedCount),
                _ => throw new ArgumentException($"Unsupported S2K type: {s2kType}", nameof(s2kType))
            };
#pragma warning restore CS0618
        }

        // Serialize S2K specifier
        var s2kSpecifier = s2kParams.Serialize();

        // Derive the key encryption key
        int keySize = GetKeySize(cipherAlgorithm);
        var kek = s2kParams.DeriveKey(passphrase, keySize);

        try
        {
            ReadOnlyMemory<byte> encryptedSessionKey;

            if (sessionKey == null)
            {
                // No session key - KEK will be used directly
                encryptedSessionKey = ReadOnlyMemory<byte>.Empty;
            }
            else
            {
                // Encrypt the session key
                // Format: algorithm_byte || session_key || 2-byte checksum
                int checksumValue = 0;
                for (int i = 0; i < sessionKey.Length; i++)
                {
                    checksumValue += sessionKey[i];
                }
                checksumValue &= 0xFFFF;

                var plaintext = new byte[1 + sessionKey.Length + 2];
                plaintext[0] = (byte)cipherAlgorithm;
                sessionKey.CopyTo(plaintext.AsSpan(1));
                plaintext[1 + sessionKey.Length] = (byte)(checksumValue >> 8);
                plaintext[1 + sessionKey.Length + 1] = (byte)(checksumValue & 0xFF);

                try
                {
                    encryptedSessionKey = EncryptCfb(plaintext, kek, cipherAlgorithm);
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(plaintext);
                }
            }

            return new PgpSymmetricKeyEncryptedSessionKeyPacket(
                cipherAlgorithm,
                s2kSpecifier,
                encryptedSessionKey);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(kek);
        }
    }

    private static byte[] EncryptCfb(byte[] plaintext, byte[] key, SymmetricCipherAlgorithm algorithm)
    {
        // OpenPGP CFB encryption with zero IV
        // Implemented manually to handle non-block-aligned input
        int blockSize = GetBlockSize(algorithm);
        var feedback = new byte[blockSize]; // Start with zero IV
        var ciphertext = new byte[plaintext.Length];

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        var keystreamBlock = new byte[blockSize];

        int offset = 0;
        while (offset < plaintext.Length)
        {
            // Encrypt the feedback to get keystream
            encryptor.TransformBlock(feedback, 0, blockSize, keystreamBlock, 0);

            // Process up to one block
            int bytesToProcess = Math.Min(blockSize, plaintext.Length - offset);
            for (int i = 0; i < bytesToProcess; i++)
            {
                ciphertext[offset + i] = (byte)(plaintext[offset + i] ^ keystreamBlock[i]);
            }

            // Update feedback with ciphertext (for full-block CFB)
            if (bytesToProcess == blockSize)
            {
                Array.Copy(ciphertext, offset, feedback, 0, blockSize);
            }
            else
            {
                // Partial block: shift feedback left and append ciphertext bytes
                Array.Copy(feedback, bytesToProcess, feedback, 0, blockSize - bytesToProcess);
                Array.Copy(ciphertext, offset, feedback, blockSize - bytesToProcess, bytesToProcess);
            }

            offset += bytesToProcess;
        }

        return ciphertext;
    }

    /// <summary>
    /// Gets the key size in bytes for a cipher algorithm.
    /// </summary>
    private static int GetKeySize(SymmetricCipherAlgorithm algorithm)
    {
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
        return algorithm switch
        {
            SymmetricCipherAlgorithm.Idea => 16,
            SymmetricCipherAlgorithm.TripleDes => 24,
            SymmetricCipherAlgorithm.Cast5 => 16,
            SymmetricCipherAlgorithm.Blowfish => 16,
            SymmetricCipherAlgorithm.Aes128 => 16,
            SymmetricCipherAlgorithm.Aes192 => 24,
            SymmetricCipherAlgorithm.Aes256 => 32,
            SymmetricCipherAlgorithm.Twofish => 32,
            SymmetricCipherAlgorithm.Camellia128 => 16,
            SymmetricCipherAlgorithm.Camellia192 => 24,
            SymmetricCipherAlgorithm.Camellia256 => 32,
            _ => throw new ArgumentException($"Unknown cipher algorithm: {algorithm}", nameof(algorithm))
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Gets the block size in bytes for a cipher algorithm.
    /// </summary>
    private static int GetBlockSize(SymmetricCipherAlgorithm algorithm)
    {
#pragma warning disable CS0618 // Suppress obsolete warning for OpenPGP compatibility
        return algorithm switch
        {
            // 64-bit block size ciphers
            SymmetricCipherAlgorithm.Idea => 8,
            SymmetricCipherAlgorithm.TripleDes => 8,
            SymmetricCipherAlgorithm.Cast5 => 8,
            SymmetricCipherAlgorithm.Blowfish => 8,
            // 128-bit block size ciphers
            SymmetricCipherAlgorithm.Aes128 => 16,
            SymmetricCipherAlgorithm.Aes192 => 16,
            SymmetricCipherAlgorithm.Aes256 => 16,
            SymmetricCipherAlgorithm.Twofish => 16,
            SymmetricCipherAlgorithm.Camellia128 => 16,
            SymmetricCipherAlgorithm.Camellia192 => 16,
            SymmetricCipherAlgorithm.Camellia256 => 16,
            _ => throw new ArgumentException($"Unknown cipher algorithm: {algorithm}", nameof(algorithm))
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        if (Version == Version4)
        {
            string eskInfo = EncryptedSessionKey.Length > 0
                ? $", ESK={EncryptedSessionKey.Length} bytes"
                : ", direct key";
            return $"SKESK(v4, {CipherAlgorithm}, S2K={S2kSpecifier.Length} bytes{eskInfo})";
        }
        else
        {
            return $"SKESK(v6, {CipherAlgorithm}, {AeadAlgorithm}, IV={IV.Length}, ESK={EncryptedSessionKey.Length} bytes)";
        }
    }

    /// <inheritdoc />
    public bool Equals(PgpSymmetricKeyEncryptedSessionKeyPacket other)
    {
        return Version == other.Version
            && CipherAlgorithm == other.CipherAlgorithm
            && AeadAlgorithm == other.AeadAlgorithm
            && S2kSpecifier.Span.SequenceEqual(other.S2kSpecifier.Span)
            && IV.Span.SequenceEqual(other.IV.Span)
            && EncryptedSessionKey.Span.SequenceEqual(other.EncryptedSessionKey.Span);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpSymmetricKeyEncryptedSessionKeyPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = 17;
            hash = hash * 31 + Version;
            hash = hash * 31 + (int)CipherAlgorithm;
            hash = hash * 31 + (int)AeadAlgorithm;
            foreach (var b in S2kSpecifier.Span)
            {
                hash = hash * 31 + b;
            }

            foreach (var b in EncryptedSessionKey.Span)
            {
                hash = hash * 31 + b;
            }

            return hash;
        }
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpSymmetricKeyEncryptedSessionKeyPacket left, PgpSymmetricKeyEncryptedSessionKeyPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpSymmetricKeyEncryptedSessionKeyPacket left, PgpSymmetricKeyEncryptedSessionKeyPacket right) => !left.Equals(right);
}
