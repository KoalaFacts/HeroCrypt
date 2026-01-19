using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for encrypting OpenPGP messages.
/// </summary>
/// <remarks>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// var encrypted = PgpMessageEncryptor.Create()
///     .AddRecipient(publicKeyRing)
///     .WithAes256()
///     .Encrypt(plaintext);
/// </code>
/// </para>
/// <para>
/// <b>Default behavior:</b>
/// <list type="bullet">
///   <item>Symmetric algorithm: AES-256</item>
///   <item>SEIPD version: 1 (CFB + MDC for compatibility)</item>
///   <item>Data format: Binary</item>
/// </list>
/// </para>
/// </remarks>
public sealed class PgpMessageEncryptor : IDisposable
{
    private readonly List<PgpPublicKeyPacket> recipients = [];
    private SymmetricCipherAlgorithm symmetricAlgorithm = SymmetricCipherAlgorithm.Aes256;
    private AeadAlgorithm aeadAlgorithm = AeadAlgorithm.None;
    private PgpCompressionAlgorithm compressionAlgorithm = PgpCompressionAlgorithm.Uncompressed;
    private PgpLiteralDataFormat dataFormat = PgpLiteralDataFormat.Binary;
    private string fileName = string.Empty;
    private DateTimeOffset fileDate = DateTimeOffset.UtcNow;
    private bool disposed;

    private PgpMessageEncryptor()
    {
    }

    /// <summary>
    /// Creates a new message encryptor.
    /// </summary>
    /// <returns>A new PgpMessageEncryptor instance.</returns>
    public static PgpMessageEncryptor Create() => new();

    #region Recipient Configuration

    /// <summary>
    /// Adds a recipient by their public key ring.
    /// </summary>
    /// <param name="keyRing">The recipient's public key ring.</param>
    /// <returns>This encryptor for chaining.</returns>
    /// <remarks>
    /// The encryption subkey will be selected automatically if available,
    /// otherwise the master key is used.
    /// </remarks>
    public PgpMessageEncryptor AddRecipient(PgpPublicKeyRing keyRing)
    {
        ThrowIfDisposed();

        // Prefer encryption-capable subkey, fall back to master key
        PgpPublicKeyPacket? encryptionKey = null;
        foreach (var subkey in keyRing.Subkeys)
        {
            if (subkey.Algorithm == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete member
                subkey.Algorithm == PgpPublicKeyAlgorithm.RsaEncryptOnly ||
#pragma warning restore CS0618
                subkey.Algorithm == PgpPublicKeyAlgorithm.X25519 ||
                subkey.Algorithm == PgpPublicKeyAlgorithm.Ecdh)
            {
                encryptionKey = subkey;
                break;
            }
        }

        if (encryptionKey == null)
        {
            encryptionKey = keyRing.MasterKey;
        }

        recipients.Add(encryptionKey.Value);
        return this;
    }

    /// <summary>
    /// Adds a recipient by their public key packet.
    /// </summary>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor AddRecipient(PgpPublicKeyPacket publicKey)
    {
        ThrowIfDisposed();
        recipients.Add(publicKey);
        return this;
    }

    #endregion

    #region Algorithm Configuration

    /// <summary>
    /// Sets the symmetric cipher algorithm.
    /// </summary>
    /// <param name="algorithm">The symmetric algorithm to use.</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor WithSymmetricAlgorithm(SymmetricCipherAlgorithm algorithm)
    {
        ThrowIfDisposed();
        symmetricAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Uses AES-128 for session key encryption.
    /// </summary>
    public PgpMessageEncryptor WithAes128() => WithSymmetricAlgorithm(SymmetricCipherAlgorithm.Aes128);

    /// <summary>
    /// Uses AES-192 for session key encryption.
    /// </summary>
    public PgpMessageEncryptor WithAes192() => WithSymmetricAlgorithm(SymmetricCipherAlgorithm.Aes192);

    /// <summary>
    /// Uses AES-256 for session key encryption (default).
    /// </summary>
    public PgpMessageEncryptor WithAes256() => WithSymmetricAlgorithm(SymmetricCipherAlgorithm.Aes256);

    /// <summary>
    /// Enables AEAD encryption (SEIPD v2) with the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The AEAD algorithm (GCM or OCB).</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor WithAead(AeadAlgorithm algorithm = AeadAlgorithm.Gcm)
    {
        ThrowIfDisposed();
        aeadAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Enables compression before encryption.
    /// </summary>
    /// <param name="algorithm">The compression algorithm.</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor WithCompression(PgpCompressionAlgorithm algorithm)
    {
        ThrowIfDisposed();
        compressionAlgorithm = algorithm;
        return this;
    }

    #endregion

    #region Metadata Configuration

    /// <summary>
    /// Sets the filename stored in the literal data packet.
    /// </summary>
    /// <param name="fileName">The filename (optional, can be empty).</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor WithFileName(string fileName)
    {
        ThrowIfDisposed();
        this.fileName = fileName ?? string.Empty;
        return this;
    }

    /// <summary>
    /// Sets the file modification date stored in the literal data packet.
    /// </summary>
    /// <param name="date">The modification date.</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor WithFileDate(DateTimeOffset date)
    {
        ThrowIfDisposed();
        fileDate = date;
        return this;
    }

    /// <summary>
    /// Sets the data format for the literal data packet.
    /// </summary>
    /// <param name="format">The data format (Binary, Text, or Utf8).</param>
    /// <returns>This encryptor for chaining.</returns>
    public PgpMessageEncryptor WithFormat(PgpLiteralDataFormat format)
    {
        ThrowIfDisposed();
        dataFormat = format;
        return this;
    }

    #endregion

    #region Encryption

    /// <summary>
    /// Encrypts the specified plaintext.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The encrypted message.</returns>
    /// <exception cref="InvalidOperationException">If no recipients have been added.</exception>
    public PgpEncryptedMessage Encrypt(ReadOnlySpan<byte> plaintext)
    {
        ThrowIfDisposed();

        if (recipients.Count == 0)
        {
            throw new InvalidOperationException("At least one recipient must be added before encryption.");
        }

        // 1. Create literal data packet and serialize with header
        var literalPacket = new PgpLiteralDataPacket(dataFormat, fileName, fileDate, plaintext.ToArray());
        byte[] literalPacketData;
        using (var literalMs = new MemoryStream())
        {
            using var literalWriter = new PgpPacketWriter(literalMs);
            literalPacket.WriteTo(literalWriter);
            literalPacketData = literalMs.ToArray();
        }

        // 2. Optionally compress
        byte[] dataToEncrypt;
        bool isCompressed = compressionAlgorithm != PgpCompressionAlgorithm.Uncompressed;

        if (isCompressed)
        {
            var compressedPacket = PgpCompressedDataPacket.Create(literalPacketData, compressionAlgorithm);
            byte[] compressedBody = compressedPacket.ToArray();
            // Write compressed packet with header
            using var compressedMs = new MemoryStream();
            using var compressedWriter = new PgpPacketWriter(compressedMs);
            compressedWriter.WritePacket(PgpPacketTag.CompressedData, compressedBody, PgpPacketFormat.New);
            dataToEncrypt = compressedMs.ToArray();
        }
        else
        {
            dataToEncrypt = literalPacketData;
        }

        // 3. Generate session key
        byte[] sessionKey = PgpKeyEncryption.GenerateSessionKey(symmetricAlgorithm);

        try
        {
            // 4. Create PKESK packets for each recipient
            var pkeskPackets = new List<byte[]>();
            foreach (var recipient in recipients)
            {
                var pkeskData = CreatePkeskPacket(recipient, sessionKey);
                pkeskPackets.Add(pkeskData);
            }

            // 5. Encrypt with SEIPD
            byte[] seipdData;
            int seipdVersion;

            if (aeadAlgorithm != AeadAlgorithm.None)
            {
                // SEIPD v2 with AEAD
                seipdData = EncryptSeipdV2(dataToEncrypt, sessionKey);
                seipdVersion = 2;
            }
            else
            {
                // SEIPD v1 with CFB + MDC
                seipdData = EncryptSeipdV1(dataToEncrypt, sessionKey);
                seipdVersion = 1;
            }

            // 6. Combine all packets
            using var output = new MemoryStream();
            using var writer = new PgpPacketWriter(output);

            foreach (var pkesk in pkeskPackets)
            {
                writer.WritePacket(PgpPacketTag.PublicKeyEncryptedSessionKey, pkesk, PgpPacketFormat.New);
            }

            writer.WritePacket(PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData, seipdData, PgpPacketFormat.New);

            // Create recipient info array from public keys
            var recipientInfos = new PgpRecipientInfo[recipients.Count];
            for (int i = 0; i < recipients.Count; i++)
            {
                recipientInfos[i] = PgpRecipientInfo.FromPublicKey(recipients[i]);
            }

            return new PgpEncryptedMessage(
                output.ToArray(),
                recipientInfos,
                seipdVersion,
                symmetricAlgorithm,
                aeadAlgorithm,
                isCompressed);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(sessionKey);
        }
    }

    /// <summary>
    /// Encrypts a text string as UTF-8.
    /// </summary>
    /// <param name="text">The text to encrypt.</param>
    /// <returns>The encrypted message.</returns>
    public PgpEncryptedMessage EncryptText(string text)
    {
        ThrowIfDisposed();
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(text);
#else
        if (text == null) throw new ArgumentNullException(nameof(text));
#endif

        return WithFormat(PgpLiteralDataFormat.Utf8).Encrypt(System.Text.Encoding.UTF8.GetBytes(text));
    }

    #endregion

    #region PKESK Creation

    private byte[] CreatePkeskPacket(PgpPublicKeyPacket recipient, byte[] sessionKey)
    {
        byte[] encryptedSessionKey;

        if (recipient.Algorithm == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete member
            recipient.Algorithm == PgpPublicKeyAlgorithm.RsaEncryptOnly)
#pragma warning restore CS0618
        {
            encryptedSessionKey = PgpKeyEncryption.EncryptSessionKeyRsa(sessionKey, symmetricAlgorithm, recipient);
        }
        else if (recipient.Algorithm == PgpPublicKeyAlgorithm.X25519)
        {
            encryptedSessionKey = PgpKeyEncryption.EncryptSessionKeyX25519(sessionKey, recipient);
        }
        else
        {
            throw new NotSupportedException($"Public key algorithm {recipient.Algorithm} is not supported for encryption.");
        }

        // Create PKESK packet based on key version
        PgpPublicKeyEncryptedSessionKeyPacket pkesk;

        if (recipient.Version == 6)
        {
            // Version 6 PKESK uses fingerprint
            pkesk = new PgpPublicKeyEncryptedSessionKeyPacket(
                recipient.Version,
                recipient.ComputeFingerprint(),
                recipient.Algorithm,
                encryptedSessionKey);
        }
        else
        {
            // Version 3 PKESK uses key ID
            pkesk = new PgpPublicKeyEncryptedSessionKeyPacket(
                recipient.GetKeyId(),
                recipient.Algorithm,
                encryptedSessionKey);
        }

        return pkesk.ToArray();
    }

    #endregion

    #region SEIPD v1 Encryption (CFB + MDC)

    private byte[] EncryptSeipdV1(byte[] plaintext, byte[] sessionKey)
    {
        int blockSize = GetBlockSize(symmetricAlgorithm);

        // Generate random prefix (block size bytes)
        byte[] prefix = new byte[blockSize + 2];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(prefix, 0, blockSize);
        }

        // Quick check: repeat last 2 bytes
        prefix[blockSize] = prefix[blockSize - 2];
        prefix[blockSize + 1] = prefix[blockSize - 1];

        // Build plaintext for MDC calculation: prefix || literal || MDC header
        // MDC header is 0xD3 0x14 (packet tag 19 new format, length 20)
        byte[] mdcHeader = [0xD3, 0x14];

        // Calculate MDC: SHA-1(prefix || plaintext || mdcHeader)
        // SHA-1 is required by RFC 4880 for SEIPD v1 MDC - we cannot use a different hash
#pragma warning disable CA5350 // SHA-1 is weak, but required by OpenPGP SEIPD v1 specification
        byte[] mdcHash;
#if NETSTANDARD2_0
        using (var sha1 = SHA1.Create())
        {
            sha1.TransformBlock(prefix, 0, prefix.Length, null, 0);
            sha1.TransformBlock(plaintext, 0, plaintext.Length, null, 0);
            sha1.TransformFinalBlock(mdcHeader, 0, mdcHeader.Length);
            mdcHash = sha1.Hash!;
        }
#else
        using (var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
        {
            sha1.AppendData(prefix);
            sha1.AppendData(plaintext);
            sha1.AppendData(mdcHeader);
            mdcHash = sha1.GetHashAndReset();
        }
#endif
#pragma warning restore CA5350

        // Full plaintext: prefix || data || MDC packet (0xD3 0x14 || hash)
        byte[] fullPlaintext = new byte[prefix.Length + plaintext.Length + 2 + 20];
        int offset = 0;
        prefix.CopyTo(fullPlaintext.AsSpan(offset));
        offset += prefix.Length;
        plaintext.CopyTo(fullPlaintext.AsSpan(offset));
        offset += plaintext.Length;
        mdcHeader.CopyTo(fullPlaintext.AsSpan(offset));
        offset += 2;
        mdcHash.CopyTo(fullPlaintext.AsSpan(offset));

        // CFB encrypt
        byte[] encrypted = CfbEncrypt(fullPlaintext, sessionKey, blockSize);

        // SEIPD v1 packet: version(1) || encrypted data
        byte[] seipdBody = new byte[1 + encrypted.Length];
        seipdBody[0] = 1; // version
        encrypted.CopyTo(seipdBody.AsSpan(1));

        return seipdBody;
    }

    private byte[] CfbEncrypt(byte[] plaintext, byte[] key, int blockSize)
    {
        // OpenPGP CFB mode per RFC 4880 Section 13.9:
        // 1. Use IV of all zeros
        // 2. Encrypt (blockSize + 2) byte prefix using normal CFB
        // 3. Resync: FR = ciphertext[2..blockSize+2]
        // 4. Continue encrypting the rest with normal CFB

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB; // We implement CFB manually for OpenPGP variant
        aes.Padding = PaddingMode.None;

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] fr = new byte[blockSize]; // Feedback register (starts as zeros - this is the IV)
        byte[] fre = new byte[blockSize]; // Encrypted feedback register

        using var encryptor = aes.CreateEncryptor();

        // Phase 1: Encrypt the (blockSize + 2) byte prefix
        int prefixLen = blockSize + 2;

        // First block of prefix (blockSize bytes)
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0);
        for (int i = 0; i < blockSize; i++)
        {
            ciphertext[i] = (byte)(plaintext[i] ^ fre[i]);
        }

        // FR = first ciphertext block for next iteration
        Array.Copy(ciphertext, 0, fr, 0, blockSize);

        // Remaining 2 bytes of prefix
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0);
        ciphertext[blockSize] = (byte)(plaintext[blockSize] ^ fre[0]);
        ciphertext[blockSize + 1] = (byte)(plaintext[blockSize + 1] ^ fre[1]);

        // Phase 2: Resync - FR = ciphertext[2..blockSize+2]
        Array.Copy(ciphertext, 2, fr, 0, blockSize);

        // Phase 3: Continue encrypting the rest of the data
        int pos = prefixLen;
        while (pos < plaintext.Length)
        {
            encryptor.TransformBlock(fr, 0, blockSize, fre, 0);

            int bytesToProcess = Math.Min(blockSize, plaintext.Length - pos);
            for (int i = 0; i < bytesToProcess; i++)
            {
                ciphertext[pos + i] = (byte)(plaintext[pos + i] ^ fre[i]);
            }

            // Normal CFB: FR = ciphertext block we just produced
            Array.Copy(ciphertext, pos, fr, 0, bytesToProcess);
            if (bytesToProcess < blockSize)
            {
                Array.Clear(fr, bytesToProcess, blockSize - bytesToProcess);
            }

            pos += bytesToProcess;
        }

        return ciphertext;
    }

    #endregion

    #region SEIPD v2 Encryption (AEAD)

    private byte[] EncryptSeipdV2(byte[] plaintext, byte[] sessionKey)
    {
        // Generate random salt (32 bytes)
        byte[] salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        // Default chunk size exponent (6 = 2^6 = 64 bytes, small for testing; typical would be 12 = 4KB)
        byte chunkSizeExponent = 12;

        // Derive message key using HKDF
        byte[] messageKey = DeriveAeadMessageKey(sessionKey, salt);

        try
        {
            // AEAD encrypt
            byte[] encryptedData = AeadEncrypt(plaintext, messageKey, salt, chunkSizeExponent);

            // Build SEIPD v2 packet body
            // version(1) + cipher(1) + aead(1) + chunkSize(1) + salt(32) + encrypted
            byte[] seipdBody = new byte[1 + 1 + 1 + 1 + 32 + encryptedData.Length];
            int offset = 0;
            seipdBody[offset++] = 2; // version
            seipdBody[offset++] = (byte)symmetricAlgorithm;
            seipdBody[offset++] = (byte)aeadAlgorithm;
            seipdBody[offset++] = chunkSizeExponent;
            salt.CopyTo(seipdBody.AsSpan(offset));
            offset += 32;
            encryptedData.CopyTo(seipdBody.AsSpan(offset));

            return seipdBody;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(messageKey);
        }
    }

    private byte[] DeriveAeadMessageKey(byte[] sessionKey, byte[] salt)
    {
        // RFC 9580: HKDF-SHA256 with info = packet tag || version || cipher || aead || chunk size
        byte[] info = [0x12, 0x02, (byte)symmetricAlgorithm, (byte)aeadAlgorithm, 12]; // tag 18, v2

        return Primitives.Hkdf.HkdfCore.DeriveKey(
            sessionKey,
            salt,
            info,
            PgpKeyEncryption.GetSessionKeySize(symmetricAlgorithm),
            System.Security.Cryptography.HashAlgorithmName.SHA256);
    }

    private byte[] AeadEncrypt(byte[] plaintext, byte[] key, byte[] salt, byte chunkSizeExponent)
    {
#if NETSTANDARD2_0
        throw new PlatformNotSupportedException("AEAD encryption requires .NET Core 3.0 or later.");
#else
        int chunkSize = 1 << chunkSizeExponent;
        int nonceSize = GetAeadNonceSize(aeadAlgorithm);
        int tagSize = 16;

        // Calculate number of chunks
        int numChunks = (plaintext.Length + chunkSize - 1) / chunkSize;
        if (numChunks == 0)
        {
            numChunks = 1;
        }

        using var output = new MemoryStream();

        // Encrypt each chunk
        for (int chunkIndex = 0; chunkIndex < numChunks; chunkIndex++)
        {
            int chunkStart = chunkIndex * chunkSize;
            int chunkLength = Math.Min(chunkSize, plaintext.Length - chunkStart);

            // Build nonce: salt prefix + chunk index (big-endian)
            byte[] nonce = new byte[nonceSize];
            int saltPrefix = Math.Min(nonceSize - 8, salt.Length);
            Array.Copy(salt, 0, nonce, 0, saltPrefix);
            // Chunk index as big-endian 64-bit
            for (int i = 0; i < 8; i++)
            {
                nonce[nonceSize - 8 + i] = (byte)((long)chunkIndex >> (56 - i * 8));
            }

            // Associated data: packet tag || version || cipher || aead || chunk size
            byte[] aad = [0x12, 0x02, (byte)symmetricAlgorithm, (byte)aeadAlgorithm, chunkSizeExponent];

            // Encrypt chunk with AEAD
            byte[] chunkPlaintext = new byte[chunkLength];
            Array.Copy(plaintext, chunkStart, chunkPlaintext, 0, chunkLength);

            byte[] ciphertext = new byte[chunkLength + tagSize];

            if (aeadAlgorithm == AeadAlgorithm.Gcm)
            {
                using var aesGcm = new System.Security.Cryptography.AesGcm(key, tagSize);
                byte[] tag = new byte[tagSize];
                aesGcm.Encrypt(nonce.AsSpan(), chunkPlaintext.AsSpan(), ciphertext.AsSpan(0, chunkLength), tag.AsSpan(), aad.AsSpan());
                tag.CopyTo(ciphertext.AsSpan(chunkLength));
            }
            else
            {
                // OCB - use custom implementation or fallback
                throw new NotSupportedException($"AEAD algorithm {aeadAlgorithm} is not yet implemented.");
            }

            output.Write(ciphertext, 0, ciphertext.Length);
        }

        // Final authentication tag (empty chunk)
        byte[] finalNonce = new byte[nonceSize];
        int finalSaltPrefix = Math.Min(nonceSize - 8, salt.Length);
        Array.Copy(salt, 0, finalNonce, 0, finalSaltPrefix);
        for (int i = 0; i < 8; i++)
        {
            finalNonce[nonceSize - 8 + i] = (byte)((long)numChunks >> (56 - i * 8));
        }

        byte[] finalAad = [0x12, 0x02, (byte)symmetricAlgorithm, (byte)aeadAlgorithm, chunkSizeExponent];

        if (aeadAlgorithm == AeadAlgorithm.Gcm)
        {
            using var aesGcm = new System.Security.Cryptography.AesGcm(key, tagSize);
            byte[] finalTag = new byte[tagSize];
            byte[] emptyPlaintext = [];
            byte[] emptyCtxt = [];
            aesGcm.Encrypt(finalNonce.AsSpan(), emptyPlaintext, emptyCtxt, finalTag.AsSpan(), finalAad.AsSpan());
            output.Write(finalTag, 0, finalTag.Length);
        }

        return output.ToArray();
#endif
    }

    #endregion

    #region Helpers

    private static int GetBlockSize(SymmetricCipherAlgorithm algorithm)
    {
        return algorithm switch
        {
            SymmetricCipherAlgorithm.Aes128 or
            SymmetricCipherAlgorithm.Aes192 or
            SymmetricCipherAlgorithm.Aes256 => 16,
            SymmetricCipherAlgorithm.TripleDes or
            SymmetricCipherAlgorithm.Cast5 or
            SymmetricCipherAlgorithm.Blowfish or
            SymmetricCipherAlgorithm.Idea => 8,
            SymmetricCipherAlgorithm.Twofish or
            SymmetricCipherAlgorithm.Camellia128 or
            SymmetricCipherAlgorithm.Camellia192 or
            SymmetricCipherAlgorithm.Camellia256 => 16,
            _ => throw new ArgumentException($"Unknown symmetric algorithm: {algorithm}", nameof(algorithm))
        };
    }

#if !NETSTANDARD2_0
    private static int GetAeadNonceSize(AeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            AeadAlgorithm.Eax => 16,
            AeadAlgorithm.Ocb => 15,
            AeadAlgorithm.Gcm => 12,
            _ => 12
        };
    }
#endif

    private void ThrowIfDisposed()
    {
#if NET8_0_OR_GREATER
        ObjectDisposedException.ThrowIf(disposed, this);
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(PgpMessageEncryptor));
        }
#endif
    }

    /// <summary>
    /// Disposes of resources.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            recipients.Clear();
            disposed = true;
        }
    }

    #endregion
}
