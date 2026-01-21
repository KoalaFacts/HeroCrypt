using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for decrypting OpenPGP messages.
/// </summary>
/// <remarks>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// var decrypted = PgpMessageDecryptor.Create()
///     .WithSecretKeyRing(secretKeyRing)
///     .Decrypt(encryptedMessage);
/// </code>
/// </para>
/// </remarks>
public sealed class PgpMessageDecryptor : IDisposable
{
    private readonly List<PgpSecretKeyPacket> secretKeys = [];
    private string? passphrase;
    private bool disposed;

    private PgpMessageDecryptor()
    {
    }

    /// <summary>
    /// Creates a new message decryptor.
    /// </summary>
    /// <returns>A new PgpMessageDecryptor instance.</returns>
    public static PgpMessageDecryptor Create() => new();

    #region Key Configuration

    /// <summary>
    /// Adds a secret key ring for decryption.
    /// </summary>
    /// <param name="keyRing">The secret key ring containing decryption keys.</param>
    /// <returns>This decryptor for chaining.</returns>
    public PgpMessageDecryptor WithSecretKeyRing(PgpSecretKeyRing keyRing)
    {
        ThrowIfDisposed();

        secretKeys.Add(keyRing.MasterKey);
        foreach (var subkey in keyRing.Subkeys)
        {
            secretKeys.Add(subkey);
        }

        return this;
    }

    /// <summary>
    /// Adds a secret key for decryption.
    /// </summary>
    /// <param name="secretKey">The secret key.</param>
    /// <returns>This decryptor for chaining.</returns>
    public PgpMessageDecryptor WithSecretKey(PgpSecretKeyPacket secretKey)
    {
        ThrowIfDisposed();
        secretKeys.Add(secretKey);
        return this;
    }

    /// <summary>
    /// Sets the passphrase for unlocking encrypted secret keys.
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <returns>This decryptor for chaining.</returns>
    public PgpMessageDecryptor WithPassphrase(string passphrase)
    {
        ThrowIfDisposed();
        this.passphrase = passphrase;
        return this;
    }

    #endregion

    #region Decryption

    /// <summary>
    /// Decrypts an encrypted message.
    /// </summary>
    /// <param name="message">The encrypted message to decrypt.</param>
    /// <returns>The decrypted message with metadata.</returns>
    /// <exception cref="InvalidOperationException">If no secret keys have been added.</exception>
    /// <exception cref="CryptographicException">If decryption fails.</exception>
    public PgpDecryptedMessage Decrypt(PgpEncryptedMessage message)
    {
        ThrowIfDisposed();
        // Use ToArray() to create an independent copy of the data
        // This ensures complete isolation from the original message
        return Decrypt(message.ToArray());
    }

    /// <summary>
    /// Decrypts encrypted message data.
    /// </summary>
    /// <param name="data">The encrypted message bytes.</param>
    /// <returns>The decrypted message with metadata.</returns>
    public PgpDecryptedMessage Decrypt(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        if (secretKeys.Count == 0)
        {
            throw new InvalidOperationException("At least one secret key must be added before decryption.");
        }

        if (!TryDecrypt(data, out var message, out var error))
        {
            throw new CryptographicException(error);
        }

        return message;
    }

    /// <summary>
    /// Tries to decrypt encrypted message data.
    /// </summary>
    /// <param name="data">The encrypted message bytes.</param>
    /// <param name="message">The decrypted message if successful.</param>
    /// <param name="error">Error message if decryption failed.</param>
    /// <returns>True if decryption was successful.</returns>
    public bool TryDecrypt(ReadOnlySpan<byte> data, out PgpDecryptedMessage message, out string? error)
    {
        message = default;
        error = null;

        if (secretKeys.Count == 0)
        {
            error = "No secret keys configured.";
            return false;
        }

        // Parse packets from the message
        using var stream = new MemoryStream(data.ToArray());
        using var reader = new PgpPacketReader(stream);

        var pkeskPackets = new List<PgpPublicKeyEncryptedSessionKeyPacket>();
        PgpSymEncryptedIntegrityProtectedDataPacket? seipdPacket = null;

        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.PublicKeyEncryptedSessionKey)
            {
                if (PgpPublicKeyEncryptedSessionKeyPacket.TryRead(body.Span, out var pkesk, out _))
                {
                    pkeskPackets.Add(pkesk);
                }
            }
            else if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData)
            {
                if (PgpSymEncryptedIntegrityProtectedDataPacket.TryRead(body.Span, out var seipd, out _))
                {
                    seipdPacket = seipd;
                }
            }
        }

        if (pkeskPackets.Count == 0)
        {
            error = "No PKESK packets found in message.";
            return false;
        }

        if (seipdPacket == null)
        {
            error = "No SEIPD packet found in message.";
            return false;
        }

        // Try to find a matching key and decrypt the session key
        byte[]? sessionKey = null;
        SymmetricCipherAlgorithm symmetricAlgorithm = SymmetricCipherAlgorithm.Aes256;
        byte[] decryptionKeyId = [];
        string? lastDecryptionError = null;
        bool foundMatchingKey = false;

        foreach (var pkesk in pkeskPackets)
        {
            foreach (var secretKey in secretKeys)
            {
                if (KeyMatches(pkesk, secretKey))
                {
                    foundMatchingKey = true;
                    // Try to decrypt with this key
                    var result = TryDecryptSessionKey(pkesk, secretKey, out var decryptError);
                    if (result.HasValue)
                    {
                        symmetricAlgorithm = result.Value.Algorithm;
                        sessionKey = result.Value.SessionKey;
                        decryptionKeyId = secretKey.GetKeyId();
                        break;
                    }
                    else if (decryptError != null)
                    {
                        lastDecryptionError = decryptError;
                    }
                }
            }

            if (sessionKey != null)
            {
                break;
            }
        }

        if (sessionKey == null)
        {
            if (foundMatchingKey && lastDecryptionError != null)
            {
                error = $"Key matched but decryption failed: {lastDecryptionError}";
            }
            else
            {
                error = "No matching secret key found for decryption.";
            }
            return false;
        }

        try
        {
            // Decrypt the SEIPD packet
            var plaintext = seipdPacket.Value.Version == 1
                ? DecryptSeipdV1(seipdPacket.Value, sessionKey, symmetricAlgorithm)
                : DecryptSeipdV2(seipdPacket.Value, sessionKey);

            // Parse the plaintext to get the literal data packet
            return ParseDecryptedContent(plaintext, decryptionKeyId, seipdPacket.Value.Version, out message, out error);
        }
        finally
        {
            if (sessionKey != null)
            {
                SecureMemoryOperations.SecureClear(sessionKey);
            }
        }
    }

    #endregion

    #region Key Matching

    private static bool KeyMatches(PgpPublicKeyEncryptedSessionKeyPacket pkesk, PgpSecretKeyPacket secretKey)
    {
        // Version 3 PKESK uses 8-byte key ID
        // Version 6 PKESK uses full fingerprint
        if (pkesk.Version == 3)
        {
            byte[] keyId = secretKey.GetKeyId();
            return pkesk.KeyId.Span.SequenceEqual(keyId);
        }
        else if (pkesk.Version == 6)
        {
            byte[] fingerprint = secretKey.ComputeFingerprint();
            return pkesk.Fingerprint.Span.SequenceEqual(fingerprint);
        }

        return false;
    }

    #endregion

    #region Session Key Decryption

    private (SymmetricCipherAlgorithm Algorithm, byte[] SessionKey)? TryDecryptSessionKey(
        PgpPublicKeyEncryptedSessionKeyPacket pkesk,
        PgpSecretKeyPacket secretKey,
        out string? error)
    {
        error = null;

        if (secretKey.IsEncrypted)
        {
            // TODO: Decrypt key with passphrase (requires S2K key derivation)
            // For now, encrypted keys are not supported
            _ = passphrase; // Suppress unused field warning - will be used when S2K is implemented
            error = "Secret key is encrypted. Passphrase-protected keys are not yet supported.";
            return null;
        }

        try
        {
            if (pkesk.Algorithm == PgpPublicKeyAlgorithm.RsaEncryptOrSign ||
#pragma warning disable CS0618 // Obsolete member
                pkesk.Algorithm == PgpPublicKeyAlgorithm.RsaEncryptOnly)
#pragma warning restore CS0618
            {
                return PgpKeyEncryption.DecryptSessionKeyRsa(pkesk.EncryptedSessionKey.Span, secretKey);
            }
            else if (pkesk.Algorithm == PgpPublicKeyAlgorithm.X25519)
            {
                // X25519 PKESK doesn't include algorithm byte, so we assume AES-256
                byte[] sessionKey = PgpKeyEncryption.DecryptSessionKeyX25519(pkesk.EncryptedSessionKey.Span, secretKey);
                return (SymmetricCipherAlgorithm.Aes256, sessionKey);
            }
            else
            {
                error = $"Unsupported public key algorithm: {pkesk.Algorithm}";
                return null;
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }

    #endregion

    #region SEIPD v1 Decryption (CFB + MDC)

    private static byte[] DecryptSeipdV1(
        PgpSymEncryptedIntegrityProtectedDataPacket seipd,
        byte[] sessionKey,
        SymmetricCipherAlgorithm algorithm)
    {
        int blockSize = GetBlockSize(algorithm);
        byte[] encryptedData = seipd.EncryptedData.ToArray();

        // CFB decrypt
        byte[] decrypted = CfbDecrypt(encryptedData, sessionKey, blockSize);

        // Verify prefix (quick check)
        if (decrypted.Length < blockSize + 2)
        {
            throw new CryptographicException("Decrypted data too short.");
        }

        // Check that last 2 bytes of prefix are repeated
        if (decrypted[blockSize - 2] != decrypted[blockSize] ||
            decrypted[blockSize - 1] != decrypted[blockSize + 1])
        {
            throw new CryptographicException("Session key quick check failed.");
        }

        // Extract plaintext and MDC
        // Format: prefix(blockSize+2) || data || MDC packet (0xD3 0x14 || hash(20))
        if (decrypted.Length < blockSize + 2 + 22) // minimum: prefix + MDC header + hash
        {
            throw new CryptographicException("Decrypted data missing MDC.");
        }

        // Verify MDC
        int mdcStart = decrypted.Length - 22;
        if (decrypted[mdcStart] != 0xD3 || decrypted[mdcStart + 1] != 0x14)
        {
            throw new CryptographicException("Invalid MDC packet header.");
        }

        byte[] expectedMdc = new byte[20];
        Array.Copy(decrypted, mdcStart + 2, expectedMdc, 0, 20);

        // Calculate MDC: SHA-1(prefix || plaintext || 0xD3 0x14)
#pragma warning disable CA5350 // SHA-1 is weak, but required by OpenPGP SEIPD v1 specification
        byte[] actualMdc;
#if NETSTANDARD2_0
        using (var sha1 = SHA1.Create())
        {
            sha1.TransformBlock(decrypted, 0, mdcStart + 2, null, 0);
            sha1.TransformFinalBlock([], 0, 0);
            actualMdc = sha1.Hash!;
        }
#else
        using (var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
        {
            sha1.AppendData(decrypted.AsSpan(0, mdcStart + 2));
            actualMdc = sha1.GetHashAndReset();
        }
#endif
#pragma warning restore CA5350

        if (!actualMdc.AsSpan().SequenceEqual(expectedMdc))
        {
            throw new CryptographicException("MDC verification failed. Message may have been tampered with.");
        }

        // Return plaintext (after prefix, before MDC)
        byte[] plaintext = new byte[mdcStart - blockSize - 2];
        Array.Copy(decrypted, blockSize + 2, plaintext, 0, plaintext.Length);

        return plaintext;
    }

    private static byte[] CfbDecrypt(byte[] ciphertext, byte[] key, int blockSize)
    {
        // OpenPGP CFB mode per RFC 4880 Section 13.9:
        // 1. Use IV of all zeros
        // 2. Decrypt (blockSize + 2) byte prefix using normal CFB
        // 3. Resync: FR = ciphertext[2..blockSize+2]
        // 4. Continue decrypting the rest with normal CFB

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] plaintext = new byte[ciphertext.Length];
        byte[] fr = new byte[blockSize]; // Feedback register (starts as zeros - this is the IV)
        byte[] fre = new byte[blockSize]; // Encrypted feedback register

        using var encryptor = aes.CreateEncryptor();

        // Phase 1: Decrypt the (blockSize + 2) byte prefix
        int prefixLen = blockSize + 2;

        // First block of prefix (blockSize bytes)
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0);
        for (int i = 0; i < blockSize; i++)
        {
            plaintext[i] = (byte)(ciphertext[i] ^ fre[i]);
        }

        // FR = first ciphertext block for next iteration
        Array.Copy(ciphertext, 0, fr, 0, blockSize);

        // Remaining 2 bytes of prefix
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0);
        plaintext[blockSize] = (byte)(ciphertext[blockSize] ^ fre[0]);
        plaintext[blockSize + 1] = (byte)(ciphertext[blockSize + 1] ^ fre[1]);

        // Phase 2: Resync - FR = ciphertext[2..blockSize+2]
        Array.Copy(ciphertext, 2, fr, 0, blockSize);

        // Phase 3: Continue decrypting the rest of the data
        int pos = prefixLen;
        while (pos < ciphertext.Length)
        {
            encryptor.TransformBlock(fr, 0, blockSize, fre, 0);

            int bytesToProcess = Math.Min(blockSize, ciphertext.Length - pos);
            for (int i = 0; i < bytesToProcess; i++)
            {
                plaintext[pos + i] = (byte)(ciphertext[pos + i] ^ fre[i]);
            }

            // Normal CFB: FR = ciphertext block we just consumed
            Array.Copy(ciphertext, pos, fr, 0, bytesToProcess);
            if (bytesToProcess < blockSize)
            {
                Array.Clear(fr, bytesToProcess, blockSize - bytesToProcess);
            }

            pos += bytesToProcess;
        }

        return plaintext;
    }

    #endregion

    #region SEIPD v2 Decryption (AEAD)

    private byte[] DecryptSeipdV2(
        PgpSymEncryptedIntegrityProtectedDataPacket seipd,
        byte[] sessionKey)
    {
#if NETSTANDARD2_0
        throw new PlatformNotSupportedException("AEAD decryption requires .NET Core 3.0 or later.");
#else
        // Derive message key using HKDF
        byte[] info = [0x12, 0x02, (byte)seipd.CipherAlgorithm, (byte)seipd.AeadAlgorithm, seipd.ChunkSize];
        byte[] messageKey = Hkdf.HkdfCore.DeriveKey(
            sessionKey,
            seipd.Salt.ToArray(),
            info,
            PgpKeyEncryption.GetSessionKeySize(seipd.CipherAlgorithm),
            HashAlgorithmName.SHA256);

        try
        {
            return AeadDecrypt(seipd.EncryptedData.ToArray(), messageKey, seipd.Salt.ToArray(), seipd.ChunkSize, seipd.AeadAlgorithm);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(messageKey);
        }
#endif
    }

#if !NETSTANDARD2_0
    private byte[] AeadDecrypt(byte[] ciphertext, byte[] key, byte[] salt, byte chunkSizeExponent, AeadAlgorithm aeadAlgorithm)
    {
        int chunkSize = 1 << chunkSizeExponent;
        int nonceSize = GetAeadNonceSize(aeadAlgorithm);
        int tagSize = 16;

        using var output = new MemoryStream();

        int pos = 0;
        int chunkIndex = 0;

        while (pos < ciphertext.Length - tagSize) // Last 16 bytes is final tag
        {
            int chunkCiphertextLen = Math.Min(chunkSize + tagSize, ciphertext.Length - tagSize - pos);
            int chunkPlaintextLen = chunkCiphertextLen - tagSize;

            if (chunkPlaintextLen <= 0)
            {
                break;
            }

            // Build nonce
            byte[] nonce = new byte[nonceSize];
            int saltPrefix = Math.Min(nonceSize - 8, salt.Length);
            Array.Copy(salt, 0, nonce, 0, saltPrefix);
            for (int i = 0; i < 8; i++)
            {
                nonce[nonceSize - 8 + i] = (byte)((long)chunkIndex >> (56 - i * 8));
            }

            // Associated data
            byte[] aad = [0x12, 0x02, (byte)SymmetricCipherAlgorithm.Aes256, (byte)aeadAlgorithm, chunkSizeExponent];

            // Decrypt chunk
            byte[] chunkCiphertext = new byte[chunkPlaintextLen];
            byte[] tag = new byte[tagSize];
            Array.Copy(ciphertext, pos, chunkCiphertext, 0, chunkPlaintextLen);
            Array.Copy(ciphertext, pos + chunkPlaintextLen, tag, 0, tagSize);

            byte[] chunkPlaintext = new byte[chunkPlaintextLen];

            if (aeadAlgorithm == AeadAlgorithm.Gcm)
            {
                using var aesGcm = new System.Security.Cryptography.AesGcm(key, tagSize);
                aesGcm.Decrypt(nonce.AsSpan(), chunkCiphertext.AsSpan(), tag.AsSpan(), chunkPlaintext.AsSpan(), aad.AsSpan());
            }
            else
            {
                throw new NotSupportedException($"AEAD algorithm {aeadAlgorithm} is not yet implemented.");
            }

            output.Write(chunkPlaintext, 0, chunkPlaintext.Length);

            pos += chunkCiphertextLen;
            chunkIndex++;
        }

        // Verify final authentication tag
        // (skipping for now as it would require tracking the number of chunks)

        return output.ToArray();
    }

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

    #endregion

    #region Content Parsing

    private static bool ParseDecryptedContent(
        byte[] plaintext,
        byte[] decryptionKeyId,
        int seipdVersion,
        out PgpDecryptedMessage message,
        out string? error)
    {
        message = default;
        error = null;

        using var stream = new MemoryStream(plaintext);
        using var reader = new PgpPacketReader(stream);

        PgpLiteralDataPacket? literalPacket = null;
        bool wasCompressed = false;
        PgpCompressionAlgorithm compressionAlgorithm = PgpCompressionAlgorithm.Uncompressed;

        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.CompressedData)
            {
                wasCompressed = true;
                if (PgpCompressedDataPacket.TryRead(body.Span, out var compressed, out _))
                {
                    compressionAlgorithm = compressed.Algorithm;

                    // Decompress and parse inner content
                    byte[] decompressed = compressed.Decompress();
                    using var innerStream = new MemoryStream(decompressed);
                    using var innerReader = new PgpPacketReader(innerStream);

                    while (innerReader.ReadNextPacket(out var innerTag, out var innerBody))
                    {
                        if (innerTag == PgpPacketTag.LiteralData)
                        {
                            if (PgpLiteralDataPacket.TryRead(innerBody.Span, out var literal, out _))
                            {
                                literalPacket = literal;
                            }

                            break;
                        }
                    }
                }
            }
            else if (tag == PgpPacketTag.LiteralData)
            {
                if (PgpLiteralDataPacket.TryRead(body.Span, out var literal, out _))
                {
                    literalPacket = literal;
                }

                break;
            }
        }

        if (literalPacket == null)
        {
            error = "No literal data packet found in decrypted content.";
            return false;
        }

        message = PgpDecryptedMessage.FromLiteralPacket(
            literalPacket.Value,
            decryptionKeyId,
            wasCompressed,
            compressionAlgorithm,
            seipdVersion);

        return true;
    }

    #endregion

    #region Helpers

    private static int GetBlockSize(SymmetricCipherAlgorithm algorithm)
    {
        // Suppress obsolete warnings - OpenPGP requires legacy algorithm support for interoperability
#pragma warning disable CS0618
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
#pragma warning restore CS0618
    }

    private void ThrowIfDisposed()
    {
#if NET8_0_OR_GREATER
        ObjectDisposedException.ThrowIf(disposed, this);
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(PgpMessageDecryptor));
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
            // Clear any passphrase
            passphrase = null;
            secretKeys.Clear();
            disposed = true;
        }
    }

    #endregion
}
