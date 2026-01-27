using System.Security.Cryptography;
using System.Text;
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
/// <para>
/// <b>Security Note:</b> String-based passphrases cannot be securely cleared from memory
/// due to .NET string immutability. For high-security applications, use the byte array
/// overloads (e.g., <see cref="WithMessagePassphrase(byte[])"/>) and manually clear the
/// byte array after use with <see cref="SecureMemoryOperations.SecureClear(byte[])"/>.
/// </para>
/// </remarks>
public sealed class PgpMessageDecryptor : IDisposable
{
    private readonly List<PgpSecretKeyPacket> secretKeys = [];
    private readonly List<byte[]> messagePassphrases = [];
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
    /// <remarks>
    /// <b>Security Warning:</b> String passphrases cannot be securely cleared from memory.
    /// For high-security applications, decrypt the secret key separately using
    /// <see cref="PgpSecretKeyPacket.Decrypt(string)"/> and provide the decrypted key.
    /// </remarks>
    public PgpMessageDecryptor WithPassphrase(string passphrase)
    {
        ThrowIfDisposed();
        this.passphrase = passphrase;
        return this;
    }

    /// <summary>
    /// Adds a passphrase for password-based message decryption (SKESK).
    /// </summary>
    /// <param name="passphrase">The passphrase bytes.</param>
    /// <returns>This decryptor for chaining.</returns>
    /// <remarks>
    /// Use this method to decrypt messages that were encrypted with a passphrase
    /// (symmetric-key encrypted session key packets).
    /// </remarks>
    public PgpMessageDecryptor WithMessagePassphrase(byte[] passphrase)
    {
        ThrowIfDisposed();
        if (passphrase == null || passphrase.Length == 0)
        {
            throw new ArgumentException("Passphrase cannot be null or empty.", nameof(passphrase));
        }

        messagePassphrases.Add([.. passphrase]);
        return this;
    }

    /// <summary>
    /// Adds a passphrase for password-based message decryption (SKESK).
    /// </summary>
    /// <param name="passphrase">The passphrase string (UTF-8 encoded).</param>
    /// <returns>This decryptor for chaining.</returns>
    /// <remarks>
    /// <b>Security Warning:</b> String passphrases cannot be securely cleared from memory.
    /// For high-security applications, use <see cref="WithMessagePassphrase(byte[])"/> instead.
    /// </remarks>
    public PgpMessageDecryptor WithMessagePassphrase(string passphrase)
    {
        ThrowIfDisposed();
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new ArgumentException("Passphrase cannot be null or empty.", nameof(passphrase));
        }

        messagePassphrases.Add(Encoding.UTF8.GetBytes(passphrase));
        return this;
    }

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

        if (secretKeys.Count == 0 && messagePassphrases.Count == 0)
        {
            throw new InvalidOperationException("At least one secret key or message passphrase must be added before decryption.");
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

        if (secretKeys.Count == 0 && messagePassphrases.Count == 0)
        {
            error = "No secret keys or message passphrases configured.";
            return false;
        }

        // Parse packets from the message
        using var stream = new MemoryStream(data.ToArray());
        using var reader = new PgpPacketReader(stream);

        var pkeskPackets = new List<PgpPublicKeyEncryptedSessionKeyPacket>();
        var skeskPackets = new List<PgpSymmetricKeyEncryptedSessionKeyPacket>();
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
            else if (tag == PgpPacketTag.SymmetricKeyEncryptedSessionKey)
            {
                if (PgpSymmetricKeyEncryptedSessionKeyPacket.TryRead(body.Span, out var skesk, out _))
                {
                    skeskPackets.Add(skesk);
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

        if (pkeskPackets.Count == 0 && skeskPackets.Count == 0)
        {
            error = "No PKESK or SKESK packets found in message.";
            return false;
        }

        if (seipdPacket == null)
        {
            error = "No SEIPD packet found in message.";
            return false;
        }

        // Try to decrypt the session key
        byte[]? sessionKey = null;
        SymmetricCipherAlgorithm symmetricAlgorithm = SymmetricCipherAlgorithm.Aes256;
        byte[] decryptionKeyId = [];
        string? lastDecryptionError = null;
        bool foundMatchingKey = false;
        bool usedPassphrase = false;

        // First try SKESK packets with message passphrases
        if (skeskPackets.Count > 0 && messagePassphrases.Count > 0)
        {
            foreach (var skesk in skeskPackets)
            {
                foreach (var passphraseBytes in messagePassphrases)
                {
                    try
                    {
                        var decryptedKey = skesk.DecryptSessionKey(passphraseBytes);
                        if (decryptedKey.Length > 0)
                        {
                            // Session key was encrypted in SKESK
                            sessionKey = decryptedKey;
                            symmetricAlgorithm = skesk.CipherAlgorithm;
                            usedPassphrase = true;
                            break;
                        }
                        else
                        {
                            // Direct key mode - derive the key from passphrase
                            // The KEK is the session key
                            var s2kParams = S2K.S2KParameters.Parse(skesk.S2kSpecifier.Span);
                            int keySize = GetKeySize(skesk.CipherAlgorithm);
                            sessionKey = s2kParams.DeriveKey(passphraseBytes, keySize);
                            symmetricAlgorithm = skesk.CipherAlgorithm;
                            usedPassphrase = true;
                            break;
                        }
                    }
                    catch
                    {
                        // Wrong passphrase, try next
                        lastDecryptionError = "Passphrase decryption failed.";
                    }
                }

                if (sessionKey != null)
                {
                    break;
                }
            }
        }

        // If SKESK didn't work, try PKESK packets with secret keys
        if (sessionKey == null && pkeskPackets.Count > 0 && secretKeys.Count > 0)
        {
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
        }

        if (sessionKey == null)
        {
            error = usedPassphrase || (foundMatchingKey && lastDecryptionError != null)
                ? $"Decryption failed: {lastDecryptionError ?? "Unknown error"}"
                : skeskPackets.Count > 0 && messagePassphrases.Count == 0
                    ? "Message requires a passphrase for decryption. Use WithMessagePassphrase()."
                    : pkeskPackets.Count > 0 && secretKeys.Count == 0
                    ? "Message requires a secret key for decryption. Use WithSecretKey() or WithSecretKeyRing()."
                    : "No matching secret key or passphrase found for decryption.";

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

    private (SymmetricCipherAlgorithm Algorithm, byte[] SessionKey)? TryDecryptSessionKey(
        PgpPublicKeyEncryptedSessionKeyPacket pkesk,
        PgpSecretKeyPacket secretKey,
        out string? error)
    {
        error = null;

        if (secretKey.IsEncrypted)
        {
            if (string.IsNullOrEmpty(passphrase))
            {
                error = "Secret key is encrypted but no passphrase was provided. Use WithPassphrase().";
                return null;
            }

            try
            {
                // Decrypt the secret key using S2K key derivation
                secretKey = secretKey.Decrypt(passphrase!);
            }
            catch (CryptographicException)
            {
                error = "Failed to decrypt secret key. Wrong passphrase?";
                return null;
            }
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
            else if (pkesk.Algorithm == PgpPublicKeyAlgorithm.Ecdh)
            {
                // ECDH (RFC 6637) - session key includes algorithm byte
                return PgpKeyEncryption.DecryptSessionKeyEcdhCurve25519(pkesk.EncryptedSessionKey.Span, secretKey);
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

    private static byte[] DecryptSeipdV1(
        PgpSymEncryptedIntegrityProtectedDataPacket seipd,
        byte[] sessionKey,
        SymmetricCipherAlgorithm algorithm)
    {
        int blockSize = GetBlockSize(algorithm);
        byte[] encryptedData = seipd.EncryptedData.ToArray();

        // CFB decrypt
        byte[] decrypted = CfbDecrypt(encryptedData, sessionKey, blockSize, algorithm);

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

    private static byte[] CfbDecrypt(byte[] ciphertext, byte[] key, int blockSize, SymmetricCipherAlgorithm algorithm)
    {
        // OpenPGP CFB mode per RFC 4880 Section 13.9
        // Note: The "resync" described in RFC 4880 is confusingly written. In practice:
        // 1. Decrypt the blockSize+2 byte prefix using standard CFB
        // 2. After the quick check, continue CFB using the REMAINING FRE bytes
        // 3. This means we don't reset FRE, we continue from where we left off
        //
        // This is different from the literal RFC text which suggests resetting FR.
        // Implementations like BouncyCastle use the "continue with remaining FRE" approach.

        using var cipher = CreateCipher(algorithm, key);

        byte[] plaintext = new byte[ciphertext.Length];
        byte[] fr = new byte[blockSize]; // Feedback register (starts as zeros - this is the IV)
        byte[] fre = new byte[blockSize]; // Encrypted feedback register

        using var encryptor = cipher.CreateEncryptor();

        // Phase 1: Decrypt the first blockSize bytes
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0);
        for (int i = 0; i < blockSize; i++)
        {
            plaintext[i] = (byte)(ciphertext[i] ^ fre[i]);
        }

        // Update FR to first ciphertext block
        Array.Copy(ciphertext, 0, fr, 0, blockSize);

        // Encrypt FR for the quick check and continuation
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0);

        // Decrypt quick check bytes (positions blockSize and blockSize+1)
        plaintext[blockSize] = (byte)(ciphertext[blockSize] ^ fre[0]);
        plaintext[blockSize + 1] = (byte)(ciphertext[blockSize + 1] ^ fre[1]);

        // Phase 2: Continue with remaining FRE bytes (no resync reset)
        // We have fre[2..blockSize-1] still unused, use them for the first blockSize-2 bytes after prefix
        int prefixLen = blockSize + 2;
        int freOffset = 2; // We've used fre[0] and fre[1] for quick check
        int pos = prefixLen;

        // Use remaining FRE bytes for positions prefixLen to prefixLen+(blockSize-2)-1
        while (freOffset < blockSize && pos < ciphertext.Length)
        {
            plaintext[pos] = (byte)(ciphertext[pos] ^ fre[freOffset]);
            freOffset++;
            pos++;
        }

        // Update FR for continuation
        // After using all of FRE, FR should be the ciphertext that aligned with FRE
        // FRE was computed from ciphertext[0:blockSize], and was XORed with ciphertext[blockSize:2*blockSize]
        // So FR = ciphertext[blockSize:2*blockSize]
        Array.Copy(ciphertext, blockSize, fr, 0, blockSize);

        // Phase 3: Continue with standard CFB for the rest
        while (pos < ciphertext.Length)
        {
            encryptor.TransformBlock(fr, 0, blockSize, fre, 0);

            int bytesToProcess = Math.Min(blockSize, ciphertext.Length - pos);
            for (int i = 0; i < bytesToProcess; i++)
            {
                plaintext[pos + i] = (byte)(ciphertext[pos + i] ^ fre[i]);
            }

            // Update FR with the ciphertext block we just processed
            Array.Copy(ciphertext, pos, fr, 0, bytesToProcess);
            if (bytesToProcess < blockSize)
            {
                Array.Clear(fr, bytesToProcess, blockSize - bytesToProcess);
            }

            pos += bytesToProcess;
        }

        return plaintext;
    }

    /// <summary>
    /// Creates a symmetric cipher configured for CFB mode implementation.
    /// </summary>
#pragma warning disable CS0618 // TripleDes is obsolete but needed for legacy PGP support
    private static SymmetricAlgorithm CreateCipher(SymmetricCipherAlgorithm algorithm, byte[] key)
    {
        SymmetricAlgorithm cipher = algorithm switch
        {
            SymmetricCipherAlgorithm.TripleDes => CreateTripleDes(),
            SymmetricCipherAlgorithm.Aes128 or
            SymmetricCipherAlgorithm.Aes192 or
            SymmetricCipherAlgorithm.Aes256 => Aes.Create(),
            _ => throw new NotSupportedException($"Cipher algorithm {algorithm} is not supported for message decryption.")
        };

        cipher.Key = key;
        cipher.Mode = CipherMode.ECB; // We implement CFB manually
        cipher.Padding = PaddingMode.None;
        return cipher;
    }
#pragma warning restore CS0618

    /// <summary>
    /// Creates a TripleDES cipher for legacy PGP message support.
    /// </summary>
#pragma warning disable CA5350 // TripleDES is weak but needed for legacy PGP support (RFC 4880)
    private static TripleDES CreateTripleDes()
    {
        return TripleDES.Create();
    }
#pragma warning restore CA5350

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
            return AeadDecrypt(seipd.EncryptedData.ToArray(), messageKey, seipd.Salt.ToArray(), seipd.ChunkSize, seipd.AeadAlgorithm, seipd.CipherAlgorithm);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(messageKey);
        }
#endif
    }

#if !NETSTANDARD2_0
    private byte[] AeadDecrypt(byte[] ciphertext, byte[] key, byte[] salt, byte chunkSizeExponent, AeadAlgorithm aeadAlgorithm, SymmetricCipherAlgorithm cipherAlgorithm)
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
            byte[] aad = [0x12, 0x02, (byte)cipherAlgorithm, (byte)aeadAlgorithm, chunkSizeExponent];

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

        // Verify final authentication tag (RFC 9580 Section 5.13.2)
        // The final tag authenticates the total number of plaintext octets
        if (ciphertext.Length >= tagSize)
        {
            byte[] finalTag = new byte[tagSize];
            Array.Copy(ciphertext, ciphertext.Length - tagSize, finalTag, 0, tagSize);

            // Build final nonce with the total chunk count
            byte[] finalNonce = new byte[nonceSize];
            int saltPrefix = Math.Min(nonceSize - 8, salt.Length);
            Array.Copy(salt, 0, finalNonce, 0, saltPrefix);
            for (int i = 0; i < 8; i++)
            {
                finalNonce[nonceSize - 8 + i] = (byte)((long)chunkIndex >> (56 - i * 8));
            }

            // Final AAD includes the total plaintext length (big-endian, 8 bytes)
            long totalPlaintextLen = output.Length;
            byte[] finalAad = new byte[5 + 8];
            finalAad[0] = 0x12; // SEIPD v2 tag
            finalAad[1] = 0x02; // Version 2
            finalAad[2] = (byte)cipherAlgorithm;
            finalAad[3] = (byte)aeadAlgorithm;
            finalAad[4] = chunkSizeExponent;
            for (int i = 0; i < 8; i++)
            {
                finalAad[5 + i] = (byte)(totalPlaintextLen >> (56 - i * 8));
            }

            // Verify final tag (empty plaintext, just authentication)
            if (aeadAlgorithm == AeadAlgorithm.Gcm)
            {
                try
                {
                    using var aesGcm = new System.Security.Cryptography.AesGcm(key, tagSize);
                    // Decrypting empty ciphertext just verifies the tag
                    // IDE0301 suppressed: using [] causes ambiguity between byte[] and Span<byte> overloads
#pragma warning disable IDE0301
                    aesGcm.Decrypt(
                        nonce: finalNonce.AsSpan(),
                        ciphertext: ReadOnlySpan<byte>.Empty,
                        tag: finalTag.AsSpan(),
                        plaintext: Span<byte>.Empty,
                        associatedData: finalAad.AsSpan());
#pragma warning restore IDE0301
                }
                catch (AuthenticationTagMismatchException)
                {
                    throw new CryptographicException(
                        "AEAD final authentication tag verification failed. Message may have been tampered with or truncated.");
                }
            }
        }

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

    private static int GetKeySize(SymmetricCipherAlgorithm algorithm)
    {
        // Suppress obsolete warnings - OpenPGP requires legacy algorithm support for interoperability
#pragma warning disable CS0618
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

            // Securely clear message passphrases
            foreach (var msgPassphrase in messagePassphrases)
            {
                SecureMemoryOperations.SecureClear(msgPassphrase);
            }

            messagePassphrases.Clear();
            disposed = true;
        }
    }
}
