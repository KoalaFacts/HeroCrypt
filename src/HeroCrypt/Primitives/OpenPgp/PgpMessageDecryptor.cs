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
    private const string AuthenticationFailure = "Message integrity could not be verified.";
    private readonly List<PgpSecretKeyPacket> secretKeys = [];
    private readonly List<byte[]> messagePassphrases = [];
    private string? passphrase;
    private int maxDecompressedSize = PgpPacketReader.DefaultMaxPacketSize;
    private bool disposed;
    private SecurityPolicyOptions securityPolicy = SecurityPolicy.CurrentPolicy;

    private PgpMessageDecryptor()
    {
    }

    /// <summary>
    /// Creates a new message decryptor.
    /// </summary>
    /// <returns>A new PgpMessageDecryptor instance.</returns>
    public static PgpMessageDecryptor Create() => new();

    /// <summary>
    /// Sets the security policy for cryptographic validation.
    /// </summary>
    /// <param name="policy">The security policy to use.</param>
    /// <returns>This decryptor for chaining.</returns>
    public PgpMessageDecryptor WithSecurityPolicy(SecurityPolicyOptions policy)
    {
        ThrowIfDisposed();
        securityPolicy = policy;
        return this;
    }

    /// <summary>
    /// Sets the security policy for cryptographic validation.
    /// </summary>
    /// <param name="configure">Function to configure the security policy.</param>
    /// <returns>This decryptor for chaining.</returns>
    public PgpMessageDecryptor WithSecurityPolicy(Func<SecurityPolicyOptions, SecurityPolicyOptions> configure)
    {
        ThrowIfDisposed();
        securityPolicy = configure(SecurityPolicy.CurrentPolicy);
        return this;
    }

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
    /// Limits the bytes produced by a compressed packet during decryption.
    /// </summary>
    /// <param name="maximumSize">Maximum decompressed size in bytes.</param>
    /// <returns>This decryptor for chaining.</returns>
    public PgpMessageDecryptor WithMaxDecompressedSize(int maximumSize)
    {
        ThrowIfDisposed();
#if NET7_0_OR_GREATER
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumSize);
#else
        if (maximumSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumSize));
        }
#endif

        maxDecompressedSize = maximumSize;
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
        ThrowIfDisposed();
        try
        {
            return TryDecryptCore(data, out message, out error);
        }
        catch (Exception ex) when (ex is InvalidDataException or CryptographicException or ArgumentException
                                   or NotSupportedException or FormatException)
        {
            message = default;
            error = ex.Message;
            return false;
        }
    }

    private bool TryDecryptCore(ReadOnlySpan<byte> data, out PgpDecryptedMessage message, out string? error)
    {
        message = default;
        error = null;
        if (secretKeys.Count == 0 && messagePassphrases.Count == 0)
        {
            error = "No secret keys or message passphrases configured.";
            return false;
        }

        using var stream = new MemoryStream(data.ToArray());
        using var reader = new PgpPacketReader(stream);
        var pkeskPackets = new List<PgpPublicKeyEncryptedSessionKeyPacket>();
        var skeskPackets = new List<PgpSymmetricKeyEncryptedSessionKeyPacket>();
        PgpSymEncryptedIntegrityProtectedDataPacket? seipdPacket = null;
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.PublicKeyEncryptedSessionKey)
            {
                if (seipdPacket != null || !PgpPublicKeyEncryptedSessionKeyPacket.TryRead(body.Span, out var pkesk, out _))
                {
                    error = "Malformed or misplaced PKESK packet.";
                    return false;
                }

                pkeskPackets.Add(pkesk);
            }
            else if (tag == PgpPacketTag.SymmetricKeyEncryptedSessionKey)
            {
                if (seipdPacket != null || !PgpSymmetricKeyEncryptedSessionKeyPacket.TryRead(body.Span, out var skesk, out _))
                {
                    error = "Malformed or misplaced SKESK packet.";
                    return false;
                }

                skeskPackets.Add(skesk);
            }
            else if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData)
            {
                if (seipdPacket != null || !PgpSymEncryptedIntegrityProtectedDataPacket.TryRead(body.Span, out var seipd, out _))
                {
                    error = "Malformed or duplicate SEIPD packet.";
                    return false;
                }

                seipdPacket = seipd;
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

        var container = seipdPacket.Value;
        int pkeskVersion = container.Version == 1 ? 3 : 6;
        int skeskVersion = container.Version == 1 ? 4 : 6;
        if (pkeskPackets.Any(packet => packet.Version != pkeskVersion) ||
            skeskPackets.Any(packet => packet.Version != skeskVersion))
        {
            error = "Session key packet versions do not match the SEIPD version.";
            return false;
        }

        // A derived or unwrapped key is only a candidate. Authenticate its entire
        // container before selecting it, including direct SKESK passphrases.
        string? lastError = null;
        foreach (var skesk in skeskPackets)
        {
            foreach (var password in messagePassphrases)
            {
                byte[]? key = null;
                try
                {
                    var candidate = skesk.DecryptSessionKeyWithAlgorithm(password, container.CipherAlgorithm, securityPolicy);
                    key = candidate.SessionKey;
                    if (TryDecryptContent(container, key, candidate.Algorithm, [], out message, out lastError))
                    {
                        return true;
                    }
                }
                catch (Exception ex) when (IsCandidateFailure(ex))
                {
                    lastError = AuthenticationFailure;
                }
                finally
                {
                    if (key != null)
                    {
                        SecureMemoryOperations.SecureClear(key);
                    }
                }
            }
        }

        foreach (var pkesk in pkeskPackets)
        {
            foreach (var secretKey in secretKeys)
            {
                if (!KeyMatches(pkesk, secretKey))
                {
                    continue;
                }

                var candidate = TryDecryptSessionKey(pkesk, secretKey, container.CipherAlgorithm, out lastError);
                if (!candidate.HasValue)
                {
                    continue;
                }

                var key = candidate.Value.SessionKey;
                try
                {
                    if (TryDecryptContent(container, key, candidate.Value.Algorithm,
                        secretKey.GetKeyId(), out message, out lastError))
                    {
                        return true;
                    }
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(key);
                }
            }
        }

        message = default;
        error = lastError != null ? $"Secret key or passphrase decryption failed: {lastError}"
            : skeskPackets.Count > 0 && messagePassphrases.Count == 0
                ? "Message requires a passphrase for decryption. Use WithMessagePassphrase()."
                : pkeskPackets.Count > 0 && secretKeys.Count == 0
                    ? "Message requires a secret key for decryption. Use WithSecretKey() or WithSecretKeyRing()."
                    : "No matching secret key or passphrase found for decryption.";
        return false;
    }

    private bool TryDecryptContent(PgpSymEncryptedIntegrityProtectedDataPacket container,
        byte[] key, SymmetricCipherAlgorithm algorithm, byte[] keyId,
        out PgpDecryptedMessage message, out string? error)
    {
        message = default;
        error = null;
        byte[]? plaintext = null;
        bool authenticated = false;
        try
        {
            if (key.Length != GetKeySize(algorithm))
            {
                throw new CryptographicException("Session key length does not match the data algorithm.");
            }

            plaintext = container.Version == 1 ? DecryptSeipdV1(container, key, algorithm)
                : DecryptSeipdV2(container, key);
            authenticated = true;
            return ParseDecryptedContent(plaintext, keyId, container.Version, maxDecompressedSize, out message, out error);
        }
        catch (Exception ex) when (IsCandidateFailure(ex))
        {
            message = default;
            // Do not distinguish session-key or integrity failures. Errors parsing
            // already-authenticated content (such as a size limit) remain useful.
            error = authenticated ? ex.Message : AuthenticationFailure;
            return false;
        }
        finally
        {
            if (plaintext != null)
            {
                SecureMemoryOperations.SecureClear(plaintext);
            }
        }
    }

    private static bool IsCandidateFailure(Exception exception)
        => exception is CryptographicException or ArgumentException or NotSupportedException or InvalidDataException or FormatException or SecurityPolicyException;

    private static bool KeyMatches(PgpPublicKeyEncryptedSessionKeyPacket pkesk, PgpSecretKeyPacket secretKey)
    {
        // Version 3 PKESK uses 8-byte key ID
        // Version 6 PKESK uses full fingerprint
        if (pkesk.Version == 3)
        {
            byte[] keyId = secretKey.GetKeyId();
            bool anonymous = true;
            foreach (byte value in pkesk.KeyId.Span)
            {
                anonymous &= value == 0;
            }

            return anonymous || pkesk.KeyId.Span.SequenceEqual(keyId);
        }
        else if (pkesk.Version == 6)
        {
            byte[] fingerprint = secretKey.ComputeFingerprint();
            return pkesk.Fingerprint.IsEmpty || (pkesk.KeyVersion == secretKey.PublicKey.Version &&
                pkesk.Fingerprint.Span.SequenceEqual(fingerprint));
        }

        return false;
    }

    private (SymmetricCipherAlgorithm Algorithm, byte[] SessionKey)? TryDecryptSessionKey(
        PgpPublicKeyEncryptedSessionKeyPacket pkesk,
        PgpSecretKeyPacket secretKey,
        SymmetricCipherAlgorithm dataAlgorithm,
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
                return PgpKeyEncryption.DecryptSessionKeyRsa(pkesk.EncryptedSessionKey.Span, secretKey, securityPolicy, pkesk.Version == 6, dataAlgorithm);
            }
            else if (pkesk.Algorithm == PgpPublicKeyAlgorithm.X25519)
            {
                var payload = pkesk.EncryptedSessionKey.ToArray();
                var algorithm = dataAlgorithm;
                if (pkesk.Version == 3)
                {
                    if (payload.Length < 34 || payload[32] != payload.Length - 33)
                    {
                        throw new CryptographicException("Invalid X25519 v3 session key framing.");
                    }

                    algorithm = (SymmetricCipherAlgorithm)payload[33];
                    if (algorithm is not (SymmetricCipherAlgorithm.Aes128 or SymmetricCipherAlgorithm.Aes192 or SymmetricCipherAlgorithm.Aes256))
                    {
                        throw new CryptographicException("X25519 requires an AES session key.");
                    }

                    var wrapped = new byte[payload.Length - 1];
                    payload.AsSpan(0, 33).CopyTo(wrapped);
                    wrapped[32]--;
                    payload.AsSpan(34).CopyTo(wrapped.AsSpan(33));
                    payload = wrapped;
                }

                byte[] sessionKey = PgpKeyEncryption.DecryptSessionKeyX25519(payload, secretKey, securityPolicy);
                return (algorithm, sessionKey);
            }
            else if (pkesk.Algorithm == PgpPublicKeyAlgorithm.Ecdh)
            {
                if (pkesk.Version != 3)
                {
                    throw new NotSupportedException("ECDH v6 session key decryption is not implemented.");
                }

                // ECDH (RFC 6637) - session key includes algorithm byte
                return PgpKeyEncryption.DecryptSessionKeyEcdhCurve25519(pkesk.EncryptedSessionKey.Span, secretKey);
            }
            else
            {
                error = $"Unsupported public key algorithm: {pkesk.Algorithm}";
                return null;
            }
        }
        catch (Exception ex) when (IsCandidateFailure(ex))
        {
            error = AuthenticationFailure;
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
        // Validate public framing before the CFB implementation indexes its prefix.
        if (encryptedData.Length < blockSize + 2 + 22)
        {
            throw new CryptographicException(AuthenticationFailure);
        }
        byte[] decrypted = CfbDecrypt(encryptedData, sessionKey, blockSize, algorithm);
        try
        {
            int mdcStart = decrypted.Length - 22;
            // Always compute the entire MDC before rejecting prefix or MDC-header
            // bytes. A separate quick-check result is a decryption oracle.
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
            bool validMdc = SecureMemoryOperations.ConstantTimeEquals(actualMdc.AsSpan(), decrypted.AsSpan(mdcStart + 2, 20));
            int framingDifference = (decrypted[mdcStart] ^ 0xD3) | (decrypted[mdcStart + 1] ^ 0x14) |
                (decrypted[blockSize - 2] ^ decrypted[blockSize]) |
                (decrypted[blockSize - 1] ^ decrypted[blockSize + 1]);
            if (!validMdc || framingDifference != 0)
                throw new CryptographicException(AuthenticationFailure);

            byte[] plaintext = new byte[mdcStart - blockSize - 2];
            Array.Copy(decrypted, blockSize + 2, plaintext, 0, plaintext.Length);
            return plaintext;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(decrypted);
        }
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
        bool completed = false;
        try
        {
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

            completed = true;
            return plaintext;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(fr);
            SecureMemoryOperations.SecureClear(fre);
            if (!completed) SecureMemoryOperations.SecureClear(plaintext);
        }
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

    private byte[] DecryptSeipdV2(PgpSymEncryptedIntegrityProtectedDataPacket seipd, byte[] sessionKey)
        => PgpSeipdAead.Decrypt(seipd, sessionKey, securityPolicy);

    private static bool ParseDecryptedContent(
        byte[] plaintext,
        byte[] decryptionKeyId,
        int seipdVersion,
        int maxDecompressedSize,
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
                    byte[] decompressed = compressed.Decompress(maxDecompressedSize);
                    using var innerStream = new MemoryStream(decompressed);
                    using var innerReader = new PgpPacketReader(innerStream, maxPacketSize: maxDecompressedSize,
                        leaveOpen: false);

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
