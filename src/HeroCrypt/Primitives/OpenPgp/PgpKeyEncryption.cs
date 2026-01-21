using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Provides algorithm-specific session key encryption and decryption for OpenPGP messages.
/// </summary>
/// <remarks>
/// <para>
/// This internal helper class implements the cryptographic operations needed to encrypt
/// and decrypt session keys for different public key algorithms:
/// <list type="bullet">
///   <item><b>RSA:</b> PKCS#1 v1.5 encryption (RFC 4880 Section 5.1)</item>
///   <item><b>X25519:</b> ECDH + HKDF + AES-KeyWrap (RFC 9580)</item>
///   <item><b>ECDH:</b> EC key agreement + KDF + AES-KeyWrap (RFC 6637)</item>
/// </list>
/// </para>
/// </remarks>
internal static class PgpKeyEncryption
{
    /// <summary>
    /// AES Key Wrap default IV (RFC 3394).
    /// </summary>
    private static readonly byte[] AesKeyWrapIv = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    #region RSA Session Key Encryption

    /// <summary>
    /// Encrypts a session key using RSA PKCS#1 v1.5.
    /// </summary>
    /// <param name="sessionKey">The session key to encrypt.</param>
    /// <param name="symmetricAlgorithm">The symmetric algorithm ID for the session key.</param>
    /// <param name="publicKey">The recipient's RSA public key packet.</param>
    /// <returns>The encrypted session key as an MPI.</returns>
    /// <remarks>
    /// <para>
    /// The session key is encrypted according to RFC 4880 Section 5.1:
    /// <code>
    /// Plaintext = [symAlg(1)] [sessionKey(16-32)] [checksum(2)]
    /// Ciphertext = RSA_PKCS1(Plaintext)
    /// Output = MPI(Ciphertext)
    /// </code>
    /// </para>
    /// </remarks>
    public static byte[] EncryptSessionKeyRsa(
        ReadOnlySpan<byte> sessionKey,
        SymmetricCipherAlgorithm symmetricAlgorithm,
        PgpPublicKeyPacket publicKey)
    {
        if (publicKey.Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOrSign &&
#pragma warning disable CS0618 // Obsolete member
            publicKey.Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOnly)
#pragma warning restore CS0618
        {
            throw new ArgumentException($"Expected RSA key, got {publicKey.Algorithm}.", nameof(publicKey));
        }

        // Read RSA key parameters
        var (n, e) = publicKey.ReadRsaKey();

        // Build PKCS#1 v1.5 plaintext: symAlg + sessionKey + checksum
        int plaintextLen = 1 + sessionKey.Length + 2;
        byte[] plaintext = new byte[plaintextLen];

        try
        {
            int offset = 0;

            // Symmetric algorithm ID
            plaintext[offset++] = (byte)symmetricAlgorithm;

            // Session key
            sessionKey.CopyTo(plaintext.AsSpan(offset));
            offset += sessionKey.Length;

            // Checksum: sum of session key bytes mod 65536
            ushort checksum = 0;
            foreach (byte b in sessionKey)
            {
                checksum = (ushort)((checksum + b) & 0xFFFF);
            }

            plaintext[offset++] = (byte)(checksum >> 8);
            plaintext[offset] = (byte)(checksum & 0xFF);

            // RSA encrypt with PKCS#1 v1.5 padding
            var rsaPublicKey = new RsaPublicKey(n, e);
            byte[] ciphertext = RsaCore.Encrypt(plaintext, rsaPublicKey, RsaPaddingMode.Pkcs1);

            // Encode as MPI
            return EncodeMpi(ciphertext);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(plaintext);
        }
    }

    /// <summary>
    /// Decrypts a session key using RSA PKCS#1 v1.5.
    /// </summary>
    /// <param name="encryptedMpi">The encrypted session key MPI.</param>
    /// <param name="secretKey">The recipient's RSA secret key packet.</param>
    /// <returns>A tuple of (symmetric algorithm, session key).</returns>
    /// <exception cref="CryptographicException">If decryption or checksum verification fails.</exception>
    public static (SymmetricCipherAlgorithm Algorithm, byte[] SessionKey) DecryptSessionKeyRsa(
        ReadOnlySpan<byte> encryptedMpi,
        PgpSecretKeyPacket secretKey)
    {
        if (secretKey.IsEncrypted)
        {
            throw new InvalidOperationException("Secret key is encrypted. Decrypt the key first.");
        }

        if (secretKey.Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOrSign &&
#pragma warning disable CS0618 // Obsolete member
            secretKey.Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOnly)
#pragma warning restore CS0618
        {
            throw new ArgumentException($"Expected RSA key, got {secretKey.Algorithm}.", nameof(secretKey));
        }

        // Read RSA key parameters
        var (pubN, pubE) = secretKey.PublicKey.ReadRsaKey();
        var (d, p, q, _) = secretKey.ReadRsaSecretKey();

        // Decode MPI
        byte[] ciphertext = DecodeMpi(encryptedMpi);

        // RSA decrypt
        var rsaPrivateKey = new RsaPrivateKey(pubN, d, p, q, pubE);
        byte[] plaintext;

        try
        {
            plaintext = RsaCore.Decrypt(ciphertext, rsaPrivateKey, RsaPaddingMode.Pkcs1);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("RSA decryption failed.", ex);
        }

        try
        {
            // Parse: symAlg(1) + sessionKey(variable) + checksum(2)
            if (plaintext.Length < 4)
            {
                throw new CryptographicException("Decrypted session key too short.");
            }

            var symmetricAlgorithm = (SymmetricCipherAlgorithm)plaintext[0];
            int sessionKeyLen = plaintext.Length - 3; // 1 for algo, 2 for checksum

            byte[] sessionKey = new byte[sessionKeyLen];
            Array.Copy(plaintext, 1, sessionKey, 0, sessionKeyLen);

            // Verify checksum
            ushort expectedChecksum = (ushort)((plaintext[^2] << 8) | plaintext[^1]);
            ushort actualChecksum = 0;
            foreach (byte b in sessionKey)
            {
                actualChecksum = (ushort)((actualChecksum + b) & 0xFFFF);
            }

            if (expectedChecksum != actualChecksum)
            {
                SecureMemoryOperations.SecureClear(sessionKey);
                throw new CryptographicException("Session key checksum mismatch.");
            }

            return (symmetricAlgorithm, sessionKey);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(plaintext);
        }
    }

    #endregion

    #region X25519 Session Key Encryption (RFC 9580)

    /// <summary>
    /// Encrypts a session key using X25519 ECDH + HKDF + AES-KeyWrap.
    /// </summary>
    /// <param name="sessionKey">The session key to encrypt.</param>
    /// <param name="publicKey">The recipient's X25519 public key packet.</param>
    /// <returns>
    /// A tuple of (ephemeral public key, wrapped session key).
    /// The wire format is: ephemeralPub(32) + len(1) + wrappedKey(variable).
    /// </returns>
    /// <remarks>
    /// <para>
    /// X25519 session key encryption per RFC 9580 Section 5.1.6:
    /// <code>
    /// 1. Generate ephemeral X25519 key pair
    /// 2. sharedSecret = X25519(ephemeralPrivate, recipientPublic)
    /// 3. KEK = HKDF-SHA256(sharedSecret, info="OpenPGP X25519")
    /// 4. wrappedKey = AES-KeyWrap(KEK, sessionKey)
    /// </code>
    /// </para>
    /// </remarks>
    public static byte[] EncryptSessionKeyX25519(
        ReadOnlySpan<byte> sessionKey,
        PgpPublicKeyPacket publicKey)
    {
        if (publicKey.Algorithm != PgpPublicKeyAlgorithm.X25519)
        {
            throw new ArgumentException($"Expected X25519 key, got {publicKey.Algorithm}.", nameof(publicKey));
        }

        // Get recipient's public key
        byte[] recipientPublic = publicKey.ReadNativePublicKey();

        // Generate ephemeral key pair
        byte[] ephemeralPrivate = Curve25519Core.GeneratePrivateKey();
        byte[] ephemeralPublic = Curve25519Core.DerivePublicKey(ephemeralPrivate);

        try
        {
            // Compute shared secret
            byte[] sharedSecret = Curve25519Core.ComputeSharedSecret(ephemeralPrivate, recipientPublic);

            try
            {
                // Derive KEK using HKDF-SHA256
                // RFC 9580: info = "OpenPGP X25519" || ephemeralPublic || recipientPublic
                byte[] info = BuildX25519HkdfInfo(ephemeralPublic, recipientPublic);
                byte[] kek = HkdfCore.DeriveKey(sharedSecret, [], info, 32, HashAlgorithmName.SHA256);

                try
                {
                    // AES Key Wrap the session key
                    byte[] wrappedKey = AesKeyWrap(kek, sessionKey.ToArray());

                    // Build output: ephemeralPublic(32) + len(1) + wrappedKey
                    byte[] result = new byte[32 + 1 + wrappedKey.Length];
                    ephemeralPublic.CopyTo(result.AsSpan(0, 32));
                    result[32] = (byte)wrappedKey.Length;
                    wrappedKey.CopyTo(result.AsSpan(33));

                    return result;
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(kek);
                }
            }
            finally
            {
                SecureMemoryOperations.SecureClear(sharedSecret);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(ephemeralPrivate);
        }
    }

    /// <summary>
    /// Decrypts a session key using X25519 ECDH + HKDF + AES-KeyUnwrap.
    /// </summary>
    /// <param name="encryptedData">The encrypted data: ephemeralPub(32) + len(1) + wrappedKey.</param>
    /// <param name="secretKey">The recipient's X25519 secret key packet.</param>
    /// <returns>The decrypted session key.</returns>
    public static byte[] DecryptSessionKeyX25519(
        ReadOnlySpan<byte> encryptedData,
        PgpSecretKeyPacket secretKey)
    {
        if (secretKey.IsEncrypted)
        {
            throw new InvalidOperationException("Secret key is encrypted. Decrypt the key first.");
        }

        if (secretKey.Algorithm != PgpPublicKeyAlgorithm.X25519)
        {
            throw new ArgumentException($"Expected X25519 key, got {secretKey.Algorithm}.", nameof(secretKey));
        }

        if (encryptedData.Length < 34) // 32 + 1 + min 1
        {
            throw new ArgumentException("Encrypted data too short.", nameof(encryptedData));
        }

        // Parse input
        byte[] ephemeralPublic = encryptedData.Slice(0, 32).ToArray();
        int wrappedKeyLen = encryptedData[32];
        if (encryptedData.Length < 33 + wrappedKeyLen)
        {
            throw new ArgumentException("Encrypted data truncated.", nameof(encryptedData));
        }

        byte[] wrappedKey = encryptedData.Slice(33, wrappedKeyLen).ToArray();

        // Get our private key and public key
        byte[] privateKey = secretKey.ReadEcSecretKey();
        byte[] ourPublic = secretKey.PublicKey.ReadNativePublicKey();

        try
        {
            // Compute shared secret
            byte[] sharedSecret = Curve25519Core.ComputeSharedSecret(privateKey, ephemeralPublic);

            try
            {
                // Derive KEK using HKDF-SHA256
                byte[] info = BuildX25519HkdfInfo(ephemeralPublic, ourPublic);
                byte[] kek = HkdfCore.DeriveKey(sharedSecret, [], info, 32, HashAlgorithmName.SHA256);

                try
                {
                    // AES Key Unwrap
                    return AesKeyUnwrap(kek, wrappedKey);
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(kek);
                }
            }
            finally
            {
                SecureMemoryOperations.SecureClear(sharedSecret);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(privateKey);
        }
    }

    /// <summary>
    /// Builds the HKDF info parameter for X25519.
    /// </summary>
    private static byte[] BuildX25519HkdfInfo(byte[] ephemeralPublic, byte[] recipientPublic)
    {
        // RFC 9580: info = "OpenPGP X25519" || ephemeralPublic || recipientPublic
        byte[] label = "OpenPGP X25519"u8.ToArray();
        byte[] info = new byte[label.Length + 32 + 32];
        label.CopyTo(info.AsSpan(0));
        ephemeralPublic.CopyTo(info.AsSpan(label.Length));
        recipientPublic.CopyTo(info.AsSpan(label.Length + 32));
        return info;
    }

    #endregion

    #region AES Key Wrap (RFC 3394)

    /// <summary>
    /// Wraps a key using AES Key Wrap (RFC 3394).
    /// </summary>
    /// <param name="kek">The key encryption key (16, 24, or 32 bytes).</param>
    /// <param name="plaintext">The key to wrap (must be multiple of 8 bytes, min 16).</param>
    /// <returns>The wrapped key (8 bytes longer than input).</returns>
    public static byte[] AesKeyWrap(byte[] kek, byte[] plaintext)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(kek);
        ArgumentNullException.ThrowIfNull(plaintext);
#else
        if (kek == null) throw new ArgumentNullException(nameof(kek));
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
#endif

        if (kek.Length != 16 && kek.Length != 24 && kek.Length != 32)
        {
            throw new ArgumentException("KEK must be 16, 24, or 32 bytes.", nameof(kek));
        }

        if (plaintext.Length < 16 || plaintext.Length % 8 != 0)
        {
            throw new ArgumentException("Plaintext must be at least 16 bytes and multiple of 8.", nameof(plaintext));
        }

        int n = plaintext.Length / 8;

        // Initialize R blocks
        byte[][] r = new byte[n + 1][];
        r[0] = (byte[])AesKeyWrapIv.Clone();
        for (int i = 1; i <= n; i++)
        {
            r[i] = new byte[8];
            Array.Copy(plaintext, (i - 1) * 8, r[i], 0, 8);
        }

        using var aes = Aes.Create();
        aes.Key = kek;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] block = new byte[16];
        byte[] encrypted = new byte[16];

        using var encryptor = aes.CreateEncryptor();

        // 6 rounds of wrapping
        for (int j = 0; j < 6; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                // A || R[i]
                Array.Copy(r[0], 0, block, 0, 8);
                Array.Copy(r[i], 0, block, 8, 8);

                // B = AES(K, A || R[i])
                encryptor.TransformBlock(block, 0, 16, encrypted, 0);

                // A = MSB(64, B) XOR t where t = (n*j)+i
                long t = (n * j) + i;
                Array.Copy(encrypted, 0, r[0], 0, 8);
                XorWithCounter(r[0], t);

                // R[i] = LSB(64, B)
                Array.Copy(encrypted, 8, r[i], 0, 8);
            }
        }

        // Output: A || R[1] || R[2] || ... || R[n]
        byte[] result = new byte[(n + 1) * 8];
        for (int i = 0; i <= n; i++)
        {
            Array.Copy(r[i], 0, result, i * 8, 8);
        }

        return result;
    }

    /// <summary>
    /// Unwraps a key using AES Key Unwrap (RFC 3394).
    /// </summary>
    /// <param name="kek">The key encryption key (16, 24, or 32 bytes).</param>
    /// <param name="ciphertext">The wrapped key (must be at least 24 bytes, multiple of 8).</param>
    /// <returns>The unwrapped key.</returns>
    /// <exception cref="CryptographicException">If integrity check fails.</exception>
    public static byte[] AesKeyUnwrap(byte[] kek, byte[] ciphertext)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(kek);
        ArgumentNullException.ThrowIfNull(ciphertext);
#else
        if (kek == null) throw new ArgumentNullException(nameof(kek));
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
#endif

        if (kek.Length != 16 && kek.Length != 24 && kek.Length != 32)
        {
            throw new ArgumentException("KEK must be 16, 24, or 32 bytes.", nameof(kek));
        }

        if (ciphertext.Length < 24 || ciphertext.Length % 8 != 0)
        {
            throw new ArgumentException("Ciphertext must be at least 24 bytes and multiple of 8.", nameof(ciphertext));
        }

        int n = (ciphertext.Length / 8) - 1;

        // Initialize A and R blocks
        byte[] a = new byte[8];
        Array.Copy(ciphertext, 0, a, 0, 8);

        byte[][] r = new byte[n + 1][];
        r[0] = a; // Not used but keeps indexing consistent
        for (int i = 1; i <= n; i++)
        {
            r[i] = new byte[8];
            Array.Copy(ciphertext, i * 8, r[i], 0, 8);
        }

        using var aes = Aes.Create();
        aes.Key = kek;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] block = new byte[16];
        byte[] decrypted = new byte[16];

        using var decryptor = aes.CreateDecryptor();

        // 6 rounds of unwrapping (in reverse)
        for (int j = 5; j >= 0; j--)
        {
            for (int i = n; i >= 1; i--)
            {
                // A XOR t where t = (n*j)+i
                long t = (n * j) + i;
                XorWithCounter(a, t);

                // (A XOR t) || R[i]
                Array.Copy(a, 0, block, 0, 8);
                Array.Copy(r[i], 0, block, 8, 8);

                // B = AES^-1(K, (A XOR t) || R[i])
                decryptor.TransformBlock(block, 0, 16, decrypted, 0);

                // A = MSB(64, B)
                Array.Copy(decrypted, 0, a, 0, 8);

                // R[i] = LSB(64, B)
                Array.Copy(decrypted, 8, r[i], 0, 8);
            }
        }

        // Verify IV
        if (!a.AsSpan().SequenceEqual(AesKeyWrapIv))
        {
            throw new CryptographicException("AES Key Unwrap integrity check failed.");
        }

        // Output: R[1] || R[2] || ... || R[n]
        byte[] result = new byte[n * 8];
        for (int i = 1; i <= n; i++)
        {
            Array.Copy(r[i], 0, result, (i - 1) * 8, 8);
        }

        return result;
    }

    /// <summary>
    /// XORs a 64-bit counter into a byte array (big-endian).
    /// </summary>
    private static void XorWithCounter(byte[] data, long counter)
    {
        data[0] ^= (byte)(counter >> 56);
        data[1] ^= (byte)(counter >> 48);
        data[2] ^= (byte)(counter >> 40);
        data[3] ^= (byte)(counter >> 32);
        data[4] ^= (byte)(counter >> 24);
        data[5] ^= (byte)(counter >> 16);
        data[6] ^= (byte)(counter >> 8);
        data[7] ^= (byte)counter;
    }

    #endregion

    #region MPI Encoding/Decoding

    /// <summary>
    /// Encodes a byte array as an OpenPGP MPI.
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <returns>MPI-encoded data (2-byte bit count + data).</returns>
    private static byte[] EncodeMpi(byte[] data)
    {
        // Skip leading zeros
        int start = 0;
        while (start < data.Length && data[start] == 0)
        {
            start++;
        }

        if (start == data.Length)
        {
            // All zeros
            return [0, 0];
        }

        // Calculate bit length
        int dataLen = data.Length - start;
        int bitLen = (dataLen - 1) * 8;
        byte msb = data[start];
        while (msb != 0)
        {
            bitLen++;
            msb >>= 1;
        }

        byte[] result = new byte[2 + dataLen];
        result[0] = (byte)(bitLen >> 8);
        result[1] = (byte)bitLen;
        Array.Copy(data, start, result, 2, dataLen);

        return result;
    }

    /// <summary>
    /// Decodes an OpenPGP MPI to a byte array.
    /// </summary>
    /// <param name="mpi">The MPI-encoded data.</param>
    /// <returns>The decoded byte data.</returns>
    private static byte[] DecodeMpi(ReadOnlySpan<byte> mpi)
    {
        if (mpi.Length < 2)
        {
            throw new ArgumentException("MPI too short.", nameof(mpi));
        }

        int bitLen = (mpi[0] << 8) | mpi[1];
        int byteLen = (bitLen + 7) / 8;

        if (mpi.Length < 2 + byteLen)
        {
            throw new ArgumentException("MPI data truncated.", nameof(mpi));
        }

        return mpi.Slice(2, byteLen).ToArray();
    }

    #endregion

    #region Session Key Generation

    /// <summary>
    /// Gets the session key size for a symmetric algorithm.
    /// </summary>
    /// <param name="algorithm">The symmetric cipher algorithm.</param>
    /// <returns>The key size in bytes.</returns>
    public static int GetSessionKeySize(SymmetricCipherAlgorithm algorithm)
    {
        // Suppress obsolete warnings - OpenPGP requires legacy algorithm support for interoperability
#pragma warning disable CS0618
        return algorithm switch
        {
            SymmetricCipherAlgorithm.Aes128 => 16,
            SymmetricCipherAlgorithm.Aes192 => 24,
            SymmetricCipherAlgorithm.Aes256 => 32,
            SymmetricCipherAlgorithm.TripleDes => 24,
            SymmetricCipherAlgorithm.Cast5 => 16,
            SymmetricCipherAlgorithm.Blowfish => 16,
            SymmetricCipherAlgorithm.Twofish => 32,
            SymmetricCipherAlgorithm.Camellia128 => 16,
            SymmetricCipherAlgorithm.Camellia192 => 24,
            SymmetricCipherAlgorithm.Camellia256 => 32,
            SymmetricCipherAlgorithm.Idea => 16,
            _ => throw new ArgumentException($"Unknown symmetric algorithm: {algorithm}", nameof(algorithm))
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Generates a random session key for the specified symmetric algorithm.
    /// </summary>
    /// <param name="algorithm">The symmetric cipher algorithm.</param>
    /// <returns>A new random session key.</returns>
    public static byte[] GenerateSessionKey(SymmetricCipherAlgorithm algorithm)
    {
        int keySize = GetSessionKeySize(algorithm);
        byte[] sessionKey = new byte[keySize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(sessionKey);
        return sessionKey;
    }

    #endregion
}
