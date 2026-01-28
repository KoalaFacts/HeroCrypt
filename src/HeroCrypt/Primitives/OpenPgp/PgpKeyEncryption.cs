using System.Numerics;
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

    /// <summary>
    /// X25519 HKDF info label per RFC 9580.
    /// </summary>
    private static readonly byte[] X25519HkdfLabel = "OpenPGP X25519"u8.ToArray();

    /// <summary>
    /// Anonymous sender string for ECDH KDF per RFC 6637 (20 bytes, padded with spaces).
    /// </summary>
    private static readonly byte[] AnonymousSenderLabel = "Anonymous Sender    "u8.ToArray();

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
            return Mpi.Encode(ciphertext);
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
        byte[] ciphertext = Mpi.ReadBytes(encryptedMpi, out _);

        // Pad ciphertext to modulus length if needed
        // MPI encoding strips leading zeros, but RSA decryption requires exact modulus length
        int modulusBytes = GetBigIntegerByteLength(pubN);
        if (ciphertext.Length < modulusBytes)
        {
            var paddedCiphertext = new byte[modulusBytes];
            Array.Copy(ciphertext, 0, paddedCiphertext, modulusBytes - ciphertext.Length, ciphertext.Length);
            ciphertext = paddedCiphertext;
        }

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

            // Use constant-time comparison to prevent timing attacks
            if (!SecureMemoryOperations.ConstantTimeEquals(expectedChecksum, actualChecksum))
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
        byte[] info = new byte[X25519HkdfLabel.Length + 32 + 32];
        X25519HkdfLabel.CopyTo(info.AsSpan(0));
        ephemeralPublic.CopyTo(info.AsSpan(X25519HkdfLabel.Length));
        recipientPublic.CopyTo(info.AsSpan(X25519HkdfLabel.Length + 32));
        return info;
    }


    /// <summary>
    /// Curve25519 OID bytes for ECDH (algorithm 18).
    /// </summary>
    private static readonly byte[] Curve25519Oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

    /// <summary>
    /// NIST P-256 OID bytes (1.2.840.10045.3.1.7).
    /// </summary>
    private static readonly byte[] NistP256Oid = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// <summary>
    /// NIST P-384 OID bytes (1.3.132.0.34).
    /// </summary>
    private static readonly byte[] NistP384Oid = [0x2B, 0x81, 0x04, 0x00, 0x22];

    /// <summary>
    /// NIST P-521 OID bytes (1.3.132.0.35).
    /// </summary>
    private static readonly byte[] NistP521Oid = [0x2B, 0x81, 0x04, 0x00, 0x23];

    /// <summary>
    /// Decrypts a session key using ECDH (RFC 6637).
    /// </summary>
    /// <param name="encryptedData">The encrypted session key data from PKESK packet.</param>
    /// <param name="secretKey">The recipient's ECDH secret key packet.</param>
    /// <returns>A tuple of (symmetric algorithm, session key).</returns>
    /// <remarks>
    /// <para>
    /// ECDH session key decryption per RFC 6637:
    /// <code>
    /// 1. Parse ephemeral public key from MPI
    /// 2. sharedSecret = ECDH(recipientPrivate, ephemeralPublic)
    /// 3. param = oidLen || oid || 0x03 || 0x01 || hash || cipher || "Anonymous Sender    " || fingerprint
    /// 4. KEK = Hash(00 00 00 01 || sharedSecret || param)
    /// 5. unwrapped = AES-KeyUnwrap(KEK, wrappedKey)
    /// 6. symAlg = unwrapped[0], sessionKey = unwrapped[1..len-padLen]
    /// </code>
    /// </para>
    /// <para>
    /// Supports Curve25519 (X25519), NIST P-256, P-384, and P-521.
    /// </para>
    /// </remarks>
    public static (SymmetricCipherAlgorithm Algorithm, byte[] SessionKey) DecryptSessionKeyEcdhCurve25519(
        ReadOnlySpan<byte> encryptedData,
        PgpSecretKeyPacket secretKey)
    {
        if (secretKey.IsEncrypted)
        {
            throw new InvalidOperationException("Secret key is encrypted. Decrypt the key first.");
        }

        if (secretKey.Algorithm != PgpPublicKeyAlgorithm.Ecdh)
        {
            throw new ArgumentException($"Expected ECDH key, got {secretKey.Algorithm}.", nameof(secretKey));
        }

        // Read ECDH key parameters
        var (oid, _, hashAlgorithm, cipherAlgorithm) = secretKey.PublicKey.ReadEcdhKey();

        // Parse PKESK encrypted data: MPI(ephemeral) + len(1) + wrappedKey
        var ephemeralMpi = Mpi.ReadBytes(encryptedData, out int consumed);

        if (encryptedData.Length < consumed + 1)
        {
            throw new ArgumentException("Encrypted data too short.", nameof(encryptedData));
        }

        int wrappedKeyLen = encryptedData[consumed];
        if (encryptedData.Length < consumed + 1 + wrappedKeyLen)
        {
            throw new ArgumentException("Encrypted data truncated.", nameof(encryptedData));
        }

        byte[] wrappedKey = encryptedData.Slice(consumed + 1, wrappedKeyLen).ToArray();

        byte[] sharedSecret;

        // Dispatch based on curve OID
        if (oid.AsSpan().SequenceEqual(Curve25519Oid))
        {
            sharedSecret = ComputeCurve25519SharedSecret(ephemeralMpi, secretKey);
        }
#if !NETSTANDARD2_0
        else if (oid.AsSpan().SequenceEqual(NistP256Oid))
        {
            sharedSecret = ComputeNistEcdhSharedSecret(ephemeralMpi, secretKey, ECCurve.NamedCurves.nistP256);
        }
        else if (oid.AsSpan().SequenceEqual(NistP384Oid))
        {
            sharedSecret = ComputeNistEcdhSharedSecret(ephemeralMpi, secretKey, ECCurve.NamedCurves.nistP384);
        }
        else if (oid.AsSpan().SequenceEqual(NistP521Oid))
        {
            sharedSecret = ComputeNistEcdhSharedSecret(ephemeralMpi, secretKey, ECCurve.NamedCurves.nistP521);
        }
#else
        else if (oid.AsSpan().SequenceEqual(NistP256Oid) || oid.AsSpan().SequenceEqual(NistP384Oid) || oid.AsSpan().SequenceEqual(NistP521Oid))
        {
            throw new NotSupportedException("NIST P-256/P-384/P-521 ECDH is not supported on .NET Standard 2.0. Please use .NET Standard 2.1 or higher.");
        }
#endif
        else
        {
            throw new ArgumentException($"Unsupported ECDH curve OID: {BitConverter.ToString(oid)}", nameof(secretKey));
        }

        try
        {
            // Build KDF parameter per RFC 6637 / RFC 9580
            // param = oidLen || oid || 0x03 || 0x01 || hash || cipher || "Anonymous Sender    " || fingerprint
            byte[] fingerprint = secretKey.PublicKey.ComputeFingerprint();

            // Per RFC 9580 Section 13.5:
            // - For V6 keys, use the full 32-byte SHA256 fingerprint
            // - For V4 keys, use the 20-byte fingerprint per RFC 6637
            byte[] fingerprintPart = secretKey.Version == 6
                ? fingerprint
                : (fingerprint.Length >= 20 ? fingerprint.AsSpan(0, 20).ToArray() : fingerprint);

            byte[] param = BuildEcdhKdfParam(oid, hashAlgorithm, cipherAlgorithm, fingerprintPart);

            // Derive KEK: Hash(00 00 00 01 || Z || param)
            byte[] kek = DeriveEcdhKek(sharedSecret, param, hashAlgorithm, cipherAlgorithm);

            try
            {
                // AES Key Unwrap
                byte[] unwrapped = AesKeyUnwrap(kek, wrappedKey);

                // Parse: symAlg(1) || sessionKey || [checksum(2)] || PKCS5 padding
                // Note: RFC 6637 says no checksum, but some implementations (OpenPGP.js) include it
                if (unwrapped.Length < 2)
                {
                    throw new CryptographicException("Unwrapped key too short.");
                }

                var symmetricAlgorithm = (SymmetricCipherAlgorithm)unwrapped[0];

                // Remove PKCS5 padding
                int padLen = unwrapped[^1];
                if (padLen < 1 || padLen > 8 || unwrapped.Length < 1 + padLen)
                {
                    throw new CryptographicException("Invalid PKCS5 padding.");
                }

                // Verify padding bytes
                for (int i = unwrapped.Length - padLen; i < unwrapped.Length; i++)
                {
                    if (unwrapped[i] != padLen)
                    {
                        throw new CryptographicException("Invalid PKCS5 padding.");
                    }
                }

                // Determine expected session key length based on algorithm
                // Suppress obsolete warnings - OpenPGP requires legacy algorithm support for interoperability
#pragma warning disable CS0618
                int expectedKeyLen = symmetricAlgorithm switch
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
                    _ => unwrapped.Length - 1 - padLen // Fallback to raw length
                };
#pragma warning restore CS0618

                int dataLen = unwrapped.Length - 1 - padLen;
                int sessionKeyLen;

                // Check if there's a checksum (2 extra bytes after key)
                if (dataLen == expectedKeyLen + 2)
                {
                    // Has checksum - verify it
                    sessionKeyLen = expectedKeyLen;
                    ushort checksum = 0;
                    for (int i = 1; i <= sessionKeyLen; i++)
                    {
                        checksum += unwrapped[i];
                    }
                    ushort storedChecksum = (ushort)((unwrapped[1 + sessionKeyLen] << 8) | unwrapped[2 + sessionKeyLen]);
                    if (checksum != storedChecksum)
                    {
                        throw new CryptographicException("Session key checksum mismatch.");
                    }
                }
                else
                {
                    // No checksum - use full data as key
                    sessionKeyLen = dataLen;
                }

                byte[] sessionKey = new byte[sessionKeyLen];
                Array.Copy(unwrapped, 1, sessionKey, 0, sessionKeyLen);

                SecureMemoryOperations.SecureClear(unwrapped);

                return (symmetricAlgorithm, sessionKey);
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

    /// <summary>
    /// Computes shared secret using Curve25519 (X25519).
    /// </summary>
    private static byte[] ComputeCurve25519SharedSecret(byte[] ephemeralMpi, PgpSecretKeyPacket secretKey)
    {
        // Extract ephemeral public key (remove 0x40 prefix for Curve25519)
        if (ephemeralMpi.Length != 33 || ephemeralMpi[0] != 0x40)
        {
            throw new ArgumentException("Invalid ephemeral key format for Curve25519.");
        }

        // Extract ephemeral public key from MPI (remove 0x40 prefix)
        // For Curve25519 with 0x40 prefix, the key is stored in native format (no reversal needed)
        byte[] ephemeralPublic = ephemeralMpi.AsSpan(1, 32).ToArray();

        // Get our private key
        // For Curve25519 ECDH (algorithm 18), the secret key is stored as a big-endian MPI,
        // but X25519 expects keys in little-endian format (per RFC 7748).
        // We must reverse the bytes after padding to convert from MPI (big-endian) to X25519 (little-endian).
        byte[] privateKeyMpi = secretKey.ReadEcSecretKey();

        // Pad to 32 bytes with leading zeros (big-endian MPI format, leading zeros stripped)
        byte[] privateKey = new byte[32];
        if (privateKeyMpi.Length <= 32)
        {
            // Copy to right side (leading zeros on left for big-endian)
            privateKeyMpi.CopyTo(privateKey.AsSpan(32 - privateKeyMpi.Length));
        }
        else
        {
            SecureMemoryOperations.SecureClear(privateKeyMpi);
            throw new ArgumentException("Invalid Curve25519 private key length.");
        }

        SecureMemoryOperations.SecureClear(privateKeyMpi);

        // Reverse to convert from big-endian (MPI) to little-endian (X25519)
        Array.Reverse(privateKey);

        try
        {
            // Compute shared secret using X25519
            return Curve25519Core.ComputeSharedSecret(privateKey, ephemeralPublic);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(privateKey);
        }
    }

#if !NETSTANDARD2_0
    /// <summary>
    /// Computes shared secret using NIST ECDH (P-256, P-384, P-521).
    /// </summary>
    private static byte[] ComputeNistEcdhSharedSecret(byte[] ephemeralMpi, PgpSecretKeyPacket secretKey, ECCurve curve)
    {
        // Ephemeral public key is in uncompressed point format: 0x04 || X || Y
        if (ephemeralMpi.Length < 3 || ephemeralMpi[0] != 0x04)
        {
            throw new ArgumentException("Invalid ephemeral key format. Expected uncompressed point (0x04 prefix).");
        }

        // Determine coordinate size based on total length
        int coordinateSize = (ephemeralMpi.Length - 1) / 2;

        // Extract X and Y coordinates
        byte[] x = ephemeralMpi.AsSpan(1, coordinateSize).ToArray();
        byte[] y = ephemeralMpi.AsSpan(1 + coordinateSize, coordinateSize).ToArray();

        // Get our private key (stored as MPI)
        byte[] privateKeyMpi = secretKey.ReadEcSecretKey();

        try
        {
            // Pad private key to coordinate size with leading zeros
            byte[] d = new byte[coordinateSize];
            if (privateKeyMpi.Length <= coordinateSize)
            {
                privateKeyMpi.CopyTo(d.AsSpan(coordinateSize - privateKeyMpi.Length));
            }
            else
            {
                throw new ArgumentException("Invalid private key length for curve.");
            }

            try
            {
                // Create ephemeral public key
                var ephemeralParams = new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = x, Y = y }
                };

                // Create our private key
                var ourParams = new ECParameters
                {
                    Curve = curve,
                    D = d
                };

                using var ourKey = ECDiffieHellman.Create(ourParams);
                using var ephemeralKey = ECDiffieHellman.Create(ephemeralParams);

                // Compute shared secret (returns just the X coordinate)
                return ourKey.DeriveRawSecretAgreement(ephemeralKey.PublicKey);
            }
            finally
            {
                SecureMemoryOperations.SecureClear(d);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(privateKeyMpi);
        }
    }
#endif

    /// <summary>
    /// Builds the KDF parameter for ECDH per RFC 6637.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per RFC 6637 Section 8:
    /// <code>
    /// Param = curve_OID_len || curve_OID || public_key_alg_ID || 03 || 01 ||
    ///         Hash-Alg-ID || Sym-Alg-ID || "Anonymous Sender    " ||
    ///         20_bytes_from_recipient_public_key_fingerprint
    /// </code>
    /// </para>
    /// </remarks>
    private static byte[] BuildEcdhKdfParam(byte[] oid, byte hashAlgorithm, byte cipherAlgorithm, byte[] fingerprint)
    {
        // param = oidLen || oid || publicKeyAlg || 03 || 01 || hash || cipher || anonymousSender || fingerprint
        const byte publicKeyAlgorithm = (byte)PgpPublicKeyAlgorithm.Ecdh; // 18
        int paramLen = 1 + oid.Length + 5 + AnonymousSenderLabel.Length + fingerprint.Length;
        byte[] param = new byte[paramLen];

        int offset = 0;
        param[offset++] = (byte)oid.Length;
        oid.CopyTo(param.AsSpan(offset));
        offset += oid.Length;
        param[offset++] = publicKeyAlgorithm;
        param[offset++] = 0x03;
        param[offset++] = 0x01;
        param[offset++] = hashAlgorithm;
        param[offset++] = cipherAlgorithm;
        AnonymousSenderLabel.CopyTo(param.AsSpan(offset));
        offset += AnonymousSenderLabel.Length;
        fingerprint.CopyTo(param.AsSpan(offset));

        return param;
    }

    /// <summary>
    /// Derives the Key Encryption Key for ECDH per RFC 6637.
    /// </summary>
    private static byte[] DeriveEcdhKek(byte[] sharedSecret, byte[] param, byte hashAlgorithm, byte cipherAlgorithm)
    {
        // KEK = Hash(00 00 00 01 || Z || param)
        // Truncate to cipher key size
        // Suppress SHA-1 obsolete warning - OpenPGP requires legacy algorithm support for interoperability
#pragma warning disable CS0618
        HashAlgorithmName hashName = hashAlgorithm switch
        {
            (byte)PgpHashAlgorithmId.Sha256 => HashAlgorithmName.SHA256,
            (byte)PgpHashAlgorithmId.Sha384 => HashAlgorithmName.SHA384,
            (byte)PgpHashAlgorithmId.Sha512 => HashAlgorithmName.SHA512,
            (byte)PgpHashAlgorithmId.Sha1 => HashAlgorithmName.SHA1,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}")
        };
#pragma warning restore CS0618

        int kekSize = cipherAlgorithm switch
        {
            (byte)SymmetricCipherAlgorithm.Aes128 => 16,
            (byte)SymmetricCipherAlgorithm.Aes192 => 24,
            (byte)SymmetricCipherAlgorithm.Aes256 => 32,
            _ => throw new ArgumentException($"Unsupported cipher algorithm: {cipherAlgorithm}")
        };

#if NETSTANDARD2_0
#pragma warning disable IDE0300 // Collection initialization can be simplified - netstandard2.0 doesn't support collection expressions
        using var hash = IncrementalHash.CreateHash(hashName);
        hash.AppendData(new byte[] { 0, 0, 0, 1 });
        hash.AppendData(sharedSecret);
        hash.AppendData(param);
        byte[] digest = hash.GetHashAndReset();
#pragma warning restore IDE0300
#else
        using var hash = IncrementalHash.CreateHash(hashName);
        hash.AppendData([0, 0, 0, 1]);
        hash.AppendData(sharedSecret);
        hash.AppendData(param);
        byte[] digest = hash.GetHashAndReset();
#endif

        // Truncate to KEK size
        if (digest.Length >= kekSize)
        {
            byte[] kek = new byte[kekSize];
            Array.Copy(digest, kek, kekSize);
            SecureMemoryOperations.SecureClear(digest);
            return kek;
        }

        throw new CryptographicException("Hash output too short for KEK.");
    }


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


    /// <summary>
    /// Gets the byte length of a BigInteger (excluding sign byte).
    /// </summary>
    private static int GetBigIntegerByteLength(BigInteger value)
    {
        if (value.IsZero)
        {
            return 1;
        }

        var bytes = value.ToByteArray();
        int length = bytes.Length;

        // Skip sign byte if present (trailing zero in little-endian)
        while (length > 1 && bytes[length - 1] == 0)
        {
            length--;
        }

        return length;
    }


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
}
