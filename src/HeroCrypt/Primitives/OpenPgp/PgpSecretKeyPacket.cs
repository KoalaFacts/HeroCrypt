using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

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
        byte[] finalMaterial;

        // V6 keys do NOT have a checksum for unencrypted keys per RFC 9580
        // V4 and earlier keys include a 2-byte checksum
        if (publicKey.Version == 6)
        {
            finalMaterial = secretKeyMaterial.ToArray();
        }
        else
        {
            // Calculate checksum: sum of all bytes mod 65536
            ushort checksum = 0;
            foreach (byte b in secretKeyMaterial.Span)
            {
                checksum = (ushort)((checksum + b) & 0xFFFF);
            }

            // Append checksum to secret key material
            finalMaterial = new byte[secretKeyMaterial.Length + 2];
            secretKeyMaterial.Span.CopyTo(finalMaterial);
            BinaryPrimitives.WriteUInt16BigEndian(finalMaterial.AsSpan(secretKeyMaterial.Length), checksum);
        }

        return new PgpSecretKeyPacket(
            publicKey,
            PgpS2KUsage.None,
            0,
            null,
            Array.Empty<byte>(),
            finalMaterial);
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

            if (!SecureMemoryOperations.ConstantTimeEquals(actualChecksum, expectedChecksum))
            {
                error = "Secret key checksum mismatch.";
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
        if (source.Length < 11) // Need at least public header + scalar octet count
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
            error = "Source too short for public key material and scalar octet count.";
            return false;
        }

        var creationTime = DateTimeOffset.FromUnixTimeSeconds(creationTimestamp);
        var publicKeyMaterial = source.Slice(offset, (int)publicKeyLength).ToArray();
        offset += (int)publicKeyLength;

        var publicKey = new PgpPublicKeyPacket(version, creationTime, algorithm, publicKeyMaterial, isSubkey);

        // V6: Scalar octet count = number of bytes of optional S2K fields
        // Per RFC 9580: If zero, the secret-key data is NOT encrypted
        byte scalarOctetCount = source[offset++];

        if (scalarOctetCount == 0)
        {
            // V6 unencrypted: No S2K data, secret material follows directly
            // IMPORTANT: V6 does NOT have a 2-byte checksum for unencrypted keys (unlike V4)
            var remaining = source.Slice(offset);

            // The secret material is just the raw key data (no checksum to verify)
            var secretMaterial = remaining.ToArray();
            packet = new PgpSecretKeyPacket(publicKey, PgpS2KUsage.None, 0, null, Array.Empty<byte>(), secretMaterial);
            return true;
        }

        // V6 encrypted: The next `scalarOctetCount` bytes contain S2K-related data
        if (source.Length < offset + scalarOctetCount)
        {
            error = "Source too short for S2K data.";
            return false;
        }

        // Read S2K usage byte (first byte of S2K data)
        var s2kUsage = (PgpS2KUsage)source[offset++];

        // Read cipher algorithm
        if (source.Length <= offset)
        {
            error = "Source too short for cipher algorithm.";
            return false;
        }

        byte cipherAlgorithm = source[offset++];

        // For AEAD (253), there's an AEAD algorithm byte too
        byte aeadAlgorithm = 0;
        if (s2kUsage == PgpS2KUsage.Aead)
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
        int ivSize = s2kUsage == PgpS2KUsage.Aead
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

        packet = new PgpSecretKeyPacket(publicKey, s2kUsage, cipherAlgorithm, s2kSpec, iv, encryptedMaterial);
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

        if (Version == 6)
        {
            // V6 format: scalar octet count (1 byte)
            length += 1;

            if (S2KUsage != PgpS2KUsage.None)
            {
                // V6 encrypted: S2K usage (1) + cipher (1) + S2K specifier + IV
                length += 1; // S2K usage
                length += 1; // Cipher algorithm
                if (S2KSpecifier.HasValue)
                {
                    length += S2KSpecifier.Value.GetEncodedLength();
                }
                length += IV.Length;
            }
            // V6 unencrypted: no checksum, just secret material
        }
        else
        {
            // V4 format: S2K usage (1 byte)
            length += 1;

            if (S2KUsage != PgpS2KUsage.None)
            {
                length += 1; // Cipher algorithm
                if (S2KSpecifier.HasValue)
                {
                    length += S2KSpecifier.Value.GetEncodedLength();
                }
                length += IV.Length;
            }
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

        if (Version == 6)
        {
            // V6 format: scalar octet count first
            if (S2KUsage == PgpS2KUsage.None)
            {
                // Unencrypted: scalar octet count = 0
                destination[offset++] = 0;
            }
            else
            {
                // Encrypted: calculate scalar octet count
                // Count = S2K usage (1) + cipher (1) + S2K specifier length + IV length
                int s2kDataLen = 2; // S2K usage + cipher
                if (S2KSpecifier.HasValue)
                {
                    s2kDataLen += S2KSpecifier.Value.GetEncodedLength();
                }
                s2kDataLen += IV.Length;
                destination[offset++] = (byte)s2kDataLen;

                // Write S2K usage, cipher, S2K specifier, IV
                destination[offset++] = (byte)S2KUsage;
                destination[offset++] = CipherAlgorithm;
                if (S2KSpecifier.HasValue)
                {
                    offset += S2KSpecifier.Value.Write(destination.Slice(offset));
                }
                IV.Span.CopyTo(destination.Slice(offset));
                offset += IV.Length;
            }
        }
        else
        {
            // V4 format
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
    /// Decrypts this secret key packet using the provided passphrase.
    /// </summary>
    /// <param name="passphrase">The passphrase used to protect the key.</param>
    /// <returns>A new unencrypted secret key packet.</returns>
    /// <exception cref="InvalidOperationException">If the key is not encrypted.</exception>
    /// <exception cref="CryptographicException">If decryption fails or integrity check fails.</exception>
    /// <remarks>
    /// <para>
    /// This method supports the following S2K usage conventions:
    /// <list type="bullet">
    ///   <item><see cref="PgpS2KUsage.Sha1Hash"/> (254): SHA-1 hash for integrity verification</item>
    ///   <item><see cref="PgpS2KUsage.Checksum"/> (255): 2-byte checksum for integrity verification</item>
    /// </list>
    /// </para>
    /// <para>
    /// The supported S2K types are:
    /// <list type="bullet">
    ///   <item>Simple S2K (type 0)</item>
    ///   <item>Salted S2K (type 1)</item>
    ///   <item>Iterated and Salted S2K (type 3)</item>
    ///   <item>Argon2 S2K (type 4) - RFC 9580</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpSecretKeyPacket Decrypt(string passphrase)
    {
        if (!IsEncrypted)
        {
            throw new InvalidOperationException("Key is not encrypted.");
        }

        if (S2KSpecifier == null)
        {
            throw new InvalidOperationException("No S2K specifier available for encrypted key.");
        }

        // Warn about weak S2K types
        WarnIfWeakS2K(S2KSpecifier.Value);

        // Determine key size based on cipher algorithm
        int keySize = GetCipherKeySize(CipherAlgorithm);

        // Convert passphrase to bytes
        byte[] passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);

        try
        {
            // Derive encryption key using S2K
            byte[] encryptionKey = DeriveS2KKey(S2KSpecifier.Value, passphraseBytes, keySize);

            try
            {
                // Decrypt the secret key material
                byte[] decrypted = CfbDecrypt(SecretKeyMaterial.ToArray(), encryptionKey, IV.ToArray(), CipherAlgorithm);

                try
                {
                    // Verify integrity and extract secret material
                    byte[] secretMaterial;
                    if (S2KUsage == PgpS2KUsage.Sha1Hash)
                    {
                        // SHA-1 hash at the end (20 bytes)
                        if (decrypted.Length < 20)
                        {
                            throw new CryptographicException("Decrypted data too short for SHA-1 hash.");
                        }

                        int materialLength = decrypted.Length - 20;
                        byte[] expectedHash = decrypted.AsSpan(materialLength, 20).ToArray();
                        secretMaterial = decrypted.AsSpan(0, materialLength).ToArray();

                        // Verify SHA-1 hash
#pragma warning disable CA5350 // SHA-1 is weak, but required by OpenPGP specification for S2KUsage 254
                        byte[] actualHash;
#if NETSTANDARD2_0
                        using (var sha1 = SHA1.Create())
                        {
                            actualHash = sha1.ComputeHash(secretMaterial);
                        }
#else
                        actualHash = SHA1.HashData(secretMaterial);
#endif
#pragma warning restore CA5350

                        if (!SecureMemoryOperations.ConstantTimeEquals(expectedHash, actualHash))
                        {
                            throw new CryptographicException("Secret key integrity check failed. Wrong passphrase or corrupted data.");
                        }
                    }
                    else if (S2KUsage == PgpS2KUsage.Checksum)
                    {
                        // 2-byte checksum at the end
                        if (decrypted.Length < 2)
                        {
                            throw new CryptographicException("Decrypted data too short for checksum.");
                        }

                        int materialLength = decrypted.Length - 2;
                        ushort expectedChecksum = (ushort)((decrypted[materialLength] << 8) | decrypted[materialLength + 1]);
                        secretMaterial = decrypted.AsSpan(0, materialLength).ToArray();

                        // Calculate checksum
                        ushort actualChecksum = 0;
                        foreach (byte b in secretMaterial)
                        {
                            actualChecksum = (ushort)((actualChecksum + b) & 0xFFFF);
                        }

                        if (!SecureMemoryOperations.ConstantTimeEquals(expectedChecksum, actualChecksum))
                        {
                            throw new CryptographicException("Secret key checksum verification failed. Wrong passphrase or corrupted data.");
                        }
                    }
                    else
                    {
                        throw new InvalidOperationException($"Unsupported S2K usage: {S2KUsage}");
                    }

                    // Create unencrypted secret key packet
                    return CreateUnencrypted(PublicKey, secretMaterial);
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(decrypted);
                }
            }
            finally
            {
                SecureMemoryOperations.SecureClear(encryptionKey);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(passphraseBytes);
        }
    }

    /// <summary>
    /// Derives an encryption key from the S2K specifier and passphrase.
    /// </summary>
    private static byte[] DeriveS2KKey(PgpS2KSpecifier specifier, byte[] passphrase, int keySize)
    {
        var hashAlgorithm = GetHashAlgorithmName(specifier.HashAlgorithm);

        return specifier.Type switch
        {
            S2KType.Simple => S2KCore.SimpleS2K(passphrase, keySize, hashAlgorithm),
            S2KType.Salted => S2KCore.SaltedS2K(passphrase, specifier.Salt.Span, keySize, hashAlgorithm),
            S2KType.IteratedAndSalted => S2KCore.IteratedS2K(
                passphrase,
                specifier.Salt.Span,
                S2KCore.DecodeIterationCount(specifier.EncodedCount),
                keySize,
                hashAlgorithm),
            S2KType.Argon2 => S2KCore.Argon2S2K(
                passphrase,
                specifier.Salt.Span,
                specifier.Argon2Params!.Value.Passes,
                specifier.Argon2Params!.Value.Parallelism,
                specifier.Argon2Params!.Value.MemoryExponent,
                keySize),
            _ => throw new InvalidOperationException($"Unsupported S2K type: {specifier.Type}")
        };
    }

    /// <summary>
    /// Outputs a warning if the S2K specifier uses a weak key derivation method.
    /// </summary>
    /// <param name="specifier">The S2K specifier to check.</param>
    /// <remarks>
    /// <para>
    /// Weak S2K types are vulnerable to brute-force attacks:
    /// <list type="bullet">
    ///   <item>Simple S2K (type 0): No salt or iteration, extremely weak</item>
    ///   <item>Salted S2K (type 1): No iteration, vulnerable to dictionary attacks</item>
    ///   <item>Iterated S2K with low count: May be vulnerable if iteration count is too low</item>
    /// </list>
    /// </para>
    /// <para>
    /// This method outputs warnings via Debug.WriteLine and
    /// Trace.TraceWarning for diagnostic purposes.
    /// </para>
    /// </remarks>
    private static void WarnIfWeakS2K(PgpS2KSpecifier specifier)
    {
        const long MinimumRecommendedIterations = 1_000_000; // 1 million iterations minimum

        string? warning = null;

        switch (specifier.Type)
        {
            case S2KType.Simple:
                warning = "SECURITY WARNING: This secret key uses Simple S2K (type 0), which provides " +
                         "minimal protection against brute-force attacks. The key should be re-encrypted " +
                         "with Iterated S2K (type 3) or Argon2 S2K (type 4).";
                break;

            case S2KType.Salted:
                warning = "SECURITY WARNING: This secret key uses Salted S2K (type 1), which does not " +
                         "include iteration and is vulnerable to dictionary attacks. The key should be " +
                         "re-encrypted with Iterated S2K (type 3) or Argon2 S2K (type 4).";
                break;

            case S2KType.IteratedAndSalted:
                var iterations = specifier.GetIterationCount();
                if (iterations < MinimumRecommendedIterations)
                {
                    warning = $"SECURITY WARNING: This secret key uses Iterated S2K with only {iterations:N0} " +
                             $"iterations. Modern recommendations suggest at least {MinimumRecommendedIterations:N0} " +
                             "iterations for adequate protection against brute-force attacks.";
                }
                break;

            case S2KType.Reserved:
                // Reserved type - unusual but not necessarily weak
                break;

            case S2KType.Argon2:
                // Argon2 is the strongest protection, no warning needed
                break;

            default:
                // Unknown S2K types - might be future types or extensions
                break;
        }

        if (warning != null)
        {
            Debug.WriteLine(warning);
            Trace.TraceWarning(warning);
        }
    }

    /// <summary>
    /// Maps a PGP hash algorithm ID to a .NET HashAlgorithmName.
    /// </summary>
    private static HashAlgorithmName GetHashAlgorithmName(byte hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            1 => HashAlgorithmName.MD5, // Not recommended, but supported for legacy
            2 => HashAlgorithmName.SHA1,
            8 => HashAlgorithmName.SHA256,
            9 => HashAlgorithmName.SHA384,
            10 => HashAlgorithmName.SHA512,
            11 => throw new NotSupportedException("SHA-224 is not supported by .NET."),
            12 => throw new NotSupportedException("SHA3-256 is not supported by .NET standard."),
            _ => throw new ArgumentException($"Unknown hash algorithm: {hashAlgorithm}", nameof(hashAlgorithm))
        };
    }

    /// <summary>
    /// Gets the key size in bytes for a cipher algorithm.
    /// </summary>
    private static int GetCipherKeySize(byte cipherAlgorithm)
    {
        return cipherAlgorithm switch
        {
            1 => 16, // IDEA
            2 => 24, // 3DES
            3 => 16, // CAST5
            4 => 16, // Blowfish
            7 => 16, // AES-128
            8 => 24, // AES-192
            9 => 32, // AES-256
            10 => 32, // Twofish
            11 => 16, // Camellia-128
            12 => 24, // Camellia-192
            13 => 32, // Camellia-256
            _ => throw new ArgumentException($"Unknown cipher algorithm: {cipherAlgorithm}", nameof(cipherAlgorithm))
        };
    }

    /// <summary>
    /// Decrypts data using CFB mode.
    /// </summary>
    private static byte[] CfbDecrypt(byte[] ciphertext, byte[] key, byte[] iv, byte cipherAlgorithm)
    {
        int blockSize = GetCipherBlockSize(cipherAlgorithm);

        byte[] plaintext = new byte[ciphertext.Length];
        byte[] fr = new byte[blockSize]; // Feedback register
        byte[] fre = new byte[blockSize]; // Encrypted feedback register

        // Initialize FR with IV
        iv.AsSpan(0, Math.Min(iv.Length, blockSize)).CopyTo(fr);

        // Create the appropriate symmetric algorithm
        using SymmetricAlgorithm cipher = cipherAlgorithm switch
        {
            2 => CreateTripleDes(key),
            7 or 8 or 9 => CreateAes(key),
            _ => throw new NotSupportedException($"Cipher algorithm {cipherAlgorithm} is not supported. Only TripleDES (2) and AES (7, 8, 9) are currently supported.")
        };

        using var encryptor = cipher.CreateEncryptor();

        try
        {
            int pos = 0;
            while (pos < ciphertext.Length)
            {
                // Encrypt the feedback register
                encryptor.TransformBlock(fr, 0, blockSize, fre, 0);

                // XOR ciphertext with encrypted FR to get plaintext
                int bytesToProcess = Math.Min(blockSize, ciphertext.Length - pos);
                for (int i = 0; i < bytesToProcess; i++)
                {
                    plaintext[pos + i] = (byte)(ciphertext[pos + i] ^ fre[i]);
                }

                // Update FR with ciphertext for next iteration
                Array.Copy(ciphertext, pos, fr, 0, bytesToProcess);
                if (bytesToProcess < blockSize)
                {
                    Array.Clear(fr, bytesToProcess, blockSize - bytesToProcess);
                }

                pos += bytesToProcess;
            }

            return plaintext;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(fr);
            SecureMemoryOperations.SecureClear(fre);
        }
    }

    /// <summary>
    /// Creates an AES cipher configured for CFB mode implementation.
    /// </summary>
    private static Aes CreateAes(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB; // We implement CFB manually
        aes.Padding = PaddingMode.None;
        return aes;
    }

    /// <summary>
    /// Creates a TripleDES cipher configured for CFB mode implementation.
    /// </summary>
    /// <remarks>
    /// TripleDES is considered weak by modern standards but is supported for
    /// backward compatibility with legacy PGP keys (RFC 4880 algorithm 2).
    /// </remarks>
#pragma warning disable CA5350 // TripleDES is weak but needed for legacy PGP support (RFC 4880)
    private static TripleDES CreateTripleDes(byte[] key)
    {
        var des3 = TripleDES.Create();
        des3.Key = key;
        des3.Mode = CipherMode.ECB; // We implement CFB manually
        des3.Padding = PaddingMode.None;
        return des3;
    }
#pragma warning restore CA5350

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

    /// <summary>
    /// Securely clears all sensitive data from memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method zeros out the secret key material, IV, and S2K salt to prevent
    /// sensitive data from lingering in memory. On modern .NET platforms, this uses
    /// CryptographicOperations.ZeroMemory for secure clearing.
    /// </para>
    /// <para>
    /// <b>Security Note:</b> Since this is a value type (struct), any copies made
    /// before calling this method will still contain the original data. To ensure
    /// complete cleanup:
    /// <list type="bullet">
    ///   <item>Call this method on all copies of the struct</item>
    ///   <item>Avoid copying the struct after use</item>
    ///   <item>Consider using <see langword="ref"/> parameters when passing the struct</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>Important:</b> This method only clears the memory if the underlying
    /// <see cref="ReadOnlyMemory{T}"/> is backed by an array. Memory from other
    /// sources (e.g., native memory) may not be cleared.
    /// </para>
    /// </remarks>
    public void ClearSensitiveData()
    {
        ClearMemory(SecretKeyMaterial);
        ClearMemory(IV);

        if (S2KSpecifier.HasValue)
        {
            ClearMemory(S2KSpecifier.Value.Salt);
        }
    }

    /// <summary>
    /// Clears the contents of a <see cref="ReadOnlyMemory{T}"/> if it is backed by an array.
    /// </summary>
    /// <param name="memory">The memory to clear.</param>
    private static void ClearMemory(ReadOnlyMemory<byte> memory)
    {
        if (memory.IsEmpty)
        {
            return;
        }

        if (MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment) && segment.Array != null)
        {
            SecureMemoryOperations.SecureClear(segment.Array.AsSpan(segment.Offset, segment.Count));
        }
    }
}
