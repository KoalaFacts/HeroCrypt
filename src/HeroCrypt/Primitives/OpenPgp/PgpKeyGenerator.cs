using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Rsa;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Fluent builder for generating OpenPGP key pairs.
/// </summary>
/// <remarks>
/// <para>
/// <b>Usage example:</b>
/// <code>
/// var result = PgpKeyGenerator.Create()
///     .WithUserId("Alice &lt;alice@example.com&gt;")
///     .GenerateRsa();
/// </code>
/// </para>
/// <para>
/// <b>Default behavior:</b>
/// <list type="bullet">
///   <item>RSA key size: 4096 bits</item>
///   <item>Key version: V4 for RSA, V6 for Ed25519/X25519</item>
///   <item>Self-certification: PositiveCertification (0x13)</item>
///   <item>Hash algorithm: SHA-256</item>
/// </list>
/// </para>
/// </remarks>
public sealed class PgpKeyGenerator
{
    private string? userId;
    private string? passphrase;
    private int keySize = 4096;
    private DateTimeOffset creationTime = DateTimeOffset.UtcNow;
    private byte? explicitVersion;
    private PgpKeyCapabilities keyFlags = PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign;
    private bool addEncryptionSubkey;
    private bool addSigningSubkey;

    private PgpKeyGenerator()
    {
    }

    /// <summary>
    /// Creates a new key generator.
    /// </summary>
    /// <returns>A new PgpKeyGenerator instance.</returns>
    public static PgpKeyGenerator Create() => new();

    #region User Identity

    /// <summary>
    /// Sets the user ID for the key.
    /// </summary>
    /// <param name="userId">The user ID string (e.g., "Name &lt;email@example.com&gt;").</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentNullException">If userId is null.</exception>
    public PgpKeyGenerator WithUserId(string userId)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(userId);
#else
        if (userId == null) throw new ArgumentNullException(nameof(userId));
#endif

        this.userId = userId;
        return this;
    }

    /// <summary>
    /// Sets the user ID from name and email components.
    /// </summary>
    /// <param name="name">The user's name.</param>
    /// <param name="email">The user's email address.</param>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithUserId(string name, string email)
    {
        var packet = PgpUserIdPacket.Create(name, email);
        this.userId = packet.UserId;
        return this;
    }

    #endregion

    #region Passphrase Protection

    /// <summary>
    /// Sets the passphrase for encrypting the secret key.
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// When a passphrase is set, the secret key will be encrypted using S2K
    /// (String-to-Key) derivation. This is the recommended practice for
    /// protecting private keys.
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithPassphrase(string passphrase)
    {
        this.passphrase = passphrase;
        return this;
    }

    #endregion

    #region Key Configuration

    /// <summary>
    /// Sets the RSA key size in bits.
    /// </summary>
    /// <param name="bits">The key size (2048, 3072, or 4096).</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentException">If the key size is not supported.</exception>
    public PgpKeyGenerator WithKeySize(int bits)
    {
        if (bits != 2048 && bits != 3072 && bits != 4096)
        {
            throw new ArgumentException("Key size must be 2048, 3072, or 4096 bits.", nameof(bits));
        }

        this.keySize = bits;
        return this;
    }

    /// <summary>
    /// Sets the key creation time.
    /// </summary>
    /// <param name="time">The creation time.</param>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithCreationTime(DateTimeOffset time)
    {
        this.creationTime = time;
        return this;
    }

    /// <summary>
    /// Sets the key version explicitly.
    /// </summary>
    /// <param name="version">The key version (4 or 6).</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentException">If the version is not supported.</exception>
    public PgpKeyGenerator WithVersion(byte version)
    {
        if (version != 4 && version != 6)
        {
            throw new ArgumentException("Key version must be 4 or 6.", nameof(version));
        }

        this.explicitVersion = version;
        return this;
    }

    /// <summary>
    /// Sets the key capabilities flags for the master key.
    /// </summary>
    /// <param name="flags">The key capability flags.</param>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithKeyFlags(PgpKeyCapabilities flags)
    {
        this.keyFlags = flags;
        return this;
    }

    #endregion

    #region Subkeys

    /// <summary>
    /// Adds a signing-capable subkey.
    /// </summary>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithSigningSubkey()
    {
        this.addSigningSubkey = true;
        return this;
    }

    /// <summary>
    /// Adds an encryption-capable subkey.
    /// </summary>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithEncryptionSubkey()
    {
        this.addEncryptionSubkey = true;
        return this;
    }

    #endregion

    #region Key Generation

    /// <summary>
    /// Generates an RSA key pair with the default key size (4096 bits).
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <exception cref="InvalidOperationException">If no user ID has been set.</exception>
    public PgpKeyGeneratorResult GenerateRsa()
    {
        return GenerateRsa(this.keySize);
    }

    /// <summary>
    /// Generates an RSA key pair with the specified key size.
    /// </summary>
    /// <param name="keySizeBits">The key size in bits (2048, 3072, or 4096).</param>
    /// <returns>The generated key pair.</returns>
    /// <exception cref="InvalidOperationException">If no user ID has been set.</exception>
    /// <exception cref="ArgumentException">If the key size is not supported.</exception>
    public PgpKeyGeneratorResult GenerateRsa(int keySizeBits)
    {
        ValidateConfiguration();

        if (keySizeBits != 2048 && keySizeBits != 3072 && keySizeBits != 4096)
        {
            throw new ArgumentException("Key size must be 2048, 3072, or 4096 bits.", nameof(keySizeBits));
        }

        byte version = explicitVersion ?? 4;

        // Generate RSA key pair
        using var rsa = RSA.Create();
        rsa.KeySize = keySizeBits;
        var rsaParams = rsa.ExportParameters(true);

        // Convert to BigInteger (unsigned big-endian)
        var n = BytesToBigInteger(rsaParams.Modulus!);
        var e = BytesToBigInteger(rsaParams.Exponent!);
        var d = BytesToBigInteger(rsaParams.D!);
        var p = BytesToBigInteger(rsaParams.P!);
        var q = BytesToBigInteger(rsaParams.Q!);

        // Compute u = p^-1 mod q (multiplicative inverse)
        var u = ComputeModularInverse(p, q);

        // Create public key packet
        var publicKey = PgpPublicKeyPacket.CreateRsa(version, creationTime, n, e, isSubkey: false);

        // Create secret key material: d || p || q || u as MPIs
        var secretMaterial = EncodeRsaSecretMaterial(d, p, q, u);

        // Create secret key packet (unencrypted for now)
        PgpSecretKeyPacket secretKey;
        if (string.IsNullOrEmpty(passphrase))
        {
            secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);
        }
        else
        {
            // TODO: Implement passphrase protection with S2K
            throw new NotSupportedException("Passphrase-protected keys are not yet implemented.");
        }

        // Create user ID packet
        var userIdPacket = new PgpUserIdPacket(userId!);

        // Create self-certification signature
        var certificationSignature = CreateUserIdCertification(publicKey, secretKey, userIdPacket, version);

        // Build key rings
        var publicKeyRing = new PgpPublicKeyRing(
            publicKey,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);

        var secretKeyRing = new PgpSecretKeyRing(
            secretKey,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);

        // Add subkeys if requested
        if (addEncryptionSubkey)
        {
            (publicKeyRing, secretKeyRing) = AddRsaEncryptionSubkey(publicKeyRing, secretKeyRing, keySizeBits, version);
        }

        if (addSigningSubkey)
        {
            (publicKeyRing, secretKeyRing) = AddRsaSigningSubkey(publicKeyRing, secretKeyRing, keySizeBits, version);
        }

        return new PgpKeyGeneratorResult(secretKeyRing, publicKeyRing, userId!);
    }

    /// <summary>
    /// Generates an Ed25519 signing key (V6 format).
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <exception cref="NotSupportedException">Ed25519 key generation is not yet implemented.</exception>
    public PgpKeyGeneratorResult GenerateEd25519()
    {
        ValidateConfiguration();
        throw new NotSupportedException("Ed25519 key generation is not yet implemented.");
    }

    /// <summary>
    /// Generates an X25519 encryption key (V6 format).
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <exception cref="NotSupportedException">X25519 key generation is not yet implemented.</exception>
    public PgpKeyGeneratorResult GenerateX25519()
    {
        ValidateConfiguration();
        throw new NotSupportedException("X25519 key generation is not yet implemented.");
    }

    /// <summary>
    /// Generates an Ed25519 signing key with an X25519 encryption subkey.
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <exception cref="NotSupportedException">Ed25519/X25519 key generation is not yet implemented.</exception>
    public PgpKeyGeneratorResult GenerateEd25519WithX25519Subkey()
    {
        ValidateConfiguration();
        throw new NotSupportedException("Ed25519/X25519 key generation is not yet implemented.");
    }

    #endregion

    #region Private Helpers

    private void ValidateConfiguration()
    {
        if (string.IsNullOrEmpty(userId))
        {
            throw new InvalidOperationException("No user ID has been set. Call WithUserId() first.");
        }
    }

    private static BigInteger ComputeModularInverse(BigInteger p, BigInteger q)
    {
        // Compute u = p^-1 mod q using Fermat's little theorem
        // Since q is prime, p^(-1) mod q = p^(q-2) mod q
        return BigInteger.ModPow(p, q - 2, q);
    }

    private static byte[] EncodeRsaSecretMaterial(BigInteger d, BigInteger p, BigInteger q, BigInteger u)
    {
        int dLen = Mpi.GetEncodedLength(d);
        int pLen = Mpi.GetEncodedLength(p);
        int qLen = Mpi.GetEncodedLength(q);
        int uLen = Mpi.GetEncodedLength(u);

        var material = new byte[dLen + pLen + qLen + uLen];
        int offset = 0;

        offset += Mpi.Write(d, material.AsSpan(offset));
        offset += Mpi.Write(p, material.AsSpan(offset));
        offset += Mpi.Write(q, material.AsSpan(offset));
        Mpi.Write(u, material.AsSpan(offset));

        return material;
    }

    private PgpSignaturePacket CreateUserIdCertification(
        PgpPublicKeyPacket publicKey,
        PgpSecretKeyPacket secretKey,
        PgpUserIdPacket userIdPacket,
        byte version)
    {
        var sigType = PgpSignatureType.PositiveCertification;
        var pubAlgo = (byte)publicKey.Algorithm;
        var hashAlgo = (byte)PgpHashAlgorithmId.Sha256;

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(creationTime),
            PgpSignatureSubpacket.CreateKeyFlags(keyFlags),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, publicKey.ComputeFingerprint()),
            PgpSignatureSubpacket.CreateFeatures(PgpFeatures.ModificationDetection)
        };

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateIssuerKeyId(publicKey.GetKeyId())
        };

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Compute the certification hash
        var hash = ComputeCertificationHash(
            publicKey,
            userIdPacket,
            version,
            (byte)sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpacketData);

        // Get hash prefix
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create signature using RSA
        var signatureData = CreateRsaSignature(secretKey, hash);

        // Build signature packet
        if (version == 6)
        {
            var salt = GenerateSalt(PgpHashAlgorithmId.Sha256);
            return PgpSignaturePacket.CreateV6(
                sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                salt,
                signatureData);
        }
        else
        {
            return PgpSignaturePacket.CreateV4(
                sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                signatureData);
        }
    }

    private static byte[] ComputeCertificationHash(
        PgpPublicKeyPacket publicKey,
        PgpUserIdPacket userIdPacket,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        using var hash = PgpHashAlgorithmId.Sha256.CreateIncrementalHash();

        // Get public key body
        byte[] keyBody = publicKey.ToArray();

        // Hash public key with tag
        // 0x99 || 2-byte length || key body
        var keyTag = new byte[3];
        keyTag[0] = 0x99;
        BinaryPrimitives.WriteUInt16BigEndian(keyTag.AsSpan(1), (ushort)keyBody.Length);
        hash.AppendData(keyTag);
        hash.AppendData(keyBody);

        // Hash user ID with tag
        // 0xB4 || 4-byte length || user ID bytes
        byte[] userIdBytes = userIdPacket.ToArray();
        var userIdTag = new byte[5];
        userIdTag[0] = 0xB4;
        BinaryPrimitives.WriteUInt32BigEndian(userIdTag.AsSpan(1), (uint)userIdBytes.Length);
        hash.AppendData(userIdTag);
        hash.AppendData(userIdBytes);

        // Hash signature header
        if (version == 4)
        {
            var header = new byte[6 + hashedSubpackets.Length];
            header[0] = version;
            header[1] = sigType;
            header[2] = pubAlgo;
            header[3] = hashAlgo;
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), (ushort)hashedSubpackets.Length);
            Array.Copy(hashedSubpackets, 0, header, 6, hashedSubpackets.Length);
            hash.AppendData(header);

            // V4 trailer: version(1) + 0xFF(1) + length(4)
            var trailer = new byte[6];
            trailer[0] = version;
            trailer[1] = 0xFF;
            uint totalLen = (uint)(4 + hashedSubpackets.Length);
            BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), totalLen);
            hash.AppendData(trailer);
        }
        else // V6
        {
            var header = new byte[8 + hashedSubpackets.Length];
            header[0] = version;
            header[1] = sigType;
            header[2] = pubAlgo;
            header[3] = hashAlgo;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashedSubpackets.Length);
            Array.Copy(hashedSubpackets, 0, header, 8, hashedSubpackets.Length);
            hash.AppendData(header);

            // V6 trailer: version(1) + 0xFF(1) + length(8)
            var trailer = new byte[10];
            trailer[0] = version;
            trailer[1] = 0xFF;
            ulong totalLen = (ulong)(4 + hashedSubpackets.Length);
            BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(2), totalLen);
            hash.AppendData(trailer);
        }

        return hash.GetHashAndReset();
    }

    private static byte[] CreateRsaSignature(PgpSecretKeyPacket secretKey, byte[] hash)
    {
        // Extract RSA private key components
        var (d, p, q, _) = secretKey.ReadRsaSecretKey();
        var (n, e) = secretKey.PublicKey.ReadRsaKey();

        // Create RSA parameters
        var rsaPrivateKey = new RsaPrivateKey(n, d, p, q, e);
        var rsaParams = RsaCore.ToRsaParameters(rsaPrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        // Sign the hash
        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Encode as MPI
        int mpiLen = Mpi.GetEncodedLength(signature);
        var mpiBuffer = new byte[mpiLen];
        Mpi.Write(signature, mpiBuffer);
        return mpiBuffer;
    }

    private PgpSignaturePacket CreateSubkeyBindingSignature(
        PgpPublicKeyPacket masterPublicKey,
        PgpSecretKeyPacket masterSecretKey,
        PgpPublicKeyPacket subkey,
        PgpKeyCapabilities subkeyFlags,
        byte version)
    {
        var sigType = PgpSignatureType.SubkeyBinding;
        var pubAlgo = (byte)masterPublicKey.Algorithm;
        var hashAlgo = (byte)PgpHashAlgorithmId.Sha256;

        // Build hashed subpackets
        var hashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateSignatureCreationTime(creationTime),
            PgpSignatureSubpacket.CreateKeyFlags(subkeyFlags),
            PgpSignatureSubpacket.CreateIssuerFingerprint(version, masterPublicKey.ComputeFingerprint())
        };

        // Build unhashed subpackets
        var unhashedSubpackets = new List<PgpSignatureSubpacket>
        {
            PgpSignatureSubpacket.CreateIssuerKeyId(masterPublicKey.GetKeyId())
        };

        // Serialize hashed subpackets
        var hashedSubpacketData = PgpSignatureSubpacket.WriteAll(hashedSubpackets);

        // Compute the binding hash
        var hash = ComputeSubkeyBindingHash(
            masterPublicKey,
            subkey,
            version,
            (byte)sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpacketData);

        // Get hash prefix
        ushort hashPrefix = BinaryPrimitives.ReadUInt16BigEndian(hash);

        // Create signature using RSA
        var signatureData = CreateRsaSignature(masterSecretKey, hash);

        // Build signature packet
        if (version == 6)
        {
            var salt = GenerateSalt(PgpHashAlgorithmId.Sha256);
            return PgpSignaturePacket.CreateV6(
                sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                salt,
                signatureData);
        }
        else
        {
            return PgpSignaturePacket.CreateV4(
                sigType,
                pubAlgo,
                hashAlgo,
                hashedSubpackets,
                unhashedSubpackets,
                hashPrefix,
                signatureData);
        }
    }

    private static byte[] ComputeSubkeyBindingHash(
        PgpPublicKeyPacket masterKey,
        PgpPublicKeyPacket subkey,
        byte version,
        byte sigType,
        byte pubAlgo,
        byte hashAlgo,
        byte[] hashedSubpackets)
    {
        using var hash = PgpHashAlgorithmId.Sha256.CreateIncrementalHash();

        // Hash master key with tag
        byte[] masterBody = masterKey.ToArray();
        var masterTag = new byte[3];
        masterTag[0] = 0x99;
        BinaryPrimitives.WriteUInt16BigEndian(masterTag.AsSpan(1), (ushort)masterBody.Length);
        hash.AppendData(masterTag);
        hash.AppendData(masterBody);

        // Hash subkey with tag
        byte[] subkeyBody = subkey.ToArray();
        var subkeyTag = new byte[3];
        subkeyTag[0] = 0x99;
        BinaryPrimitives.WriteUInt16BigEndian(subkeyTag.AsSpan(1), (ushort)subkeyBody.Length);
        hash.AppendData(subkeyTag);
        hash.AppendData(subkeyBody);

        // Hash signature header
        if (version == 4)
        {
            var header = new byte[6 + hashedSubpackets.Length];
            header[0] = version;
            header[1] = sigType;
            header[2] = pubAlgo;
            header[3] = hashAlgo;
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), (ushort)hashedSubpackets.Length);
            Array.Copy(hashedSubpackets, 0, header, 6, hashedSubpackets.Length);
            hash.AppendData(header);

            var trailer = new byte[6];
            trailer[0] = version;
            trailer[1] = 0xFF;
            uint totalLen = (uint)(4 + hashedSubpackets.Length);
            BinaryPrimitives.WriteUInt32BigEndian(trailer.AsSpan(2), totalLen);
            hash.AppendData(trailer);
        }
        else
        {
            var header = new byte[8 + hashedSubpackets.Length];
            header[0] = version;
            header[1] = sigType;
            header[2] = pubAlgo;
            header[3] = hashAlgo;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)hashedSubpackets.Length);
            Array.Copy(hashedSubpackets, 0, header, 8, hashedSubpackets.Length);
            hash.AppendData(header);

            var trailer = new byte[10];
            trailer[0] = version;
            trailer[1] = 0xFF;
            ulong totalLen = (ulong)(4 + hashedSubpackets.Length);
            BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(2), totalLen);
            hash.AppendData(trailer);
        }

        return hash.GetHashAndReset();
    }

    private (PgpPublicKeyRing, PgpSecretKeyRing) AddRsaEncryptionSubkey(
        PgpPublicKeyRing publicRing,
        PgpSecretKeyRing secretRing,
        int keySizeBits,
        byte version)
    {
        // Generate RSA subkey
        using var rsa = RSA.Create();
        rsa.KeySize = keySizeBits;
        var rsaParams = rsa.ExportParameters(true);

        var n = BytesToBigInteger(rsaParams.Modulus!);
        var e = BytesToBigInteger(rsaParams.Exponent!);
        var d = BytesToBigInteger(rsaParams.D!);
        var p = BytesToBigInteger(rsaParams.P!);
        var q = BytesToBigInteger(rsaParams.Q!);
        var u = ComputeModularInverse(p, q);

        // Create subkey packets
        var subkeyPublic = PgpPublicKeyPacket.CreateRsa(version, creationTime, n, e, isSubkey: true);
        var subkeyMaterial = EncodeRsaSecretMaterial(d, p, q, u);
        var subkeySecret = PgpSecretKeyPacket.CreateUnencrypted(subkeyPublic, subkeyMaterial);

        // Create binding signature
        var subkeyFlags = PgpKeyCapabilities.EncryptCommunications | PgpKeyCapabilities.EncryptStorage;
        var bindingSig = CreateSubkeyBindingSignature(
            publicRing.MasterKey,
            secretRing.MasterKey,
            subkeyPublic,
            subkeyFlags,
            version);

        // Add to key rings
        return (
            publicRing.AddSubkey(subkeyPublic, bindingSig),
            secretRing.AddSubkey(subkeySecret, bindingSig)
        );
    }

    private (PgpPublicKeyRing, PgpSecretKeyRing) AddRsaSigningSubkey(
        PgpPublicKeyRing publicRing,
        PgpSecretKeyRing secretRing,
        int keySizeBits,
        byte version)
    {
        // Generate RSA subkey
        using var rsa = RSA.Create();
        rsa.KeySize = keySizeBits;
        var rsaParams = rsa.ExportParameters(true);

        var n = BytesToBigInteger(rsaParams.Modulus!);
        var e = BytesToBigInteger(rsaParams.Exponent!);
        var d = BytesToBigInteger(rsaParams.D!);
        var p = BytesToBigInteger(rsaParams.P!);
        var q = BytesToBigInteger(rsaParams.Q!);
        var u = ComputeModularInverse(p, q);

        // Create subkey packets
        var subkeyPublic = PgpPublicKeyPacket.CreateRsa(version, creationTime, n, e, isSubkey: true);
        var subkeyMaterial = EncodeRsaSecretMaterial(d, p, q, u);
        var subkeySecret = PgpSecretKeyPacket.CreateUnencrypted(subkeyPublic, subkeyMaterial);

        // Create binding signature
        var subkeyFlags = PgpKeyCapabilities.Sign;
        var bindingSig = CreateSubkeyBindingSignature(
            publicRing.MasterKey,
            secretRing.MasterKey,
            subkeyPublic,
            subkeyFlags,
            version);

        // Add to key rings
        return (
            publicRing.AddSubkey(subkeyPublic, bindingSig),
            secretRing.AddSubkey(subkeySecret, bindingSig)
        );
    }

    private static byte[] GenerateSalt(PgpHashAlgorithmId hashAlg)
    {
        int saltLen = PgpSignaturePacket.GetExpectedSaltLength((byte)hashAlg);
        var salt = new byte[saltLen];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Converts a big-endian byte array to BigInteger.
    /// </summary>
    private static BigInteger BytesToBigInteger(byte[] bytes)
    {
        // BigInteger constructor expects little-endian with optional sign byte
        var leBytes = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            leBytes[bytes.Length - 1 - i] = bytes[i];
        }
        leBytes[bytes.Length] = 0; // Ensure positive
        return new BigInteger(leBytes);
    }

    #endregion
}
