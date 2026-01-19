using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Primitives.S2K;

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

        // Create unencrypted secret key first (for signing)
        var unencryptedSecretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);

        // Create user ID packet
        var userIdPacket = new PgpUserIdPacket(userId!);

        // Create self-certification signature (using unencrypted key)
        var certificationSignature = CreateUserIdCertification(publicKey, unencryptedSecretKey, userIdPacket, version);

        // Build key rings with UNENCRYPTED keys (encryption happens at the end)
        var publicKeyRing = new PgpPublicKeyRing(
            publicKey,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);

        var secretKeyRing = new PgpSecretKeyRing(
            unencryptedSecretKey,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);

        // Add subkeys if requested (still using unencrypted keys for signing)
        if (addEncryptionSubkey)
        {
            (publicKeyRing, secretKeyRing) = AddRsaEncryptionSubkey(publicKeyRing, secretKeyRing, keySizeBits, version);
        }

        if (addSigningSubkey)
        {
            (publicKeyRing, secretKeyRing) = AddRsaSigningSubkey(publicKeyRing, secretKeyRing, keySizeBits, version);
        }

        // NOW encrypt all secret keys if passphrase is provided
        if (!string.IsNullOrEmpty(passphrase))
        {
            secretKeyRing = EncryptSecretKeyRing(secretKeyRing, passphrase!);
        }

        return new PgpKeyGeneratorResult(secretKeyRing, publicKeyRing, userId!);
    }

    /// <summary>
    /// Generates an Ed25519 signing key (V6 format).
    /// </summary>
    /// <returns>The generated key pair.</returns>
    public PgpKeyGeneratorResult GenerateEd25519()
    {
        ValidateConfiguration();

        // Ed25519 always uses V6 format per RFC 9580
        byte version = 6;

        // Generate Ed25519 key pair
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

        // Create public key packet (V6, Ed25519 native format - raw 32 bytes)
        var publicKeyPacket = PgpPublicKeyPacket.CreateEd25519(creationTime, publicKey, isSubkey: false);

        // Create secret key packet
        // Ed25519 secret material is raw 32-byte seed (no MPI encoding)
        PgpSecretKeyPacket secretKeyPacket;
        if (string.IsNullOrEmpty(passphrase))
        {
            secretKeyPacket = PgpSecretKeyPacket.CreateUnencrypted(publicKeyPacket, privateKey);
        }
        else
        {
            secretKeyPacket = CreateEncryptedSecretKey(publicKeyPacket, privateKey, passphrase!);
        }

        // Create user ID packet
        var userIdPacket = new PgpUserIdPacket(userId!);

        // Create self-certification signature (Ed25519 signing key, so Certify | Sign flags)
        var certFlags = PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign;
        var certificationSignature = CreateEd25519UserIdCertification(
            publicKeyPacket,
            privateKey,
            userIdPacket,
            certFlags,
            version);

        // Build key rings
        var publicKeyRing = new PgpPublicKeyRing(
            publicKeyPacket,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);

        var secretKeyRing = new PgpSecretKeyRing(
            secretKeyPacket,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);

        return new PgpKeyGeneratorResult(secretKeyRing, publicKeyRing, userId!);
    }

    /// <summary>
    /// Generates an X25519 encryption key (V6 format).
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <remarks>
    /// <para>
    /// X25519 is an encryption-only algorithm. The generated key will have
    /// <see cref="PgpKeyCapabilities.EncryptCommunications"/> and
    /// <see cref="PgpKeyCapabilities.EncryptStorage"/> flags.
    /// </para>
    /// <para>
    /// Note: An X25519-only key cannot create signatures for self-certification.
    /// This method generates a key that can only be used as a subkey bound to
    /// a signing-capable master key. For a complete key pair, use
    /// <see cref="GenerateEd25519WithX25519Subkey"/> instead.
    /// </para>
    /// </remarks>
    public PgpKeyGeneratorResult GenerateX25519()
    {
        ValidateConfiguration();

        // Generate X25519 key pair (V6 format per RFC 9580)
        var privateKey = Curve25519Core.GeneratePrivateKey();
        var publicKey = Curve25519Core.DerivePublicKey(privateKey);

        // Create public key packet (V6, X25519 native format - raw 32 bytes)
        var publicKeyPacket = PgpPublicKeyPacket.CreateX25519(creationTime, publicKey, isSubkey: false);

        // Create secret key packet
        // X25519 secret material is raw 32-byte clamped key (no MPI encoding)
        PgpSecretKeyPacket secretKeyPacket;
        if (string.IsNullOrEmpty(passphrase))
        {
            secretKeyPacket = PgpSecretKeyPacket.CreateUnencrypted(publicKeyPacket, privateKey);
        }
        else
        {
            secretKeyPacket = CreateEncryptedSecretKey(publicKeyPacket, privateKey, passphrase!);
        }

        // Create user ID packet
        var userIdPacket = new PgpUserIdPacket(userId!);

        // X25519 cannot sign, so we cannot create a proper self-certification.
        // Create a key ring without certification signature.
        // In practice, X25519 keys should be used as subkeys bound to an Ed25519 master.
        var publicKeyRing = new PgpPublicKeyRing(
            publicKeyPacket,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: null);

        var secretKeyRing = new PgpSecretKeyRing(
            secretKeyPacket,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: null);

        return new PgpKeyGeneratorResult(secretKeyRing, publicKeyRing, userId!);
    }

    /// <summary>
    /// Generates an Ed25519 signing key with an X25519 encryption subkey.
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <remarks>
    /// <para>
    /// This is the recommended method for creating modern OpenPGP keys.
    /// The Ed25519 master key provides signing and certification capabilities,
    /// while the X25519 subkey provides encryption capabilities.
    /// </para>
    /// </remarks>
    public PgpKeyGeneratorResult GenerateEd25519WithX25519Subkey()
    {
        ValidateConfiguration();

        // Ed25519/X25519 always use V6 format per RFC 9580
        byte version = 6;

        // Generate Ed25519 master key
        var (ed25519Private, ed25519Public) = Ed25519Core.GenerateKeyPair();
        var masterPublicPacket = PgpPublicKeyPacket.CreateEd25519(creationTime, ed25519Public, isSubkey: false);

        PgpSecretKeyPacket masterSecretPacket;
        if (string.IsNullOrEmpty(passphrase))
        {
            masterSecretPacket = PgpSecretKeyPacket.CreateUnencrypted(masterPublicPacket, ed25519Private);
        }
        else
        {
            masterSecretPacket = CreateEncryptedSecretKey(masterPublicPacket, ed25519Private, passphrase!);
        }

        // Create user ID packet
        var userIdPacket = new PgpUserIdPacket(userId!);

        // Create self-certification signature (Certify | Sign for master key)
        var certFlags = PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign;
        var certificationSignature = CreateEd25519UserIdCertification(
            masterPublicPacket,
            ed25519Private,
            userIdPacket,
            certFlags,
            version);

        // Generate X25519 encryption subkey
        var x25519Private = Curve25519Core.GeneratePrivateKey();
        var x25519Public = Curve25519Core.DerivePublicKey(x25519Private);
        var subkeyPublicPacket = PgpPublicKeyPacket.CreateX25519(creationTime, x25519Public, isSubkey: true);

        PgpSecretKeyPacket subkeySecretPacket;
        if (string.IsNullOrEmpty(passphrase))
        {
            subkeySecretPacket = PgpSecretKeyPacket.CreateUnencrypted(subkeyPublicPacket, x25519Private);
        }
        else
        {
            subkeySecretPacket = CreateEncryptedSecretKey(subkeyPublicPacket, x25519Private, passphrase!);
        }

        // Create subkey binding signature
        var subkeyFlags = PgpKeyCapabilities.EncryptCommunications | PgpKeyCapabilities.EncryptStorage;
        var bindingSignature = CreateEd25519SubkeyBindingSignature(
            masterPublicPacket,
            ed25519Private,
            subkeyPublicPacket,
            subkeyFlags,
            version);

        // Build key rings
        var publicKeyRing = new PgpPublicKeyRing(
            masterPublicPacket,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);
        publicKeyRing = publicKeyRing.AddSubkey(subkeyPublicPacket, bindingSignature);

        var secretKeyRing = new PgpSecretKeyRing(
            masterSecretPacket,
            subkeys: null,
            userIds: [userIdPacket],
            userAttributes: null,
            signatures: [certificationSignature]);
        secretKeyRing = secretKeyRing.AddSubkey(subkeySecretPacket, bindingSignature);

        return new PgpKeyGeneratorResult(secretKeyRing, publicKeyRing, userId!);
    }

    #endregion

    #region Private Helpers

    // AES-256 cipher algorithm ID
    private const byte AES_256 = 9;
    // SHA-256 hash algorithm ID
    private const byte SHA256_HASH = 8;
    // Default iteration count: 65536 iterations (encoded as 96)
    private const byte DEFAULT_ITERATION_COUNT = 96;
    // AES-256 key size in bytes
    private const int AES_256_KEY_SIZE = 32;
    // AES block size in bytes
    private const int AES_BLOCK_SIZE = 16;

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

    /// <summary>
    /// Creates an encrypted secret key packet from plaintext secret material.
    /// </summary>
    /// <param name="publicKey">The public key portion.</param>
    /// <param name="secretMaterial">The plaintext secret key material (MPIs).</param>
    /// <param name="passphrase">The passphrase to encrypt with.</param>
    /// <returns>An encrypted secret key packet.</returns>
    private static PgpSecretKeyPacket CreateEncryptedSecretKey(
        PgpPublicKeyPacket publicKey,
        byte[] secretMaterial,
        string passphrase)
    {
        // Generate salt for S2K
        byte[] salt = S2KCore.GenerateSalt();

        // Derive encryption key using iterated S2K
        long iterationCount = S2KCore.DecodeIterationCount(DEFAULT_ITERATION_COUNT);
        byte[] passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);
        byte[] encryptionKey = S2KCore.IteratedS2K(
            passphraseBytes,
            salt,
            iterationCount,
            AES_256_KEY_SIZE,
            HashAlgorithmName.SHA256);

        try
        {
            // Calculate SHA-1 hash of secret material for integrity (S2KUsage 254)
            // SHA-1 is required by RFC 4880 for S2KUsage 254 - we cannot use a different hash
#pragma warning disable CA5350 // SHA-1 is weak, but required by OpenPGP specification
            byte[] sha1Hash;
#if NETSTANDARD2_0
            using (var sha1 = SHA1.Create())
            {
                sha1Hash = sha1.ComputeHash(secretMaterial);
            }
#else
            sha1Hash = SHA1.HashData(secretMaterial);
#endif
#pragma warning restore CA5350

            // Plaintext for encryption: secret material + SHA-1 hash
            byte[] plaintextWithHash = new byte[secretMaterial.Length + 20];
            secretMaterial.CopyTo(plaintextWithHash.AsSpan());
            sha1Hash.CopyTo(plaintextWithHash.AsSpan(secretMaterial.Length));

            // Generate IV for CFB encryption
            byte[] iv = new byte[AES_BLOCK_SIZE];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            // Encrypt using standard CFB mode
            byte[] encrypted = CfbEncryptStandard(plaintextWithHash, encryptionKey, iv);

            // Create S2K specifier
            var s2kSpecifier = PgpS2KSpecifier.CreateIterated(SHA256_HASH, salt, DEFAULT_ITERATION_COUNT);

            // Create encrypted secret key packet
            return PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                AES_256,
                s2kSpecifier,
                iv,
                encrypted);
        }
        finally
        {
            // Clear sensitive data
            Array.Clear(encryptionKey, 0, encryptionKey.Length);
            Array.Clear(passphraseBytes, 0, passphraseBytes.Length);
        }
    }

    /// <summary>
    /// Encrypts all secret keys in a secret key ring with the specified passphrase.
    /// </summary>
    /// <param name="ring">The secret key ring with unencrypted keys.</param>
    /// <param name="passphrase">The passphrase to encrypt with.</param>
    /// <returns>A new secret key ring with all keys encrypted.</returns>
    private static PgpSecretKeyRing EncryptSecretKeyRing(PgpSecretKeyRing ring, string passphrase)
    {
        // Encrypt master key
        var masterSecretMaterial = ring.MasterKey.SecretKeyMaterial.ToArray();
        // Remove checksum (last 2 bytes) since CreateEncryptedSecretKey adds its own hash
        var masterPlainMaterial = new byte[masterSecretMaterial.Length - 2];
        Array.Copy(masterSecretMaterial, 0, masterPlainMaterial, 0, masterPlainMaterial.Length);
        var encryptedMaster = CreateEncryptedSecretKey(ring.MasterKey.PublicKey, masterPlainMaterial, passphrase);

        // Encrypt subkeys
        var encryptedSubkeys = new List<PgpSecretKeyPacket>();
        foreach (var subkey in ring.Subkeys)
        {
            var subkeySecretMaterial = subkey.SecretKeyMaterial.ToArray();
            // Remove checksum (last 2 bytes) since CreateEncryptedSecretKey adds its own hash
            var subkeyPlainMaterial = new byte[subkeySecretMaterial.Length - 2];
            Array.Copy(subkeySecretMaterial, 0, subkeyPlainMaterial, 0, subkeyPlainMaterial.Length);
            var encryptedSubkey = CreateEncryptedSecretKey(subkey.PublicKey, subkeyPlainMaterial, passphrase);
            encryptedSubkeys.Add(encryptedSubkey);
        }

        // Build new ring with encrypted keys
        return new PgpSecretKeyRing(
            encryptedMaster,
            subkeys: encryptedSubkeys.Count > 0 ? encryptedSubkeys : null,
            userIds: ring.UserIds,
            userAttributes: ring.UserAttributes,
            signatures: ring.Signatures);
    }

    /// <summary>
    /// Encrypts data using standard AES-CFB mode.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>The encrypted data.</returns>
    private static byte[] CfbEncryptStandard(byte[] plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB; // We implement CFB manually
        aes.Padding = PaddingMode.None;

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] fr = new byte[AES_BLOCK_SIZE]; // Feedback register
        byte[] fre = new byte[AES_BLOCK_SIZE]; // Encrypted feedback register

        // Initialize FR with IV
        iv.CopyTo(fr, 0);

        using var encryptor = aes.CreateEncryptor();

        int pos = 0;
        while (pos < plaintext.Length)
        {
            // Encrypt the feedback register
            encryptor.TransformBlock(fr, 0, AES_BLOCK_SIZE, fre, 0);

            // XOR plaintext with encrypted FR
            int bytesToProcess = Math.Min(AES_BLOCK_SIZE, plaintext.Length - pos);
            for (int i = 0; i < bytesToProcess; i++)
            {
                ciphertext[pos + i] = (byte)(plaintext[pos + i] ^ fre[i]);
            }

            // Update FR with ciphertext for next iteration
            Array.Copy(ciphertext, pos, fr, 0, bytesToProcess);
            if (bytesToProcess < AES_BLOCK_SIZE)
            {
                Array.Clear(fr, bytesToProcess, AES_BLOCK_SIZE - bytesToProcess);
            }

            pos += bytesToProcess;
        }

        return ciphertext;
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

        return CreateRsaSignatureFromParams(n, e, d, p, q, hash);
    }

    private static byte[] CreateRsaSignatureFromParams(
        BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, byte[] hash)
    {
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

        // Create subkey packets (always unencrypted - encryption happens at the end of GenerateRsa)
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

        // Create subkey packets (always unencrypted - encryption happens at the end of GenerateRsa)
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

    #region Ed25519 Signature Helpers

    private PgpSignaturePacket CreateEd25519UserIdCertification(
        PgpPublicKeyPacket publicKey,
        byte[] ed25519PrivateKey,
        PgpUserIdPacket userIdPacket,
        PgpKeyCapabilities keyFlags,
        byte version)
    {
        var sigType = PgpSignatureType.PositiveCertification;
        var pubAlgo = (byte)PgpPublicKeyAlgorithm.Ed25519;
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

        // Create Ed25519 signature
        var signatureData = Ed25519Core.Sign(hash, ed25519PrivateKey);

        // Build signature packet (Ed25519 always V6)
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

    private PgpSignaturePacket CreateEd25519SubkeyBindingSignature(
        PgpPublicKeyPacket masterPublicKey,
        byte[] ed25519PrivateKey,
        PgpPublicKeyPacket subkey,
        PgpKeyCapabilities subkeyFlags,
        byte version)
    {
        var sigType = PgpSignatureType.SubkeyBinding;
        var pubAlgo = (byte)PgpPublicKeyAlgorithm.Ed25519;
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

        // Create Ed25519 signature
        var signatureData = Ed25519Core.Sign(hash, ed25519PrivateKey);

        // Build signature packet (Ed25519 always V6)
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

    #endregion

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
