using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.AesCfb;
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
    private byte[]? passphraseBytes;
    private bool useArgon2;
    private byte argon2Passes = 3;
    private byte argon2Parallelism = 4;
    private byte argon2MemoryExponent = 19; // 2^19 KB = 512 MB
    private int keySize = 4096;
    private DateTimeOffset creationTime = DateTimeOffset.UtcNow;
    private byte? explicitVersion;
    private PgpKeyCapabilities keyFlags = PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign;
    private bool addEncryptionSubkey;
    private bool addSigningSubkey;
    private TimeSpan? keyExpiration;
    private TimeSpan? subkeyExpiration;
    private byte[]? preferredSymmetricAlgorithms;
    private byte[]? preferredHashAlgorithms;
    private byte[]? preferredCompressionAlgorithms;
    private byte[]? preferredAeadAlgorithms;
    private List<(string Name, string Value, bool IsHumanReadable, bool IsCritical)>? notations;

    private PgpKeyGenerator()
    {
    }

    /// <summary>
    /// Creates a new key generator.
    /// </summary>
    /// <returns>A new PgpKeyGenerator instance.</returns>
    public static PgpKeyGenerator Create() => new();

    /// <summary>
    /// Sets the user ID for the key.
    /// </summary>
    /// <param name="userId">The user ID string (e.g., "Name &lt;email@example.com&gt;").</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentNullException">If userId is null.</exception>
    public PgpKeyGenerator WithUserId(string userId)
    {

#if !NETSTANDARD2_0
#else
#endif

        this.userId = userId ?? throw new ArgumentNullException(nameof(userId));
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
        userId = packet.UserId;
        return this;
    }

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
    /// <para>
    /// <b>Security Note:</b> Strings in .NET are immutable and may persist in memory
    /// longer than necessary. For enhanced security, consider using
    /// <see cref="WithPassphrase(byte[])"/> instead, which allows you to clear
    /// the passphrase bytes after key generation.
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithPassphrase(string passphrase)
    {
        this.passphrase = passphrase;
        passphraseBytes = null;
        return this;
    }

    /// <summary>
    /// Sets the passphrase for encrypting the secret key using raw bytes.
    /// </summary>
    /// <param name="passphraseBytes">The passphrase as UTF-8 encoded bytes.</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This overload allows for more secure passphrase handling by accepting
    /// raw bytes that can be securely cleared from memory after key generation.
    /// </para>
    /// <para>
    /// <b>Security Best Practice:</b> After calling a Generate method, clear
    /// the passphrase bytes by calling <c>Array.Clear(passphraseBytes, 0, passphraseBytes.Length)</c>.
    /// </para>
    /// <para>
    /// Example:
    /// <code>
    /// byte[] passBytes = Encoding.UTF8.GetBytes("mypassphrase");
    /// try
    /// {
    ///     var result = PgpKeyGenerator.Create()
    ///         .WithUserId("User &lt;user@example.com&gt;")
    ///         .WithPassphrase(passBytes)
    ///         .GenerateRsa();
    /// }
    /// finally
    /// {
    ///     Array.Clear(passBytes, 0, passBytes.Length);
    /// }
    /// </code>
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">If passphraseBytes is null.</exception>
    public PgpKeyGenerator WithPassphrase(byte[] passphraseBytes)
    {

#if !NETSTANDARD2_0
#else
#endif

        this.passphraseBytes = passphraseBytes ?? throw new ArgumentNullException(nameof(passphraseBytes));
        passphrase = null;
        return this;
    }

    /// <summary>
    /// Sets the passphrase for encrypting the secret key using Argon2 S2K (RFC 9580).
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Argon2id is a modern memory-hard key derivation function that provides
    /// superior protection against both GPU-based and ASIC-based brute-force attacks.
    /// This method uses secure default parameters:
    /// <list type="bullet">
    ///   <item>Passes: 3</item>
    ///   <item>Parallelism: 4</item>
    ///   <item>Memory: 512 MB (2^19 KB)</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>Recommendation:</b> Use this method for new keys. The iterated S2K
    /// (used by <see cref="WithPassphrase(string)"/>) is a legacy method.
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithArgon2Passphrase(string passphrase)
    {
        this.passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));
        passphraseBytes = null;
        useArgon2 = true;
        return this;
    }

    /// <summary>
    /// Sets the passphrase for encrypting the secret key using Argon2 S2K with raw bytes.
    /// </summary>
    /// <param name="passphraseBytes">The passphrase as UTF-8 encoded bytes.</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This overload allows for more secure passphrase handling by accepting
    /// raw bytes that can be securely cleared from memory after key generation.
    /// Uses the same default parameters as <see cref="WithArgon2Passphrase(string)"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">If passphraseBytes is null.</exception>
    public PgpKeyGenerator WithArgon2Passphrase(byte[] passphraseBytes)
    {
        this.passphraseBytes = passphraseBytes ?? throw new ArgumentNullException(nameof(passphraseBytes));
        passphrase = null;
        useArgon2 = true;
        return this;
    }

    /// <summary>
    /// Sets the passphrase for encrypting the secret key using Argon2 S2K with custom parameters.
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <param name="passes">Number of passes (iterations). Must be at least 1. Higher values increase security but slow down derivation.</param>
    /// <param name="parallelism">Degree of parallelism. Should match available CPU cores.</param>
    /// <param name="memoryExponent">Memory exponent (memory = 2^exponent KB). Must be in [3, 31]. Higher values increase security but require more RAM.</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Use this overload when you need to customize the Argon2 parameters based on
    /// the target environment's capabilities. Consider:
    /// <list type="bullet">
    ///   <item>Mobile devices: memoryExponent=16 (64 MB), passes=3, parallelism=2</item>
    ///   <item>Desktop: memoryExponent=19 (512 MB), passes=3, parallelism=4</item>
    ///   <item>Server: memoryExponent=21 (2 GB), passes=1, parallelism=8</item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">If any parameter is out of valid range.</exception>
    public PgpKeyGenerator WithArgon2Passphrase(string passphrase, byte passes, byte parallelism, byte memoryExponent)
    {
        PgpS2KSpecifier.ValidateArgon2Parameters(passes, parallelism, memoryExponent);
        this.passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));
        passphraseBytes = null;
        useArgon2 = true;
        argon2Passes = passes;
        argon2Parallelism = parallelism;
        argon2MemoryExponent = memoryExponent;
        return this;
    }

    /// <summary>
    /// Sets the passphrase for encrypting the secret key using Argon2 S2K with custom parameters and raw bytes.
    /// </summary>
    /// <param name="passphraseBytes">The passphrase as UTF-8 encoded bytes.</param>
    /// <param name="passes">Number of passes (iterations).</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="memoryExponent">Memory exponent (memory = 2^exponent KB).</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentNullException">If passphraseBytes is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">If any parameter is out of valid range.</exception>
    public PgpKeyGenerator WithArgon2Passphrase(byte[] passphraseBytes, byte passes, byte parallelism, byte memoryExponent)
    {
        PgpS2KSpecifier.ValidateArgon2Parameters(passes, parallelism, memoryExponent);
        this.passphraseBytes = passphraseBytes ?? throw new ArgumentNullException(nameof(passphraseBytes));
        passphrase = null;
        useArgon2 = true;
        argon2Passes = passes;
        argon2Parallelism = parallelism;
        argon2MemoryExponent = memoryExponent;
        return this;
    }


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

        keySize = bits;
        return this;
    }

    /// <summary>
    /// Sets the key creation time.
    /// </summary>
    /// <param name="time">The creation time.</param>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithCreationTime(DateTimeOffset time)
    {
        creationTime = time;
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

        explicitVersion = version;
        return this;
    }

    /// <summary>
    /// Sets the key capabilities flags for the master key.
    /// </summary>
    /// <param name="flags">The key capability flags.</param>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithKeyFlags(PgpKeyCapabilities flags)
    {
        keyFlags = flags;
        return this;
    }

    /// <summary>
    /// Sets the key expiration time as a duration from key creation.
    /// </summary>
    /// <param name="lifetime">The key lifetime (e.g., TimeSpan.FromDays(365) for 1 year).</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If lifetime is negative or exceeds ~136 years.</exception>
    /// <remarks>
    /// <para>
    /// The expiration time is stored in the key's self-signature as seconds from
    /// the key creation time. Setting this to <see cref="TimeSpan.Zero"/> means the
    /// key never expires (this is also the default if WithExpiration is not called).
    /// </para>
    /// <para>
    /// <b>Common values:</b>
    /// <list type="bullet">
    ///   <item><c>TimeSpan.FromDays(365)</c> - 1 year</item>
    ///   <item><c>TimeSpan.FromDays(730)</c> - 2 years</item>
    ///   <item><c>TimeSpan.FromDays(1095)</c> - 3 years</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithExpiration(TimeSpan lifetime)
    {
        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime cannot be negative.");
        }

        if (lifetime.TotalSeconds > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime exceeds maximum value (~136 years).");
        }

        keyExpiration = lifetime == TimeSpan.Zero ? null : lifetime;
        return this;
    }

    /// <summary>
    /// Sets the key expiration to a specific date.
    /// </summary>
    /// <param name="expirationDate">The date when the key should expire.</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If expiration date is before creation time or too far in the future.</exception>
    /// <remarks>
    /// <para>
    /// The expiration date is converted to a duration from the key creation time.
    /// If no creation time has been set, <see cref="DateTimeOffset.UtcNow"/> is assumed.
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithExpirationDate(DateTimeOffset expirationDate)
    {
        var effectiveCreationTime = creationTime;
        var lifetime = expirationDate - effectiveCreationTime;

        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(expirationDate), "Expiration date cannot be before creation time.");
        }

        return WithExpiration(lifetime);
    }

    /// <summary>
    /// Sets the subkey expiration time as a duration from key creation.
    /// </summary>
    /// <param name="lifetime">The subkey lifetime (e.g., TimeSpan.FromDays(365) for 1 year).</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If lifetime is negative or exceeds ~136 years.</exception>
    /// <remarks>
    /// <para>
    /// The expiration time is stored in the subkey binding signature as seconds from
    /// the key creation time. Setting this to <see cref="TimeSpan.Zero"/> means the
    /// subkey never expires (this is also the default if WithSubkeyExpiration is not called).
    /// </para>
    /// <para>
    /// If not set, subkeys will inherit the master key expiration (if any).
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithSubkeyExpiration(TimeSpan lifetime)
    {
        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime cannot be negative.");
        }

        if (lifetime.TotalSeconds > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime exceeds maximum value (~136 years).");
        }

        subkeyExpiration = lifetime == TimeSpan.Zero ? null : lifetime;
        return this;
    }

    /// <summary>
    /// Sets the subkey expiration to a specific date.
    /// </summary>
    /// <param name="expirationDate">The date when the subkey should expire.</param>
    /// <returns>This generator for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If expiration date is before creation time or too far in the future.</exception>
    /// <remarks>
    /// <para>
    /// The expiration date is converted to a duration from the key creation time.
    /// If no creation time has been set, <see cref="DateTimeOffset.UtcNow"/> is assumed.
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithSubkeyExpirationDate(DateTimeOffset expirationDate)
    {
        var effectiveCreationTime = creationTime;
        var lifetime = expirationDate - effectiveCreationTime;

        if (lifetime < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(expirationDate), "Expiration date cannot be before creation time.");
        }

        return WithSubkeyExpiration(lifetime);
    }


    /// <summary>
    /// Sets the preferred symmetric encryption algorithms.
    /// </summary>
    /// <param name="algorithms">The algorithm IDs in order of preference (most preferred first).</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This subpacket tells other implementations which symmetric algorithms this key prefers
    /// when encrypting messages to it. Common values:
    /// <list type="bullet">
    ///   <item>9 = AES-256</item>
    ///   <item>8 = AES-192</item>
    ///   <item>7 = AES-128</item>
    ///   <item>2 = Triple-DES (legacy)</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithPreferredSymmetricAlgorithms(params byte[] algorithms)
    {
        preferredSymmetricAlgorithms = algorithms.Length > 0 ? algorithms : null;
        return this;
    }

    /// <summary>
    /// Sets the preferred hash algorithms.
    /// </summary>
    /// <param name="algorithms">The algorithm IDs in order of preference (most preferred first).</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This subpacket tells other implementations which hash algorithms this key prefers.
    /// Common values:
    /// <list type="bullet">
    ///   <item>10 = SHA-512</item>
    ///   <item>9 = SHA-384</item>
    ///   <item>8 = SHA-256</item>
    ///   <item>2 = SHA-1 (legacy, not recommended)</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithPreferredHashAlgorithms(params byte[] algorithms)
    {
        preferredHashAlgorithms = algorithms.Length > 0 ? algorithms : null;
        return this;
    }

    /// <summary>
    /// Sets the preferred compression algorithms.
    /// </summary>
    /// <param name="algorithms">The algorithm IDs in order of preference (most preferred first).</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This subpacket tells other implementations which compression algorithms this key prefers.
    /// Common values:
    /// <list type="bullet">
    ///   <item>0 = Uncompressed</item>
    ///   <item>1 = ZIP</item>
    ///   <item>2 = ZLIB</item>
    ///   <item>3 = BZip2</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithPreferredCompressionAlgorithms(params byte[] algorithms)
    {
        preferredCompressionAlgorithms = algorithms.Length > 0 ? algorithms : null;
        return this;
    }

    /// <summary>
    /// Sets the preferred AEAD algorithms (RFC 9580).
    /// </summary>
    /// <param name="cipherAeadPairs">Pairs of (symmetric cipher, AEAD algorithm) in order of preference.</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Per RFC 9580, this subpacket contains pairs of bytes: each pair is
    /// (symmetric cipher algorithm, AEAD algorithm).
    /// Common AEAD values:
    /// <list type="bullet">
    ///   <item>1 = EAX</item>
    ///   <item>2 = OCB</item>
    ///   <item>3 = GCM</item>
    /// </list>
    /// Example: <c>WithPreferredAeadAlgorithms(9, 3, 9, 2)</c> means prefer AES-256+GCM, then AES-256+OCB.
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithPreferredAeadAlgorithms(params byte[] cipherAeadPairs)
    {
        if (cipherAeadPairs.Length % 2 != 0)
        {
            throw new ArgumentException("AEAD preferences must be pairs of (cipher, aead) algorithms.", nameof(cipherAeadPairs));
        }
        preferredAeadAlgorithms = cipherAeadPairs.Length > 0 ? cipherAeadPairs : null;
        return this;
    }

    /// <summary>
    /// Sets recommended default preferred algorithms for modern interoperability.
    /// </summary>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This sets commonly accepted defaults:
    /// <list type="bullet">
    ///   <item>Symmetric: AES-256, AES-192, AES-128</item>
    ///   <item>Hash: SHA-512, SHA-384, SHA-256</item>
    ///   <item>Compression: ZLIB, ZIP, Uncompressed</item>
    /// </list>
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithDefaultPreferences()
    {
        preferredSymmetricAlgorithms = [9, 8, 7]; // AES-256, AES-192, AES-128
        preferredHashAlgorithms = [10, 9, 8];    // SHA-512, SHA-384, SHA-256
        preferredCompressionAlgorithms = [2, 1, 0]; // ZLIB, ZIP, Uncompressed
        return this;
    }

    /// <summary>
    /// Adds a notation data entry to the key's self-signature.
    /// </summary>
    /// <param name="name">The notation name (typically in "name@domain" format).</param>
    /// <param name="value">The notation value.</param>
    /// <param name="isHumanReadable">Whether the value is human-readable text (default true).</param>
    /// <param name="isCritical">Whether the notation is critical (default false).</param>
    /// <returns>This generator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Notation data allows applications to attach arbitrary name-value pairs to signatures.
    /// Per RFC 4880, names should be in the format "name@domain" to avoid conflicts.
    /// </para>
    /// <para>
    /// <b>Example:</b>
    /// <code>
    /// var result = PgpKeyGenerator.Create()
    ///     .WithUserId("Alice &lt;alice@example.com&gt;")
    ///     .WithNotationData("comment@example.com", "Generated by MyApp")
    ///     .GenerateRsa();
    /// </code>
    /// </para>
    /// </remarks>
    public PgpKeyGenerator WithNotationData(string name, string value, bool isHumanReadable = true, bool isCritical = false)
    {
        notations ??= new List<(string, string, bool, bool)>();
        notations.Add((name, value, isHumanReadable, isCritical));
        return this;
    }


    /// <summary>
    /// Adds a signing-capable subkey.
    /// </summary>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithSigningSubkey()
    {
        addSigningSubkey = true;
        return this;
    }

    /// <summary>
    /// Adds an encryption-capable subkey.
    /// </summary>
    /// <returns>This generator for chaining.</returns>
    public PgpKeyGenerator WithEncryptionSubkey()
    {
        addEncryptionSubkey = true;
        return this;
    }


    /// <summary>
    /// Generates an RSA key pair with the default key size (4096 bits).
    /// </summary>
    /// <returns>The generated key pair.</returns>
    /// <exception cref="InvalidOperationException">If no user ID has been set.</exception>
    public PgpKeyGeneratorResult GenerateRsa()
    {
        return GenerateRsa(keySize);
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
        if (HasPassphrase)
        {
            var (passBytes, shouldClear) = GetPassphraseBytes();
            try
            {
                secretKeyRing = EncryptSecretKeyRingWithBytes(secretKeyRing, passBytes);
            }
            finally
            {
                if (shouldClear)
                {
                    Array.Clear(passBytes, 0, passBytes.Length);
                }
            }
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
        if (!HasPassphrase)
        {
            secretKeyPacket = PgpSecretKeyPacket.CreateUnencrypted(publicKeyPacket, privateKey);
        }
        else
        {
            var (passBytes, shouldClear) = GetPassphraseBytes();
            try
            {
                secretKeyPacket = EncryptSecretKey(publicKeyPacket, privateKey, passBytes);
            }
            finally
            {
                if (shouldClear)
                {
                    Array.Clear(passBytes, 0, passBytes.Length);
                }
            }
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
        PgpSecretKeyPacket subkeySecretPacket;

        // Get passphrase bytes once for both master and subkey encryption
        byte[]? passBytes = null;
        bool shouldClear = false;
        if (HasPassphrase)
        {
            (passBytes, shouldClear) = GetPassphraseBytes();
        }

        try
        {
            masterSecretPacket = passBytes == null
                ? PgpSecretKeyPacket.CreateUnencrypted(masterPublicPacket, ed25519Private)
                : EncryptSecretKey(masterPublicPacket, ed25519Private, passBytes);

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

            subkeySecretPacket = passBytes == null
                ? PgpSecretKeyPacket.CreateUnencrypted(subkeyPublicPacket, x25519Private)
                : EncryptSecretKey(subkeyPublicPacket, x25519Private, passBytes);

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
        finally
        {
            if (shouldClear && passBytes != null)
            {
                Array.Clear(passBytes, 0, passBytes.Length);
            }
        }
    }


    // AES-256 cipher algorithm ID
    private const byte AES_256 = 9;
    // SHA-256 hash algorithm ID
    private const byte SHA256_HASH = 8;
    // Default iteration count: ~65 million iterations (encoded as 255)
    // This provides strong protection against brute-force attacks on passphrases.
    // Formula: count = (16 + (c & 15)) << ((c >> 4) + 6) = (16 + 15) << 21 = 65,011,712
    private const byte DEFAULT_ITERATION_COUNT = 255;
    // AES-256 key size in bytes
    private const int AES_256_KEY_SIZE = 32;

    private void ValidateConfiguration()
    {
        if (string.IsNullOrEmpty(userId))
        {
            throw new InvalidOperationException("No user ID has been set. Call WithUserId() first.");
        }
    }

    /// <summary>
    /// Returns true if a passphrase has been configured (either string or bytes).
    /// </summary>
    private bool HasPassphrase => !string.IsNullOrEmpty(passphrase) || passphraseBytes is { Length: > 0 };

    /// <summary>
    /// Gets the passphrase as bytes, converting from string if necessary.
    /// The caller is responsible for clearing the returned bytes if they were created from a string.
    /// </summary>
    /// <returns>A tuple containing the passphrase bytes and whether the caller should clear them.</returns>
    private (byte[] bytes, bool shouldClear) GetPassphraseBytes()
    {
        if (passphraseBytes is { Length: > 0 })
        {
            // User provided bytes directly - they are responsible for clearing
            return (passphraseBytes, false);
        }

        if (!string.IsNullOrEmpty(passphrase))
        {
            // Convert string to bytes - caller should clear these
            return (System.Text.Encoding.UTF8.GetBytes(passphrase), true);
        }

        throw new InvalidOperationException("No passphrase has been set.");
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
    /// Creates an encrypted secret key packet from plaintext secret material using raw passphrase bytes.
    /// </summary>
    /// <param name="publicKey">The public key portion.</param>
    /// <param name="secretMaterial">The plaintext secret key material (MPIs).</param>
    /// <param name="passphraseBytes">The passphrase as raw bytes.</param>
    /// <returns>An encrypted secret key packet.</returns>
    /// <remarks>
    /// This overload does not clear the passphrase bytes - the caller is responsible
    /// for clearing them after use if needed.
    /// </remarks>
    private static PgpSecretKeyPacket CreateEncryptedSecretKeyFromBytes(
        PgpPublicKeyPacket publicKey,
        byte[] secretMaterial,
        byte[] passphraseBytes)
    {
        // Generate salt for S2K
        byte[] salt = S2KCore.GenerateSalt();

        // Derive encryption key using iterated S2K
        long iterationCount = S2KCore.DecodeIterationCount(DEFAULT_ITERATION_COUNT);
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
            byte[] iv = new byte[AesCfbCore.BlockSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            // Encrypt using standard CFB mode
            byte[] encrypted = AesCfbCore.Encrypt(plaintextWithHash, encryptionKey, iv);

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
            // Clear sensitive data (caller is responsible for clearing passphraseBytes)
            Array.Clear(encryptionKey, 0, encryptionKey.Length);
        }
    }

    /// <summary>
    /// Creates an encrypted secret key packet using Argon2 S2K (RFC 9580).
    /// </summary>
    /// <param name="publicKey">The public key portion.</param>
    /// <param name="secretMaterial">The plaintext secret key material (MPIs).</param>
    /// <param name="passphraseBytes">The passphrase as raw bytes.</param>
    /// <param name="passes">Number of Argon2 passes.</param>
    /// <param name="parallelism">Argon2 parallelism degree.</param>
    /// <param name="memoryExponent">Argon2 memory exponent.</param>
    /// <returns>An encrypted secret key packet with Argon2 S2K.</returns>
    private static PgpSecretKeyPacket CreateArgon2EncryptedSecretKeyFromBytes(
        PgpPublicKeyPacket publicKey,
        byte[] secretMaterial,
        byte[] passphraseBytes,
        byte passes,
        byte parallelism,
        byte memoryExponent)
    {
        // Generate 16-byte salt for Argon2
        byte[] salt = S2KCore.GenerateArgon2Salt();

        // Derive encryption key using Argon2
        byte[] encryptionKey = S2KCore.Argon2S2K(
            passphraseBytes,
            salt,
            passes,
            parallelism,
            memoryExponent,
            AES_256_KEY_SIZE);

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
            byte[] iv = new byte[AesCfbCore.BlockSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            // Encrypt using standard CFB mode
            byte[] encrypted = AesCfbCore.Encrypt(plaintextWithHash, encryptionKey, iv);

            // Create Argon2 S2K specifier
            var s2kSpecifier = PgpS2KSpecifier.CreateArgon2(SHA256_HASH, salt, passes, parallelism, memoryExponent);

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
            // Clear sensitive data (caller is responsible for clearing passphraseBytes)
            Array.Clear(encryptionKey, 0, encryptionKey.Length);
        }
    }

    /// <summary>
    /// Encrypts all secret keys in a secret key ring with the specified passphrase bytes.
    /// </summary>
    /// <param name="ring">The secret key ring with unencrypted keys.</param>
    /// <param name="passphraseBytes">The passphrase as raw bytes.</param>
    /// <returns>A new secret key ring with all keys encrypted.</returns>
    private PgpSecretKeyRing EncryptSecretKeyRingWithBytes(PgpSecretKeyRing ring, byte[] passphraseBytes)
    {
        // Encrypt master key
        var masterSecretMaterial = ring.MasterKey.SecretKeyMaterial.ToArray();
        // Remove checksum (last 2 bytes) since Create*EncryptedSecretKeyFromBytes adds its own hash
        var masterPlainMaterial = new byte[masterSecretMaterial.Length - 2];
        Array.Copy(masterSecretMaterial, 0, masterPlainMaterial, 0, masterPlainMaterial.Length);
        var encryptedMaster = EncryptSecretKey(ring.MasterKey.PublicKey, masterPlainMaterial, passphraseBytes);

        // Encrypt subkeys
        var encryptedSubkeys = new List<PgpSecretKeyPacket>();
        foreach (var subkey in ring.Subkeys)
        {
            var subkeySecretMaterial = subkey.SecretKeyMaterial.ToArray();
            // Remove checksum (last 2 bytes) since Create*EncryptedSecretKeyFromBytes adds its own hash
            var subkeyPlainMaterial = new byte[subkeySecretMaterial.Length - 2];
            Array.Copy(subkeySecretMaterial, 0, subkeyPlainMaterial, 0, subkeyPlainMaterial.Length);
            var encryptedSubkey = EncryptSecretKey(subkey.PublicKey, subkeyPlainMaterial, passphraseBytes);
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
    /// Encrypts a secret key using the configured S2K method (iterated or Argon2).
    /// </summary>
    private PgpSecretKeyPacket EncryptSecretKey(PgpPublicKeyPacket publicKey, byte[] secretMaterial, byte[] passphraseBytes)
    {
        if (useArgon2)
        {
            return CreateArgon2EncryptedSecretKeyFromBytes(
                publicKey,
                secretMaterial,
                passphraseBytes,
                argon2Passes,
                argon2Parallelism,
                argon2MemoryExponent);
        }

        return CreateEncryptedSecretKeyFromBytes(publicKey, secretMaterial, passphraseBytes);
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

        // Add key expiration if set
        if (keyExpiration.HasValue)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreateKeyExpirationTime(keyExpiration.Value));
        }

        // Add preferred algorithms if set
        if (preferredSymmetricAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredSymmetricAlgorithms(preferredSymmetricAlgorithms));
        }
        if (preferredHashAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredHashAlgorithms(preferredHashAlgorithms));
        }
        if (preferredCompressionAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredCompressionAlgorithms(preferredCompressionAlgorithms));
        }
        if (preferredAeadAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredAeadAlgorithms(preferredAeadAlgorithms));
        }

        // Add notation data if set
        if (notations != null)
        {
            foreach (var (name, value, isHumanReadable, isCritical) in notations)
            {
                hashedSubpackets.Add(PgpSignatureSubpacket.CreateNotationData(name, value, isHumanReadable, isCritical));
            }
        }

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
        return PgpSignatureHashHelper.ComputeCertificationHash(
            publicKey,
            userIdPacket,
            version,
            sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpackets);
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

        // Add subkey expiration if set (or inherit from master key expiration)
        var effectiveSubkeyExpiration = subkeyExpiration ?? keyExpiration;
        if (effectiveSubkeyExpiration.HasValue)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreateKeyExpirationTime(effectiveSubkeyExpiration.Value));
        }

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
        return PgpSignatureHashHelper.ComputeKeySignatureHash(
            masterKey,
            subkey,
            version,
            sigType,
            pubAlgo,
            hashAlgo,
            hashedSubpackets);
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

        // Add key expiration if set
        if (keyExpiration.HasValue)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreateKeyExpirationTime(keyExpiration.Value));
        }

        // Add preferred algorithms if set
        if (preferredSymmetricAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredSymmetricAlgorithms(preferredSymmetricAlgorithms));
        }
        if (preferredHashAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredHashAlgorithms(preferredHashAlgorithms));
        }
        if (preferredCompressionAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredCompressionAlgorithms(preferredCompressionAlgorithms));
        }
        if (preferredAeadAlgorithms != null)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreatePreferredAeadAlgorithms(preferredAeadAlgorithms));
        }

        // Add notation data if set
        if (notations != null)
        {
            foreach (var (name, value, isHumanReadable, isCritical) in notations)
            {
                hashedSubpackets.Add(PgpSignatureSubpacket.CreateNotationData(name, value, isHumanReadable, isCritical));
            }
        }

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

        // Add subkey expiration if set (or inherit from master key expiration)
        var effectiveSubkeyExpiration = subkeyExpiration ?? keyExpiration;
        if (effectiveSubkeyExpiration.HasValue)
        {
            hashedSubpackets.Add(PgpSignatureSubpacket.CreateKeyExpirationTime(effectiveSubkeyExpiration.Value));
        }

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
}
