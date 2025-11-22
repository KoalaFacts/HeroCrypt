using System.Linq;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Encryption;
using HeroCrypt.Hashing;
using HeroCrypt.Security;
using HeroCrypt.Signatures;
using HashAlgorithm = HeroCrypt.Hashing.HashAlgorithm;

namespace HeroCrypt;

/// <summary>
/// Fluent builder for HeroCrypt cryptographic operations.
/// </summary>
/// <remarks>
/// <para>
/// HeroCryptBuilder provides a unified fluent API for all cryptographic operations in HeroCrypt.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Hashing
/// var hash = HeroCryptBuilder.Hash()
///     .WithAlgorithm(HashAlgorithm.Sha256)
///     .Compute(data);
///
/// // Encryption
/// var result = HeroCryptBuilder.Encrypt()
///     .WithAlgorithm(EncryptionAlgorithm.AesGcm)
///     .WithKey(key)
///     .Build(plaintext);
///
/// // Signatures
/// var signature = HeroCryptBuilder.Sign()
///     .WithAlgorithm(SignatureAlgorithm.Ed25519)
///     .WithKey(privateKey)
///     .Build(data);
///
/// // Key Derivation
/// var derivedKey = HeroCryptBuilder.DeriveKey()
///     .UsePBKDF2()
///     .WithPassword(password)
///     .WithSalt(salt)
///     .WithIterations(100000)
///     .Build();
/// </code>
/// </example>
public static class HeroCryptBuilder
{
    /// <summary>
    /// Starts building a hash operation
    /// </summary>
    public static HashBuilder Hash() => new();

    /// <summary>
    /// Starts building an encryption operation
    /// </summary>
    public static EncryptionBuilder Encrypt() => new();

    /// <summary>
    /// Starts building a decryption operation
    /// </summary>
    public static DecryptionBuilder Decrypt() => new();

    /// <summary>
    /// Starts building a signing operation
    /// </summary>
    public static SignatureBuilder Sign() => new();

    /// <summary>
    /// Starts building a signature verification operation
    /// </summary>
    public static VerificationBuilder Verify() => new();

    /// <summary>
    /// Starts building a key derivation operation
    /// </summary>
    public static KeyDerivationBuilder DeriveKey() => new();

#if !NETSTANDARD2_0
    /// <summary>
    /// Starts building a PGP-style hybrid encryption operation.
    /// </summary>
    public static PgpBuilder Pgp() => new();
#endif
}

/// <summary>
/// Fluent builder for hash operations
/// </summary>
public class HashBuilder
{
    private HashAlgorithm algorithm = HashAlgorithm.Sha256;
    private byte[]? key;

    /// <summary>
    /// Sets the hash algorithm to use
    /// </summary>
    public HashBuilder WithAlgorithm(HashAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the key for keyed hashing (HMAC)
    /// </summary>
    public HashBuilder WithKey(byte[] key)
    {
        this.key = key;
        return this;
    }

    /// <summary>
    /// Computes the hash
    /// </summary>
    public byte[] Compute(byte[] data)
    {
        InputValidator.ValidateByteArray(data, nameof(data));

        if (key != null)
        {
            InputValidator.ValidateByteArray(key, nameof(key));
            return Hash.ComputeKeyed(data, key, algorithm);
        }
        return Hash.Compute(data, algorithm);
    }
}

/// <summary>
/// Fluent builder for encryption operations
/// </summary>
public class EncryptionBuilder
{
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? key;
    private byte[]? associatedData;

    /// <summary>
    /// Sets the encryption algorithm to use
    /// </summary>
    public EncryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Convenience for RSA-OAEP (SHA-256) hybrid encryption.
    /// </summary>
    public EncryptionBuilder WithRsaOaepSha256()
    {
        algorithm = EncryptionAlgorithm.RsaOaepSha256;
        return this;
    }

    /// <summary>
    /// Convenience for ChaCha20-Poly1305 AEAD.
    /// </summary>
    public EncryptionBuilder WithChaCha20Poly1305()
    {
        algorithm = EncryptionAlgorithm.ChaCha20Poly1305;
        return this;
    }

    /// <summary>
    /// Convenience for AES-GCM AEAD (256-bit key expected).
    /// </summary>
    public EncryptionBuilder WithAesGcm()
    {
        algorithm = EncryptionAlgorithm.AesGcm;
        return this;
    }

    /// <summary>
    /// Sets the encryption key
    /// </summary>
    public EncryptionBuilder WithKey(byte[] key)
    {
        this.key = key;
        return this;
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD)
    /// </summary>
    public EncryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        this.associatedData = associatedData;
        return this;
    }

    /// <summary>
    /// Encrypts the plaintext and returns the result
    /// </summary>
    public EncryptionResult Build(byte[] plaintext)
    {
        if (key == null)
        {
            throw new InvalidOperationException("Encryption key must be set using WithKey()");
        }

        InputValidator.ValidateByteArray(plaintext, nameof(plaintext), allowEmpty: true);
        InputValidator.ValidateByteArray(key, nameof(key));
        if (associatedData != null)
        {
            InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);
        }

        return Encryption.Encryption.Encrypt(
            plaintext,
            key,
            algorithm,
            associatedData ?? []);
    }
}

/// <summary>
/// Fluent builder for decryption operations
/// </summary>
public class DecryptionBuilder
{
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private byte[]? keyCiphertext;

    /// <summary>
    /// Sets the encryption algorithm to use
    /// </summary>
    public DecryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the decryption key
    /// </summary>
    public DecryptionBuilder WithKey(byte[] key)
    {
        this.key = key;
        return this;
    }

    /// <summary>
    /// Sets the nonce used during encryption
    /// </summary>
    public DecryptionBuilder WithNonce(byte[] nonce)
    {
        this.nonce = nonce;
        return this;
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD)
    /// </summary>
    public DecryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        this.associatedData = associatedData;
        return this;
    }

    /// <summary>
    /// Sets the key ciphertext for hybrid encryption
    /// </summary>
    public DecryptionBuilder WithKeyCiphertext(byte[] keyCiphertext)
    {
        this.keyCiphertext = keyCiphertext;
        return this;
    }

    /// <summary>
    /// Decrypts the ciphertext and returns the plaintext
    /// </summary>
    public byte[] Build(byte[] ciphertext)
    {
        if (key == null)
        {
            throw new InvalidOperationException("Decryption key must be set using WithKey()");
        }
        if (nonce == null)
        {
            throw new InvalidOperationException("Nonce must be set using WithNonce()");
        }

        InputValidator.ValidateByteArray(ciphertext, nameof(ciphertext));
        InputValidator.ValidateByteArray(key, nameof(key));
        InputValidator.ValidateByteArray(nonce, nameof(nonce));
        if (associatedData != null)
        {
            InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);
        }
        if (keyCiphertext != null)
        {
            InputValidator.ValidateByteArray(keyCiphertext, nameof(keyCiphertext));
        }

        return Encryption.Encryption.Decrypt(
            ciphertext,
            key,
            nonce,
            algorithm,
            associatedData ?? [],
            keyCiphertext);
    }
}

/// <summary>
/// Fluent builder for signature operations
/// </summary>
public class SignatureBuilder
{
    private SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;
    private byte[]? privateKey;

    /// <summary>
    /// Sets the signature algorithm to use
    /// </summary>
    public SignatureBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Use RSA-PSS with SHA-256 for signing.
    /// </summary>
    public SignatureBuilder WithRsaPssSha256()
    {
        algorithm = SignatureAlgorithm.RsaPssSha256;
        return this;
    }

    /// <summary>
    /// Use RSA-PKCS1 with SHA-256 for signing.
    /// </summary>
    public SignatureBuilder WithRsaSha256()
    {
        algorithm = SignatureAlgorithm.RsaSha256;
        return this;
    }

    /// <summary>
    /// Use Ed25519 for signing.
    /// </summary>
    public SignatureBuilder WithEd25519()
    {
        algorithm = SignatureAlgorithm.Ed25519;
        return this;
    }

    /// <summary>
    /// Use ECDSA P-256 with SHA-256.
    /// </summary>
    public SignatureBuilder WithEcdsaP256()
    {
        algorithm = SignatureAlgorithm.EcdsaP256Sha256;
        return this;
    }

    /// <summary>
    /// Use ECDSA P-384 with SHA-384.
    /// </summary>
    public SignatureBuilder WithEcdsaP384()
    {
        algorithm = SignatureAlgorithm.EcdsaP384Sha384;
        return this;
    }

    /// <summary>
    /// Use ECDSA P-521 with SHA-512.
    /// </summary>
    public SignatureBuilder WithEcdsaP521()
    {
        algorithm = SignatureAlgorithm.EcdsaP521Sha512;
        return this;
    }

    /// <summary>
    /// Sets the private key for signing
    /// </summary>
    public SignatureBuilder WithPrivateKey(byte[] privateKey)
    {
        this.privateKey = privateKey;
        return this;
    }

    /// <summary>
    /// Signs the data and returns the signature
    /// </summary>
    public byte[] Build(byte[] data)
    {
        if (privateKey == null)
        {
            throw new InvalidOperationException("Private key must be set using WithKey()");
        }

        InputValidator.ValidateByteArray(data, nameof(data));
        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        return DigitalSignature.Sign(data, privateKey, algorithm);
    }
}

/// <summary>
/// Fluent builder for signature verification operations
/// </summary>
public class VerificationBuilder
{
    private SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;
    private byte[]? publicKey;
    private byte[]? signature;

    /// <summary>
    /// Sets the signature algorithm to use
    /// </summary>
    public VerificationBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Use RSA-PSS with SHA-256 for verification.
    /// </summary>
    public VerificationBuilder WithRsaPssSha256()
    {
        algorithm = SignatureAlgorithm.RsaPssSha256;
        return this;
    }

    /// <summary>
    /// Use RSA-PKCS1 with SHA-256 for verification.
    /// </summary>
    public VerificationBuilder WithRsaSha256()
    {
        algorithm = SignatureAlgorithm.RsaSha256;
        return this;
    }

    /// <summary>
    /// Use Ed25519 for verification.
    /// </summary>
    public VerificationBuilder WithEd25519()
    {
        algorithm = SignatureAlgorithm.Ed25519;
        return this;
    }

    /// <summary>
    /// Use ECDSA P-256 with SHA-256.
    /// </summary>
    public VerificationBuilder WithEcdsaP256()
    {
        algorithm = SignatureAlgorithm.EcdsaP256Sha256;
        return this;
    }

    /// <summary>
    /// Use ECDSA P-384 with SHA-384.
    /// </summary>
    public VerificationBuilder WithEcdsaP384()
    {
        algorithm = SignatureAlgorithm.EcdsaP384Sha384;
        return this;
    }

    /// <summary>
    /// Use ECDSA P-521 with SHA-512.
    /// </summary>
    public VerificationBuilder WithEcdsaP521()
    {
        algorithm = SignatureAlgorithm.EcdsaP521Sha512;
        return this;
    }

    /// <summary>
    /// Sets the public key for verification
    /// </summary>
    public VerificationBuilder WithPublicKey(byte[] publicKey)
    {
        this.publicKey = publicKey;
        return this;
    }

    /// <summary>
    /// Sets the signature to verify
    /// </summary>
    public VerificationBuilder WithSignature(byte[] signature)
    {
        this.signature = signature;
        return this;
    }

    /// <summary>
    /// Verifies the signature against the data
    /// </summary>
    public bool Build(byte[] data)
    {
        if (publicKey == null)
        {
            throw new InvalidOperationException("Public key must be set using WithPublicKey()");
        }
        if (signature == null)
        {
            throw new InvalidOperationException("Signature must be set using WithSignature()");
        }

        InputValidator.ValidateByteArray(data, nameof(data));
        InputValidator.ValidateByteArray(signature, nameof(signature));
        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        return DigitalSignature.Verify(data, signature, publicKey, algorithm);
    }
}

/// <summary>
/// Fluent builder for key derivation operations
/// </summary>
public class KeyDerivationBuilder
{
    private byte[]? password;
    private byte[]? salt;
    private byte[]? ikm;
    private byte[]? info;
    private int iterations = 100000;
    private int keyLength = 32;
    private int blockSize = 8;
    private int parallelism = 1;
    private KeyManagement.HashAlgorithmName hashAlgorithm = KeyManagement.HashAlgorithmName.SHA256;
    private KeyDerivationType derivationType = KeyDerivationType.PBKDF2;

    private enum KeyDerivationType
    {
        PBKDF2,
        HKDF,
        Scrypt,
        Argon2
    }

    /// <summary>
    /// Sets the password for password-based key derivation
    /// </summary>
    public KeyDerivationBuilder WithPassword(byte[] password)
    {
        this.password = password;
        return this;
    }

    /// <summary>
    /// Sets the salt value
    /// </summary>
    public KeyDerivationBuilder WithSalt(byte[] salt)
    {
        this.salt = salt;
        return this;
    }

    /// <summary>
    /// Sets the input keying material for HKDF
    /// </summary>
    public KeyDerivationBuilder WithInputKeyingMaterial(byte[] ikm)
    {
        this.ikm = ikm;
        return this;
    }

    /// <summary>
    /// Sets the info/context for HKDF
    /// </summary>
    public KeyDerivationBuilder WithInfo(byte[] info)
    {
        this.info = info;
        return this;
    }

    /// <summary>
    /// Sets the number of iterations (for PBKDF2)
    /// </summary>
    public KeyDerivationBuilder WithIterations(int iterations)
    {
        this.iterations = iterations;
        return this;
    }

    /// <summary>
    /// Sets the desired output key length in bytes
    /// </summary>
    public KeyDerivationBuilder WithKeyLength(int keyLength)
    {
        this.keyLength = keyLength;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm to use
    /// </summary>
    public KeyDerivationBuilder WithHashAlgorithm(KeyManagement.HashAlgorithmName hashAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /// <summary>
    /// Sets the block size for Scrypt
    /// </summary>
    public KeyDerivationBuilder WithBlockSize(int blockSize)
    {
        this.blockSize = blockSize;
        return this;
    }

    /// <summary>
    /// Sets the parallelism for Scrypt
    /// </summary>
    public KeyDerivationBuilder WithParallelism(int parallelism)
    {
        this.parallelism = parallelism;
        return this;
    }

    /// <summary>
    /// Use PBKDF2 for key derivation
    /// </summary>
    public KeyDerivationBuilder UsePBKDF2()
    {
        derivationType = KeyDerivationType.PBKDF2;
        return this;
    }

    /// <summary>
    /// Use HKDF for key derivation
    /// </summary>
    public KeyDerivationBuilder UseHKDF()
    {
        derivationType = KeyDerivationType.HKDF;
        return this;
    }

    /// <summary>
    /// Use Scrypt for key derivation
    /// </summary>
    public KeyDerivationBuilder UseScrypt()
    {
        derivationType = KeyDerivationType.Scrypt;
        return this;
    }

    /// <summary>
    /// Use Argon2 for key derivation
    /// </summary>
    public KeyDerivationBuilder UseArgon2()
    {
        derivationType = KeyDerivationType.Argon2;
        return this;
    }

    /// <summary>
    /// Derives the key based on the configured parameters
    /// </summary>
    public byte[] Build()
    {
        return derivationType switch
        {
            KeyDerivationType.PBKDF2 => DerivePBKDF2(),
            KeyDerivationType.HKDF => DeriveHKDF(),
            KeyDerivationType.Scrypt => DeriveScrypt(),
            KeyDerivationType.Argon2 => DeriveArgon2(),
            _ => throw new InvalidOperationException($"Unsupported key derivation type: {derivationType}")
        };
    }

    private byte[] DerivePBKDF2()
    {
        if (password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }
        if (salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        // Validate parameters
        InputValidator.ValidatePbkdf2Parameters(password, salt, iterations, keyLength);

        // Call PBKDF2 primitive directly
        var hashName = hashAlgorithm.Name switch
        {
            "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
            "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
            "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => System.Security.Cryptography.HashAlgorithmName.SHA256
        };

#if !NETSTANDARD2_0
        return System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashName, keyLength);
#else
        // Use Rfc2898DeriveBytes for .NET Standard 2.0
        // Note: netstandard2.0 constructor doesn't support HashAlgorithmName parameter,
        // so we suppress the analyzer warning
#pragma warning disable CA5379 // Do not use weak key derivation function algorithm
        using var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, iterations);
#pragma warning restore CA5379
        return pbkdf2.GetBytes(keyLength);
#endif
    }

    private byte[] DeriveHKDF()
    {
        if (ikm == null)
        {
            throw new InvalidOperationException("Input keying material must be set using WithInputKeyingMaterial()");
        }

        // Validate parameters
        InputValidator.ValidateHkdfParameters(ikm, salt ?? [], info ?? [], keyLength);

        var hashName = hashAlgorithm.Name switch
        {
            "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
            "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
            "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => System.Security.Cryptography.HashAlgorithmName.SHA256
        };

#if !NETSTANDARD2_0
        return System.Security.Cryptography.HKDF.DeriveKey(hashName, ikm, keyLength, salt, info);
#else
        // Use HeroCrypt's HKDF implementation for .NET Standard 2.0
        return Cryptography.Primitives.Kdf.HkdfCore.DeriveKey(ikm, salt ?? [], info ?? [], keyLength, hashName);
#endif
    }

    private byte[] DeriveScrypt()
    {
        if (password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }
        if (salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        // Validate parameters
        InputValidator.ValidateScryptParameters(password, salt, iterations, blockSize, parallelism, keyLength);

        // Use HeroCrypt's Scrypt implementation
        return Cryptography.Primitives.Kdf.ScryptCore.DeriveKey(password, salt, iterations, blockSize, parallelism, keyLength);
    }

    private byte[] DeriveArgon2()
    {
        if (password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }
        if (salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        // Validate parameters (use PBKDF2 validator as baseline for password/salt/iterations)
        InputValidator.ValidateByteArray(password, nameof(password), allowEmpty: true);
        InputValidator.ValidateByteArray(salt, nameof(salt), allowEmpty: false);
        InputValidator.ValidateArraySize(keyLength, "Argon2 key derivation");

        if (iterations < 1)
        {
            throw new ArgumentException("Iterations must be at least 1", nameof(iterations));
        }
        if (iterations > InputValidator.MAX_ITERATION_COUNT)
        {
            throw new ArgumentException($"Iterations {iterations} exceeds maximum {InputValidator.MAX_ITERATION_COUNT}", nameof(iterations));
        }

        // Call Argon2 primitive directly
        return Cryptography.Primitives.Kdf.Argon2Core.Hash(
            password,
            salt,
            iterations,
            65536, // memory size in KB
            parallelism,
            keyLength,
            Cryptography.Primitives.Kdf.Argon2Type.Argon2id,
            null,
            null);
    }
}

