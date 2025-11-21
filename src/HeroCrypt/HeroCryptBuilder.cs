using HeroCrypt.Encryption;
using HeroCrypt.Hashing;
using HeroCrypt.Security;
using HeroCrypt.Signatures;

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
}

/// <summary>
/// Fluent builder for hash operations
/// </summary>
public class HashBuilder
{
    private HashAlgorithm _algorithm = HashAlgorithm.Sha256;
    private byte[]? _key;

    /// <summary>
    /// Sets the hash algorithm to use
    /// </summary>
    public HashBuilder WithAlgorithm(HashAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the key for keyed hashing (HMAC)
    /// </summary>
    public HashBuilder WithKey(byte[] key)
    {
        _key = key;
        return this;
    }

    /// <summary>
    /// Computes the hash
    /// </summary>
    public byte[] Compute(byte[] data)
    {
        InputValidator.ValidateByteArray(data, nameof(data));

        if (_key != null)
        {
            InputValidator.ValidateByteArray(_key, nameof(_key));
            return Hashing.Hash.ComputeKeyed(data, _key, _algorithm);
        }
        return Hashing.Hash.Compute(data, _algorithm);
    }
}

/// <summary>
/// Fluent builder for encryption operations
/// </summary>
public class EncryptionBuilder
{
    private EncryptionAlgorithm _algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? _key;
    private byte[]? _associatedData;

    /// <summary>
    /// Sets the encryption algorithm to use
    /// </summary>
    public EncryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the encryption key
    /// </summary>
    public EncryptionBuilder WithKey(byte[] key)
    {
        _key = key;
        return this;
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD)
    /// </summary>
    public EncryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        _associatedData = associatedData;
        return this;
    }

    /// <summary>
    /// Encrypts the plaintext and returns the result
    /// </summary>
    public EncryptionResult Build(byte[] plaintext)
    {
        if (_key == null)
        {
            throw new InvalidOperationException("Encryption key must be set using WithKey()");
        }

        InputValidator.ValidateByteArray(plaintext, nameof(plaintext));
        InputValidator.ValidateByteArray(_key, nameof(_key));
        if (_associatedData != null)
        {
            InputValidator.ValidateByteArray(_associatedData, nameof(_associatedData), allowEmpty: true);
        }

        return Encryption.Encryption.Encrypt(
            plaintext,
            _key,
            _algorithm,
            _associatedData ?? []);
    }
}

/// <summary>
/// Fluent builder for decryption operations
/// </summary>
public class DecryptionBuilder
{
    private EncryptionAlgorithm _algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? _key;
    private byte[]? _nonce;
    private byte[]? _associatedData;
    private byte[]? _keyCiphertext;

    /// <summary>
    /// Sets the encryption algorithm to use
    /// </summary>
    public DecryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the decryption key
    /// </summary>
    public DecryptionBuilder WithKey(byte[] key)
    {
        _key = key;
        return this;
    }

    /// <summary>
    /// Sets the nonce used during encryption
    /// </summary>
    public DecryptionBuilder WithNonce(byte[] nonce)
    {
        _nonce = nonce;
        return this;
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD)
    /// </summary>
    public DecryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        _associatedData = associatedData;
        return this;
    }

    /// <summary>
    /// Sets the key ciphertext for hybrid encryption
    /// </summary>
    public DecryptionBuilder WithKeyCiphertext(byte[] keyCiphertext)
    {
        _keyCiphertext = keyCiphertext;
        return this;
    }

    /// <summary>
    /// Decrypts the ciphertext and returns the plaintext
    /// </summary>
    public byte[] Build(byte[] ciphertext)
    {
        if (_key == null)
        {
            throw new InvalidOperationException("Decryption key must be set using WithKey()");
        }
        if (_nonce == null)
        {
            throw new InvalidOperationException("Nonce must be set using WithNonce()");
        }

        InputValidator.ValidateByteArray(ciphertext, nameof(ciphertext));
        InputValidator.ValidateByteArray(_key, nameof(_key));
        InputValidator.ValidateByteArray(_nonce, nameof(_nonce));
        if (_associatedData != null)
        {
            InputValidator.ValidateByteArray(_associatedData, nameof(_associatedData), allowEmpty: true);
        }
        if (_keyCiphertext != null)
        {
            InputValidator.ValidateByteArray(_keyCiphertext, nameof(_keyCiphertext));
        }

        return Encryption.Encryption.Decrypt(
            ciphertext,
            _key,
            _nonce,
            _algorithm,
            _associatedData ?? Array.Empty<byte>(),
            _keyCiphertext);
    }
}

/// <summary>
/// Fluent builder for signature operations
/// </summary>
public class SignatureBuilder
{
    private SignatureAlgorithm _algorithm = SignatureAlgorithm.Ed25519;
    private byte[]? _key;

    /// <summary>
    /// Sets the signature algorithm to use
    /// </summary>
    public SignatureBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the private key for signing
    /// </summary>
    public SignatureBuilder WithKey(byte[] privateKey)
    {
        _key = privateKey;
        return this;
    }

    /// <summary>
    /// Signs the data and returns the signature
    /// </summary>
    public byte[] Build(byte[] data)
    {
        if (_key == null)
        {
            throw new InvalidOperationException("Private key must be set using WithKey()");
        }

        InputValidator.ValidateByteArray(data, nameof(data));
        InputValidator.ValidateByteArray(_key, nameof(_key));

        return Signatures.DigitalSignature.Sign(data, _key, _algorithm);
    }
}

/// <summary>
/// Fluent builder for signature verification operations
/// </summary>
public class VerificationBuilder
{
    private SignatureAlgorithm _algorithm = SignatureAlgorithm.Ed25519;
    private byte[]? _key;
    private byte[]? _signature;

    /// <summary>
    /// Sets the signature algorithm to use
    /// </summary>
    public VerificationBuilder WithAlgorithm(SignatureAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the public key for verification
    /// </summary>
    public VerificationBuilder WithKey(byte[] publicKey)
    {
        _key = publicKey;
        return this;
    }

    /// <summary>
    /// Sets the signature to verify
    /// </summary>
    public VerificationBuilder WithSignature(byte[] signature)
    {
        _signature = signature;
        return this;
    }

    /// <summary>
    /// Verifies the signature against the data
    /// </summary>
    public bool Build(byte[] data)
    {
        if (_key == null)
        {
            throw new InvalidOperationException("Public key must be set using WithKey()");
        }
        if (_signature == null)
        {
            throw new InvalidOperationException("Signature must be set using WithSignature()");
        }

        InputValidator.ValidateByteArray(data, nameof(data));
        InputValidator.ValidateByteArray(_signature, nameof(_signature));
        InputValidator.ValidateByteArray(_key, nameof(_key));

        return Signatures.DigitalSignature.Verify(data, _signature, _key, _algorithm);
    }
}

/// <summary>
/// Fluent builder for key derivation operations
/// </summary>
public class KeyDerivationBuilder
{
    private byte[]? _password;
    private byte[]? _salt;
    private byte[]? _ikm;
    private byte[]? _info;
    private int _iterations = 100000;
    private int _keyLength = 32;
    private int _blockSize = 8;
    private int _parallelism = 1;
    private KeyManagement.HashAlgorithmName _hashAlgorithm = KeyManagement.HashAlgorithmName.SHA256;
    private KeyDerivationType _type = KeyDerivationType.PBKDF2;

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
        _password = password;
        return this;
    }

    /// <summary>
    /// Sets the salt value
    /// </summary>
    public KeyDerivationBuilder WithSalt(byte[] salt)
    {
        _salt = salt;
        return this;
    }

    /// <summary>
    /// Sets the input keying material for HKDF
    /// </summary>
    public KeyDerivationBuilder WithInputKeyingMaterial(byte[] ikm)
    {
        _ikm = ikm;
        return this;
    }

    /// <summary>
    /// Sets the info/context for HKDF
    /// </summary>
    public KeyDerivationBuilder WithInfo(byte[] info)
    {
        _info = info;
        return this;
    }

    /// <summary>
    /// Sets the number of iterations (for PBKDF2)
    /// </summary>
    public KeyDerivationBuilder WithIterations(int iterations)
    {
        _iterations = iterations;
        return this;
    }

    /// <summary>
    /// Sets the desired output key length in bytes
    /// </summary>
    public KeyDerivationBuilder WithKeyLength(int keyLength)
    {
        _keyLength = keyLength;
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm to use
    /// </summary>
    public KeyDerivationBuilder WithHashAlgorithm(KeyManagement.HashAlgorithmName hashAlgorithm)
    {
        _hashAlgorithm = hashAlgorithm;
        return this;
    }

    /// <summary>
    /// Sets the block size for Scrypt
    /// </summary>
    public KeyDerivationBuilder WithBlockSize(int blockSize)
    {
        _blockSize = blockSize;
        return this;
    }

    /// <summary>
    /// Sets the parallelism for Scrypt
    /// </summary>
    public KeyDerivationBuilder WithParallelism(int parallelism)
    {
        _parallelism = parallelism;
        return this;
    }

    /// <summary>
    /// Use PBKDF2 for key derivation
    /// </summary>
    public KeyDerivationBuilder UsePBKDF2()
    {
        _type = KeyDerivationType.PBKDF2;
        return this;
    }

    /// <summary>
    /// Use HKDF for key derivation
    /// </summary>
    public KeyDerivationBuilder UseHKDF()
    {
        _type = KeyDerivationType.HKDF;
        return this;
    }

    /// <summary>
    /// Use Scrypt for key derivation
    /// </summary>
    public KeyDerivationBuilder UseScrypt()
    {
        _type = KeyDerivationType.Scrypt;
        return this;
    }

    /// <summary>
    /// Use Argon2 for key derivation
    /// </summary>
    public KeyDerivationBuilder UseArgon2()
    {
        _type = KeyDerivationType.Argon2;
        return this;
    }

    /// <summary>
    /// Derives the key based on the configured parameters
    /// </summary>
    public byte[] Build()
    {
        return _type switch
        {
            KeyDerivationType.PBKDF2 => DerivePBKDF2(),
            KeyDerivationType.HKDF => DeriveHKDF(),
            KeyDerivationType.Scrypt => DeriveScrypt(),
            KeyDerivationType.Argon2 => DeriveArgon2(),
            _ => throw new InvalidOperationException($"Unsupported key derivation type: {_type}")
        };
    }

    private byte[] DerivePBKDF2()
    {
        if (_password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }
        if (_salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        // Validate parameters
        InputValidator.ValidatePbkdf2Parameters(_password, _salt, _iterations, _keyLength);

        // Call PBKDF2 primitive directly
        var hashName = _hashAlgorithm.Name switch
        {
            "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
            "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
            "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => System.Security.Cryptography.HashAlgorithmName.SHA256
        };

#if !NETSTANDARD2_0
        return System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(_password, _salt, _iterations, hashName, _keyLength);
#else
        // Use Rfc2898DeriveBytes for .NET Standard 2.0
        // Note: netstandard2.0 constructor doesn't support HashAlgorithmName parameter,
        // so we suppress the analyzer warning
#pragma warning disable CA5379 // Do not use weak key derivation function algorithm
        using var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(_password, _salt, _iterations);
#pragma warning restore CA5379
        return pbkdf2.GetBytes(_keyLength);
#endif
    }

    private byte[] DeriveHKDF()
    {
        if (_ikm == null)
        {
            throw new InvalidOperationException("Input keying material must be set using WithInputKeyingMaterial()");
        }

        // Validate parameters
        InputValidator.ValidateHkdfParameters(_ikm, _salt ?? [], _info ?? Array.Empty<byte>(), _keyLength);

        var hashName = _hashAlgorithm.Name switch
        {
            "SHA256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
            "SHA384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
            "SHA512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => System.Security.Cryptography.HashAlgorithmName.SHA256
        };

#if !NETSTANDARD2_0
        return System.Security.Cryptography.HKDF.DeriveKey(hashName, _ikm, _keyLength, _salt, _info);
#else
        // Use HeroCrypt's HKDF implementation for .NET Standard 2.0
        return Cryptography.Primitives.Kdf.HkdfCore.DeriveKey(_ikm, _salt ?? Array.Empty<byte>(), _info ?? Array.Empty<byte>(), _keyLength, hashName);
#endif
    }

    private byte[] DeriveScrypt()
    {
        if (_password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }
        if (_salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        // Validate parameters
        InputValidator.ValidateScryptParameters(_password, _salt, _iterations, _blockSize, _parallelism, _keyLength);

        // Use HeroCrypt's Scrypt implementation
        return Cryptography.Primitives.Kdf.ScryptCore.DeriveKey(_password, _salt, _iterations, _blockSize, _parallelism, _keyLength);
    }

    private byte[] DeriveArgon2()
    {
        if (_password == null)
        {
            throw new InvalidOperationException("Password must be set using WithPassword()");
        }
        if (_salt == null)
        {
            throw new InvalidOperationException("Salt must be set using WithSalt()");
        }

        // Validate parameters (use PBKDF2 validator as baseline for password/salt/iterations)
        InputValidator.ValidateByteArray(_password, nameof(_password), allowEmpty: true);
        InputValidator.ValidateByteArray(_salt, nameof(_salt), allowEmpty: false);
        InputValidator.ValidateArraySize(_keyLength, "Argon2 key derivation");

        if (_iterations < 1)
        {
            throw new ArgumentException("Iterations must be at least 1", nameof(_iterations));
        }
        if (_iterations > InputValidator.MAX_ITERATION_COUNT)
        {
            throw new ArgumentException($"Iterations {_iterations} exceeds maximum {InputValidator.MAX_ITERATION_COUNT}", nameof(_iterations));
        }

        // Call Argon2 primitive directly
        return Cryptography.Primitives.Kdf.Argon2Core.Hash(
            _password,
            _salt,
            _iterations,
            65536, // memory size in KB
            _parallelism,
            _keyLength,
            Cryptography.Primitives.Kdf.Argon2Type.Argon2id,
            null,
            null);
    }
}
