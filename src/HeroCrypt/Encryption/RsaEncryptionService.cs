using HeroCrypt.Cryptography.Primitives.Signature.Rsa;
using HeroCrypt.Security;
using BigInteger = HeroCrypt.Cryptography.Primitives.Signature.Rsa.BigInteger;
using SystemHashAlgorithmName = System.Security.Cryptography.HashAlgorithmName;

namespace HeroCrypt.Encryption;

/// <summary>
/// RSA encryption/decryption service implementation
/// </summary>
public sealed class RsaEncryptionService
{
    private readonly int _keySize;
    private readonly RsaPaddingMode _defaultPadding;
    private readonly SystemHashAlgorithmName _defaultHashAlgorithm;

    /// <summary>
    /// Initializes a new instance of the RSA encryption service
    /// </summary>
    /// <param name="keySize">RSA key size in bits (default: 2048)</param>
    /// <param name="defaultPadding">Default padding mode (default: OAEP for better security)</param>
    /// <param name="defaultHashAlgorithm">Default hash algorithm for OAEP (default: SHA256)</param>
    public RsaEncryptionService(
        int keySize = 2048,
        RsaPaddingMode defaultPadding = RsaPaddingMode.Oaep,
        SystemHashAlgorithmName? defaultHashAlgorithm = null)
    {
        InputValidator.ValidateRsaKeySize(keySize, nameof(keySize));

        _keySize = keySize;
        _defaultPadding = defaultPadding;
        _defaultHashAlgorithm = defaultHashAlgorithm ?? SystemHashAlgorithmName.SHA256;
    }

    /// <summary>
    /// Gets the algorithm name
    /// </summary>
    public string AlgorithmName => $"RSA-{_keySize}";

    /// <summary>
    /// Gets the key size in bits
    /// </summary>
    public int KeySizeBits => _keySize;

    /// <summary>
    /// Gets the maximum message size that can be encrypted in bytes
    /// </summary>
    public int MaxMessageSize
    {
        get
        {
            var modulusSize = _keySize / 8;
            return _defaultPadding switch
            {
                RsaPaddingMode.Pkcs1 => modulusSize - 11,
                RsaPaddingMode.Oaep => modulusSize - 2 * (GetHashSize(_defaultHashAlgorithm) / 8) - 2,
                _ => modulusSize - 11
            };
        }
    }

    /// <summary>
    /// Generates a new RSA key pair
    /// </summary>
    /// <returns>Tuple containing private key and public key as byte arrays</returns>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        try
        {
            var keyPair = RsaCore.GenerateKeyPair(_keySize);

            // Serialize keys to byte arrays
            var privateKey = SerializePrivateKey(keyPair.PrivateKey);
            var publicKey = SerializePublicKey(keyPair.PublicKey);

            return (privateKey, publicKey);
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Derives the public key from a private key
    /// </summary>
    /// <param name="privateKey">Private key bytes</param>
    /// <returns>Public key bytes</returns>
    public byte[] DerivePublicKey(byte[] privateKey)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#endif

        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        try
        {
            var rsaPrivateKey = DeserializePrivateKey(privateKey);
            var rsaPublicKey = new RsaPublicKey(rsaPrivateKey.Modulus, rsaPrivateKey.E);

            var publicKey = SerializePublicKey(rsaPublicKey);

            return publicKey;
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Encrypts data using the public key
    /// </summary>
    /// <param name="data">Data to encrypt</param>
    /// <param name="publicKey">Public key for encryption</param>
    /// <param name="padding">Padding mode (defaults to service default)</param>
    /// <param name="hashAlgorithm">Hash algorithm for OAEP padding (defaults to service default)</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(byte[] data, byte[] publicKey, RsaPaddingMode? padding = null, SystemHashAlgorithmName? hashAlgorithm = null)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(publicKey);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }
#endif

        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: false);
        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        var actualPadding = padding ?? _defaultPadding;
        var actualHashAlgorithm = hashAlgorithm ?? _defaultHashAlgorithm;

        // Validate message size
        var maxSize = CalculateMaxMessageSize(actualPadding, actualHashAlgorithm);
        if (data.Length > maxSize)
        {
            throw new ArgumentException(
                $"Data size ({data.Length} bytes) exceeds maximum message size ({maxSize} bytes) for {_keySize}-bit RSA with {actualPadding} padding",
                nameof(data));
        }

        try
        {
            var rsaPublicKey = DeserializePublicKey(publicKey);
            var encrypted = RsaCore.Encrypt(data, rsaPublicKey, actualPadding, actualHashAlgorithm);

            return encrypted;
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Encrypts data asynchronously using the public key
    /// </summary>
    /// <param name="data">Data to encrypt</param>
    /// <param name="publicKey">Public key for encryption</param>
    /// <param name="padding">Padding mode (defaults to service default)</param>
    /// <param name="hashAlgorithm">Hash algorithm for OAEP padding (defaults to service default)</param>
    /// <returns>Encrypted data</returns>
    public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey, RsaPaddingMode? padding = null, SystemHashAlgorithmName? hashAlgorithm = null)
    {
        // RSA encryption is CPU-bound, so we run it on a background thread
        return await Task.Run(() => Encrypt(data, publicKey, padding, hashAlgorithm)).ConfigureAwait(false);
    }

    /// <summary>
    /// Decrypts data using the private key
    /// </summary>
    /// <param name="encryptedData">Encrypted data</param>
    /// <param name="privateKey">Private key for decryption</param>
    /// <param name="padding">Padding mode (defaults to service default)</param>
    /// <param name="hashAlgorithm">Hash algorithm for OAEP padding (defaults to service default)</param>
    /// <returns>Decrypted data</returns>
    public byte[] Decrypt(byte[] encryptedData, byte[] privateKey, RsaPaddingMode? padding = null, SystemHashAlgorithmName? hashAlgorithm = null)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (encryptedData == null)
        {
            throw new ArgumentNullException(nameof(encryptedData));
        }
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#endif

        InputValidator.ValidateByteArray(encryptedData, nameof(encryptedData));
        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        var actualPadding = padding ?? _defaultPadding;
        var actualHashAlgorithm = hashAlgorithm ?? _defaultHashAlgorithm;

        try
        {
            var rsaPrivateKey = DeserializePrivateKey(privateKey);
            var decrypted = RsaCore.Decrypt(encryptedData, rsaPrivateKey, actualPadding, actualHashAlgorithm);

            return decrypted;
        }
        catch
        {
            throw;
        }
    }

    /// <summary>
    /// Decrypts data asynchronously using the private key
    /// </summary>
    /// <param name="encryptedData">Encrypted data</param>
    /// <param name="privateKey">Private key for decryption</param>
    /// <param name="padding">Padding mode (defaults to service default)</param>
    /// <param name="hashAlgorithm">Hash algorithm for OAEP padding (defaults to service default)</param>
    /// <returns>Decrypted data</returns>
    public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] privateKey, RsaPaddingMode? padding = null, SystemHashAlgorithmName? hashAlgorithm = null)
    {
        // RSA decryption is CPU-bound, so we run it on a background thread
        return await Task.Run(() => Decrypt(encryptedData, privateKey, padding, hashAlgorithm)).ConfigureAwait(false);
    }

    private int CalculateMaxMessageSize(RsaPaddingMode padding, SystemHashAlgorithmName hashAlgorithm)
    {
        var modulusSize = _keySize / 8;
        return padding switch
        {
            RsaPaddingMode.Pkcs1 => modulusSize - 11,
            RsaPaddingMode.Oaep => modulusSize - 2 * (GetHashSize(hashAlgorithm) / 8) - 2,
            _ => modulusSize - 11
        };
    }

    private static int GetHashSize(SystemHashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == SystemHashAlgorithmName.SHA256)
        {
            return 256;
        }

        if (hashAlgorithm == SystemHashAlgorithmName.SHA384)
        {
            return 384;
        }

        if (hashAlgorithm == SystemHashAlgorithmName.SHA512)
        {
            return 512;
        }

        if (hashAlgorithm == SystemHashAlgorithmName.SHA1)
        {
            return 160;
        }

        // Default to SHA256
        return 256;
    }

    private static byte[] SerializePrivateKey(RsaPrivateKey privateKey)
    {
        // Simple serialization format: [modulus_length][modulus][d_length][d][p_length][p][q_length][q][e_length][e]
        var modulusBytes = privateKey.Modulus.ToByteArray();
        var dBytes = privateKey.D.ToByteArray();
        var pBytes = privateKey.P.ToByteArray();
        var qBytes = privateKey.Q.ToByteArray();
        var eBytes = privateKey.E.ToByteArray();

        try
        {
            var totalSize = 20 + modulusBytes.Length + dBytes.Length + pBytes.Length + qBytes.Length + eBytes.Length; // 5 length fields (4 bytes each)
            var result = new byte[totalSize];
            var offset = 0;

            // Modulus
            BitConverter.GetBytes(modulusBytes.Length).CopyTo(result, offset);
            offset += 4;
            modulusBytes.CopyTo(result, offset);
            offset += modulusBytes.Length;

            // D
            BitConverter.GetBytes(dBytes.Length).CopyTo(result, offset);
            offset += 4;
            dBytes.CopyTo(result, offset);
            offset += dBytes.Length;

            // P
            BitConverter.GetBytes(pBytes.Length).CopyTo(result, offset);
            offset += 4;
            pBytes.CopyTo(result, offset);
            offset += pBytes.Length;

            // Q
            BitConverter.GetBytes(qBytes.Length).CopyTo(result, offset);
            offset += 4;
            qBytes.CopyTo(result, offset);
            offset += qBytes.Length;

            // E
            BitConverter.GetBytes(eBytes.Length).CopyTo(result, offset);
            offset += 4;
            eBytes.CopyTo(result, offset);

            return result;
        }
        finally
        {
            // Securely clear all sensitive intermediate arrays
            SecureMemoryOperations.SecureClear(modulusBytes, dBytes, pBytes, qBytes, eBytes);
        }
    }

    #region PKCS#8 and X.509 Key Format Support

    /// <summary>
    /// Exports a private key in PKCS#8 format (RFC 5208)
    /// </summary>
    /// <param name="privateKey">Private key in internal format</param>
    /// <returns>PKCS#8 encoded private key</returns>
    /// <remarks>
    /// PKCS#8 is the standard format for private keys, widely supported by OpenSSL,
    /// Java, Python, and other cryptographic libraries. Use this for interoperability.
    /// Note: This method requires .NET 5.0 or later. Not available in .NET Standard 2.0.
    /// </remarks>
    public byte[] ExportPkcs8PrivateKey(byte[] privateKey)
    {
#if NET5_0_OR_GREATER
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
#endif

        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        try
        {
            var rsaPrivateKey = DeserializePrivateKey(privateKey);

            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportParameters(RsaCore.ToRsaParameters(rsaPrivateKey));

            var pkcs8Bytes = rsa.ExportPkcs8PrivateKey();

            return pkcs8Bytes;
        }
        catch
        {
            throw;
        }
#else
        throw new PlatformNotSupportedException(
            "PKCS#8 export is only supported on .NET 5.0 or later. " +
            "Please upgrade to .NET 5.0+ or use the internal key format.");
#endif
    }

    /// <summary>
    /// Imports a private key from PKCS#8 format (RFC 5208)
    /// </summary>
    /// <param name="pkcs8Data">PKCS#8 encoded private key</param>
    /// <returns>Private key in internal format</returns>
    /// <remarks>
    /// Supports standard PKCS#8 private keys from OpenSSL, Java, Python, etc.
    /// Example OpenSSL command: openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
    /// Note: This method requires .NET 5.0 or later. Not available in .NET Standard 2.0.
    /// </remarks>
    public byte[] ImportPkcs8PrivateKey(byte[] pkcs8Data)
    {
#if NET5_0_OR_GREATER
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(pkcs8Data);
#else
        if (pkcs8Data == null)
            {
                throw new ArgumentNullException(nameof(pkcs8Data));
            }
#endif

        InputValidator.ValidateByteArray(pkcs8Data, nameof(pkcs8Data));

        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportPkcs8PrivateKey(pkcs8Data, out _);

            // Validate key size
            if (rsa.KeySize < 2048)
            {
                throw new ArgumentException(
                    $"Imported RSA key size ({rsa.KeySize} bits) is too small. Minimum 2048 bits required.",
                    nameof(pkcs8Data));
            }

            var parameters = rsa.ExportParameters(includePrivateParameters: true);

            var rsaPrivateKey = new RsaPrivateKey(
                new BigInteger(parameters.Modulus!),
                new BigInteger(parameters.D!),
                new BigInteger(parameters.P!),
                new BigInteger(parameters.Q!),
                new BigInteger(parameters.Exponent!)
            );

            var internalFormat = SerializePrivateKey(rsaPrivateKey);

            return internalFormat;
        }
        catch
        {
            throw;
        }
#else
        throw new PlatformNotSupportedException(
            "PKCS#8 import is only supported on .NET 5.0 or later. " +
            "Please upgrade to .NET 5.0+ or use the internal key format.");
#endif
    }

    /// <summary>
    /// Exports a public key in X.509 SubjectPublicKeyInfo format (RFC 5280)
    /// </summary>
    /// <param name="publicKey">Public key in internal format</param>
    /// <returns>X.509 SubjectPublicKeyInfo encoded public key</returns>
    /// <remarks>
    /// X.509 SubjectPublicKeyInfo is the standard format for public keys.
    /// Compatible with OpenSSL, Java, Python, and other cryptographic libraries.
    /// Note: This method requires .NET 5.0 or later. Not available in .NET Standard 2.0.
    /// </remarks>
    public byte[] ExportSubjectPublicKeyInfo(byte[] publicKey)
    {
#if NET5_0_OR_GREATER
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(publicKey);
#else
        if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
#endif

        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        try
        {
            var rsaPublicKey = DeserializePublicKey(publicKey);

            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportParameters(RsaCore.ToRsaParameters(rsaPublicKey));

            var spkiBytes = rsa.ExportSubjectPublicKeyInfo();

            return spkiBytes;
        }
        catch
        {
            throw;
        }
#else
        throw new PlatformNotSupportedException(
            "X.509 SubjectPublicKeyInfo export is only supported on .NET 5.0 or later. " +
            "Please upgrade to .NET 5.0+ or use the internal key format.");
#endif
    }

    /// <summary>
    /// Imports a public key from X.509 SubjectPublicKeyInfo format (RFC 5280)
    /// </summary>
    /// <param name="subjectPublicKeyInfo">X.509 SubjectPublicKeyInfo encoded public key</param>
    /// <returns>Public key in internal format</returns>
    /// <remarks>
    /// Supports standard X.509 public keys from OpenSSL, certificates, etc.
    /// Example OpenSSL command: openssl rsa -in private.pem -pubout -out public.pem
    /// Note: This method requires .NET 5.0 or later. Not available in .NET Standard 2.0.
    /// </remarks>
    public byte[] ImportSubjectPublicKeyInfo(byte[] subjectPublicKeyInfo)
    {
#if NET5_0_OR_GREATER
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
#else
        if (subjectPublicKeyInfo == null)
            {
                throw new ArgumentNullException(nameof(subjectPublicKeyInfo));
            }
#endif

        InputValidator.ValidateByteArray(subjectPublicKeyInfo, nameof(subjectPublicKeyInfo));

        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);

            var parameters = rsa.ExportParameters(includePrivateParameters: false);

            var rsaPublicKey = new RsaPublicKey(
                new BigInteger(parameters.Modulus!),
                new BigInteger(parameters.Exponent!)
            );

            var internalFormat = SerializePublicKey(rsaPublicKey);

            return internalFormat;
        }
        catch
        {
            throw;
        }
#else
        throw new PlatformNotSupportedException(
            "X.509 SubjectPublicKeyInfo import is only supported on .NET 5.0 or later. " +
            "Please upgrade to .NET 5.0+ or use the internal key format.");
#endif
    }

    #endregion

    private static byte[] SerializePublicKey(RsaPublicKey publicKey)
    {
        // Simple serialization format: [modulus_length][modulus][exponent_length][exponent]
        var modulusBytes = publicKey.Modulus.ToByteArray();
        var exponentBytes = publicKey.Exponent.ToByteArray();

        var totalSize = 8 + modulusBytes.Length + exponentBytes.Length; // 2 length fields (4 bytes each)
        var result = new byte[totalSize];
        var offset = 0;

        // Modulus
        BitConverter.GetBytes(modulusBytes.Length).CopyTo(result, offset);
        offset += 4;
        modulusBytes.CopyTo(result, offset);
        offset += modulusBytes.Length;

        // Exponent
        BitConverter.GetBytes(exponentBytes.Length).CopyTo(result, offset);
        offset += 4;
        exponentBytes.CopyTo(result, offset);

        return result;
    }

    private static RsaPrivateKey DeserializePrivateKey(byte[] data)
    {
        if (data.Length < 20)
        {
            throw new ArgumentException("Invalid private key data");
        }

        var offset = 0;

        // Modulus
        var modulusLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var modulusBytes = new byte[modulusLength];
        Array.Copy(data, offset, modulusBytes, 0, modulusLength);
        offset += modulusLength;
        var modulus = new BigInteger(modulusBytes);

        // D
        var dLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var dBytes = new byte[dLength];
        Array.Copy(data, offset, dBytes, 0, dLength);
        offset += dLength;
        var d = new BigInteger(dBytes);

        // P
        var pLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var pBytes = new byte[pLength];
        Array.Copy(data, offset, pBytes, 0, pLength);
        offset += pLength;
        var p = new BigInteger(pBytes);

        // Q
        var qLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var qBytes = new byte[qLength];
        Array.Copy(data, offset, qBytes, 0, qLength);
        offset += qLength;
        var q = new BigInteger(qBytes);

        // E
        var eLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var eBytes = new byte[eLength];
        Array.Copy(data, offset, eBytes, 0, eLength);
        var e = new BigInteger(eBytes);

        return new RsaPrivateKey(modulus, d, p, q, e);
    }

    private static RsaPublicKey DeserializePublicKey(byte[] data)
    {
        if (data.Length < 8)
        {
            throw new ArgumentException("Invalid public key data");
        }

        var offset = 0;

        // Modulus
        var modulusLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var modulusBytes = new byte[modulusLength];
        Array.Copy(data, offset, modulusBytes, 0, modulusLength);
        offset += modulusLength;
        var modulus = new BigInteger(modulusBytes);

        // Exponent
        var exponentLength = BitConverter.ToInt32(data, offset);
        offset += 4;
        var exponentBytes = new byte[exponentLength];
        Array.Copy(data, offset, exponentBytes, 0, exponentLength);
        var exponent = new BigInteger(exponentBytes);

        return new RsaPublicKey(modulus, exponent);
    }
}
