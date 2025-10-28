using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.RSA;
using HeroCrypt.Security;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using BigInteger = HeroCrypt.Cryptography.RSA.BigInteger;

namespace HeroCrypt.Services;

/// <summary>
/// RSA encryption/decryption service implementation
/// </summary>
public sealed class RsaEncryptionService
{
    private readonly ILogger<RsaEncryptionService>? _logger;
    private readonly ISecureMemoryManager? _memoryManager;
    private readonly int _keySize;
    private readonly RsaPaddingMode _defaultPadding;
    private readonly HashAlgorithmName _defaultHashAlgorithm;

    /// <summary>
    /// Initializes a new instance of the RSA encryption service
    /// </summary>
    /// <param name="keySize">RSA key size in bits (default: 2048)</param>
    /// <param name="defaultPadding">Default padding mode (default: OAEP for better security)</param>
    /// <param name="defaultHashAlgorithm">Default hash algorithm for OAEP (default: SHA256)</param>
    /// <param name="logger">Optional logger instance</param>
    /// <param name="memoryManager">Optional secure memory manager</param>
    public RsaEncryptionService(
        int keySize = 2048,
        RsaPaddingMode defaultPadding = RsaPaddingMode.Oaep,
        HashAlgorithmName? defaultHashAlgorithm = null,
        ILogger<RsaEncryptionService>? logger = null,
        ISecureMemoryManager? memoryManager = null)
    {
        InputValidator.ValidateRsaKeySize(keySize, nameof(keySize));

        _keySize = keySize;
        _defaultPadding = defaultPadding;
        _defaultHashAlgorithm = defaultHashAlgorithm ?? HashAlgorithmName.SHA256;
        _logger = logger;
        _memoryManager = memoryManager;

        _logger?.LogDebug("RSA Encryption Service initialized with {KeySize}-bit keys, {Padding} padding, {HashAlgorithm} hash",
            keySize, defaultPadding, _defaultHashAlgorithm.Name);
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
        _logger?.LogDebug("Generating RSA key pair with {KeySize}-bit keys", _keySize);

        try
        {
            var keyPair = RsaCore.GenerateKeyPair(_keySize);

            // Serialize keys to byte arrays
            var privateKey = SerializePrivateKey(keyPair.PrivateKey);
            var publicKey = SerializePublicKey(keyPair.PublicKey);

            _logger?.LogInformation("Successfully generated RSA key pair with {KeySize}-bit keys", _keySize);

            return (privateKey, publicKey);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate RSA key pair");
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
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
#endif

        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        _logger?.LogDebug("Deriving public key from private key");

        try
        {
            var rsaPrivateKey = DeserializePrivateKey(privateKey);
            var rsaPublicKey = new RsaPublicKey(rsaPrivateKey.Modulus, rsaPrivateKey.E);

            var publicKey = SerializePublicKey(rsaPublicKey);

            _logger?.LogDebug("Successfully derived public key from private key");

            return publicKey;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to derive public key from private key");
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
    public byte[] Encrypt(byte[] data, byte[] publicKey, RsaPaddingMode? padding = null, HashAlgorithmName? hashAlgorithm = null)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(publicKey);
#else
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
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

        _logger?.LogDebug("Encrypting data with RSA public key (data size: {DataSize} bytes, padding: {Padding})",
            data.Length, actualPadding);

        try
        {
            var rsaPublicKey = DeserializePublicKey(publicKey);
            var encrypted = RsaCore.Encrypt(data, rsaPublicKey, actualPadding, actualHashAlgorithm);

            _logger?.LogInformation("Successfully encrypted data (output size: {OutputSize} bytes)", encrypted.Length);

            return encrypted;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to encrypt data with RSA public key");
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
    public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey, RsaPaddingMode? padding = null, HashAlgorithmName? hashAlgorithm = null)
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
    public byte[] Decrypt(byte[] encryptedData, byte[] privateKey, RsaPaddingMode? padding = null, HashAlgorithmName? hashAlgorithm = null)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
#endif

        InputValidator.ValidateByteArray(encryptedData, nameof(encryptedData));
        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        var actualPadding = padding ?? _defaultPadding;
        var actualHashAlgorithm = hashAlgorithm ?? _defaultHashAlgorithm;

        _logger?.LogDebug("Decrypting data with RSA private key (data size: {DataSize} bytes, padding: {Padding})",
            encryptedData.Length, actualPadding);

        try
        {
            var rsaPrivateKey = DeserializePrivateKey(privateKey);
            var decrypted = RsaCore.Decrypt(encryptedData, rsaPrivateKey, actualPadding, actualHashAlgorithm);

            _logger?.LogInformation("Successfully decrypted data (output size: {OutputSize} bytes)", decrypted.Length);

            return decrypted;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to decrypt data with RSA private key");
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
    public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] privateKey, RsaPaddingMode? padding = null, HashAlgorithmName? hashAlgorithm = null)
    {
        // RSA decryption is CPU-bound, so we run it on a background thread
        return await Task.Run(() => Decrypt(encryptedData, privateKey, padding, hashAlgorithm)).ConfigureAwait(false);
    }

    private int CalculateMaxMessageSize(RsaPaddingMode padding, HashAlgorithmName hashAlgorithm)
    {
        var modulusSize = _keySize / 8;
        return padding switch
        {
            RsaPaddingMode.Pkcs1 => modulusSize - 11,
            RsaPaddingMode.Oaep => modulusSize - 2 * (GetHashSize(hashAlgorithm) / 8) - 2,
            _ => modulusSize - 11
        };
    }

    private static int GetHashSize(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256) return 256;
        if (hashAlgorithm == HashAlgorithmName.SHA384) return 384;
        if (hashAlgorithm == HashAlgorithmName.SHA512) return 512;
        if (hashAlgorithm == HashAlgorithmName.SHA1) return 160;

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
            throw new ArgumentException("Invalid private key data");

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
            throw new ArgumentException("Invalid public key data");

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
