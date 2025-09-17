using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.RSA;
using HeroCrypt.Memory;
using BigInteger = HeroCrypt.Cryptography.RSA.BigInteger;

namespace HeroCrypt.Services;

/// <summary>
/// Service implementation for generating cryptographically secure keys and key material
/// </summary>
public sealed class CryptographicKeyGenerationService : ICryptographicKeyGenerationService
{
    private readonly ILogger<CryptographicKeyGenerationService>? _logger;
    private readonly ISecureMemoryManager? _memoryManager;
    private readonly RandomNumberGenerator _rng;

    /// <summary>
    /// Initializes a new instance of the cryptographic key generation service
    /// </summary>
    /// <param name="logger">Optional logger instance</param>
    /// <param name="memoryManager">Optional secure memory manager</param>
    public CryptographicKeyGenerationService(
        ILogger<CryptographicKeyGenerationService>? logger = null,
        ISecureMemoryManager? memoryManager = null)
    {
        _logger = logger;
        _memoryManager = memoryManager;
        _rng = RandomNumberGenerator.Create();

        _logger?.LogDebug("Cryptographic Key Generation Service initialized");
    }

    /// <inheritdoc />
    public byte[] GenerateRandomBytes(int length)
    {
        if (length <= 0)
            throw new ArgumentException("Length must be positive", nameof(length));

        _logger?.LogDebug("Generating {Length} random bytes", length);

        var bytes = new byte[length];
        _rng.GetBytes(bytes);

        _logger?.LogDebug("Successfully generated {Length} random bytes", length);
        return bytes;
    }

    /// <inheritdoc />
    public async Task<byte[]> GenerateRandomBytesAsync(int length, CancellationToken cancellationToken = default)
    {
        if (length <= 0)
            throw new ArgumentException("Length must be positive", nameof(length));

        _logger?.LogDebug("Asynchronously generating {Length} random bytes", length);

        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return GenerateRandomBytes(length);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public byte[] GenerateSymmetricKey(int keyLength)
    {
        if (keyLength <= 0)
            throw new ArgumentException("Key length must be positive", nameof(keyLength));

        _logger?.LogDebug("Generating symmetric key of {KeyLength} bytes", keyLength);

        var key = GenerateRandomBytes(keyLength);

        _logger?.LogInformation("Generated symmetric key: {KeyLength} bytes", keyLength);
        return key;
    }

    /// <inheritdoc />
    public byte[] GenerateSymmetricKey(CryptographicAlgorithm algorithm)
    {
        var keyLength = algorithm switch
        {
            CryptographicAlgorithm.Aes128 => 16,
            CryptographicAlgorithm.Aes192 => 24,
            CryptographicAlgorithm.Aes256 => 32,
            CryptographicAlgorithm.ChaCha20 => 32,
            CryptographicAlgorithm.ChaCha20Poly1305 => 32,
            _ => throw new ArgumentException($"Unsupported symmetric algorithm: {algorithm}", nameof(algorithm))
        };

        _logger?.LogDebug("Generating symmetric key for {Algorithm} ({KeyLength} bytes)", algorithm, keyLength);

        var key = GenerateSymmetricKey(keyLength);

        _logger?.LogInformation("Generated {Algorithm} key: {KeyLength} bytes", algorithm, keyLength);
        return key;
    }

    /// <inheritdoc />
    public byte[] GenerateIV(int ivLength)
    {
        if (ivLength <= 0)
            throw new ArgumentException("IV length must be positive", nameof(ivLength));

        _logger?.LogDebug("Generating IV of {IvLength} bytes", ivLength);

        var iv = GenerateRandomBytes(ivLength);

        _logger?.LogDebug("Generated IV: {IvLength} bytes", ivLength);
        return iv;
    }

    /// <inheritdoc />
    public byte[] GenerateIV(CryptographicAlgorithm algorithm)
    {
        var ivLength = algorithm switch
        {
            CryptographicAlgorithm.Aes128 => 16,
            CryptographicAlgorithm.Aes192 => 16,
            CryptographicAlgorithm.Aes256 => 16,
            CryptographicAlgorithm.ChaCha20 => 12,
            CryptographicAlgorithm.ChaCha20Poly1305 => 12,
            _ => throw new ArgumentException($"Unsupported symmetric algorithm: {algorithm}", nameof(algorithm))
        };

        _logger?.LogDebug("Generating IV for {Algorithm} ({IvLength} bytes)", algorithm, ivLength);

        var iv = GenerateIV(ivLength);

        _logger?.LogDebug("Generated {Algorithm} IV: {IvLength} bytes", algorithm, ivLength);
        return iv;
    }

    /// <inheritdoc />
    public byte[] GenerateSalt(int saltLength = 32)
    {
        if (saltLength <= 0)
            throw new ArgumentException("Salt length must be positive", nameof(saltLength));

        _logger?.LogDebug("Generating salt of {SaltLength} bytes", saltLength);

        var salt = GenerateRandomBytes(saltLength);

        _logger?.LogDebug("Generated salt: {SaltLength} bytes", saltLength);
        return salt;
    }

    /// <inheritdoc />
    public byte[] GenerateNonce(int nonceLength)
    {
        if (nonceLength <= 0)
            throw new ArgumentException("Nonce length must be positive", nameof(nonceLength));

        _logger?.LogDebug("Generating nonce of {NonceLength} bytes", nonceLength);

        var nonce = GenerateRandomBytes(nonceLength);

        _logger?.LogDebug("Generated nonce: {NonceLength} bytes", nonceLength);
        return nonce;
    }

    /// <inheritdoc />
    public byte[] GenerateNonce(NonceAlgorithm algorithm)
    {
        var nonceLength = algorithm switch
        {
            NonceAlgorithm.ChaCha20 => 12,
            NonceAlgorithm.ChaCha20Poly1305 => 12,
            NonceAlgorithm.AesGcm => 12,
            _ => throw new ArgumentException($"Unsupported nonce algorithm: {algorithm}", nameof(algorithm))
        };

        _logger?.LogDebug("Generating nonce for {Algorithm} ({NonceLength} bytes)", algorithm, nonceLength);

        var nonce = GenerateNonce(nonceLength);

        _logger?.LogDebug("Generated {Algorithm} nonce: {NonceLength} bytes", algorithm, nonceLength);
        return nonce;
    }

    /// <inheritdoc />
    public (byte[] privateKey, byte[] publicKey) GenerateRsaKeyPair(int keySize = 2048)
    {
        if (keySize < 1024)
            throw new ArgumentException("RSA key size must be at least 1024 bits for security", nameof(keySize));
        if (keySize % 8 != 0)
            throw new ArgumentException("RSA key size must be a multiple of 8", nameof(keySize));

        _logger?.LogDebug("Generating RSA key pair with {KeySize}-bit keys", keySize);

        try
        {
            var keyPair = RsaCore.GenerateKeyPair(keySize);

            // Serialize keys to byte arrays using the same format as RsaDigitalSignatureService
            var privateKey = SerializePrivateKey(keyPair.PrivateKey);
            var publicKey = SerializePublicKey(keyPair.PublicKey);

            _logger?.LogInformation("Successfully generated RSA key pair with {KeySize}-bit keys", keySize);

            return (privateKey, publicKey);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate RSA key pair");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<(byte[] privateKey, byte[] publicKey)> GenerateRsaKeyPairAsync(int keySize = 2048, CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("Asynchronously generating RSA key pair with {KeySize}-bit keys", keySize);

        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            return GenerateRsaKeyPair(keySize);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public byte[] GenerateHmacKey(Abstractions.HashAlgorithmName algorithm)
    {
        var keyLength = algorithm.Name?.ToUpperInvariant() switch
        {
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            "BLAKE2B" => 64,
            _ => 32 // Default to 32 bytes for unknown algorithms
        };

        _logger?.LogDebug("Generating HMAC key for {Algorithm} ({KeyLength} bytes)", algorithm.Name, keyLength);

        var key = GenerateRandomBytes(keyLength);

        _logger?.LogInformation("Generated HMAC-{Algorithm} key: {KeyLength} bytes", algorithm.Name, keyLength);
        return key;
    }

    /// <inheritdoc />
    public byte[] GenerateKeyDerivationMaterial(int keyLength = 32)
    {
        if (keyLength <= 0)
            throw new ArgumentException("Key length must be positive", nameof(keyLength));

        _logger?.LogDebug("Generating key derivation material of {KeyLength} bytes", keyLength);

        var material = GenerateRandomBytes(keyLength);

        _logger?.LogDebug("Generated key derivation material: {KeyLength} bytes", keyLength);
        return material;
    }

    /// <inheritdoc />
    public bool ValidateKeyMaterial(byte[] keyMaterial, string algorithm)
    {
        if (keyMaterial == null || keyMaterial.Length == 0)
        {
            _logger?.LogWarning("Key material validation failed: null or empty");
            return false;
        }

        if (string.IsNullOrEmpty(algorithm))
        {
            _logger?.LogWarning("Key material validation failed: null or empty algorithm");
            return false;
        }

        // Basic validation - check for all-zero keys (weak keys)
        var allZero = true;
        for (var i = 0; i < keyMaterial.Length; i++)
        {
            if (keyMaterial[i] != 0)
            {
                allZero = false;
                break;
            }
        }

        if (allZero)
        {
            _logger?.LogWarning("Key material validation failed: all-zero key detected");
            return false;
        }

        // Algorithm-specific validation
        var valid = algorithm.ToUpperInvariant() switch
        {
            "AES" or "AES128" => keyMaterial.Length >= 16,
            "AES192" => keyMaterial.Length >= 24,
            "AES256" => keyMaterial.Length >= 32,
            "CHACHA20" => keyMaterial.Length >= 32,
            "RSA" => keyMaterial.Length >= 128, // Minimum for 1024-bit RSA
            "HMAC" => keyMaterial.Length >= 16,
            _ => keyMaterial.Length >= 16 // Minimum 128-bit security for unknown algorithms
        };

        if (!valid)
        {
            _logger?.LogWarning("Key material validation failed for {Algorithm}: insufficient length {Length}",
                algorithm, keyMaterial.Length);
        }

        return valid;
    }

    /// <inheritdoc />
    public string GenerateSecurePassword(int length = 32, bool includeSymbols = true, bool includeNumbers = true,
        bool includeUppercase = true, bool includeLowercase = true)
    {
        if (length <= 0)
            throw new ArgumentException("Password length must be positive", nameof(length));

        if (!includeSymbols && !includeNumbers && !includeUppercase && !includeLowercase)
            throw new ArgumentException("At least one character set must be included");

        _logger?.LogDebug("Generating secure password of {Length} characters", length);

        var characterSets = new StringBuilder();

        if (includeLowercase)
            characterSets.Append("abcdefghijklmnopqrstuvwxyz");
        if (includeUppercase)
            characterSets.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (includeNumbers)
            characterSets.Append("0123456789");
        if (includeSymbols)
            characterSets.Append("!@#$%^&*()_+-=[]{}|;:,.<>?");

        var characters = characterSets.ToString();
        var password = new StringBuilder(length);

        for (var i = 0; i < length; i++)
        {
            var randomBytes = GenerateRandomBytes(4);
            var randomIndex = BitConverter.ToUInt32(randomBytes, 0) % characters.Length;
            password.Append(characters[(int)randomIndex]);
        }

        _logger?.LogInformation("Generated secure password: {Length} characters", length);
        return password.ToString();
    }

    private static byte[] SerializePrivateKey(RsaPrivateKey privateKey)
    {
        // Simple serialization format: [modulus_length][modulus][d_length][d][p_length][p][q_length][q][e_length][e]
        var modulusBytes = privateKey.Modulus.ToByteArray();
        var dBytes = privateKey.D.ToByteArray();
        var pBytes = privateKey.P.ToByteArray();
        var qBytes = privateKey.Q.ToByteArray();
        var eBytes = privateKey.E.ToByteArray();

        var totalSize = 20 + modulusBytes.Length + dBytes.Length + pBytes.Length + qBytes.Length + eBytes.Length;
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

    private static byte[] SerializePublicKey(RsaPublicKey publicKey)
    {
        // Simple serialization format: [modulus_length][modulus][exponent_length][exponent]
        var modulusBytes = publicKey.Modulus.ToByteArray();
        var exponentBytes = publicKey.Exponent.ToByteArray();

        var totalSize = 8 + modulusBytes.Length + exponentBytes.Length;
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

    /// <summary>
    /// Dispose of the random number generator
    /// </summary>
    public void Dispose()
    {
        _rng?.Dispose();
    }
}