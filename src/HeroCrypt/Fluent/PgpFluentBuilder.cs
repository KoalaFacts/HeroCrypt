using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Services;
using Microsoft.Extensions.Options;
using System.Text;

namespace HeroCrypt.Fluent;

/// <summary>
/// Fluent builder implementation for PGP operations
/// </summary>
public class PgpFluentBuilder : IPgpFluentBuilder
{
    private readonly HeroCryptOptions _options;
    private readonly IHardwareAccelerator _hardwareAccelerator;

    private byte[]? _data;
    private byte[]? _encryptedData;
    private string? _publicKey;
    private string? _privateKey;
    private string? _identity;
    private string? _passphrase;
    private int _keySize;
    private bool _useHardwareAcceleration;

    /// <summary>
    /// Initializes a new instance of the PgpFluentBuilder class
    /// </summary>
    /// <param name="options">HeroCrypt configuration options</param>
    /// <param name="hardwareAccelerator">Hardware acceleration service</param>
    public PgpFluentBuilder(IOptions<HeroCryptOptions> options, IHardwareAccelerator hardwareAccelerator)
    {
        _options = options.Value;
        _hardwareAccelerator = hardwareAccelerator;
        _keySize = _options.DefaultRsaKeySize;
        _useHardwareAcceleration = _options.EnableHardwareAcceleration;
    }

    /// <summary>
    /// Sets the plaintext data to be encrypted
    /// </summary>
    /// <param name="data">The plaintext string to encrypt</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">Thrown when data is null or empty</exception>
    public IPgpFluentBuilder WithData(string data)
    {
        if (string.IsNullOrEmpty(data))
            throw new ArgumentException("Data cannot be null or empty", nameof(data));

        _data = Encoding.UTF8.GetBytes(data);
        return this;
    }

    /// <summary>
    /// Sets the plaintext data to be encrypted
    /// </summary>
    /// <param name="data">The plaintext bytes to encrypt</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">Thrown when data is null</exception>
    public IPgpFluentBuilder WithData(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        return this;
    }

    /// <summary>
    /// Sets the encrypted data to be decrypted
    /// </summary>
    /// <param name="encryptedData">The encrypted string to decrypt</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">Thrown when encryptedData is null or empty</exception>
    public IPgpFluentBuilder WithEncryptedData(string encryptedData)
    {
        if (string.IsNullOrEmpty(encryptedData))
            throw new ArgumentException("Encrypted data cannot be null or empty", nameof(encryptedData));

        _encryptedData = Encoding.UTF8.GetBytes(encryptedData);
        return this;
    }

    /// <summary>
    /// Sets the encrypted data to be decrypted
    /// </summary>
    /// <param name="encryptedData">The encrypted bytes to decrypt</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">Thrown when encryptedData is null</exception>
    public IPgpFluentBuilder WithEncryptedData(byte[] encryptedData)
    {
        _encryptedData = encryptedData ?? throw new ArgumentNullException(nameof(encryptedData));
        return this;
    }

    /// <summary>
    /// Sets the PGP public key for encryption
    /// </summary>
    /// <param name="publicKey">The PGP public key in ASCII-armored format</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">Thrown when publicKey is null</exception>
    public IPgpFluentBuilder WithPublicKey(string publicKey)
    {
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        return this;
    }

    /// <summary>
    /// Sets the PGP private key for decryption
    /// </summary>
    /// <param name="privateKey">The PGP private key in ASCII-armored format</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKey is null</exception>
    public IPgpFluentBuilder WithPrivateKey(string privateKey)
    {
        _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        return this;
    }

    /// <summary>
    /// Sets the identity (email or name) for key pair generation
    /// </summary>
    /// <param name="identity">The identity to associate with the key pair (typically an email address)</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">Thrown when identity is null</exception>
    public IPgpFluentBuilder WithIdentity(string identity)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        return this;
    }

    /// <summary>
    /// Sets the passphrase for protecting the private key
    /// </summary>
    /// <param name="passphrase">The passphrase to protect the private key</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentNullException">Thrown when passphrase is null</exception>
    public IPgpFluentBuilder WithPassphrase(string passphrase)
    {
        _passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));
        return this;
    }

    /// <summary>
    /// Sets the RSA key size for key pair generation
    /// </summary>
    /// <param name="keySize">The key size in bits (1024, 2048, 3072, 4096, or 8192)</param>
    /// <returns>The builder instance for method chaining</returns>
    /// <exception cref="ArgumentException">Thrown when keySize is invalid</exception>
    public IPgpFluentBuilder WithKeySize(int keySize)
    {
        if (keySize < 1024)
            throw new ArgumentException("Key size must be at least 1024 bits", nameof(keySize));

        if (keySize > 8192)
            throw new ArgumentException("Key size cannot exceed 8192 bits", nameof(keySize));

        // Validate common key sizes
        if (keySize != 1024 && keySize != 2048 && keySize != 3072 && keySize != 4096 && keySize != 8192)
        {
            throw new ArgumentException("Key size should be one of: 1024, 2048, 3072, 4096, or 8192 bits", nameof(keySize));
        }

        _keySize = keySize;
        return this;
    }

    /// <summary>
    /// Configures the key size based on a predefined security level
    /// </summary>
    /// <param name="securityLevel">The security level (Low, Medium, High, or Military)</param>
    /// <returns>The builder instance for method chaining</returns>
    public IPgpFluentBuilder WithSecurityLevel(SecurityLevel securityLevel)
    {
        _keySize = SecurityPolicies.GetRsaKeySize(securityLevel);
        return this;
    }

    /// <summary>
    /// Enables hardware acceleration for cryptographic operations when available
    /// </summary>
    /// <returns>The builder instance for method chaining</returns>
    public IPgpFluentBuilder WithHardwareAcceleration()
    {
        _useHardwareAcceleration = true;
        return this;
    }

    /// <summary>
    /// Encrypts the data using PGP and returns the result as a string
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted data as an ASCII-armored string or Base64 string</returns>
    /// <exception cref="InvalidOperationException">Thrown when data or public key is not set</exception>
    public async Task<string> EncryptAsync(CancellationToken cancellationToken = default)
    {
        ValidateEncryption();

        var service = CreateService();

        if (_data!.Length == Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(_data)).Length)
        {
            // Data appears to be text, use text encryption
            var text = Encoding.UTF8.GetString(_data);
            return await service.EncryptTextAsync(text, _publicKey!, cancellationToken);
        }
        else
        {
            // Use binary encryption and return base64
            var encrypted = await service.EncryptAsync(_data, _publicKey!, cancellationToken);
            return Convert.ToBase64String(encrypted);
        }
    }

    /// <summary>
    /// Encrypts the data using PGP and returns the result as raw bytes
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Encrypted data as bytes</returns>
    /// <exception cref="InvalidOperationException">Thrown when data or public key is not set</exception>
    public async Task<byte[]> EncryptBytesAsync(CancellationToken cancellationToken = default)
    {
        ValidateEncryption();

        var service = CreateService();
        return await service.EncryptAsync(_data!, _publicKey!, cancellationToken);
    }

    /// <summary>
    /// Decrypts PGP encrypted data and returns the result as a string
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted plaintext as a string</returns>
    /// <exception cref="InvalidOperationException">Thrown when encrypted data or private key is not set</exception>
    public async Task<string> DecryptAsync(CancellationToken cancellationToken = default)
    {
        ValidateDecryption();

        var service = CreateService();

        try
        {
            // Try text decryption first
            var text = Encoding.UTF8.GetString(_encryptedData!);
            return await service.DecryptTextAsync(text, _privateKey!, _passphrase, cancellationToken);
        }
        catch
        {
            // Fall back to binary decryption
            var decrypted = await service.DecryptAsync(_encryptedData!, _privateKey!, _passphrase, cancellationToken);
            return Encoding.UTF8.GetString(decrypted);
        }
    }

    /// <summary>
    /// Decrypts PGP encrypted data and returns the result as raw bytes
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Decrypted plaintext as bytes</returns>
    /// <exception cref="InvalidOperationException">Thrown when encrypted data or private key is not set</exception>
    public async Task<byte[]> DecryptBytesAsync(CancellationToken cancellationToken = default)
    {
        ValidateDecryption();

        var service = CreateService();
        return await service.DecryptAsync(_encryptedData!, _privateKey!, _passphrase, cancellationToken);
    }

    /// <summary>
    /// Generates a new PGP key pair with the configured parameters
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Generated PGP key pair containing public and private keys</returns>
    public async Task<KeyPair> GenerateKeyPairAsync(CancellationToken cancellationToken = default)
    {
        ValidateKeyGeneration();

        var service = CreateService();

        if (!string.IsNullOrEmpty(_identity) && !string.IsNullOrEmpty(_passphrase))
        {
            return await service.GenerateKeyPairAsync(_identity!, _passphrase!, _keySize, cancellationToken);
        }
        else if (!string.IsNullOrEmpty(_identity))
        {
            return await service.GenerateKeyPairAsync(_identity!, string.Empty, _keySize, cancellationToken);
        }
        else
        {
            return await service.GenerateKeyPairAsync(_keySize, cancellationToken);
        }
    }

    private void ValidateEncryption()
    {
        if (_data == null)
            throw new InvalidOperationException("Data must be set before encryption");

        if (string.IsNullOrEmpty(_publicKey))
            throw new InvalidOperationException("Public key must be set before encryption");
    }

    private void ValidateDecryption()
    {
        if (_encryptedData == null)
            throw new InvalidOperationException("Encrypted data must be set before decryption");

        if (string.IsNullOrEmpty(_privateKey))
            throw new InvalidOperationException("Private key must be set before decryption");
    }

    private static void ValidateKeyGeneration()
    {
        // Key generation is always valid with default parameters
        // Identity and passphrase are optional
    }

    private static PgpCryptographyService CreateService()
    {
        return new PgpCryptographyService();
    }
}

