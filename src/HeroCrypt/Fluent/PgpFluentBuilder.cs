using System.Text;
using Microsoft.Extensions.Options;
using HeroCrypt.Abstractions;
using HeroCrypt.Configuration;
using HeroCrypt.Services;

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

    public PgpFluentBuilder(IOptions<HeroCryptOptions> options, IHardwareAccelerator hardwareAccelerator)
    {
        _options = options.Value;
        _hardwareAccelerator = hardwareAccelerator;
        _keySize = _options.DefaultRsaKeySize;
        _useHardwareAcceleration = _options.EnableHardwareAcceleration;
    }

    public IPgpFluentBuilder WithData(string data)
    {
        if (string.IsNullOrEmpty(data))
            throw new ArgumentException("Data cannot be null or empty", nameof(data));

        _data = Encoding.UTF8.GetBytes(data);
        return this;
    }

    public IPgpFluentBuilder WithData(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        return this;
    }

    public IPgpFluentBuilder WithEncryptedData(string encryptedData)
    {
        if (string.IsNullOrEmpty(encryptedData))
            throw new ArgumentException("Encrypted data cannot be null or empty", nameof(encryptedData));

        _encryptedData = Encoding.UTF8.GetBytes(encryptedData);
        return this;
    }

    public IPgpFluentBuilder WithEncryptedData(byte[] encryptedData)
    {
        _encryptedData = encryptedData ?? throw new ArgumentNullException(nameof(encryptedData));
        return this;
    }

    public IPgpFluentBuilder WithPublicKey(string publicKey)
    {
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        return this;
    }

    public IPgpFluentBuilder WithPrivateKey(string privateKey)
    {
        _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        return this;
    }

    public IPgpFluentBuilder WithIdentity(string identity)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        return this;
    }

    public IPgpFluentBuilder WithPassphrase(string passphrase)
    {
        _passphrase = passphrase ?? throw new ArgumentNullException(nameof(passphrase));
        return this;
    }

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

    public IPgpFluentBuilder WithSecurityLevel(SecurityLevel securityLevel)
    {
        _keySize = SecurityPolicies.GetRsaKeySize(securityLevel);
        return this;
    }

    public IPgpFluentBuilder WithHardwareAcceleration()
    {
        _useHardwareAcceleration = true;
        return this;
    }

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

    public async Task<byte[]> EncryptBytesAsync(CancellationToken cancellationToken = default)
    {
        ValidateEncryption();

        var service = CreateService();
        return await service.EncryptAsync(_data!, _publicKey!, cancellationToken);
    }

    public async Task<string> DecryptAsync(CancellationToken cancellationToken = default)
    {
        ValidateDecryption();

        var service = CreateService();
        
        try
        {
            // Try text decryption first
            var text = Encoding.UTF8.GetString(_encryptedData!);
            return await service.DecryptTextAsync(text, _privateKey!, cancellationToken);
        }
        catch
        {
            // Fall back to binary decryption
            var decrypted = await service.DecryptAsync(_encryptedData!, _privateKey!, cancellationToken);
            return Encoding.UTF8.GetString(decrypted);
        }
    }

    public async Task<byte[]> DecryptBytesAsync(CancellationToken cancellationToken = default)
    {
        ValidateDecryption();

        var service = CreateService();
        return await service.DecryptAsync(_encryptedData!, _privateKey!, cancellationToken);
    }

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