using HeroCrypt.Cryptography.Primitives.Signature.Rsa;
using HeroCrypt.Security;
using Microsoft.Extensions.Logging;
using BigInteger = HeroCrypt.Cryptography.Primitives.Signature.Rsa.BigInteger;

namespace HeroCrypt.Signatures;

/// <summary>
/// RSA digital signature service implementation
/// </summary>
public sealed class RsaDigitalSignatureService : IDigitalSignatureService
{
    private readonly ILogger<RsaDigitalSignatureService>? _logger;
    private readonly int _keySize;

    /// <summary>
    /// Initializes a new instance of the RSA digital signature service
    /// </summary>
    /// <param name="keySize">RSA key size in bits (default: 2048)</param>
    /// <param name="logger">Optional logger instance</param>
    public RsaDigitalSignatureService(
        int keySize = 2048,
        ILogger<RsaDigitalSignatureService>? logger = null)
    {
        InputValidator.ValidateRsaKeySize(keySize, nameof(keySize));

        _keySize = keySize;
        _logger = logger;

        _logger?.LogDebug("RSA Digital Signature Service initialized with {KeySize}-bit keys", keySize);
    }

    /// <inheritdoc />
    public string AlgorithmName => "RSA-SHA256";

    /// <inheritdoc />
    public int KeySizeBits => _keySize;

    /// <inheritdoc />
    public int SignatureSize => _keySize / 8; // RSA signature size equals key size in bytes

    /// <inheritdoc />
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

    /// <inheritdoc />
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

    /// <inheritdoc />
    public byte[] Sign(byte[] data, byte[] privateKey)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(privateKey);
#else
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
#endif

        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: true);
        InputValidator.ValidateByteArray(privateKey, nameof(privateKey));

        _logger?.LogDebug("Signing data with RSA private key (data size: {DataSize} bytes)", data.Length);

        try
        {
            var rsaPrivateKey = DeserializePrivateKey(privateKey);
            var signature = RsaCore.Sign(data, rsaPrivateKey);

            _logger?.LogInformation("Successfully signed data (signature size: {SignatureSize} bytes)", signature.Length);

            return signature;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to sign data with RSA private key");
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<byte[]> SignAsync(byte[] data, byte[] privateKey)
    {
        // RSA signing is CPU-bound, so we run it on a background thread
        return await Task.Run(() => Sign(data, privateKey)).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public bool Verify(byte[] signature, byte[] data, byte[] publicKey)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(publicKey);
#else
        if (signature == null) throw new ArgumentNullException(nameof(signature));
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
#endif

        InputValidator.ValidateByteArray(signature, nameof(signature));
        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: true);
        InputValidator.ValidateByteArray(publicKey, nameof(publicKey));

        _logger?.LogDebug("Verifying RSA signature (data size: {DataSize} bytes, signature size: {SignatureSize} bytes)",
            data.Length, signature.Length);

        try
        {
            var rsaPublicKey = DeserializePublicKey(publicKey);
            var isValid = RsaCore.Verify(data, signature, rsaPublicKey);

            _logger?.LogInformation("RSA signature verification result: {IsValid}", isValid);

            return isValid;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to verify RSA signature");
            return false; // Return false instead of throwing for verification failures
        }
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(byte[] signature, byte[] data, byte[] publicKey)
    {
        // RSA verification is CPU-bound, so we run it on a background thread
        return await Task.Run(() => Verify(signature, data, publicKey)).ConfigureAwait(false);
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
