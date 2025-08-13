using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.RSA;
using BigInteger = HeroCrypt.Cryptography.RSA.BigInteger;
#if !NET8_0_OR_GREATER
using System;
#endif

namespace HeroCrypt.Services;

internal sealed class PublicKeyData
{
    public string Identity { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public string Modulus { get; set; } = string.Empty;
    public string Exponent { get; set; } = string.Empty;
    public DateTime Created { get; set; }
}

internal sealed class PrivateKeyData
{
    public string Identity { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public string Modulus { get; set; } = string.Empty;
    public string D { get; set; } = string.Empty;
    public string P { get; set; } = string.Empty;
    public string Q { get; set; } = string.Empty;
    public string E { get; set; } = string.Empty;
    public DateTime Created { get; set; }
}

public sealed class PgpCryptographyService : ICryptographyService, IKeyGenerationService
{
    private const string PublicKeyHeader = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    private const string PublicKeyFooter = "-----END PGP PUBLIC KEY BLOCK-----";
    private const string PrivateKeyHeader = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    private const string PrivateKeyFooter = "-----END PGP PRIVATE KEY BLOCK-----";
    private const string MessageHeader = "-----BEGIN PGP MESSAGE-----";
    private const string MessageFooter = "-----END PGP MESSAGE-----";

    public async Task<byte[]> EncryptAsync(byte[] data, string publicKey, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(data);
#else
        ArgumentNullExceptionExtensions.ThrowIfNull(data, nameof(data));
#endif
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKey);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(publicKey, nameof(publicKey));
#endif

        return await Task.Run(() =>
        {
            var rsaPublicKey = ParsePublicKey(publicKey);
            
            using var aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();
            
            var encryptedSessionKey = RsaCore.Encrypt(aes.Key, rsaPublicKey);
            
            byte[] encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(data, 0, data.Length);
                }
                encryptedData = msEncrypt.ToArray();
            }
            
            var result = new List<byte>();
            
            result.AddRange(BitConverter.GetBytes(encryptedSessionKey.Length));
            result.AddRange(encryptedSessionKey);
            
            result.AddRange(BitConverter.GetBytes(aes.IV.Length));
            result.AddRange(aes.IV);
            
            result.AddRange(BitConverter.GetBytes(encryptedData.Length));
            result.AddRange(encryptedData);
            
            var pgpMessage = FormatPgpMessage(result.ToArray());
            return Encoding.UTF8.GetBytes(pgpMessage);
        }, cancellationToken);
    }

    public async Task<byte[]> DecryptAsync(byte[] encryptedData, string privateKey, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(encryptedData);
#else
        ArgumentNullExceptionExtensions.ThrowIfNull(encryptedData, nameof(encryptedData));
#endif
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKey);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(privateKey, nameof(privateKey));
#endif

        return await Task.Run(() =>
        {
            var rsaPrivateKey = ParsePrivateKey(privateKey);
            
            var pgpMessage = Encoding.UTF8.GetString(encryptedData);
            var messageData = ParsePgpMessage(pgpMessage);
            
            using var ms = new MemoryStream(messageData);
            using var reader = new BinaryReader(ms);
            
            var sessionKeyLength = reader.ReadInt32();
            var encryptedSessionKey = reader.ReadBytes(sessionKeyLength);
            
            var ivLength = reader.ReadInt32();
            var iv = reader.ReadBytes(ivLength);
            
            var encryptedContentLength = reader.ReadInt32();
            var encryptedContent = reader.ReadBytes(encryptedContentLength);
            
            var sessionKey = RsaCore.Decrypt(encryptedSessionKey, rsaPrivateKey);
            
            using var aes = Aes.Create();
            aes.Key = sessionKey;
            aes.IV = iv;
            
            using var decryptor = aes.CreateDecryptor();
            using var msDecrypt = new MemoryStream(encryptedContent);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var resultStream = new MemoryStream();
            
            csDecrypt.CopyTo(resultStream);
            return resultStream.ToArray();
        }, cancellationToken);
    }

    public async Task<string> EncryptTextAsync(string plainText, string publicKey, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(plainText);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(plainText, nameof(plainText));
#endif
        var encryptedBytes = await EncryptAsync(Encoding.UTF8.GetBytes(plainText), publicKey, cancellationToken);
        return Encoding.UTF8.GetString(encryptedBytes);
    }

    public async Task<string> DecryptTextAsync(string encryptedText, string privateKey, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedText);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(encryptedText, nameof(encryptedText));
#endif
        var decryptedBytes = await DecryptAsync(Encoding.UTF8.GetBytes(encryptedText), privateKey, cancellationToken);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public async Task<KeyPair> GenerateKeyPairAsync(int keySize = 2048, CancellationToken cancellationToken = default)
    {
        return await GenerateKeyPairAsync($"user_{Guid.NewGuid():N}", string.Empty, keySize, cancellationToken);
    }

    public async Task<KeyPair> GenerateKeyPairAsync(string identity, string passphrase, int keySize = 2048, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
#else
        ArgumentExceptionExtensions.ThrowIfNullOrWhiteSpace(identity, nameof(identity));
#endif
        
        return await Task.Run(() =>
        {
            var rsaKeyPair = RsaCore.GenerateKeyPair(keySize);
            
            var publicKeyData = new PublicKeyData
            {
                Identity = identity,
                KeySize = keySize,
                Modulus = Convert.ToBase64String(rsaKeyPair.PublicKey.Modulus.ToByteArray()),
                Exponent = Convert.ToBase64String(rsaKeyPair.PublicKey.Exponent.ToByteArray()),
                Created = DateTime.UtcNow
            };
            
            var privateKeyData = new PrivateKeyData
            {
                Identity = identity,
                KeySize = keySize,
                Modulus = Convert.ToBase64String(rsaKeyPair.PrivateKey.Modulus.ToByteArray()),
                D = Convert.ToBase64String(rsaKeyPair.PrivateKey.D.ToByteArray()),
                P = Convert.ToBase64String(rsaKeyPair.PrivateKey.P.ToByteArray()),
                Q = Convert.ToBase64String(rsaKeyPair.PrivateKey.Q.ToByteArray()),
                E = Convert.ToBase64String(rsaKeyPair.PrivateKey.E.ToByteArray()),
                Created = DateTime.UtcNow
            };
            
            var publicKeyString = FormatPublicKey(publicKeyData);
            var privateKeyString = FormatPrivateKey(privateKeyData, passphrase);
            
            return new KeyPair(publicKeyString, privateKeyString);
        }, cancellationToken);
    }

    private static string FormatPublicKey(PublicKeyData keyData)
    {
        var sb = new StringBuilder();
        sb.AppendLine(PublicKeyHeader);
        sb.AppendLine();
        sb.AppendLine($"Identity: {keyData.Identity}");
        sb.AppendLine($"Created: {keyData.Created:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"KeySize: {keyData.KeySize}");
        sb.AppendLine();
        sb.AppendLine($"Modulus: {keyData.Modulus}");
        sb.AppendLine($"Exponent: {keyData.Exponent}");
        sb.AppendLine();
        sb.AppendLine(PublicKeyFooter);
        return sb.ToString();
    }

    private static string FormatPrivateKey(PrivateKeyData keyData, string passphrase)
    {
        var sb = new StringBuilder();
        sb.AppendLine(PrivateKeyHeader);
        sb.AppendLine();
        sb.AppendLine($"Identity: {keyData.Identity}");
        sb.AppendLine($"Created: {keyData.Created:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"KeySize: {keyData.KeySize}");
        sb.AppendLine();
        
        if (!string.IsNullOrEmpty(passphrase))
        {
            var keyContent = $"{keyData.Modulus}|{keyData.D}|{keyData.P}|{keyData.Q}|{keyData.E}";
            var encrypted = EncryptWithPassphrase(keyContent, passphrase);
            sb.AppendLine($"Encrypted: true");
            sb.AppendLine($"Data: {encrypted}");
        }
        else
        {
            sb.AppendLine($"Modulus: {keyData.Modulus}");
            sb.AppendLine($"D: {keyData.D}");
            sb.AppendLine($"P: {keyData.P}");
            sb.AppendLine($"Q: {keyData.Q}");
            sb.AppendLine($"E: {keyData.E}");
        }
        
        sb.AppendLine();
        sb.AppendLine(PrivateKeyFooter);
        return sb.ToString();
    }

    private static string FormatPgpMessage(byte[] data)
    {
        var sb = new StringBuilder();
        sb.AppendLine(MessageHeader);
        sb.AppendLine();
        
        var base64 = Convert.ToBase64String(data);
        for (var i = 0; i < base64.Length; i += 64)
        {
            sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
        }
        
        sb.AppendLine();
        sb.AppendLine(MessageFooter);
        return sb.ToString();
    }

    private static byte[] ParsePgpMessage(string pgpMessage)
    {
        var lines = pgpMessage.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        var dataLines = new List<string>();
        var inData = false;
        
        foreach (var line in lines)
        {
            if (line.Trim() == MessageHeader)
            {
                inData = true;
                continue;
            }
            if (line.Trim() == MessageFooter)
            {
                break;
            }
            if (inData && !string.IsNullOrWhiteSpace(line))
            {
                dataLines.Add(line.Trim());
            }
        }
        
        var base64 = string.Join("", dataLines);
        return Convert.FromBase64String(base64);
    }

    private static RsaPublicKey ParsePublicKey(string publicKeyString)
    {
        var lines = publicKeyString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        string? modulus = null;
        string? exponent = null;
        
        foreach (var line in lines)
        {
            if (line.StartsWith("Modulus:"))
                modulus = line.Substring("Modulus:".Length).Trim();
            else if (line.StartsWith("Exponent:"))
                exponent = line.Substring("Exponent:".Length).Trim();
        }
        
        if (modulus == null || exponent == null)
            throw new ArgumentException("Invalid public key format");
        
        return new RsaPublicKey(
            new BigInteger(Convert.FromBase64String(modulus)),
            new BigInteger(Convert.FromBase64String(exponent)));
    }

    private static RsaPrivateKey ParsePrivateKey(string privateKeyString)
    {
        var lines = privateKeyString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        string? modulus = null;
        string? d = null;
        string? p = null;
        string? q = null;
        string? e = null;
        
        foreach (var line in lines)
        {
            if (line.StartsWith("Modulus:"))
                modulus = line.Substring("Modulus:".Length).Trim();
            else if (line.StartsWith("D:"))
                d = line.Substring("D:".Length).Trim();
            else if (line.StartsWith("P:"))
                p = line.Substring("P:".Length).Trim();
            else if (line.StartsWith("Q:"))
                q = line.Substring("Q:".Length).Trim();
            else if (line.StartsWith("E:"))
                e = line.Substring("E:".Length).Trim();
        }
        
        if (modulus == null || d == null || p == null || q == null || e == null)
            throw new ArgumentException("Invalid private key format");
        
        return new RsaPrivateKey(
            new BigInteger(Convert.FromBase64String(modulus)),
            new BigInteger(Convert.FromBase64String(d)),
            new BigInteger(Convert.FromBase64String(p)),
            new BigInteger(Convert.FromBase64String(q)),
            new BigInteger(Convert.FromBase64String(e)));
    }

    private static string EncryptWithPassphrase(string data, string passphrase)
    {
        using var aes = Aes.Create();
        using var sha256 = SHA256.Create();
        
        aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();
        
        ms.Write(aes.IV, 0, aes.IV.Length);
        
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            var dataBytes = Encoding.UTF8.GetBytes(data);
            cs.Write(dataBytes, 0, dataBytes.Length);
        }
        
        return Convert.ToBase64String(ms.ToArray());
    }
}