using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Signature.Rsa;
using HeroCrypt.KeyManagement;
using BigInteger = HeroCrypt.Cryptography.Primitives.Signature.Rsa.BigInteger;

namespace HeroCrypt.Encryption;

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

/// <summary>
/// PGP-compatible cryptography service that uses RSA for key encapsulation and AES for data encryption.
/// </summary>
public sealed class PgpCryptographyService : ICryptographyService, IPgpKeyGenerator
{
    private const string PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    private const string PUBLIC_KEY_FOOTER = "-----END PGP PUBLIC KEY BLOCK-----";
    private const string PRIVATE_KEY_HEADER = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    private const string PRIVATE_KEY_FOOTER = "-----END PGP PRIVATE KEY BLOCK-----";
    private const string MESSAGE_HEADER = "-----BEGIN PGP MESSAGE-----";
    private const string MESSAGE_FOOTER = "-----END PGP MESSAGE-----";

    private static readonly char[] _lineSeparators = { '\n' };

    /// <summary>
    /// Encrypts data using PGP-compatible encryption with RSA and AES.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="publicKey">The PGP public key in ASCII-armored format.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The encrypted data in PGP message format.</returns>
    /// <exception cref="ArgumentNullException">Thrown when data is null.</exception>
    /// <exception cref="ArgumentException">Thrown when publicKey is null or whitespace.</exception>
    public async Task<byte[]> EncryptAsync(byte[] data, string publicKey, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(data);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKey);
#else
        if (data == null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        if (string.IsNullOrWhiteSpace(publicKey))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(publicKey));
        }
#endif

        return await Task.Run(() =>
        {
            var rsaPublicKey = ParsePublicKey(publicKey);

            using var aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();

            var keyBuffer = new byte[aes.Key.Length];
            Array.Copy(aes.Key, keyBuffer, aes.Key.Length);

            try
            {
                var encryptedSessionKey = RsaCore.Encrypt(keyBuffer, rsaPublicKey);

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

                ZeroMemory(aes.Key);
                ZeroMemory(keyBuffer);

                return CombineEncryptedComponents(encryptedSessionKey, aes.IV, encryptedData);
            }
            finally
            {
                if (aes.Key != null)
                {
                    ZeroMemory(aes.Key);
                }
                ZeroMemory(keyBuffer);
            }
        }, cancellationToken);
    }

    private static byte[] CombineEncryptedComponents(byte[] encryptedSessionKey, byte[] iv, byte[] encryptedData)
    {
        var result = new List<byte>();

        result.AddRange(BitConverter.GetBytes(encryptedSessionKey.Length));
        result.AddRange(encryptedSessionKey);

        result.AddRange(BitConverter.GetBytes(iv.Length));
        result.AddRange(iv);

        result.AddRange(BitConverter.GetBytes(encryptedData.Length));
        result.AddRange(encryptedData);

        var pgpMessage = FormatPgpMessage(result.ToArray());
        return Encoding.UTF8.GetBytes(pgpMessage);
    }

    /// <summary>
    /// Decrypts PGP-encrypted data using the provided private key.
    /// </summary>
    /// <param name="encryptedData">The encrypted data in PGP message format.</param>
    /// <param name="privateKey">The PGP private key in ASCII-armored format.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The decrypted data.</returns>
    public Task<byte[]> DecryptAsync(byte[] encryptedData, string privateKey, CancellationToken cancellationToken = default)
    {
        return DecryptAsync(encryptedData, privateKey, passphrase: null, cancellationToken);
    }

    /// <summary>
    /// Decrypts PGP-encrypted data using the provided private key and optional passphrase.
    /// </summary>
    /// <param name="encryptedData">The encrypted data in PGP message format.</param>
    /// <param name="privateKey">The PGP private key in ASCII-armored format.</param>
    /// <param name="passphrase">Optional passphrase to decrypt the private key (not currently implemented).</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The decrypted data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when encryptedData is null.</exception>
    /// <exception cref="ArgumentException">Thrown when privateKey is null or whitespace.</exception>
    public async Task<byte[]> DecryptAsync(byte[] encryptedData, string privateKey, string? passphrase, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKey);
#else
        if (encryptedData == null)
        {
            throw new ArgumentNullException(nameof(encryptedData));
        }
        if (string.IsNullOrWhiteSpace(privateKey))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(privateKey));
        }
#endif

        return await Task.Run(() =>
        {
            var rsaPrivateKey = ParsePrivateKey(privateKey, passphrase);

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
            var result = resultStream.ToArray();
            ZeroMemory(sessionKey);
            if (aes.Key != null)
            {
                ZeroMemory(aes.Key);
            }
            return result;
        }, cancellationToken);
    }

    /// <summary>
    /// Encrypts text using PGP-compatible encryption and returns ASCII-armored format.
    /// </summary>
    /// <param name="plainText">The plaintext to encrypt.</param>
    /// <param name="publicKey">The PGP public key in ASCII-armored format.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The encrypted text in ASCII-armored PGP message format.</returns>
    public async Task<string> EncryptTextAsync(string plainText, string publicKey, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentException.ThrowIfNullOrWhiteSpace(plainText);
#else
        if (string.IsNullOrWhiteSpace(plainText))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(plainText));
        }
#endif
        var encryptedBytes = await EncryptAsync(Encoding.UTF8.GetBytes(plainText), publicKey, cancellationToken);
        return Encoding.UTF8.GetString(encryptedBytes);
    }

    /// <summary>
    /// Decrypts PGP-encrypted text using the provided private key.
    /// </summary>
    /// <param name="encryptedText">The encrypted text in ASCII-armored PGP message format.</param>
    /// <param name="privateKey">The PGP private key in ASCII-armored format.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The decrypted plaintext.</returns>
    public Task<string> DecryptTextAsync(string encryptedText, string privateKey, CancellationToken cancellationToken = default)
    {
        return DecryptTextAsync(encryptedText, privateKey, passphrase: null, cancellationToken);
    }

    /// <summary>
    /// Decrypts PGP-encrypted text using the provided private key and optional passphrase.
    /// </summary>
    /// <param name="encryptedText">The encrypted text in ASCII-armored PGP message format.</param>
    /// <param name="privateKey">The PGP private key in ASCII-armored format.</param>
    /// <param name="passphrase">Optional passphrase to decrypt the private key (not currently implemented).</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The decrypted plaintext.</returns>
    public async Task<string> DecryptTextAsync(string encryptedText, string privateKey, string? passphrase, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedText);
#else
        if (string.IsNullOrWhiteSpace(encryptedText))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(encryptedText));
        }
#endif
        var decryptedBytes = await DecryptAsync(Encoding.UTF8.GetBytes(encryptedText), privateKey, passphrase, cancellationToken);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    /// <summary>
    /// Generates a new PGP-compatible RSA key pair with a random user identity.
    /// </summary>
    /// <param name="keySize">The size of the RSA key in bits (default: 2048).</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A <see cref="KeyPair"/> containing the generated public and private keys in ASCII-armored format.</returns>
    public async Task<KeyPair> GenerateKeyPairAsync(int keySize = 2048, CancellationToken cancellationToken = default)
    {
        return await GenerateKeyPairAsync($"user_{Guid.NewGuid():N}", string.Empty, keySize, cancellationToken);
    }

    /// <summary>
    /// Generates a new PGP-compatible RSA key pair with identity and passphrase.
    /// </summary>
    /// <param name="identity">The user identity to associate with the key.</param>
    /// <param name="passphrase">The passphrase to encrypt the private key (currently not used in key generation).</param>
    /// <param name="keySize">The size of the RSA key in bits (default: 2048).</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A <see cref="KeyPair"/> containing the generated public and private keys in ASCII-armored format.</returns>
    /// <exception cref="ArgumentException">Thrown when identity is null or whitespace.</exception>
    public async Task<KeyPair> GenerateKeyPairAsync(string identity, string passphrase, int keySize = 2048, CancellationToken cancellationToken = default)
    {
#if !NETSTANDARD2_0
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
#else
        if (string.IsNullOrWhiteSpace(identity))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(identity));
        }
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
        sb.AppendLine(PUBLIC_KEY_HEADER);
        sb.AppendLine();
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Identity: {0}", keyData.Identity));
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Created: {0:yyyy-MM-dd HH:mm:ss} UTC", keyData.Created));
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "KeySize: {0}", keyData.KeySize));
        sb.AppendLine();
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Modulus: {0}", keyData.Modulus));
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Exponent: {0}", keyData.Exponent));
        sb.AppendLine();
        sb.AppendLine(PUBLIC_KEY_FOOTER);
        return sb.ToString();
    }

    private static string FormatPrivateKey(PrivateKeyData keyData, string passphrase)
    {
        var sb = new StringBuilder();
        sb.AppendLine(PRIVATE_KEY_HEADER);
        sb.AppendLine();
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Identity: {0}", keyData.Identity));
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Created: {0:yyyy-MM-dd HH:mm:ss} UTC", keyData.Created));
        sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "KeySize: {0}", keyData.KeySize));
        sb.AppendLine();

        if (!string.IsNullOrEmpty(passphrase))
        {
            var keyContent = $"{keyData.Modulus}|{keyData.D}|{keyData.P}|{keyData.Q}|{keyData.E}";
            var encrypted = EncryptWithPassphrase(keyContent, passphrase);
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Encrypted: {0}", "true"));
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Data: {0}", encrypted));
        }
        else
        {
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Modulus: {0}", keyData.Modulus));
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "D: {0}", keyData.D));
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "P: {0}", keyData.P));
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Q: {0}", keyData.Q));
            sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "E: {0}", keyData.E));
        }

        sb.AppendLine();
        sb.AppendLine(PRIVATE_KEY_FOOTER);
        return sb.ToString();
    }

    private static string FormatPgpMessage(byte[] data)
    {
        var sb = new StringBuilder();
        sb.AppendLine(MESSAGE_HEADER);
        sb.AppendLine();

        var base64 = Convert.ToBase64String(data);
        for (var i = 0; i < base64.Length; i += 64)
        {
            sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
        }

        sb.AppendLine();
        sb.AppendLine(MESSAGE_FOOTER);
        return sb.ToString();
    }

    private static byte[] ParsePgpMessage(string pgpMessage)
    {
        var lines = pgpMessage.Split(_lineSeparators, StringSplitOptions.RemoveEmptyEntries);
        var dataLines = new List<string>();
        var inData = false;

        foreach (var line in lines)
        {
            if (line.Trim() == MESSAGE_HEADER)
            {
                inData = true;
                continue;
            }
            if (line.Trim() == MESSAGE_FOOTER)
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
        var lines = publicKeyString.Split(_lineSeparators, StringSplitOptions.RemoveEmptyEntries);
        string? modulus = null;
        string? exponent = null;

        foreach (var line in lines)
        {
            if (line.StartsWith("Modulus:", StringComparison.Ordinal))
            {
                modulus = line.Substring("Modulus:".Length).Trim();
            }
            else if (line.StartsWith("Exponent:", StringComparison.Ordinal))
            {
                exponent = line.Substring("Exponent:".Length).Trim();
            }
        }

        if (modulus == null || exponent == null)
        {
            throw new ArgumentException("Invalid public key format");
        }

        return new RsaPublicKey(
            new BigInteger(Convert.FromBase64String(modulus)),
            new BigInteger(Convert.FromBase64String(exponent)));
    }

    private static RsaPrivateKey ParsePrivateKey(string privateKeyString, string? passphrase)
    {
        var lines = privateKeyString.Split(_lineSeparators, StringSplitOptions.RemoveEmptyEntries);
        string? modulus = null;
        string? d = null;
        string? p = null;
        string? q = null;
        string? e = null;
        var encrypted = false;
        string? encryptedPayload = null;

        foreach (var line in lines)
        {
            if (line.StartsWith("Encrypted:", StringComparison.Ordinal))
            {
                var value = line.Substring("Encrypted:".Length).Trim();
                encrypted = bool.TryParse(value, out var parsed) && parsed;
            }
            else if (line.StartsWith("Data:", StringComparison.Ordinal))
            {
                encryptedPayload = line.Substring("Data:".Length).Trim();
            }
            else if (line.StartsWith("Modulus:", StringComparison.Ordinal))
            {
                modulus = line.Substring("Modulus:".Length).Trim();
            }
            else if (line.StartsWith("D:", StringComparison.Ordinal))
            {
                d = line.Substring("D:".Length).Trim();
            }
            else if (line.StartsWith("P:", StringComparison.Ordinal))
            {
                p = line.Substring("P:".Length).Trim();
            }
            else if (line.StartsWith("Q:", StringComparison.Ordinal))
            {
                q = line.Substring("Q:".Length).Trim();
            }
            else if (line.StartsWith("E:", StringComparison.Ordinal))
            {
                e = line.Substring("E:".Length).Trim();
            }
        }

        if (encrypted)
        {
            if (string.IsNullOrEmpty(encryptedPayload))
            {
                throw new ArgumentException("Invalid private key format");
            }
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new ArgumentException("Passphrase is required for encrypted private keys.", nameof(passphrase));
            }

            string decryptedContent;
            try
            {
                // encryptedPayload and passphrase are checked above, safe to use
                decryptedContent = DecryptWithPassphrase(encryptedPayload!, passphrase!);
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Invalid passphrase for encrypted private key.", nameof(passphrase), ex);
            }

            var parts = decryptedContent.Split('|');
            if (parts.Length != 5)
            {
                throw new ArgumentException("Invalid encrypted private key data.");
            }

            modulus = parts[0];
            d = parts[1];
            p = parts[2];
            q = parts[3];
            e = parts[4];
        }

        if (modulus == null || d == null || p == null || q == null || e == null)
        {
            throw new ArgumentException("Invalid private key format");
        }

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
        var key = DerivePassphraseKey(passphrase);
        try
        {
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                var dataBytes = Encoding.UTF8.GetBytes(data);
                cs.Write(dataBytes, 0, dataBytes.Length);
                ZeroMemory(dataBytes);
            }

            return Convert.ToBase64String(ms.ToArray());
        }
        finally
        {
            ZeroMemory(key);
            if (aes.Key != null)
            {
                ZeroMemory(aes.Key);
            }
        }
    }

    private static string DecryptWithPassphrase(string encryptedData, string passphrase)
    {
        using var aes = Aes.Create();
        var buffer = Convert.FromBase64String(encryptedData);
        var ivLength = aes.BlockSize / 8;

        if (buffer.Length < ivLength)
        {
            throw new ArgumentException("Invalid encrypted private key data.", nameof(encryptedData));
        }

        var iv = new byte[ivLength];
        Array.Copy(buffer, 0, iv, 0, ivLength);
        var cipher = new byte[buffer.Length - ivLength];
        Array.Copy(buffer, ivLength, cipher, 0, cipher.Length);

        var key = DerivePassphraseKey(passphrase);
        try
        {
            aes.Key = key;
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            using var ms = new MemoryStream(cipher);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var reader = new StreamReader(cs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: false);
            return reader.ReadToEnd();
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Invalid passphrase for encrypted private key.", nameof(passphrase), ex);
        }
        finally
        {
            ZeroMemory(key);
            if (aes.Key != null)
            {
                ZeroMemory(aes.Key);
            }
        }
    }

    private static byte[] DerivePassphraseKey(string passphrase)
    {
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
#if NET5_0_OR_GREATER
            return SHA256.HashData(passphraseBytes);
#else
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(passphraseBytes);
#endif
        }
        finally
        {
            ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>
    /// Zero out memory to prevent key material leakage
    /// </summary>
    private static void ZeroMemory(byte[] data)
    {
        if (data != null)
        {
            Array.Clear(data, 0, data.Length);
        }
    }
}



