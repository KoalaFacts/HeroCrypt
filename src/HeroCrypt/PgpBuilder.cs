using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Encryption;
using HeroCrypt.KeyManagement;
using HeroCrypt.Security;

namespace HeroCrypt;

#if !NETSTANDARD2_0
/// <summary>
/// Fluent builder for simplified PGP-style hybrid encryption (RSA + AEAD).
/// </summary>
public class PgpBuilder
{
    private static readonly char[] pemSeparators = ['\r', '\n'];
    private int keySize = 2048;
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;

    /// <summary>
    /// Sets the RSA key size to use for new key pairs (defaults to 2048).
    /// </summary>
    public PgpBuilder WithKeySize(int size)
    {
        keySize = size;
        return this;
    }

    /// <summary>
    /// Sets the symmetric encryption algorithm to use for payload encryption.
    /// </summary>
    public PgpBuilder WithEncryptionAlgorithm(EncryptionAlgorithm value)
    {
        algorithm = value;
        return this;
    }

    /// <summary>
    /// Generates an RSA key pair encoded as PEM strings.
    /// </summary>
    public KeyPair GenerateRsaKeyPair()
    {
        if (keySize < 2048 || keySize % 8 != 0)
        {
            throw new ArgumentException("RSA key size must be a multiple of 8 and at least 2048 bits.", nameof(keySize));
        }

        using var rsa = RSA.Create(keySize);
        var publicKey = ToPem("PUBLIC KEY", rsa.ExportSubjectPublicKeyInfo());
        var privateKey = ToPem("PRIVATE KEY", rsa.ExportPkcs8PrivateKey());
        return new KeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Encrypts UTF-8 text using a hybrid RSA + AEAD scheme and returns a portable envelope.
    /// </summary>
    public PgpEnvelope Encrypt(string plaintext, string publicKeyPem, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var envelope = Encrypt(bytes, publicKeyPem, associatedData);
        envelope.IsText = true;
        return envelope;
    }

    /// <summary>
    /// Encrypts binary data using a hybrid RSA + AEAD scheme and returns a portable envelope.
    /// </summary>
    public PgpEnvelope Encrypt(byte[] data, string publicKeyPem, byte[]? associatedData = null)
    {
        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: false);

        var symmetricKey = RandomNumberGenerator.GetBytes(32);

        var encResult = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(symmetricKey)
            .WithAssociatedData(associatedData ?? [])
            .Build(data);

        var encryptedKey = EncryptKeyWithRsa(symmetricKey, publicKeyPem);

        return new PgpEnvelope
        {
            Ciphertext = Convert.ToBase64String(encResult.Ciphertext),
            Nonce = Convert.ToBase64String(encResult.Nonce),
            EncryptedKey = Convert.ToBase64String(encryptedKey),
            AssociatedData = associatedData is null ? null : Convert.ToBase64String(associatedData),
            Algorithm = algorithm.ToString(),
            IsText = false
        };
    }

    /// <summary>
    /// Decrypts a PGP envelope to UTF-8 text using the provided RSA private key.
    /// </summary>
    public static string DecryptToString(PgpEnvelope envelope, string privateKeyPem)
    {
        var data = DecryptToBytes(envelope, privateKeyPem);
        return Encoding.UTF8.GetString(data);
    }

    /// <summary>
    /// Decrypts a PGP envelope to raw bytes using the provided RSA private key.
    /// </summary>
    public static byte[] DecryptToBytes(PgpEnvelope envelope, string privateKeyPem)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        var symmetricKey = DecryptKeyWithRsa(Convert.FromBase64String(envelope.EncryptedKey), privateKeyPem);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var nonce = Convert.FromBase64String(envelope.Nonce);
        var aad = envelope.AssociatedData is null ? [] : Convert.FromBase64String(envelope.AssociatedData);

        var alg = Enum.TryParse<EncryptionAlgorithm>(envelope.Algorithm, out var parsed) ? parsed : EncryptionAlgorithm.AesGcm;

        return HeroCryptBuilder.Decrypt()
            .WithAlgorithm(alg)
            .WithKey(symmetricKey)
            .WithNonce(nonce)
            .WithAssociatedData(aad)
            .Build(ciphertext);
    }

    private static byte[] EncryptKeyWithRsa(byte[] key, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        ImportPublicPem(rsa, publicKeyPem);
        return rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
    }

    private static byte[] DecryptKeyWithRsa(byte[] encryptedKey, string privateKeyPem)
    {
        using var rsa = RSA.Create();
        ImportPrivatePem(rsa, privateKeyPem);
        return rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
    }

    private static string ToPem(string header, byte[] data)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN " + header + "-----");
        builder.AppendLine(Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END " + header + "-----");
        return builder.ToString();
    }

    private static void ImportPublicPem(RSA rsa, string pem)
    {
        var raw = ExtractPemContent(pem);
        rsa.ImportSubjectPublicKeyInfo(raw, out _);
    }

    private static void ImportPrivatePem(RSA rsa, string pem)
    {
        var raw = ExtractPemContent(pem);
        rsa.ImportPkcs8PrivateKey(raw, out _);
    }

    private static byte[] ExtractPemContent(string pem)
    {
        var lines = pem.Split(pemSeparators, StringSplitOptions.RemoveEmptyEntries)
            .Where(l => !l.StartsWith("-----", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var base64 = string.Concat(lines);
        return Convert.FromBase64String(base64);
    }
}
#endif

/// <summary>
/// Represents a portable hybrid-encryption envelope (ciphertext + RSA-wrapped key).
/// </summary>
public class PgpEnvelope
{
    /// <summary>
    /// Base64-encoded ciphertext bytes.
    /// </summary>
    public string Ciphertext { get; init; } = string.Empty;

    /// <summary>
    /// Base64-encoded nonce/IV used for the symmetric cipher.
    /// </summary>
    public string Nonce { get; init; } = string.Empty;

    /// <summary>
    /// Base64-encoded RSA-encrypted symmetric key.
    /// </summary>
    public string EncryptedKey { get; init; } = string.Empty;

    /// <summary>
    /// Optional base64-encoded associated data used during encryption.
    /// </summary>
    public string? AssociatedData { get; init; }

    /// <summary>
    /// Name of the symmetric algorithm used (from <see cref="EncryptionAlgorithm" />).
    /// </summary>
    public string Algorithm { get; init; } = EncryptionAlgorithm.AesGcm.ToString();

    /// <summary>
    /// Indicates whether the original payload was text.
    /// </summary>
    public bool IsText { get; set; }
}
