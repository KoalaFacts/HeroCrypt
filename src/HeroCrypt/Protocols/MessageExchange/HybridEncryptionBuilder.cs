using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Operations;
using HeroCrypt.Protocols.KeyManagement;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.MessageExchange;

#if !NETSTANDARD2_0
/// <summary>
/// Fluent builder for hybrid encryption (RSA key exchange + AEAD symmetric encryption).
/// </summary>
/// <remarks>
/// <para>
/// This builder provides a secure hybrid encryption scheme that combines:
/// </para>
/// <list type="bullet">
///   <item><description>RSA-OAEP (SHA-256) for asymmetric key exchange</description></item>
///   <item><description>AEAD ciphers (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) for data encryption</description></item>
/// </list>
/// <para>
/// For OpenPGP (RFC 4880) compatible operations, use <c>HeroCryptBuilder.Pgp()</c> instead.
/// </para>
/// </remarks>
public class HybridEncryptionBuilder
{
    private static readonly char[] PemSeparators = ['\r', '\n'];
    private int keySize = 2048;
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;

    /// <summary>
    /// Sets the RSA key size to use for new key pairs (defaults to 2048).
    /// </summary>
    public HybridEncryptionBuilder WithKeySize(int size)
    {
        keySize = size;
        return this;
    }

    /// <summary>
    /// Sets the symmetric encryption algorithm to use for payload encryption.
    /// </summary>
    public HybridEncryptionBuilder WithEncryptionAlgorithm(EncryptionAlgorithm value)
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
    public HybridEncryptionEnvelope Encrypt(string plaintext, string publicKeyPem, byte[]? associatedData = null)
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
    public HybridEncryptionEnvelope Encrypt(byte[] data, string publicKeyPem, byte[]? associatedData = null)
    {
        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: false);

        var symmetricKey = RandomNumberGenerator.GetBytes(32);

        var encResult = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(symmetricKey)
            .WithAssociatedData(associatedData ?? [])
            .Encrypt(data);

        var encryptedKey = EncryptKeyWithRsa(symmetricKey, publicKeyPem);

        return new HybridEncryptionEnvelope
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
    /// Decrypts a hybrid encryption envelope to UTF-8 text using the provided RSA private key.
    /// </summary>
    public static string DecryptToString(HybridEncryptionEnvelope envelope, string privateKeyPem)
    {
        var data = DecryptToBytes(envelope, privateKeyPem);
        return Encoding.UTF8.GetString(data);
    }

    /// <summary>
    /// Decrypts a hybrid encryption envelope to raw bytes using the provided RSA private key.
    /// </summary>
    public static byte[] DecryptToBytes(HybridEncryptionEnvelope envelope, string privateKeyPem)
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
            .Decrypt(ciphertext);
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
        var lines = pem.Split(PemSeparators, StringSplitOptions.RemoveEmptyEntries)
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
/// <remarks>
/// This envelope contains all the data needed to decrypt a message:
/// the encrypted symmetric key (wrapped with RSA), the ciphertext,
/// the nonce/IV, and optional associated data for AEAD authentication.
/// </remarks>
public class HybridEncryptionEnvelope
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
