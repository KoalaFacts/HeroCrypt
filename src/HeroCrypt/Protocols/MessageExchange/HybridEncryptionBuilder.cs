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
/// <para>
/// This custom envelope is not HPKE and does not authenticate the sender or prevent replay.
/// Recipients must check associated data against their expected application context.
/// <see cref="HybridEncryptionEnvelope.IsText"/> is an unauthenticated display hint.
/// </para>
/// </remarks>
public class HybridEncryptionBuilder
{
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
        ValidateAlgorithm(value);
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
        var privateDer = rsa.ExportPkcs8PrivateKey();
        try
        {
            return new KeyPair(publicKey, ToPem("PRIVATE KEY", privateDer));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateDer);
        }
    }

    /// <summary>
    /// Encrypts UTF-8 text using a hybrid RSA + AEAD scheme and returns a portable envelope.
    /// </summary>
    public HybridEncryptionEnvelope Encrypt(string plaintext, string publicKeyPem, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        var bytes = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            var envelope = Encrypt(bytes, publicKeyPem, associatedData);
            envelope.IsText = true;
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Encrypts binary data using a hybrid RSA + AEAD scheme and returns a portable envelope.
    /// </summary>
    public HybridEncryptionEnvelope Encrypt(byte[] data, string publicKeyPem, byte[]? associatedData = null)
    {
        InputValidator.ValidateByteArray(data, nameof(data), allowEmpty: false);

        var policy = SecurityPolicy.CurrentPolicy;
        policy.ValidateHash("SHA256");
        var selectedAlgorithm = algorithm;
        ValidateAlgorithm(selectedAlgorithm);
        var symmetricKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var encryptedKey = EncryptKeyWithRsa(symmetricKey, publicKeyPem);
            using var cipher = HeroCryptBuilder.Encrypt()
                .WithSecurityPolicy(policy)
                .WithAlgorithm(selectedAlgorithm)
                .WithKey(symmetricKey)
                .WithAssociatedData(associatedData ?? []);
            var encResult = cipher.Encrypt(data);
            return new HybridEncryptionEnvelope
            {
                Ciphertext = Convert.ToBase64String(encResult.Ciphertext),
                Nonce = Convert.ToBase64String(encResult.Nonce),
                EncryptedKey = Convert.ToBase64String(encryptedKey),
                AssociatedData = associatedData is null ? null : Convert.ToBase64String(associatedData),
                Algorithm = selectedAlgorithm.ToString(),
                IsText = false
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symmetricKey);
        }
    }

    /// <summary>
    /// Decrypts a hybrid encryption envelope to UTF-8 text using the provided RSA private key.
    /// </summary>
    public static string DecryptToString(HybridEncryptionEnvelope envelope, string privateKeyPem)
    {
        var data = DecryptToBytes(envelope, privateKeyPem);
        try
        {
            return Encoding.UTF8.GetString(data);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <summary>
    /// Decrypts a hybrid encryption envelope to raw bytes using the provided RSA private key.
    /// </summary>
    public static byte[] DecryptToBytes(HybridEncryptionEnvelope envelope, string privateKeyPem)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var alg = envelope.Algorithm switch
        {
            nameof(EncryptionAlgorithm.AesGcm) => EncryptionAlgorithm.AesGcm,
            nameof(EncryptionAlgorithm.ChaCha20Poly1305) => EncryptionAlgorithm.ChaCha20Poly1305,
            nameof(EncryptionAlgorithm.XChaCha20Poly1305) => EncryptionAlgorithm.XChaCha20Poly1305,
            _ => throw new ArgumentException("Envelope algorithm must name a supported AEAD cipher exactly.", nameof(envelope))
        };
        var policy = SecurityPolicy.CurrentPolicy;
        policy.ValidateHash("SHA256");
        var symmetricKey = DecryptKeyWithRsa(Convert.FromBase64String(envelope.EncryptedKey), privateKeyPem);
        try
        {
            if (symmetricKey.Length != 32)
                throw new CryptographicException("Hybrid envelopes require a 32-byte payload key.");
            var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            var nonce = Convert.FromBase64String(envelope.Nonce);
            var aad = envelope.AssociatedData is null ? [] : Convert.FromBase64String(envelope.AssociatedData);
            using var cipher = HeroCryptBuilder.Decrypt()
                .WithSecurityPolicy(policy)
                .WithAlgorithm(alg)
                .WithKey(symmetricKey)
                .WithNonce(nonce)
                .WithAssociatedData(aad);
            return cipher.Decrypt(ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symmetricKey);
        }
    }

    private static byte[] EncryptKeyWithRsa(byte[] key, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        ImportPublicPem(rsa, publicKeyPem);
        ValidateRsaKey(rsa);
        return rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
    }

    private static byte[] DecryptKeyWithRsa(byte[] encryptedKey, string privateKeyPem)
    {
        using var rsa = RSA.Create();
        ImportPrivatePem(rsa, privateKeyPem);
        ValidateRsaKey(rsa);
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
        var raw = ExtractPemContent(pem, "PUBLIC KEY");
        try
        {
            rsa.ImportSubjectPublicKeyInfo(raw, out var bytesRead);
            if (bytesRead != raw.Length)
                throw new CryptographicException("Trailing data after RSA public key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static void ImportPrivatePem(RSA rsa, string pem)
    {
        var raw = ExtractPemContent(pem, "PRIVATE KEY");
        try
        {
            rsa.ImportPkcs8PrivateKey(raw, out var bytesRead);
            if (bytesRead != raw.Length)
                throw new CryptographicException("Trailing data after RSA private key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static byte[] ExtractPemContent(string pem, string expectedLabel)
    {
        ArgumentNullException.ThrowIfNull(pem);
        var text = pem.AsSpan().Trim();
        if (!PemEncoding.TryFind(text, out var fields)
            || fields.Location.GetOffsetAndLength(text.Length) != (0, text.Length)
            || !text[fields.Label].SequenceEqual(expectedLabel.AsSpan()))
            throw new ArgumentException($"Expected exactly one {expectedLabel} PEM block.", nameof(pem));

        var raw = new byte[fields.DecodedDataLength];
        if (!Convert.TryFromBase64Chars(text[fields.Base64Data], raw, out var bytesWritten) || bytesWritten != raw.Length)
        {
            CryptographicOperations.ZeroMemory(raw);
            throw new ArgumentException("Invalid PEM base64 data.", nameof(pem));
        }
        return raw;
    }

    private static void ValidateRsaKey(RSA rsa)
    {
        if (rsa.KeySize < 2048)
            throw new CryptographicException("Hybrid envelopes require RSA keys of at least 2048 bits.");
    }

    private static void ValidateAlgorithm(EncryptionAlgorithm value)
    {
        if (value is not (EncryptionAlgorithm.AesGcm or EncryptionAlgorithm.ChaCha20Poly1305 or EncryptionAlgorithm.XChaCha20Poly1305))
            throw new ArgumentException("Hybrid RSA encryption supports AES-GCM, ChaCha20-Poly1305 and XChaCha20-Poly1305 only.", nameof(value));
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
    public string Algorithm { get; init; } = string.Empty;

    /// <summary>
    /// Unauthenticated display hint indicating whether the original payload was text.
    /// Do not use this field for authorization or content validation.
    /// </summary>
    public bool IsText { get; set; }
}
