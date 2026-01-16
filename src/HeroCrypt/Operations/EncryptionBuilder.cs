using System.Security.Cryptography;
using HeroCrypt.Primitives.AesCcm;
using HeroCrypt.Primitives.AesGcm;
using HeroCrypt.Primitives.AesOcb;
using HeroCrypt.Primitives.AesSiv;
using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Primitives.XChaCha20Poly1305;
using HeroCrypt.Security;
#if NET10_OR_GREATER
using HeroCrypt.Primitives.MLKem;
#endif

namespace HeroCrypt.Operations;

/// <summary>
/// Result of an encryption operation.
/// </summary>
public readonly struct EncryptionResult
{
    /// <summary>
    /// The ciphertext (encrypted data).
    /// </summary>
    public readonly byte[] Ciphertext { get; init; }

    /// <summary>
    /// The nonce/IV used for encryption (needed for decryption).
    /// </summary>
    public readonly byte[] Nonce { get; init; }

    /// <summary>
    /// Optional: Ciphertext for the encapsulated key (for hybrid encryption).
    /// </summary>
    public readonly byte[]? EncapsulatedKey { get; init; }
}

/// <summary>
/// Fluent builder for encryption operations.
/// </summary>
public class EncryptionBuilder
{
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AesGcm;
    private byte[]? key;
    private byte[]? nonce;
    private byte[]? associatedData;
    private bool deterministicMode;

    /// <summary>
    /// Sets the encryption algorithm to use.
    /// </summary>
    public EncryptionBuilder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Use AES-GCM for encryption (default).
    /// </summary>
    public EncryptionBuilder WithAesGcm() => WithAlgorithm(EncryptionAlgorithm.AesGcm);

    /// <summary>
    /// Use AES-CCM for encryption.
    /// </summary>
    public EncryptionBuilder WithAesCcm() => WithAlgorithm(EncryptionAlgorithm.AesCcm);

    /// <summary>
    /// Use AES-OCB for encryption (high-performance AEAD).
    /// </summary>
    public EncryptionBuilder WithAesOcb() => WithAlgorithm(EncryptionAlgorithm.AesOcb);

    /// <summary>
    /// Use AES-SIV for encryption (nonce-misuse resistant).
    /// </summary>
    public EncryptionBuilder WithAesSiv() => WithAlgorithm(EncryptionAlgorithm.AesSiv);

    /// <summary>
    /// Use ChaCha20-Poly1305 for encryption.
    /// </summary>
    public EncryptionBuilder WithChaCha20Poly1305() => WithAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305);

    /// <summary>
    /// Use XChaCha20-Poly1305 for encryption.
    /// </summary>
    public EncryptionBuilder WithXChaCha20Poly1305() => WithAlgorithm(EncryptionAlgorithm.XChaCha20Poly1305);

    /// <summary>
    /// Use RSA-OAEP with SHA-256 for encryption.
    /// </summary>
    public EncryptionBuilder WithRsaOaep() => WithAlgorithm(EncryptionAlgorithm.RsaOaepSha256);

    /// <summary>
    /// Sets the encryption key.
    /// </summary>
    public EncryptionBuilder WithKey(byte[] key)
    {
        this.key = key;
        return this;
    }

    /// <summary>
    /// Sets a specific nonce/IV for encryption.
    /// When not set, a secure random nonce is auto-generated (recommended).
    /// </summary>
    /// <remarks>
    /// WARNING: Nonce reuse with the same key is catastrophic for most AEAD algorithms
    /// (AES-GCM, ChaCha20-Poly1305, etc.). Only use this if you have a specific requirement
    /// and understand the security implications. AES-SIV is the only algorithm that is
    /// nonce-misuse resistant.
    /// </remarks>
    public EncryptionBuilder WithNonce(byte[] nonce)
    {
        this.nonce = nonce;
        return this;
    }

    /// <summary>
    /// Sets optional authenticated associated data (for AEAD).
    /// </summary>
    public EncryptionBuilder WithAssociatedData(byte[] associatedData)
    {
        this.associatedData = associatedData;
        return this;
    }

    /// <summary>
    /// Enables deterministic encryption mode.
    /// When enabled and no nonce is provided, uses empty nonce for RFC-compliant deterministic encryption.
    /// </summary>
    /// <remarks>
    /// <para>WARNING: Deterministic encryption has security implications:</para>
    /// <list type="bullet">
    /// <item>Same plaintext + key produces identical ciphertext (reveals duplicate messages)</item>
    /// <item>For AES-SIV: Safe, designed for nonce-misuse resistance</item>
    /// <item>For other algorithms (AES-GCM, ChaCha20-Poly1305): Dangerous, only use for testing or specific protocols</item>
    /// </list>
    /// </remarks>
    public EncryptionBuilder WithDeterministicMode()
    {
        deterministicMode = true;
        return this;
    }

    /// <summary>
    /// Encrypts the plaintext and returns the result containing ciphertext and nonce.
    /// </summary>
    public EncryptionResult Encrypt(byte[] plaintext)
    {
        if (key == null)
            throw new InvalidOperationException("Encryption key must be set using WithKey()");

        InputValidator.ValidateByteArray(plaintext, nameof(plaintext), allowEmpty: true);
        InputValidator.ValidateByteArray(key, nameof(key));

        if (associatedData != null)
            InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);

        if (nonce != null)
            InputValidator.ValidateByteArray(nonce, nameof(nonce), allowEmpty: true);

        var aad = associatedData ?? [];
        ReadOnlySpan<byte> nonceSpan = nonce ?? default;

        return algorithm switch
        {
            EncryptionAlgorithm.AesGcm => EncryptAesGcm(plaintext, key, nonceSpan, aad, deterministicMode),
            EncryptionAlgorithm.AesCcm => EncryptAesCcm(plaintext, key, nonceSpan, aad, deterministicMode),
            EncryptionAlgorithm.AesOcb => EncryptAesOcb(plaintext, key, nonceSpan, aad, deterministicMode),
            EncryptionAlgorithm.AesSiv => EncryptAesSiv(plaintext, key, nonceSpan, aad, deterministicMode),
            EncryptionAlgorithm.ChaCha20Poly1305 => EncryptChaCha20Poly1305(plaintext, key, nonceSpan, aad, deterministicMode),
            EncryptionAlgorithm.XChaCha20Poly1305 => EncryptXChaCha20Poly1305(plaintext, key, nonceSpan, aad, deterministicMode),
            EncryptionAlgorithm.RsaOaepSha256 => EncryptRsa(plaintext, key, RSAEncryptionPadding.OaepSHA256),
            EncryptionAlgorithm.RsaOaepSha384 => EncryptRsa(plaintext, key, RSAEncryptionPadding.OaepSHA384),
            EncryptionAlgorithm.RsaOaepSha512 => EncryptRsa(plaintext, key, RSAEncryptionPadding.OaepSHA512),
            EncryptionAlgorithm.RsaPkcs1v15 => EncryptRsa(plaintext, key, RSAEncryptionPadding.Pkcs1),
            EncryptionAlgorithm.X25519ChaCha20Poly1305 => EncryptX25519ChaCha20Poly1305(plaintext, key, aad),
            EncryptionAlgorithm.X25519XChaCha20Poly1305 => EncryptX25519XChaCha20Poly1305(plaintext, key, aad),
            EncryptionAlgorithm.X25519AesGcm => EncryptX25519AesGcm(plaintext, key, aad),
            EncryptionAlgorithm.AesGcmSiv => throw new NotImplementedException(),
            EncryptionAlgorithm.Ascon128 => throw new NotImplementedException(),
            EncryptionAlgorithm.Ascon128a => throw new NotImplementedException(),
            EncryptionAlgorithm.EciesP256 => throw new NotImplementedException(),
            EncryptionAlgorithm.EciesP384 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeX25519ChaCha20Poly1305 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeX25519AesGcm128 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeX25519AesGcm256 => throw new NotImplementedException(),
            EncryptionAlgorithm.HpkeP256AesGcm128 => throw new NotImplementedException(),
            EncryptionAlgorithm.AesCbcHmacSha256 => throw new NotImplementedException(),
#if NET10_OR_GREATER
            EncryptionAlgorithm.MLKem768AesGcm => EncryptMLKemAesGcm(plaintext, key, aad),
            EncryptionAlgorithm.MLKem1024AesGcm => EncryptMLKemAesGcm(plaintext, key, aad),
            EncryptionAlgorithm.MLKem768ChaCha20Poly1305 => EncryptMLKemChaCha20Poly1305(plaintext, key, aad),
            EncryptionAlgorithm.MLKem1024ChaCha20Poly1305 => EncryptMLKemChaCha20Poly1305(plaintext, key, aad),
#endif
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    private static EncryptionResult EncryptAesGcm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesGcmCore.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptAesCcm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesCcmCore.Encrypt(plaintext, key, nonce, aad, deterministicMode: deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptAesOcb(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesOcbCore.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptAesSiv(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = AesSivCore.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptChaCha20Poly1305(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

    private static EncryptionResult EncryptXChaCha20Poly1305(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, bool deterministicMode)
    {
        var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, nonce, aad, deterministicMode);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce
        };
    }

#if NETSTANDARD2_0
    private static EncryptionResult EncryptRsa(byte[] plaintext, byte[] publicKeyBytes, RSAEncryptionPadding padding)
    {
        _ = plaintext;
        _ = publicKeyBytes;
        _ = padding;
        throw new PlatformNotSupportedException("RSA key import is not supported on .NET Standard 2.0.");
    }

    private static EncryptionResult EncryptX25519ChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, X25519AeadCipher.ChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519XChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, X25519AeadCipher.XChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519AesGcm(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, X25519AeadCipher.AesGcm);
    }

    private static EncryptionResult EncryptX25519Hybrid(byte[] plaintext, byte[] recipientPublicKey, byte[] aad, X25519AeadCipher cipher)
    {
        _ = plaintext;
        _ = recipientPublicKey;
        _ = aad;
        _ = cipher;
        throw new PlatformNotSupportedException("X25519 hybrid encryption is not supported on .NET Standard 2.0.");
    }
#else
    private static EncryptionResult EncryptRsa(byte[] plaintext, byte[] publicKeyBytes, RSAEncryptionPadding padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

        var ciphertext = rsa.Encrypt(plaintext, padding);

        return new EncryptionResult
        {
            Ciphertext = ciphertext,
            Nonce = []
        };
    }

    private static EncryptionResult EncryptX25519ChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, X25519AeadCipher.ChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519XChaCha20Poly1305(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, X25519AeadCipher.XChaCha20Poly1305);
    }

    private static EncryptionResult EncryptX25519AesGcm(byte[] plaintext, byte[] recipientPublicKey, byte[] aad)
    {
        return EncryptX25519Hybrid(plaintext, recipientPublicKey, aad, X25519AeadCipher.AesGcm);
    }

    private static EncryptionResult EncryptX25519Hybrid(byte[] plaintext, byte[] recipientPublicKey, byte[] aad, X25519AeadCipher cipher)
    {
        // Generate ephemeral key pair
        var ephemeralPrivateKey = Curve25519Core.GeneratePrivateKey();
        var ephemeralPublicKey = Curve25519Core.DerivePublicKey(ephemeralPrivateKey);

        try
        {
            // Compute shared secret via X25519 key agreement
            var sharedSecret = Curve25519Core.ComputeSharedSecret(ephemeralPrivateKey, recipientPublicKey);

            try
            {
                // Derive symmetric key using HKDF
                var symmetricKey = HkdfCore.DeriveKey(
                    sharedSecret,
                    salt: [],
                    info: System.Text.Encoding.UTF8.GetBytes("X25519-Hybrid-Encryption"),
                    length: 32,
                    HashAlgorithmName.SHA256);

                try
                {
                    // Encrypt with the selected AEAD cipher
                    var (ciphertext, nonce) = cipher switch
                    {
                        X25519AeadCipher.ChaCha20Poly1305 => EncryptWithChaCha20Poly1305(plaintext, symmetricKey, aad),
                        X25519AeadCipher.XChaCha20Poly1305 => EncryptWithXChaCha20Poly1305(plaintext, symmetricKey, aad),
                        X25519AeadCipher.AesGcm => EncryptWithAesGcm(plaintext, symmetricKey, aad),
                        _ => throw new NotSupportedException($"Cipher {cipher} is not supported")
                    };

                    return new EncryptionResult
                    {
                        Ciphertext = ciphertext,
                        Nonce = nonce,
                        EncapsulatedKey = ephemeralPublicKey
                    };
                }
                finally
                {
                    SecureMemoryOperations.SecureClear(symmetricKey);
                }
            }
            finally
            {
                SecureMemoryOperations.SecureClear(sharedSecret);
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(ephemeralPrivateKey);
        }
    }

    private static (byte[] Ciphertext, byte[] Nonce) EncryptWithChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] aad)
    {
        var result = ChaCha20Poly1305Core.Encrypt(plaintext, key, associatedData: aad);
        return (result.Ciphertext, result.Nonce);
    }

    private static (byte[] Ciphertext, byte[] Nonce) EncryptWithXChaCha20Poly1305(byte[] plaintext, byte[] key, byte[] aad)
    {
        var result = XChaCha20Poly1305Core.Encrypt(plaintext, key, associatedData: aad);
        return (result.Ciphertext, result.Nonce);
    }

    private static (byte[] Ciphertext, byte[] Nonce) EncryptWithAesGcm(byte[] plaintext, byte[] key, byte[] aad)
    {
        var result = AesGcmCore.Encrypt(plaintext, key, associatedData: aad);
        return (result.Ciphertext, result.Nonce);
    }
#endif

    private enum X25519AeadCipher
    {
        ChaCha20Poly1305,
        XChaCha20Poly1305,
        AesGcm
    }

#if NET10_OR_GREATER
#pragma warning disable SYSLIB5006
    private static EncryptionResult EncryptMLKemAesGcm(byte[] plaintext, byte[] publicKeyPemBytes, byte[] aad)
    {
        var publicKeyPem = System.Text.Encoding.UTF8.GetString(publicKeyPemBytes);

        using var encapsulation = MLKemCore.Encapsulate(publicKeyPem);

        var result = AesGcmCore.Encrypt(plaintext, encapsulation.SharedSecret, associatedData: aad);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce,
            EncapsulatedKey = encapsulation.Ciphertext
        };
    }

    private static EncryptionResult EncryptMLKemChaCha20Poly1305(byte[] plaintext, byte[] publicKeyPemBytes, byte[] aad)
    {
        var publicKeyPem = System.Text.Encoding.UTF8.GetString(publicKeyPemBytes);

        using var encapsulation = MLKemCore.Encapsulate(publicKeyPem);

        var result = ChaCha20Poly1305Core.Encrypt(plaintext, encapsulation.SharedSecret, associatedData: aad);

        return new EncryptionResult
        {
            Ciphertext = result.Ciphertext,
            Nonce = result.Nonce,
            EncapsulatedKey = encapsulation.Ciphertext
        };
    }
#pragma warning restore SYSLIB5006
#endif
}
