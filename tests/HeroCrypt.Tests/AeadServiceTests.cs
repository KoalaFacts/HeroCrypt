using System.Security.Cryptography;
using HeroCrypt;
using HeroCrypt.Encryption;

namespace HeroCrypt.Tests;

public class AeadServiceTests
{
    public static IEnumerable<object[]> AeadCases =>
        new[]
        {
            new object[] { EncryptionAlgorithm.ChaCha20Poly1305, 32 },
            new object[] { EncryptionAlgorithm.XChaCha20Poly1305, 32 },
            new object[] { EncryptionAlgorithm.AesGcm, 16 },
            new object[] { EncryptionAlgorithm.AesGcm, 32 },
            new object[] { EncryptionAlgorithm.AesCcm, 16 },
            new object[] { EncryptionAlgorithm.AesCcm, 32 }
        };

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void EncryptDecrypt_RoundTrip_Succeeds(EncryptionAlgorithm algorithm, int keySize)
    {
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = RandomNumberGenerator.GetBytes(keySize);
        var associatedData = "metadata"u8.ToArray();

        var result = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .WithAssociatedData(associatedData)
            .Build(plaintext);

        var decrypted = HeroCryptBuilder.Decrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .WithNonce(result.Nonce)
            .WithAssociatedData(associatedData)
            .Build(result.Ciphertext);

        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, result.Ciphertext);
    }

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void Decrypt_TamperedCiphertext_Fails(EncryptionAlgorithm algorithm, int keySize)
    {
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = RandomNumberGenerator.GetBytes(keySize);

        var result = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .Build(plaintext);

        var tampered = (byte[])result.Ciphertext.Clone();
        tampered[0] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() =>
            HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Build(tampered));
    }

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void Decrypt_WrongKey_Fails(EncryptionAlgorithm algorithm, int keySize)
    {
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = RandomNumberGenerator.GetBytes(keySize);
        var wrongKey = RandomNumberGenerator.GetBytes(keySize);

        var result = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .Build(plaintext);

        Assert.ThrowsAny<CryptographicException>(() =>
            HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(wrongKey)
                .WithNonce(result.Nonce)
                .Build(result.Ciphertext));
    }

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void Decrypt_WrongNonce_Fails(EncryptionAlgorithm algorithm, int keySize)
    {
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = RandomNumberGenerator.GetBytes(keySize);

        var result = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .Build(plaintext);

        var wrongNonce = RandomNumberGenerator.GetBytes(result.Nonce.Length);

        Assert.ThrowsAny<CryptographicException>(() =>
            HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(wrongNonce)
                .Build(result.Ciphertext));
    }

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void Decrypt_WrongAssociatedData_Fails(EncryptionAlgorithm algorithm, int keySize)
    {
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = RandomNumberGenerator.GetBytes(keySize);
        var aad = "metadata"u8.ToArray();
        var wrongAad = "wrong"u8.ToArray();

        var result = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .WithAssociatedData(aad)
            .Build(plaintext);

        Assert.ThrowsAny<CryptographicException>(() =>
            HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(wrongAad)
                .Build(result.Ciphertext));
    }

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void Encrypt_SamePlaintextDifferentNonce_ProducesDifferentCiphertext(EncryptionAlgorithm algorithm, int keySize)
    {
        var plaintext = "Same plaintext, different nonce"u8.ToArray();
        var key = RandomNumberGenerator.GetBytes(keySize);

        var result1 = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .Build(plaintext);

        var result2 = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .Build(plaintext);

        Assert.NotEqual(result1.Ciphertext, result2.Ciphertext);
        Assert.NotEqual(result1.Nonce, result2.Nonce);
    }
}
