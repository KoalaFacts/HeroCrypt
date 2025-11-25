using System.Security.Cryptography;
using HeroCrypt;
using HeroCrypt.Encryption;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for AEAD (Authenticated Encryption with Associated Data) algorithms.
/// </summary>
/// <remarks>
/// <para><b>Platform Support Notes:</b></para>
/// <list type="bullet">
///   <item>
///     <term>AES-CCM on macOS</term>
///     <description>
///       AES-CCM is not supported on macOS. The macOS Security framework does not implement
///       the CCM (Counter with CBC-MAC) mode. Tests using AES-CCM are automatically skipped
///       on macOS using <c>Assert.Skip()</c>. Use AES-GCM as an alternative on macOS.
///     </description>
///   </item>
///   <item>
///     <term>ChaCha20-Poly1305</term>
///     <description>Supported on all platforms (.NET 6+).</description>
///   </item>
///   <item>
///     <term>XChaCha20-Poly1305</term>
///     <description>Custom implementation, supported on all platforms.</description>
///   </item>
///   <item>
///     <term>AES-GCM</term>
///     <description>Supported on all platforms.</description>
///   </item>
/// </list>
/// </remarks>
public class AeadServiceTests
{
    public static IEnumerable<object[]> AeadCases =>
    [
        [EncryptionAlgorithm.ChaCha20Poly1305, 32],
        [EncryptionAlgorithm.XChaCha20Poly1305, 32],
        [EncryptionAlgorithm.AesGcm, 16],
        [EncryptionAlgorithm.AesGcm, 32],
        [EncryptionAlgorithm.AesCcm, 16],
        [EncryptionAlgorithm.AesCcm, 32]
    ];

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void EncryptDecrypt_RoundTrip_Succeeds(EncryptionAlgorithm algorithm, int keySize)
    {
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

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
    public void EncryptDecrypt_EmptyPlaintext_Succeeds(EncryptionAlgorithm algorithm, int keySize)
    {
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

        var plaintext = Array.Empty<byte>();
        var key = RandomNumberGenerator.GetBytes(keySize);

        var result = HeroCryptBuilder.Encrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .Build(plaintext);

        var decrypted = HeroCryptBuilder.Decrypt()
            .WithAlgorithm(algorithm)
            .WithKey(key)
            .WithNonce(result.Nonce)
            .Build(result.Ciphertext);

        Assert.Equal(plaintext, decrypted);
        Assert.NotEmpty(result.Ciphertext); // tag present
    }

    [Theory]
    [MemberData(nameof(AeadCases))]
    public void Decrypt_TamperedCiphertext_Fails(EncryptionAlgorithm algorithm, int keySize)
    {
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

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
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

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
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

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
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

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
        if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
        {
            Assert.Skip("AES-CCM not supported on macOS");
            return;
        }

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
