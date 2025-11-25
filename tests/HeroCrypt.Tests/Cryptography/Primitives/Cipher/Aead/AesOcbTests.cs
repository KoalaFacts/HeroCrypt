using System.Text;
using HeroCrypt.Cryptography.Primitives.Cipher.Aead;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Aead;

/// <summary>
/// Tests for AES-OCB (Offset Codebook Mode) per RFC 7253
/// </summary>
public class AesOcbTests
{
    [Fact]
    public void Encrypt_WithValidParameters_Success()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        var written = AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);

        // Assert
        Assert.Equal(plaintext.Length + AesOcbCore.TAG_SIZE, written);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        var encryptedLength = AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
        var decryptedLength = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert
        Assert.Equal(plaintext.Length + AesOcbCore.TAG_SIZE, encryptedLength);
        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithAssociatedData_Success()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Secret message");
        var associatedData = Encoding.UTF8.GetBytes("user_id=12345");
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData);
        var decryptedLength = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, associatedData);

        // Assert
        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAssociatedData_Fails()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Secret message");
        var correctAd = Encoding.UTF8.GetBytes("user_id=12345");
        var wrongAd = Encoding.UTF8.GetBytes("user_id=99999");
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, correctAd);
        var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, wrongAd);

        // Assert - Should fail authentication
        Assert.Equal(-1, result);
        Assert.All(decrypted, b => Assert.Equal(0, b)); // Plaintext cleared on failure
    }

    [Fact]
    public void Decrypt_WithModifiedCiphertext_Fails()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Secret message");
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);

        // Act - Modify ciphertext
        ciphertext[0] ^= 0xFF;
        var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert - Should fail authentication
        Assert.Equal(-1, result);
    }

    [Fact]
    public void Decrypt_WithModifiedTag_Fails()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Secret message");
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);

        // Act - Modify tag
        ciphertext[ciphertext.Length - 1] ^= 0xFF;
        var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert - Should fail authentication
        Assert.Equal(-1, result);
    }

    [Fact]
    public void EncryptDecrypt_EmptyPlaintext_Success()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = Array.Empty<byte>();
        var ciphertext = new byte[AesOcbCore.TAG_SIZE];
        var decrypted = Array.Empty<byte>();

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        var encryptedLength = AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
        var decryptedLength = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert
        Assert.Equal(AesOcbCore.TAG_SIZE, encryptedLength);
        Assert.Equal(0, decryptedLength);
    }

    [Fact]
    public void Encrypt_WithDifferentKeySizes_Success()
    {
        // Test AES-128, AES-192, AES-256
        var keySizes = new[] { 16, 24, 32 };
        var nonce = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Test message");

        foreach (var keySize in keySizes)
        {
            // Arrange
            var key = new byte[keySize];
            for (var i = 0; i < key.Length; i++)
            {
                key[i] = (byte)(i + 1);
            }
            for (var i = 0; i < nonce.Length; i++)
            {
                nonce[i] = (byte)(i + 100);
            }

            var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            Assert.Equal(plaintext.Length, result);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public void Encrypt_WithDifferentNonceSizes_Success()
    {
        // Test nonce sizes from 1 to 15 bytes (RFC 7253 allows 1-15)
        var key = new byte[16];
        var plaintext = Encoding.UTF8.GetBytes("Test");

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }

        for (var nonceSize = 1; nonceSize <= 15; nonceSize++)
        {
            // Arrange
            var nonce = new byte[nonceSize];
            for (var i = 0; i < nonce.Length; i++)
            {
                nonce[i] = (byte)(i + 100);
            }

            var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
            var decrypted = new byte[plaintext.Length];

            // Act
            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
            var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

            // Assert
            Assert.Equal(plaintext.Length, result);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public void Encrypt_WithLargeData_Success()
    {
        // Arrange - 1MB of data
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = new byte[1024 * 1024];
        new Random(42).NextBytes(plaintext);
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
        var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert
        Assert.Equal(plaintext.Length, result);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_WithPartialBlock_Success()
    {
        // Test with data that is not a multiple of block size
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = new byte[13]; // Not a multiple of 16
        for (var i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)(i + 50);
        }

        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
        var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert
        Assert.Equal(plaintext.Length, result);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[15]; // Should be 16, 24, or 32
        var nonce = new byte[12];
        var plaintext = new byte[10];
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AesOcbCore.Encrypt(ciphertext, plaintext, invalidKey, nonce, []));
        Assert.Contains("16, 24, or 32 bytes", ex.Message);
    }

    [Fact]
    public void Encrypt_InvalidNonceSize_ThrowsException()
    {
        // Arrange
        var key = new byte[16];
        var invalidNonce = new byte[16]; // Should be 1-15 bytes
        var plaintext = new byte[10];
        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AesOcbCore.Encrypt(ciphertext, plaintext, key, invalidNonce, []));
        Assert.Contains("between", ex.Message);
    }

    [Fact]
    public void Encrypt_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = new byte[10];
        var ciphertext = new byte[10]; // Too small - needs 10 + 16

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []));
    }

    [Fact]
    public void Decrypt_CiphertextTooShort_ThrowsException()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];
        var ciphertext = new byte[10]; // Less than TagSize (16)
        var plaintext = new byte[10];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            AesOcbCore.Decrypt(plaintext, ciphertext, key, nonce, []));
    }

    [Fact]
    public void DifferentNonces_ProduceDifferentCiphertexts()
    {
        // Arrange
        var key = new byte[16];
        var nonce1 = new byte[12];
        var nonce2 = new byte[12];
        var plaintext = Encoding.UTF8.GetBytes("Same plaintext");

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce1.Length; i++)
        {
            nonce1[i] = (byte)(i + 100);
        }
        for (var i = 0; i < nonce2.Length; i++)
        {
            nonce2[i] = (byte)(i + 200);
        }

        var ciphertext1 = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var ciphertext2 = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];

        // Act
        AesOcbCore.Encrypt(ciphertext1, plaintext, key, nonce1, []);
        AesOcbCore.Encrypt(ciphertext2, plaintext, key, nonce2, []);

        // Assert - Different nonces should produce different ciphertexts
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Arrange
        var key = new byte[16];
        var nonce = new byte[12];

        // Act & Assert - Should not throw
        AesOcbCore.ValidateParameters(key, nonce, 100, 84);
    }

    [Fact]
    public void GetMaxPlaintextLength_ReturnsPositiveValue()
    {
        // Act
        var maxLength = AesOcbCore.GetMaxPlaintextLength();

        // Assert
        Assert.True(maxLength > 0);
    }

    [Fact]
    public void EncryptDecrypt_MultipleBlocks_Success()
    {
        // Arrange - Exactly 3 full blocks (48 bytes)
        var key = new byte[16];
        var nonce = new byte[12];
        var plaintext = new byte[48];
        for (var i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = (byte)(i % 256);
        }

        var ciphertext = new byte[plaintext.Length + AesOcbCore.TAG_SIZE];
        var decrypted = new byte[plaintext.Length];

        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i + 1);
        }
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i] = (byte)(i + 100);
        }

        // Act
        AesOcbCore.Encrypt(ciphertext, plaintext, key, nonce, []);
        var result = AesOcbCore.Decrypt(decrypted, ciphertext, key, nonce, []);

        // Assert
        Assert.Equal(plaintext.Length, result);
        Assert.Equal(plaintext, decrypted);
    }
}




