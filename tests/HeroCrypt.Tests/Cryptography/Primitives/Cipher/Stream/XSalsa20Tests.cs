using System.Text;
using HeroCrypt.Cryptography.Primitives.Cipher.Stream;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// Tests for XSalsa20 stream cipher implementation
/// </summary>
public class XSalsa20Tests
{
    private readonly byte[] testKey = new byte[32];
    private readonly byte[] testNonce = new byte[24]; // XSalsa20 uses 24-byte nonces
    private readonly byte[] testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public XSalsa20Tests()
    {
        // Initialize test key and nonce with predictable values
        for (var i = 0; i < testKey.Length; i++)
        {
            testKey[i] = (byte)(i + 1);
        }

        for (var i = 0; i < testNonce.Length; i++)
        {
            testNonce[i] = (byte)(i + 50);
        }
    }

    [Fact]
    public void XSalsa20_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        XSalsa20Core.Transform(ciphertext, plaintext, testKey, testNonce);

        // Act - Decrypt (XSalsa20 is symmetric)
        XSalsa20Core.Transform(decrypted, ciphertext, testKey, testNonce);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void Transform_EmptyInput_ReturnsEmpty()
    {
        // Arrange
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        // Act & Assert - Should handle empty input gracefully
        XSalsa20Core.Transform(ciphertext, plaintext, testKey, testNonce);
    }

    [Fact]
    public void Transform_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Should be 32 bytes
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            XSalsa20Core.Transform(ciphertext, plaintext, invalidKey, testNonce));
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public void Transform_InvalidNonceSize_ThrowsException()
    {
        // Arrange
        var invalidNonce = new byte[12]; // Should be 24 bytes for XSalsa20
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            XSalsa20Core.Transform(ciphertext, plaintext, testKey, invalidNonce));
        Assert.Contains("24 bytes", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length - 1]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            XSalsa20Core.Transform(ciphertext, plaintext, testKey, testNonce));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void Transform_DifferentNonces_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];
        var nonce1 = new byte[24];
        var nonce2 = new byte[24];

        for (var i = 0; i < 24; i++)
        {
            nonce1[i] = (byte)i;
            nonce2[i] = (byte)(i + 100);
        }

        // Act
        XSalsa20Core.Transform(ciphertext1, plaintext, testKey, nonce1);
        XSalsa20Core.Transform(ciphertext2, plaintext, testKey, nonce2);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_DifferentKeys_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];
        var key1 = new byte[32];
        var key2 = new byte[32];

        for (var i = 0; i < 32; i++)
        {
            key1[i] = (byte)i;
            key2[i] = (byte)(i + 100);
        }

        // Act
        XSalsa20Core.Transform(ciphertext1, plaintext, key1, testNonce);
        XSalsa20Core.Transform(ciphertext2, plaintext, key2, testNonce);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void LargeData_EncryptsCorrectly()
    {
        // Arrange - 1MB of data
        var largeData = new byte[1024 * 1024];
        new Random(42).NextBytes(largeData);
        var ciphertext = new byte[largeData.Length];
        var decrypted = new byte[largeData.Length];

        // Act
        XSalsa20Core.Transform(ciphertext, largeData, testKey, testNonce);
        XSalsa20Core.Transform(decrypted, ciphertext, testKey, testNonce);

        // Assert
        Assert.Equal(largeData, decrypted);
        Assert.NotEqual(largeData, ciphertext);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        XSalsa20Core.ValidateParameters(testKey, testNonce);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            XSalsa20Core.ValidateParameters(invalidKey, testNonce));
    }

    [Fact]
    public void GetMaxPlaintextLength_ReturnsValidValue()
    {
        // Act
        var maxLength = XSalsa20Core.GetMaxPlaintextLength();

        // Assert
        Assert.True(maxLength > 0);
        Assert.True(maxLength > 1024 * 1024 * 1024); // Should be very large
    }
}

