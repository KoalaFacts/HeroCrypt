using System.Text;
using static HeroCrypt.Cryptography.Primitives.Cipher.Stream.ChaChaVariants;

namespace HeroCrypt.Tests.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// Tests for ChaCha20 variants (ChaCha8, ChaCha12, ChaCha20)
/// </summary>
public class ChaChaVariantsTests
{
    private readonly byte[] testKey = new byte[32];
    private readonly byte[] testNonce = new byte[12];
    private readonly byte[] testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public ChaChaVariantsTests()
    {
        // Initialize test key and nonce with predictable values
        for (var i = 0; i < testKey.Length; i++)
        {
            testKey[i] = (byte)(i + 1);
        }

        for (var i = 0; i < testNonce.Length; i++)
        {
            testNonce[i] = (byte)(i + 100);
        }
    }

    [Fact]
    public void ChaCha8_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        Transform(ciphertext, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha8);

        // Act - Decrypt (ChaCha is symmetric)
        Transform(decrypted, ciphertext, testKey, testNonce, 0, ChaChaVariant.ChaCha8);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void ChaCha12_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Transform(ciphertext, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha12);
        Transform(decrypted, ciphertext, testKey, testNonce, 0, ChaChaVariant.ChaCha12);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void ChaCha20_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Transform(ciphertext, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha20);
        Transform(decrypted, ciphertext, testKey, testNonce, 0, ChaChaVariant.ChaCha20);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void DifferentVariants_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext8 = new byte[plaintext.Length];
        var ciphertext12 = new byte[plaintext.Length];
        var ciphertext20 = new byte[plaintext.Length];

        // Act
        Transform(ciphertext8, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha8);
        Transform(ciphertext12, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha12);
        Transform(ciphertext20, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha20);

        // Assert - Different variants should produce different outputs
        Assert.NotEqual(ciphertext8, ciphertext12);
        Assert.NotEqual(ciphertext8, ciphertext20);
        Assert.NotEqual(ciphertext12, ciphertext20);
    }

    [Fact]
    public void Transform_WithCounter_ProducesCorrectOutput()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];

        // Act - Same key/nonce but different counter values
        Transform(ciphertext1, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha20);
        Transform(ciphertext2, plaintext, testKey, testNonce, 1, ChaChaVariant.ChaCha20);

        // Assert - Different counter values should produce different outputs
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_EmptyInput_ReturnsEmpty()
    {
        // Arrange
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        // Act & Assert - Should handle empty input gracefully
        Transform(ciphertext, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha20);
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
            Transform(ciphertext, plaintext, invalidKey, testNonce, 0, ChaChaVariant.ChaCha20));
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public void Transform_InvalidNonceSize_ThrowsException()
    {
        // Arrange
        var invalidNonce = new byte[8]; // Should be 12 bytes
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Transform(ciphertext, plaintext, testKey, invalidNonce, 0, ChaChaVariant.ChaCha20));
        Assert.Contains("12 bytes", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = testPlaintext;
        var ciphertext = new byte[plaintext.Length - 1]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Transform(ciphertext, plaintext, testKey, testNonce, 0, ChaChaVariant.ChaCha20));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void GetSecurityBits_ReturnsCorrectValues()
    {
        // Act & Assert
        Assert.Equal(64, GetSecurityBits(ChaChaVariant.ChaCha8));
        Assert.Equal(96, GetSecurityBits(ChaChaVariant.ChaCha12));
        Assert.Equal(128, GetSecurityBits(ChaChaVariant.ChaCha20));
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
        Transform(ciphertext, largeData, testKey, testNonce, 0, ChaChaVariant.ChaCha20);
        Transform(decrypted, ciphertext, testKey, testNonce, 0, ChaChaVariant.ChaCha20);

        // Assert
        Assert.Equal(largeData, decrypted);
    }

    [Theory]
    [InlineData(ChaChaVariant.ChaCha8)]
    [InlineData(ChaChaVariant.ChaCha12)]
    [InlineData(ChaChaVariant.ChaCha20)]
    public void AllVariants_WorkCorrectly(ChaChaVariant variant)
    {
        // Arrange
        var plaintext = Encoding.UTF8.GetBytes($"Testing {variant}");
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Transform(ciphertext, plaintext, testKey, testNonce, 0, variant);
        Transform(decrypted, ciphertext, testKey, testNonce, 0, variant);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        ValidateParameters(testKey, testNonce, ChaChaVariant.ChaCha20);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ValidateParameters(invalidKey, testNonce, ChaChaVariant.ChaCha20));
    }
}


