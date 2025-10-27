using HeroCrypt.Cryptography.Symmetric.ChaCha;
using System.Text;
using static HeroCrypt.Cryptography.Symmetric.ChaCha.ChaChaVariants;

namespace HeroCrypt.Tests;


/// <summary>
/// Tests for ChaCha20 variants (ChaCha8, ChaCha12, ChaCha20)
/// </summary>
public class ChaChaVariantsTests
{
    private readonly byte[] _testKey = new byte[32];
    private readonly byte[] _testNonce = new byte[12];
    private readonly byte[] _testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public ChaChaVariantsTests()
    {
        // Initialize test key and nonce with predictable values
        for (var i = 0; i < _testKey.Length; i++)
            _testKey[i] = (byte)(i + 1);
        for (var i = 0; i < _testNonce.Length; i++)
            _testNonce[i] = (byte)(i + 100);
    }

    [Fact]
    public void ChaCha8_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        ChaChaVariants.Transform(ciphertext, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha8);

        // Act - Decrypt (ChaCha is symmetric)
        ChaChaVariants.Transform(decrypted, ciphertext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha8);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void ChaCha12_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        ChaChaVariants.Transform(ciphertext, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha12);
        ChaChaVariants.Transform(decrypted, ciphertext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha12);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void ChaCha20_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        ChaChaVariants.Transform(ciphertext, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);
        ChaChaVariants.Transform(decrypted, ciphertext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void DifferentVariants_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext8 = new byte[plaintext.Length];
        var ciphertext12 = new byte[plaintext.Length];
        var ciphertext20 = new byte[plaintext.Length];

        // Act
        ChaChaVariants.Transform(ciphertext8, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha8);
        ChaChaVariants.Transform(ciphertext12, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha12);
        ChaChaVariants.Transform(ciphertext20, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);

        // Assert - Different variants should produce different outputs
        Assert.NotEqual(ciphertext8, ciphertext12);
        Assert.NotEqual(ciphertext8, ciphertext20);
        Assert.NotEqual(ciphertext12, ciphertext20);
    }

    [Fact]
    public void Transform_WithCounter_ProducesCorrectOutput()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];

        // Act - Same key/nonce but different counter values
        ChaChaVariants.Transform(ciphertext1, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);
        ChaChaVariants.Transform(ciphertext2, plaintext, _testKey, _testNonce, 1, ChaChaVariant.ChaCha20);

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
        ChaChaVariants.Transform(ciphertext, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);
    }

    [Fact]
    public void Transform_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Should be 32 bytes
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            ChaChaVariants.Transform(ciphertext, plaintext, invalidKey, _testNonce, 0, ChaChaVariant.ChaCha20));
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public void Transform_InvalidNonceSize_ThrowsException()
    {
        // Arrange
        var invalidNonce = new byte[8]; // Should be 12 bytes
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            ChaChaVariants.Transform(ciphertext, plaintext, _testKey, invalidNonce, 0, ChaChaVariant.ChaCha20));
        Assert.Contains("12 bytes", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length - 1]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            ChaChaVariants.Transform(ciphertext, plaintext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void GetSecurityBits_ReturnsCorrectValues()
    {
        // Act & Assert
        Assert.Equal(64, ChaChaVariants.GetSecurityBits(ChaChaVariant.ChaCha8));
        Assert.Equal(96, ChaChaVariants.GetSecurityBits(ChaChaVariant.ChaCha12));
        Assert.Equal(128, ChaChaVariants.GetSecurityBits(ChaChaVariant.ChaCha20));
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
        ChaChaVariants.Transform(ciphertext, largeData, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);
        ChaChaVariants.Transform(decrypted, ciphertext, _testKey, _testNonce, 0, ChaChaVariant.ChaCha20);

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
        ChaChaVariants.Transform(ciphertext, plaintext, _testKey, _testNonce, 0, variant);
        ChaChaVariants.Transform(decrypted, ciphertext, _testKey, _testNonce, 0, variant);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        ChaChaVariants.ValidateParameters(_testKey, _testNonce, ChaChaVariant.ChaCha20);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ChaChaVariants.ValidateParameters(invalidKey, _testNonce, ChaChaVariant.ChaCha20));
    }
}

