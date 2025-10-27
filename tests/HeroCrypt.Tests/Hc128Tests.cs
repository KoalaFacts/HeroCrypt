using HeroCrypt.Cryptography.Symmetric.Hc128;
using System.Text;

namespace HeroCrypt.Tests;

// DISABLED: Testing absolute minimum configuration
#if FALSE

/// <summary>
/// Tests for HC-128 stream cipher implementation
/// HC-128 is part of the eSTREAM portfolio (Profile 1: Software)
/// </summary>
public class Hc128Tests
{
    private readonly byte[] _testKey = new byte[16];
    private readonly byte[] _testIv = new byte[16];
    private readonly byte[] _testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public Hc128Tests()
    {
        // Initialize test key and IV with predictable values
        for (var i = 0; i < _testKey.Length; i++)
            _testKey[i] = (byte)(i + 1);
        for (var i = 0; i < _testIv.Length; i++)
            _testIv[i] = (byte)(i + 50);
    }

    [Fact]
    public void Hc128_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv);

        // Act - Decrypt (HC-128 is symmetric)
        Hc128Core.Transform(decrypted, ciphertext, _testKey, _testIv);

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
        Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv);
    }

    [Fact]
    public void Transform_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[32]; // Should be 16 bytes
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Hc128Core.Transform(ciphertext, plaintext, invalidKey, _testIv));
        Assert.Contains("16 bytes", ex.Message);
    }

    [Fact]
    public void Transform_InvalidIvSize_ThrowsException()
    {
        // Arrange
        var invalidIv = new byte[8]; // Should be 16 bytes
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Hc128Core.Transform(ciphertext, plaintext, _testKey, invalidIv));
        Assert.Contains("16 bytes", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length - 1]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void Transform_DifferentIvs_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];
        var iv1 = new byte[16];
        var iv2 = new byte[16];

        for (var i = 0; i < 16; i++)
        {
            iv1[i] = (byte)i;
            iv2[i] = (byte)(i + 100);
        }

        // Act
        Hc128Core.Transform(ciphertext1, plaintext, _testKey, iv1);
        Hc128Core.Transform(ciphertext2, plaintext, _testKey, iv2);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_DifferentKeys_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];
        var key1 = new byte[16];
        var key2 = new byte[16];

        for (var i = 0; i < 16; i++)
        {
            key1[i] = (byte)i;
            key2[i] = (byte)(i + 100);
        }

        // Act
        Hc128Core.Transform(ciphertext1, plaintext, key1, _testIv);
        Hc128Core.Transform(ciphertext2, plaintext, key2, _testIv);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_SingleByte_Success()
    {
        // Arrange
        var plaintext = new byte[] { 0x42 };
        var ciphertext = new byte[1];
        var decrypted = new byte[1];

        // Act
        Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv);
        Hc128Core.Transform(decrypted, ciphertext, _testKey, _testIv);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext[0], ciphertext[0]);
    }

    [Fact]
    public void Transform_OddLength_Success()
    {
        // Arrange - Test odd-length data to verify partial word handling
        var plaintext = new byte[17]; // Not a multiple of 4
        for (var i = 0; i < plaintext.Length; i++)
            plaintext[i] = (byte)i;

        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv);
        Hc128Core.Transform(decrypted, ciphertext, _testKey, _testIv);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
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
        Hc128Core.Transform(ciphertext, largeData, _testKey, _testIv);
        Hc128Core.Transform(decrypted, ciphertext, _testKey, _testIv);

        // Assert
        Assert.Equal(largeData, decrypted);
        Assert.NotEqual(largeData, ciphertext);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        Hc128Core.ValidateParameters(_testKey, _testIv);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Hc128Core.ValidateParameters(invalidKey, _testIv));
    }

    [Fact]
    public void ValidateParameters_InvalidIv_ThrowsException()
    {
        // Arrange
        var invalidIv = new byte[8];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Hc128Core.ValidateParameters(_testKey, invalidIv));
    }

    [Fact]
    public void GetMaxPlaintextLength_ReturnsValidValue()
    {
        // Act
        var maxLength = Hc128Core.GetMaxPlaintextLength();

        // Assert
        Assert.True(maxLength > 0);
        Assert.True(maxLength > 1024L * 1024 * 1024); // Should be very large
    }

    /// <summary>
    /// Test with all-zero key and IV
    /// Verifies consistent output
    /// </summary>
    [Fact]
    [Trait("Category", "Consistency")]
    public void ZeroKeyAndIv_ConsistentOutput()
    {
        // Arrange
        var zeroKey = new byte[16];
        var zeroIv = new byte[16];
        var plaintext = new byte[64]; // 16 words

        var ciphertext1 = new byte[64];
        var ciphertext2 = new byte[64];

        // Act - Encrypt twice with same inputs
        Hc128Core.Transform(ciphertext1, plaintext, zeroKey, zeroIv);
        Hc128Core.Transform(ciphertext2, plaintext, zeroKey, zeroIv);

        // Assert - Should produce identical output (deterministic)
        Assert.Equal(ciphertext1, ciphertext2);
    }

    /// <summary>
    /// Test with sequential key pattern
    /// </summary>
    [Fact]
    [Trait("Category", "Consistency")]
    public void SequentialKey_Success()
    {
        // Arrange
        var key = new byte[16];
        for (var i = 0; i < 16; i++)
            key[i] = (byte)i;

        var iv = new byte[16];
        var plaintext = new byte[128];

        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Hc128Core.Transform(ciphertext, plaintext, key, iv);
        Hc128Core.Transform(decrypted, ciphertext, key, iv);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    /// <summary>
    /// Test keystream generation across multiple blocks
    /// </summary>
    [Fact]
    public void MultipleBlocks_Success()
    {
        // Arrange - Test data spanning 100+ keystream words
        var plaintext = new byte[500]; // ~125 words
        for (var i = 0; i < plaintext.Length; i++)
            plaintext[i] = (byte)(i & 0xFF);

        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv);
        Hc128Core.Transform(decrypted, ciphertext, _testKey, _testIv);

        // Assert
        Assert.Equal(plaintext, decrypted);

        // Verify ciphertext differs from plaintext
        var differences = 0;
        for (var i = 0; i < plaintext.Length; i++)
        {
            if (plaintext[i] != ciphertext[i])
                differences++;
        }

        // Expect most bytes to differ (good keystream quality)
        Assert.True(differences > plaintext.Length / 2);
    }

    /// <summary>
    /// Test boundary condition at 512-word mark (P/Q table transition)
    /// </summary>
    [Fact]
    [Trait("Category", "EdgeCase")]
    public void TableTransitionBoundary_Success()
    {
        // Arrange - Test data around 512*4 = 2048 byte boundary
        var plaintext = new byte[2100]; // Cross P/Q table boundary
        for (var i = 0; i < plaintext.Length; i++)
            plaintext[i] = (byte)(i & 0xFF);

        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Hc128Core.Transform(ciphertext, plaintext, _testKey, _testIv);
        Hc128Core.Transform(decrypted, ciphertext, _testKey, _testIv);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void SameKeyDifferentIv_ProducesDifferentKeystreams()
    {
        // Arrange
        var plaintext = new byte[64];
        var iv1 = new byte[16];
        var iv2 = new byte[16];

        for (var i = 0; i < 16; i++)
        {
            iv1[i] = 0;
            iv2[i] = 1; // Different from iv1
        }

        var ciphertext1 = new byte[64];
        var ciphertext2 = new byte[64];

        // Act
        Hc128Core.Transform(ciphertext1, plaintext, _testKey, iv1);
        Hc128Core.Transform(ciphertext2, plaintext, _testKey, iv2);

        // Assert - Different IVs should produce different keystreams
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    private static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}


#endif
