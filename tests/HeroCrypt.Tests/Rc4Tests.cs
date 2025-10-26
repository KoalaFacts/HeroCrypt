using HeroCrypt.Cryptography.Symmetric.Rc4;
using System.Text;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for RC4 stream cipher (legacy compatibility only)
/// </summary>
#pragma warning disable CS0618 // Type or member is obsolete
public class Rc4Tests
{
    private readonly byte[] _testKey = Encoding.UTF8.GetBytes("TestKey12345678"); // 16 bytes
    private readonly byte[] _testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    [Fact]
    public void Transform_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        Rc4Core.Transform(ciphertext, plaintext, _testKey, dropBytes: 0);

        // Act - Decrypt (RC4 is symmetric)
        Rc4Core.Transform(decrypted, ciphertext, _testKey, dropBytes: 0);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void Transform_WithDropBytes_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];
        var dropBytes = 3072; // Recommended drop bytes

        // Act - Encrypt
        Rc4Core.Transform(ciphertext, plaintext, _testKey, dropBytes);

        // Act - Decrypt
        Rc4Core.Transform(decrypted, ciphertext, _testKey, dropBytes);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Transform_DifferentDropBytes_ProducesDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];

        // Act
        Rc4Core.Transform(ciphertext1, plaintext, _testKey, dropBytes: 0);
        Rc4Core.Transform(ciphertext2, plaintext, _testKey, dropBytes: 256);

        // Assert - Different drop bytes should produce different ciphertexts
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_WithDifferentKeys_ProducesDifferentCiphertexts()
    {
        // Arrange
        var key1 = Encoding.UTF8.GetBytes("Key1234567890123");
        var key2 = Encoding.UTF8.GetBytes("DifferentKey1234");
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];

        // Act
        Rc4Core.Transform(ciphertext1, plaintext, key1, dropBytes: 0);
        Rc4Core.Transform(ciphertext2, plaintext, key2, dropBytes: 0);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_EmptyInput_Success()
    {
        // Arrange
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        // Act & Assert - Should handle empty input gracefully
        Rc4Core.Transform(ciphertext, plaintext, _testKey, dropBytes: 0);
    }

    [Fact]
    public void Transform_SingleByte_Success()
    {
        // Arrange
        var plaintext = new byte[] { 0x42 };
        var ciphertext = new byte[1];
        var decrypted = new byte[1];

        // Act
        Rc4Core.Transform(ciphertext, plaintext, _testKey, dropBytes: 0);
        Rc4Core.Transform(decrypted, ciphertext, _testKey, dropBytes: 0);

        // Assert
        Assert.Equal(plaintext[0], decrypted[0]);
    }

    [Fact]
    public void Transform_LargeData_Success()
    {
        // Arrange - 1MB of data
        var largeData = new byte[1024 * 1024];
        new Random(42).NextBytes(largeData);
        var ciphertext = new byte[largeData.Length];
        var decrypted = new byte[largeData.Length];

        // Act
        Rc4Core.Transform(ciphertext, largeData, _testKey, dropBytes: 0);
        Rc4Core.Transform(decrypted, ciphertext, _testKey, dropBytes: 0);

        // Assert
        Assert.Equal(largeData, decrypted);
    }

    [Fact]
    public void Transform_MinimumKeySize_Success()
    {
        // Arrange - Minimum key size is 5 bytes
        var minKey = new byte[5] { 1, 2, 3, 4, 5 };
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Rc4Core.Transform(ciphertext, plaintext, minKey, dropBytes: 0);
        Rc4Core.Transform(decrypted, ciphertext, minKey, dropBytes: 0);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Transform_MaximumKeySize_Success()
    {
        // Arrange - Maximum key size is 256 bytes
        var maxKey = new byte[256];
        for (var i = 0; i < maxKey.Length; i++)
            maxKey[i] = (byte)i;

        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act
        Rc4Core.Transform(ciphertext, plaintext, maxKey, dropBytes: 0);
        Rc4Core.Transform(decrypted, ciphertext, maxKey, dropBytes: 0);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Transform_KeySizeTooSmall_ThrowsException()
    {
        // Arrange - Key must be at least 5 bytes
        var tooSmallKey = new byte[4];
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Rc4Core.Transform(ciphertext, plaintext, tooSmallKey, dropBytes: 0));
        Assert.Contains("between", ex.Message);
    }

    [Fact]
    public void Transform_KeySizeTooLarge_ThrowsException()
    {
        // Arrange - Key must be at most 256 bytes
        var tooLargeKey = new byte[257];
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Rc4Core.Transform(ciphertext, plaintext, tooLargeKey, dropBytes: 0));
        Assert.Contains("between", ex.Message);
    }

    [Fact]
    public void Transform_NegativeDropBytes_ThrowsException()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Rc4Core.Transform(ciphertext, plaintext, _testKey, dropBytes: -1));
        Assert.Contains("cannot be negative", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length - 1]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Rc4Core.Transform(ciphertext, plaintext, _testKey, dropBytes: 0));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        Rc4Core.ValidateParameters(_testKey, dropBytes: 0);
        Rc4Core.ValidateParameters(_testKey, dropBytes: 3072);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[3]; // Too small

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Rc4Core.ValidateParameters(invalidKey));
    }

    [Fact]
    public void IsSecureConfiguration_InsecureParameters_ReturnsFalse()
    {
        // Act & Assert
        Assert.False(Rc4Core.IsSecureConfiguration(keySize: 8, dropBytes: 0));
        Assert.False(Rc4Core.IsSecureConfiguration(keySize: 16, dropBytes: 0));
        Assert.False(Rc4Core.IsSecureConfiguration(keySize: 8, dropBytes: 3072));
    }

    [Fact]
    public void IsSecureConfiguration_MitigatedParameters_ReturnsTrue()
    {
        // Act - Even with mitigations, RC4 is not truly secure, but this checks if mitigations are applied
        var result = Rc4Core.IsSecureConfiguration(keySize: 16, dropBytes: 3072);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void GetSecurityWarning_ReturnsWarning()
    {
        // Act
        var warning = Rc4Core.GetSecurityWarning();

        // Assert
        Assert.Contains("broken", warning);
        Assert.Contains("legacy", warning);
    }

    [Fact]
    public void GetRecommendedDropBytes_ReturnsPositiveValue()
    {
        // Act
        var recommended = Rc4Core.GetRecommendedDropBytes();

        // Assert
        Assert.True(recommended > 0);
        Assert.Equal(3072, recommended);
    }

    [Fact]
    public void Transform_ConsistentOutput_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];

        // Act - Encrypt same plaintext twice
        Rc4Core.Transform(ciphertext1, plaintext, _testKey, dropBytes: 0);
        Rc4Core.Transform(ciphertext2, plaintext, _testKey, dropBytes: 0);

        // Assert - Should produce identical output
        Assert.Equal(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Transform_RFC_TestVector_Success()
    {
        // Arrange - Test vector from RFC 6229
        // Key: 0x0102030405 (5 bytes)
        // Keystream offset 0: 0xb2 0x39 0x63 0x05 0xf0 0x3d 0xc0 0x27
        var key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var plaintext = new byte[8];  // All zeros
        var ciphertext = new byte[8];

        // Act
        Rc4Core.Transform(ciphertext, plaintext, key, dropBytes: 0);

        // Assert - Compare with known keystream values
        Assert.Equal(0xb2, ciphertext[0]);
        Assert.Equal(0x39, ciphertext[1]);
        Assert.Equal(0x63, ciphertext[2]);
        Assert.Equal(0x05, ciphertext[3]);
        Assert.Equal(0xf0, ciphertext[4]);
        Assert.Equal(0x3d, ciphertext[5]);
        Assert.Equal(0xc0, ciphertext[6]);
        Assert.Equal(0x27, ciphertext[7]);
    }

    [Fact]
    public void Transform_AllZeroKey_ProducesDeterministicOutput()
    {
        // Arrange
        var zeroKey = new byte[16]; // All zeros
        var plaintext = new byte[64];
        var ciphertext1 = new byte[64];
        var ciphertext2 = new byte[64];

        // Act
        Rc4Core.Transform(ciphertext1, plaintext, zeroKey, dropBytes: 0);
        Rc4Core.Transform(ciphertext2, plaintext, zeroKey, dropBytes: 0);

        // Assert - Deterministic output
        Assert.Equal(ciphertext1, ciphertext2);
        Assert.NotEqual(plaintext, ciphertext1); // Should have encrypted
    }
}
#pragma warning restore CS0618 // Type or member is obsolete
