using HeroCrypt.Cryptography.Symmetric.Rabbit;
using System.Text;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for Rabbit stream cipher implementation
/// Based on RFC 4503 test vectors
/// </summary>
public class RabbitTests
{
    private readonly byte[] _testKey = new byte[16];
    private readonly byte[] _testIv = new byte[8];
    private readonly byte[] _testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public RabbitTests()
    {
        // Initialize test key and IV with predictable values
        for (var i = 0; i < _testKey.Length; i++)
            _testKey[i] = (byte)(i + 1);
        for (var i = 0; i < _testIv.Length; i++)
            _testIv[i] = (byte)(i + 50);
    }

    [Fact]
    public void Rabbit_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        RabbitCore.Transform(ciphertext, plaintext, _testKey, _testIv);

        // Act - Decrypt (Rabbit is symmetric)
        RabbitCore.Transform(decrypted, ciphertext, _testKey, _testIv);

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
        RabbitCore.Transform(ciphertext, plaintext, _testKey, _testIv);
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
            RabbitCore.Transform(ciphertext, plaintext, invalidKey, _testIv));
        Assert.Contains("16 bytes", ex.Message);
    }

    [Fact]
    public void Transform_InvalidIvSize_ThrowsException()
    {
        // Arrange
        var invalidIv = new byte[16]; // Should be 8 bytes
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            RabbitCore.Transform(ciphertext, plaintext, _testKey, invalidIv));
        Assert.Contains("8 bytes", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length - 1]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            RabbitCore.Transform(ciphertext, plaintext, _testKey, _testIv));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void Transform_DifferentIvs_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length];
        var ciphertext2 = new byte[plaintext.Length];
        var iv1 = new byte[8];
        var iv2 = new byte[8];

        for (var i = 0; i < 8; i++)
        {
            iv1[i] = (byte)i;
            iv2[i] = (byte)(i + 100);
        }

        // Act
        RabbitCore.Transform(ciphertext1, plaintext, _testKey, iv1);
        RabbitCore.Transform(ciphertext2, plaintext, _testKey, iv2);

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
        RabbitCore.Transform(ciphertext1, plaintext, key1, _testIv);
        RabbitCore.Transform(ciphertext2, plaintext, key2, _testIv);

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
        RabbitCore.Transform(ciphertext, largeData, _testKey, _testIv);
        RabbitCore.Transform(decrypted, ciphertext, _testKey, _testIv);

        // Assert
        Assert.Equal(largeData, decrypted);
        Assert.NotEqual(largeData, ciphertext);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        RabbitCore.ValidateParameters(_testKey, _testIv);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            RabbitCore.ValidateParameters(invalidKey, _testIv));
    }

    [Fact]
    public void GetMaxPlaintextLength_ReturnsValidValue()
    {
        // Act
        var maxLength = RabbitCore.GetMaxPlaintextLength();

        // Assert
        Assert.True(maxLength > 0);
        Assert.True(maxLength > 1024L * 1024 * 1024); // Should be very large
    }

    /// <summary>
    /// RFC 4503 Appendix A.1 - Test Vector 1
    /// Testing without IV Setup (key-only mode)
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector1_ZeroKey_Success()
    {
        // Arrange - Zero key, NO IV (key-only mode per RFC 4503 Appendix A.1)
        var key = new byte[16]; // All zeros
        var iv = Array.Empty<byte>();   // Empty IV = key-only mode
        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "02F74A1C26456BF5ECD6A536F05457B1" +
            "A78AC689476C697B390C9CC515D8E888" +
            "96D6731688D168DA51D40C70C3A116F4");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A.2 - Test Vector 2
    /// Testing without IV Setup (key-only mode)
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector2_SequentialKey_Success()
    {
        // Arrange - Sequential key: 0x00, 0x01, 0x02, ..., 0x0F, NO IV
        var key = new byte[16];
        for (var i = 0; i < 16; i++)
            key[i] = (byte)i;

        var iv = Array.Empty<byte>(); // Empty IV = key-only mode per RFC 4503 Appendix A.2
        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "9C51E28784C37FE9A127F63EC8F32D3D" +
            "19FC5485AA53BF96885B40F461CD76F5" +
            "5E4C4D20203BE58A5043DBFB5A087C0D");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A test - zero key with zero IV
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector3_ZeroKeyZeroIv_Success()
    {
        // Arrange - Zero key, zero IV
        var key = new byte[16]; // All zeros
        var iv = new byte[8];   // All zeros

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "ED B7 05 67 37 5D CD 7C D8 95 54 F8 5E 27 A7 C6" +
            "8D 4A DC 70 32 29 8F 7B D4 EF F5 04 AC A6 29 5F" +
            "66 8F BF 47 8A DB 2B E5 1E 6C DE 29 2B 82 DE 2A");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A.4 - Test Vector 4
    /// IV setup with sequential key and IV
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector4_SequentialKeyAndIv_Success()
    {
        // Arrange - Sequential key and IV
        var key = new byte[16];
        for (var i = 0; i < 16; i++)
            key[i] = (byte)i;

        var iv = new byte[8];
        for (var i = 0; i < 8; i++)
            iv[i] = (byte)(7 - i); // 0x07, 0x06, ..., 0x00

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "E8 1B 26 F3 70 99 C6 1C 7C 24 D3 1E 98 2D F2 FE" +
            "72 07 1F A8 B4 81 9F 82 4C 70 FB 4E 90 5D 6C 6C" +
            "F4 F9 60 DD 61 DD 27 6D 86 6D 9E 49 51 D1 89 C2");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A.5 - Test Vector 5
    /// Testing without IV Setup (key-only mode with alternating pattern)
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector5_AlternatingKey_Success()
    {
        // Arrange - Alternating 0xAA pattern, NO IV
        var key = new byte[16];
        for (var i = 0; i < 16; i++)
            key[i] = 0xAA;

        var iv = Array.Empty<byte>(); // Empty IV = key-only mode
        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "E5 04 0C B4 0C B4 5D 7C 2D 99 24 08 33 E7 13 2C" +
            "35 58 EE 45 41 5D 7E 6B 2B 38 9B 3C 38 92 ED E8" +
            "F7 81 1A A4 E5 FE 5D 88 5B 02 69 B0 DA F1 B8 8B");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A.6 - Test Vector 6
    /// IV setup with alternating pattern
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector6_AlternatingIv_Success()
    {
        // Arrange - Zero key, alternating 0x55 IV
        var key = new byte[16]; // All zeros
        var iv = new byte[8];
        for (var i = 0; i < 8; i++)
            iv[i] = 0x55;

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "F0 53 12 95 AB F9 C8 82 6F 41 7E 98 12 BA C5 A2" +
            "2E B5 FF 96 77 D2 40 E9 25 90 A9 F0 E7 C6 3F 3A" +
            "B6 71 58 EE 1C 8F 6F 27 DE 48 C4 0D CB F9 F5 A0");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
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
