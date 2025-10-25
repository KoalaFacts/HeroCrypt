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
    /// Testing without IV Setup
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector2_SpecificKey_Success()
    {
        // Arrange - Key: 0x912813292E3D36FE3BFC62F1DC51C3AC (little-endian), NO IV
        var key = HexToBytes("ACC351DCF162FC3BFE363D2E29132891");
        var iv = Array.Empty<byte>(); // Empty IV = key-only mode per RFC 4503 Appendix A.1

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "9C51E28784C37FE9A127F63EC8F32D3D" +
            "19FC5485AA53BF96885B40F461CD76F5" +
            "5E4C4D20203BE58A5043DBFB737454E5");

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
    /// RFC 4503 Appendix A - Test Vector 4
    /// Testing with IV Setup
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector4_ZeroKeyIv1_Success()
    {
        // Arrange - Zero key, IV = 0xC373F575C1267E59 (little-endian)
        var key = new byte[16]; // All zeros
        var iv = HexToBytes("597E26C175F573C3");

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "6D7D012292CCDCE0E2120058B94ECD1F" +
            "2E6F93EDFF99247B012521D1104E5FA7" +
            "A79B0212D0BD56233938E793C312C1EB");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A - Test Vector 5
    /// Testing with IV Setup
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector5_ZeroKeyIv2_Success()
    {
        // Arrange - Zero key, IV = 0xA6EB561AD2F41727 (little-endian)
        var key = new byte[16]; // All zeros
        var iv = HexToBytes("2717F4D21A56EBA6");

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "4D1051A123AFB670BF8D8505C8D85A44" +
            "035BC3ACC667AEAE5B2CF44779F2C896" +
            "CB5115F034F03D31171CA75F89FCCB9F");

        var ciphertext = new byte[plaintext.Length];

        // Act
        RabbitCore.Transform(ciphertext, plaintext, key, iv);

        // Assert
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    /// <summary>
    /// RFC 4503 Appendix A - Test Vector 6
    /// Testing without IV Setup
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc4503_TestVector6_SpecificKey2_Success()
    {
        // Arrange - Key: 0x8395741587E0C733E9E9AB01C09B0043 (little-endian), NO IV
        var key = HexToBytes("43009BC001ABE9E933C7E08715749583");
        var iv = Array.Empty<byte>(); // Empty IV = key-only mode

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "9B60D002FD5CEB32ACCD41A0CD0DB10C" +
            "AD3EFF4C1192707B5A01170FCA9FFC95" +
            "2874943AAD4741923F7FFC8BDEE54996");

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
