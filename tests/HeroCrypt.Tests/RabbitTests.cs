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
            "B15754F036A5D6ECF56B45261C4AF702" +
            "88E8D815C59C0C397B696C4789C68AA7" +
            "F416A1C3700CD451DA68D1881673D696");

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
        // Arrange - Key: 0x912813292E3D36FE3BFC62F1DC51C3AC (reversed byte order), NO IV
        var key = HexToBytes("ACC351DCF162FC3BFE363D2E29132891");
        var iv = Array.Empty<byte>(); // Empty IV = key-only mode per RFC 4503 Appendix A.2

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "3D2DF3C83EF627A1E97FC38487E2519C" +
            "F576CD61F4405B8896BF53AA8554FC19" +
            "E5547473FBDB43508AE53B20204D4C5E");

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
            "C6A7275EF85495D87CCD5D376705B7ED" +
            "5F29A6AC04F5EFD47B8F293270DC4A8D" +
            "2ADE822B29DE6C1EE52BDB8A47BF8F66");

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
        // Arrange - Zero key, IV = 0xC373F575C1267E59 (reversed byte order)
        var key = new byte[16]; // All zeros
        var iv = HexToBytes("597E26C175F573C3");

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "1FCD4EB9580012E2E0DCCC9222017D6D" +
            "A75F4E10D12125017B2499FFED936F2E" +
            "EBC112C393E738392356BDD012029BA7");

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
        // Arrange - Zero key, IV = 0xA6EB561AD2F41727 (reversed byte order)
        var key = new byte[16]; // All zeros
        var iv = HexToBytes("2717F4D21A56EBA6");

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "445AD8C805858DBF70B6AF23A151104D" +
            "96C8F27947F42C5BAEAE67C6ACC35B03" +
            "9FCBFC895FA71C17313DF034F01551CB");

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
        // Arrange - Key: 0x8395741587E0C733E9E9AB01C09B0043 (reversed byte order), NO IV
        var key = HexToBytes("43009BC001ABE9E933C7E08715749583");
        var iv = Array.Empty<byte>(); // Empty IV = key-only mode

        var plaintext = new byte[48]; // 3 blocks of zeros

        var expectedCiphertext = HexToBytes(
            "0CB10DCDA041CDAC32EB5CFD02D0609B" +
            "95FC9FCA0F17015A7B7092114CFF3EAD" +
            "9649E5DE8BFC7F3F924147AD3A947428");

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


