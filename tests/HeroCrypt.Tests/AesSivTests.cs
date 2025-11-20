using System.Text;
using HeroCrypt.Cryptography.Primitives.Cipher.Aead;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for AES-SIV (Synthetic IV) implementation
/// Based on RFC 5297 test vectors
/// </summary>
public class AesSivTests
{
    private readonly byte[] _testKey256 = new byte[64]; // 32+32 for MAC+CTR
    private readonly byte[] _testNonce = new byte[12];
    private readonly byte[] _testPlaintext = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    public AesSivTests()
    {
        // Initialize test key and nonce with predictable values
        for (var i = 0; i < _testKey256.Length; i++)
        {
            _testKey256[i] = (byte)(i + 1);
        }
        for (var i = 0; i < _testNonce.Length; i++)
        {
            _testNonce[i] = (byte)(i + 50);
        }
    }

    [Fact]
    public void AesSiv_EncryptDecrypt_RoundTrip_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, Array.Empty<byte>());

        // Act - Decrypt
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, Array.Empty<byte>());

        // Assert
        Assert.Equal(plaintext.Length + AesSivCore.SivSize, encryptedLength);
        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
        Assert.NotEqual(plaintext, ciphertext.AsSpan(AesSivCore.SivSize, plaintext.Length).ToArray());
    }

    [Fact]
    public void AesSiv_WithAssociatedData_Success()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var associatedData = Encoding.UTF8.GetBytes("metadata");
        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, associatedData);

        // Act - Decrypt
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, associatedData);

        // Assert
        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void AesSiv_WrongAssociatedData_AuthenticationFails()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var associatedData = Encoding.UTF8.GetBytes("metadata");
        var wrongAssociatedData = Encoding.UTF8.GetBytes("wrong");
        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt with correct AAD
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, associatedData);

        // Act - Decrypt with wrong AAD
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, wrongAssociatedData);

        // Assert - Should fail authentication
        Assert.Equal(-1, decryptedLength);
    }

    [Fact]
    public void AesSiv_TamperedCiphertext_AuthenticationFails()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, Array.Empty<byte>());

        // Tamper with ciphertext
        ciphertext[AesSivCore.SivSize + 5] ^= 0xFF;

        // Act - Decrypt
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, Array.Empty<byte>());

        // Assert - Should fail authentication
        Assert.Equal(-1, decryptedLength);
    }

    [Fact]
    public void AesSiv_TamperedSiv_AuthenticationFails()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, Array.Empty<byte>());

        // Tamper with SIV (tag)
        ciphertext[5] ^= 0xFF;

        // Act - Decrypt
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, Array.Empty<byte>());

        // Assert - Should fail authentication
        Assert.Equal(-1, decryptedLength);
    }

    [Fact]
    public void Transform_EmptyInput_Success()
    {
        // Arrange
        var plaintext = Array.Empty<byte>();
        var ciphertext = new byte[AesSivCore.SivSize];
        var decrypted = Array.Empty<byte>();

        // Act - Encrypt
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, Array.Empty<byte>());

        // Act - Decrypt
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, Array.Empty<byte>());

        // Assert
        Assert.Equal(AesSivCore.SivSize, encryptedLength);
        Assert.Equal(0, decryptedLength);
    }

    [Fact]
    public void Transform_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Invalid - must be 32, 48, or 64 bytes
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AesSivCore.Encrypt(ciphertext, plaintext, invalidKey, _testNonce, Array.Empty<byte>()));
        Assert.Contains("Key must be", ex.Message);
    }

    [Fact]
    public void Transform_OutputBufferTooSmall_ThrowsException()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext = new byte[plaintext.Length]; // Too small (missing space for SIV)

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AesSivCore.Encrypt(ciphertext, plaintext, _testKey256, _testNonce, Array.Empty<byte>()));
        Assert.Contains("too small", ex.Message);
    }

    [Fact]
    public void Decrypt_CiphertextTooShort_ThrowsException()
    {
        // Arrange
        var ciphertext = new byte[AesSivCore.SivSize - 1]; // Too short
        var plaintext = Array.Empty<byte>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AesSivCore.Decrypt(plaintext, ciphertext, _testKey256, _testNonce, Array.Empty<byte>()));
        Assert.Contains("too short", ex.Message);
    }

    [Fact]
    public void AesSiv_DifferentNonces_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length + AesSivCore.SivSize];
        var ciphertext2 = new byte[plaintext.Length + AesSivCore.SivSize];
        var nonce1 = new byte[12];
        var nonce2 = new byte[12];

        for (var i = 0; i < 12; i++)
        {
            nonce1[i] = (byte)i;
            nonce2[i] = (byte)(i + 100);
        }

        // Act
        AesSivCore.Encrypt(ciphertext1, plaintext, _testKey256, nonce1, Array.Empty<byte>());
        AesSivCore.Encrypt(ciphertext2, plaintext, _testKey256, nonce2, Array.Empty<byte>());

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void AesSiv_DifferentKeys_ProduceDifferentCiphertexts()
    {
        // Arrange
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length + AesSivCore.SivSize];
        var ciphertext2 = new byte[plaintext.Length + AesSivCore.SivSize];
        var key1 = new byte[64];
        var key2 = new byte[64];

        for (var i = 0; i < 64; i++)
        {
            key1[i] = (byte)i;
            key2[i] = (byte)(i + 100);
        }

        // Act
        AesSivCore.Encrypt(ciphertext1, plaintext, key1, _testNonce, Array.Empty<byte>());
        AesSivCore.Encrypt(ciphertext2, plaintext, key2, _testNonce, Array.Empty<byte>());

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void AesSiv_NonceMisuseResistance_SameNonce_StillSecure()
    {
        // Arrange - AES-SIV is designed to be safe even if nonce is reused
        var plaintext1 = Encoding.UTF8.GetBytes("Message 1");
        var plaintext2 = Encoding.UTF8.GetBytes("Message 2");
        var sameNonce = new byte[12];
        var ciphertext1 = new byte[plaintext1.Length + AesSivCore.SivSize];
        var ciphertext2 = new byte[plaintext2.Length + AesSivCore.SivSize];

        // Act - Use same nonce for both encryptions
        AesSivCore.Encrypt(ciphertext1, plaintext1, _testKey256, sameNonce, Array.Empty<byte>());
        AesSivCore.Encrypt(ciphertext2, plaintext2, _testKey256, sameNonce, Array.Empty<byte>());

        // Assert - Ciphertexts should still be different due to different plaintexts
        Assert.NotEqual(ciphertext1.AsSpan(0, Math.Min(ciphertext1.Length, ciphertext2.Length)).ToArray(),
                        ciphertext2.AsSpan(0, Math.Min(ciphertext1.Length, ciphertext2.Length)).ToArray());

        // Decrypt both successfully
        var decrypted1 = new byte[plaintext1.Length];
        var decrypted2 = new byte[plaintext2.Length];
        Assert.Equal(plaintext1.Length, AesSivCore.Decrypt(decrypted1, ciphertext1, _testKey256, sameNonce, Array.Empty<byte>()));
        Assert.Equal(plaintext2.Length, AesSivCore.Decrypt(decrypted2, ciphertext2, _testKey256, sameNonce, Array.Empty<byte>()));
        Assert.Equal(plaintext1, decrypted1);
        Assert.Equal(plaintext2, decrypted2);
    }

    [Fact]
    public void AesSiv_Deterministic_SameInputs_ProduceSameCiphertext()
    {
        // Arrange - AES-SIV is deterministic (same inputs = same output)
        var plaintext = _testPlaintext;
        var ciphertext1 = new byte[plaintext.Length + AesSivCore.SivSize];
        var ciphertext2 = new byte[plaintext.Length + AesSivCore.SivSize];

        // Act - Encrypt same plaintext twice with same key and nonce
        AesSivCore.Encrypt(ciphertext1, plaintext, _testKey256, _testNonce, Array.Empty<byte>());
        AesSivCore.Encrypt(ciphertext2, plaintext, _testKey256, _testNonce, Array.Empty<byte>());

        // Assert - Should produce identical ciphertext
        Assert.Equal(ciphertext1, ciphertext2);
    }

    [Fact]
    public void LargeData_EncryptsCorrectly()
    {
        // Arrange - 1MB of data
        var largeData = new byte[1024 * 1024];
        new Random(42).NextBytes(largeData);
        var ciphertext = new byte[largeData.Length + AesSivCore.SivSize];
        var decrypted = new byte[largeData.Length];

        // Act
        var encryptedLength = AesSivCore.Encrypt(ciphertext, largeData, _testKey256, _testNonce, Array.Empty<byte>());
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), _testKey256, _testNonce, Array.Empty<byte>());

        // Assert
        Assert.Equal(largeData.Length + AesSivCore.SivSize, encryptedLength);
        Assert.Equal(largeData.Length, decryptedLength);
        Assert.Equal(largeData, decrypted);
    }

    [Fact]
    public void ValidateParameters_ValidInput_DoesNotThrow()
    {
        // Act & Assert - Should not throw
        AesSivCore.ValidateParameters(_testKey256, _testNonce);
    }

    [Fact]
    public void ValidateParameters_InvalidKey_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[16]; // Invalid - must be 32, 48, or 64 bytes

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            AesSivCore.ValidateParameters(invalidKey, _testNonce));
    }

    /// <summary>
    /// RFC 5297 Appendix A - Test Vector 1
    /// AES-SIV-256 with associated data
    /// </summary>
    [Fact]
    [Trait("Category", "Compliance")]
    public void Rfc5297_TestVector1_Success()
    {
        // Arrange - From RFC 5297 Appendix A.1
        var key = HexToBytes(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" +
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        var associatedData = HexToBytes(
            "101112131415161718191a1b1c1d1e1f" +
            "2021222324252627");

        var plaintext = HexToBytes(
            "112233445566778899aabbccddee");

        var expectedCiphertext = HexToBytes(
            "85632d07c6e8f37f950acd320a2ecc93" + // SIV
            "40c02b9690c4dc04daef7f6afe5c");     // Ciphertext

        var ciphertext = new byte[plaintext.Length + AesSivCore.SivSize];
        var decrypted = new byte[plaintext.Length];

        // Act - Encrypt
        var encryptedLength = AesSivCore.Encrypt(ciphertext, plaintext, key, Array.Empty<byte>(), associatedData);

        // Assert encryption
        Assert.Equal(expectedCiphertext.Length, encryptedLength);
        Assert.Equal(expectedCiphertext, ciphertext.AsSpan(0, encryptedLength).ToArray());

        // Act - Decrypt
        var decryptedLength = AesSivCore.Decrypt(decrypted, ciphertext.AsSpan(0, encryptedLength), key, Array.Empty<byte>(), associatedData);

        // Assert decryption
        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
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





