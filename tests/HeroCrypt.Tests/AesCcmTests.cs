using System.Text;
using HeroCrypt.Cryptography.Primitives.Cipher.Aead;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for AES-CCM (Counter with CBC-MAC) implementation using RFC 3610 vectors and validation cases.
/// </summary>
public class AesCcmTests
{
    #region RFC 3610 Test Vectors

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public void Rfc3610_TestVector1_EncryptDecrypt_Success()
    {
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000003020100A0A1A2A3A4A5");
        var plaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        var associatedData = Convert.FromHexString("0001020304050607");
        var expectedCiphertext = Convert.FromHexString("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0");

        var ciphertext = new byte[plaintext.Length + 8];
        var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData, tagSize: 8);

        Assert.Equal(plaintext.Length + 8, actualLength);
        Assert.Equal(expectedCiphertext, ciphertext);

        var decrypted = new byte[plaintext.Length];
        var decryptedLength = AesCcmCore.Decrypt(decrypted, ciphertext, key, nonce, associatedData, tagSize: 8);

        Assert.Equal(plaintext.Length, decryptedLength);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public void Rfc3610_TestVector2_Encrypt_Success()
    {
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000004030201A0A1A2A3A4A5");
        var plaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        var associatedData = Convert.FromHexString("0001020304050607");
        var expectedCiphertext = Convert.FromHexString("72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916");

        var ciphertext = new byte[plaintext.Length + 8];
        var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData, tagSize: 8);

        Assert.Equal(plaintext.Length + 8, actualLength);
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
    public void Rfc3610_TestVector3_Encrypt_Success()
    {
        var key = Convert.FromHexString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        var nonce = Convert.FromHexString("00000005040302A0A1A2A3A4A5");
        var plaintext = Convert.FromHexString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
        var associatedData = Convert.FromHexString("0001020304050607");
        var expectedCiphertext = Convert.FromHexString("51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0C5");

        var ciphertext = new byte[plaintext.Length + 8];
        var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData, tagSize: 8);

        Assert.Equal(plaintext.Length + 8, actualLength);
        Assert.Equal(expectedCiphertext, ciphertext);
    }

    #endregion

    #region Parameter Validation

    [Fact]
    public void AesCcm_InvalidKeySize_Throws()
    {
        var invalidKey = new byte[12];
        var nonce = new byte[13];
        var plaintext = new byte[10];
        var ciphertext = new byte[26];

        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, invalidKey, nonce, []));
    }

    [Fact]
    public void AesCcm_NonceTooShort_Throws()
    {
        var key = new byte[16];
        var nonce = new byte[6];
        var plaintext = new byte[10];
        var ciphertext = new byte[26];

        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, []));
    }

    [Fact]
    public void AesCcm_NonceTooLong_Throws()
    {
        var key = new byte[16];
        var nonce = new byte[14];
        var plaintext = new byte[10];
        var ciphertext = new byte[26];

        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, []));
    }

    [Fact]
    public void AesCcm_InvalidTagSize_Throws()
    {
        var key = new byte[16];
        var nonce = new byte[13];
        var plaintext = new byte[10];
        var ciphertext = new byte[20];

        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, [], tagSize: 7));

        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, [], tagSize: 2));

        Assert.Throws<ArgumentException>(() =>
            AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, [], tagSize: 18));
    }

    [Fact]
    public void AesCcm_GetMaxPlaintextLength_ReturnsExpected()
    {
        Assert.Equal((1L << 16) - 1, AesCcmCore.GetMaxPlaintextLength(13));
        Assert.Equal((1L << 24) - 1, AesCcmCore.GetMaxPlaintextLength(12));
        Assert.Equal((1L << 32) - 1, AesCcmCore.GetMaxPlaintextLength(11));
    }

    #endregion

    #region Variable Tag Sizes

    [Fact]
    public void AesCcm_VariableTagSizes_Work()
    {
        var key = new byte[16];
        var nonce = new byte[13];
        var plaintext = Encoding.UTF8.GetBytes("Tag size test");
        var tagSizes = new[] { 4, 6, 8, 10, 12, 14, 16 };

        foreach (var tagSize in tagSizes)
        {
            var ciphertext = new byte[plaintext.Length + tagSize];
            var actualLength = AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, [], tagSize);

            var decrypted = new byte[plaintext.Length];
            var decryptedLength = AesCcmCore.Decrypt(decrypted, ciphertext, key, nonce, [], tagSize);

            Assert.Equal(plaintext.Length + tagSize, actualLength);
            Assert.Equal(plaintext.Length, decryptedLength);
            Assert.Equal(plaintext, decrypted);
        }
    }

    #endregion
}
