using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Rsa;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Rsa;

/// <summary>
/// Comprehensive tests for RSA Core implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class RsaCoreTests
{
    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)] // RSA KeyGen is slow
    public class BasicFunctionality
    {
        [Fact]
        public void GenerateKeyPair_ValidKeySize_ReturnsKeys()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);

            Assert.NotNull(keyPair);
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);

            // Basic parameter checks
            Assert.NotNull(keyPair.PublicKey.Modulus);
            Assert.NotNull(keyPair.PublicKey.Exponent);
            Assert.NotNull(keyPair.PrivateKey.D);
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = Encoding.UTF8.GetBytes("Hello RSA World!");

            var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = RsaCore.Decrypt(ciphertext, keyPair.PrivateKey);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void SignVerify_RoundTrip_Success()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var data = Encoding.UTF8.GetBytes("Data to sign");

            var signature = RsaCore.Sign(data, keyPair.PrivateKey);
            var isValid = RsaCore.Verify(data, signature, keyPair.PublicKey);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_InvalidSignature_ReturnsFalse()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var data = Encoding.UTF8.GetBytes("Data to sign");

            var signature = RsaCore.Sign(data, keyPair.PrivateKey);
            signature[0] ^= 0xFF; // Corrupt signature

            var isValid = RsaCore.Verify(data, signature, keyPair.PublicKey);

            Assert.False(isValid);
        }
    }

    /// <summary>
    /// OAEP Padding tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class OaepPadding
    {
        [Fact]
        public void EncryptDecrypt_OaepSha256_Success()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = TestHelpers.RandomBytes(32);

            var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);
            var decrypted = RsaCore.Decrypt(ciphertext, keyPair.PrivateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_OaepSha512_Success()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = TestHelpers.RandomBytes(32);

            var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA512);
            var decrypted = RsaCore.Decrypt(ciphertext, keyPair.PrivateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA512);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        [Fact]
        public void Decrypt_InvalidPadding_ThrowsCryptographicException()
        {
            // Note: Generating keys is slow, but necessary for valid inputs. 
            // Mocking internal classes might be hard, so using real generation.
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = new byte[16];

            // Encrypt with PKCS1
            var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Pkcs1);

            // Try to decrypt with OAEP (should fail)
            Assert.Throws<CryptographicException>(() =>
                RsaCore.Decrypt(ciphertext, keyPair.PrivateKey, RsaPaddingMode.Oaep));
        }
    }
}
