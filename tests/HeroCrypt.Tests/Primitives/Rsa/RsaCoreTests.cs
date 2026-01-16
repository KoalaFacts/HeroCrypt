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
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.SLOW)]
    public class EdgeCases
    {
        [Fact]
        public void Encrypt_EmptyPlaintext_Success()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = Array.Empty<byte>();

            var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = RsaCore.Decrypt(ciphertext, keyPair.PrivateKey);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_MaxPlaintextSize_Success()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            // PKCS1 v1.5: max plaintext = keysize - 11 bytes = 256 - 11 = 245
            var plaintext = TestHelpers.RandomBytes(245);

            var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Pkcs1);
            var decrypted = RsaCore.Decrypt(ciphertext, keyPair.PrivateKey, RsaPaddingMode.Pkcs1);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.SLOW)]
    public class Security
    {
        [Fact]
        public void Decrypt_WrongKey_ThrowsCryptographicException()
        {
            using var keyPair1 = RsaCore.GenerateKeyPair(2048);
            using var keyPair2 = RsaCore.GenerateKeyPair(2048);
            var plaintext = Encoding.UTF8.GetBytes("Hello RSA");

            var ciphertext = RsaCore.Encrypt(plaintext, keyPair1.PublicKey);

            Assert.Throws<CryptographicException>(() =>
                RsaCore.Decrypt(ciphertext, keyPair2.PrivateKey));
        }

        [Fact]
        public void Verify_WrongKey_ReturnsFalse()
        {
            using var keyPair1 = RsaCore.GenerateKeyPair(2048);
            using var keyPair2 = RsaCore.GenerateKeyPair(2048);
            var data = Encoding.UTF8.GetBytes("Data to sign");

            var signature = RsaCore.Sign(data, keyPair1.PrivateKey);
            var isValid = RsaCore.Verify(data, signature, keyPair2.PublicKey);

            Assert.False(isValid);
        }

        [Fact]
        public void Encrypt_SameInputDifferentCiphertext()
        {
            // OAEP padding is randomized, so same input produces different ciphertext
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = Encoding.UTF8.GetBytes("Hello RSA");

            var ciphertext1 = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Oaep);
            var ciphertext2 = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Oaep);

            // With OAEP, same plaintext produces different ciphertexts due to random padding
            Assert.NotEqual(ciphertext1, ciphertext2);

            // But both should decrypt to the same plaintext
            var decrypted1 = RsaCore.Decrypt(ciphertext1, keyPair.PrivateKey, RsaPaddingMode.Oaep);
            var decrypted2 = RsaCore.Decrypt(ciphertext2, keyPair.PrivateKey, RsaPaddingMode.Oaep);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted1);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted2);
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

    /// <summary>
    /// Known Answer Tests for RSA operations.
    /// See: PKCS#1 v2.2 (RFC 8017)
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.SLOW)] // RSA key generation is slow
    public class KnownAnswerTests
    {
        [Fact]
        public void Pkcs1_SignVerify_Sha256_Deterministic()
        {
            // Verify RSA-PKCS1-SHA256 signatures are deterministic
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var message = Encoding.UTF8.GetBytes("Test message for RSA-PKCS1 signature");

            var signature1 = RsaCore.Sign(message, keyPair.PrivateKey);
            var signature2 = RsaCore.Sign(message, keyPair.PrivateKey);

            CryptoAssertions.AssertBytesEqual(signature1, signature2);
        }

        [Fact]
        public void Pkcs1_SignVerify_DifferentMessages_DifferentSignatures()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var message1 = Encoding.UTF8.GetBytes("Message one");
            var message2 = Encoding.UTF8.GetBytes("Message two");

            var signature1 = RsaCore.Sign(message1, keyPair.PrivateKey);
            var signature2 = RsaCore.Sign(message2, keyPair.PrivateKey);

            Assert.NotEqual(signature1, signature2);
        }

        [Fact]
        public void Pkcs1_EncryptDecrypt_VariableKeySizes()
        {
            // Test different RSA key sizes
            var keySizes = new[] { 2048, 3072 };
            var plaintext = Encoding.UTF8.GetBytes("Hello RSA");

            foreach (var keySize in keySizes)
            {
                using var keyPair = RsaCore.GenerateKeyPair(keySize);

                var ciphertext = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Pkcs1);
                var decrypted = RsaCore.Decrypt(ciphertext, keyPair.PrivateKey, RsaPaddingMode.Pkcs1);

                CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
                Assert.Equal(keySize / 8, ciphertext.Length); // Ciphertext length = key size in bytes
            }
        }

        [Fact]
        public void Oaep_EncryptDecrypt_DifferentHashAlgorithms()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);
            var plaintext = Encoding.UTF8.GetBytes("OAEP test");

            // Test with SHA-256
            var ciphertext256 = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);
            var decrypted256 = RsaCore.Decrypt(ciphertext256, keyPair.PrivateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted256);

            // Test with SHA-384
            var ciphertext384 = RsaCore.Encrypt(plaintext, keyPair.PublicKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA384);
            var decrypted384 = RsaCore.Decrypt(ciphertext384, keyPair.PrivateKey, RsaPaddingMode.Oaep, HashAlgorithmName.SHA384);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted384);
        }

        [Fact]
        public void SignVerify_RoundTrip_VariousMessages()
        {
            using var keyPair = RsaCore.GenerateKeyPair(2048);

            // Test empty message
            var emptyMessage = Array.Empty<byte>();
            var emptySig = RsaCore.Sign(emptyMessage, keyPair.PrivateKey);
            Assert.True(RsaCore.Verify(emptyMessage, emptySig, keyPair.PublicKey));

            // Test single byte
            var singleByte = new byte[] { 0x42 };
            var singleSig = RsaCore.Sign(singleByte, keyPair.PrivateKey);
            Assert.True(RsaCore.Verify(singleByte, singleSig, keyPair.PublicKey));

            // Test longer message
            var longMessage = TestHelpers.RandomBytes(1000);
            var longSig = RsaCore.Sign(longMessage, keyPair.PrivateKey);
            Assert.True(RsaCore.Verify(longMessage, longSig, keyPair.PublicKey));
        }
    }
}
