using HeroCrypt.Operations;
using HeroCrypt.Protocols.MessageExchange;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.MessageExchange;

#if !NETSTANDARD2_0

/// <summary>
/// Comprehensive tests for PgpBuilder hybrid encryption.
/// </summary>
public class PgpBuilderTests
{
    /// <summary>
    /// Tests for RSA key pair generation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyGenerationTests
    {
        [Fact]
        public void GenerateRsaKeyPair_Default_ReturnsValidKeyPair()
        {
            var builder = new PgpBuilder();

            var keyPair = builder.GenerateRsaKeyPair();

            Assert.NotNull(keyPair);
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);
            Assert.Contains("-----BEGIN PUBLIC KEY-----", keyPair.PublicKey);
            Assert.Contains("-----BEGIN PRIVATE KEY-----", keyPair.PrivateKey);
        }

        [Fact]
        public void GenerateRsaKeyPair_With4096Bits_ReturnsValidKeyPair()
        {
            var builder = new PgpBuilder().WithKeySize(4096);

            var keyPair = builder.GenerateRsaKeyPair();

            Assert.NotNull(keyPair);
            Assert.Contains("-----BEGIN PUBLIC KEY-----", keyPair.PublicKey);
        }

        [Fact]
        public void GenerateRsaKeyPair_TooSmallKeySize_ThrowsArgumentException()
        {
            var builder = new PgpBuilder().WithKeySize(1024);

            Assert.Throws<ArgumentException>(() => builder.GenerateRsaKeyPair());
        }

        [Fact]
        public void GenerateRsaKeyPair_InvalidKeySize_ThrowsArgumentException()
        {
            var builder = new PgpBuilder().WithKeySize(2047);

            Assert.Throws<ArgumentException>(() => builder.GenerateRsaKeyPair());
        }
    }

    /// <summary>
    /// Tests for text encryption/decryption.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class TextEncryptionTests
    {
        [Fact]
        public void EncryptDecrypt_StringRoundTrip_Succeeds()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Hello, PGP World!";

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.True(envelope.IsText);
        }

        [Fact]
        public void EncryptDecrypt_LongText_Succeeds()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = new string('A', 10000);

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_UnicodeText_Succeeds()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Hello, \u4e16\u754c! \ud83d\udd10";

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for binary data encryption/decryption.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class BinaryEncryptionTests
    {
        [Fact]
        public void EncryptDecrypt_BytesRoundTrip_Succeeds()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = TestHelpers.RandomBytes(256);

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToBytes(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.False(envelope.IsText);
        }

        [Fact]
        public void EncryptDecrypt_LargeData_Succeeds()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = TestHelpers.RandomBytes(100000);

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToBytes(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for associated data handling.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class AssociatedDataTests
    {
        [Fact]
        public void EncryptDecrypt_WithAssociatedData_Succeeds()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Secret message";
            var aad = "metadata"u8.ToArray();

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey, aad);
            var decrypted = PgpBuilder.DecryptToString(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.NotNull(envelope.AssociatedData);
        }

        [Fact]
        public void Decrypt_WithoutAssociatedData_WhenRequired_Fails()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Secret message";
            var aad = "metadata"u8.ToArray();

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey, aad);

            // Tamper with AAD by creating a new envelope without it
            var tamperedEnvelope = new PgpEnvelope
            {
                Ciphertext = envelope.Ciphertext,
                Nonce = envelope.Nonce,
                EncryptedKey = envelope.EncryptedKey,
                AssociatedData = null,
                Algorithm = envelope.Algorithm,
                IsText = envelope.IsText
            };

            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                PgpBuilder.DecryptToString(tamperedEnvelope, keyPair.PrivateKey));
        }
    }

    /// <summary>
    /// Tests for different encryption algorithms.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class AlgorithmSelectionTests
    {
        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305)]
        public void EncryptDecrypt_DifferentAlgorithms_Succeed(EncryptionAlgorithm algorithm)
        {
            var builder = new PgpBuilder().WithEncryptionAlgorithm(algorithm);
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Test with different algorithms";

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, keyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.Equal(algorithm.ToString(), envelope.Algorithm);
        }
    }

    /// <summary>
    /// Tests for envelope structure.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class EnvelopeTests
    {
        [Fact]
        public void Envelope_ContainsAllRequiredFields()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Test message";

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);

            Assert.NotEmpty(envelope.Ciphertext);
            Assert.NotEmpty(envelope.Nonce);
            Assert.NotEmpty(envelope.EncryptedKey);
            Assert.NotEmpty(envelope.Algorithm);
        }

        [Fact]
        public void Envelope_FieldsAreBase64Encoded()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Test message";

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);

            // Should not throw
            Convert.FromBase64String(envelope.Ciphertext);
            Convert.FromBase64String(envelope.Nonce);
            Convert.FromBase64String(envelope.EncryptedKey);
        }
    }

    /// <summary>
    /// Tests for error handling.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class ErrorHandlingTests
    {
        [Fact]
        public void Encrypt_NullPlaintext_ThrowsArgumentNullException()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();

            Assert.Throws<ArgumentNullException>(() =>
                builder.Encrypt((string)null!, keyPair.PublicKey));
        }

        [Fact]
        public void Encrypt_EmptyData_ThrowsArgumentException()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();

            Assert.Throws<ArgumentException>(() =>
                builder.Encrypt(Array.Empty<byte>(), keyPair.PublicKey));
        }

        [Fact]
        public void Decrypt_WrongPrivateKey_ThrowsCryptographicException()
        {
            var builder = new PgpBuilder();
            var keyPair1 = builder.GenerateRsaKeyPair();
            var keyPair2 = builder.GenerateRsaKeyPair();
            var plaintext = "Secret message";

            var envelope = builder.Encrypt(plaintext, keyPair1.PublicKey);

            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                PgpBuilder.DecryptToString(envelope, keyPair2.PrivateKey));
        }

        [Fact]
        public void Decrypt_NullEnvelope_ThrowsArgumentNullException()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();

            Assert.Throws<ArgumentNullException>(() =>
                PgpBuilder.DecryptToString(null!, keyPair.PrivateKey));
        }

        [Fact]
        public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
        {
            var builder = new PgpBuilder();
            var keyPair = builder.GenerateRsaKeyPair();
            var plaintext = "Secret message";

            var envelope = builder.Encrypt(plaintext, keyPair.PublicKey);
            var tamperedCiphertext = Convert.FromBase64String(envelope.Ciphertext);
            tamperedCiphertext[0] ^= 0xFF;
            var tamperedEnvelope = new PgpEnvelope
            {
                Ciphertext = Convert.ToBase64String(tamperedCiphertext),
                Nonce = envelope.Nonce,
                EncryptedKey = envelope.EncryptedKey,
                AssociatedData = envelope.AssociatedData,
                Algorithm = envelope.Algorithm,
                IsText = envelope.IsText
            };

            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                PgpBuilder.DecryptToString(tamperedEnvelope, keyPair.PrivateKey));
        }
    }

    /// <summary>
    /// Tests for fluent API chaining.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class FluentApiTests
    {
        [Fact]
        public void FluentChaining_Works()
        {
            var builder = new PgpBuilder()
                .WithKeySize(2048)
                .WithEncryptionAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305);

            var keyPair = builder.GenerateRsaKeyPair();
            var envelope = builder.Encrypt("Test", keyPair.PublicKey);

            Assert.Equal("ChaCha20Poly1305", envelope.Algorithm);
        }
    }
}

#endif
