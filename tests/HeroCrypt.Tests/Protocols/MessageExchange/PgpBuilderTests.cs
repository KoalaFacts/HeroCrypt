using HeroCrypt.Operations;
using HeroCrypt.Protocols.KeyManagement;
using HeroCrypt.Protocols.MessageExchange;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.MessageExchange;

#if !NETSTANDARD2_0

/// <summary>
/// Shared fixture for PGP tests that generates RSA key pairs once.
/// </summary>
public class PgpKeyFixture
{
    public PgpBuilder Builder { get; } = new PgpBuilder();
    public KeyPair KeyPair { get; }

    public PgpKeyFixture()
    {
        // Generate once for all tests in the collection
        KeyPair = Builder.GenerateRsaKeyPair();
    }
}

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
        public void GenerateRsaKeyPair_TooSmallKeySize_ThrowsArgumentException()
        {
            var builder = new PgpBuilder().WithKeySize(1024);

            Assert.Throws<ArgumentException>(builder.GenerateRsaKeyPair);
        }

        [Fact]
        public void GenerateRsaKeyPair_InvalidKeySize_ThrowsArgumentException()
        {
            var builder = new PgpBuilder().WithKeySize(2047);

            Assert.Throws<ArgumentException>(builder.GenerateRsaKeyPair);
        }
    }

    /// <summary>
    /// Tests for text encryption/decryption using shared key pair.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class TextEncryptionTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public TextEncryptionTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void EncryptDecrypt_StringRoundTrip_Succeeds()
        {
            var plaintext = "Hello, PGP World!";

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.True(envelope.IsText);
        }

        [Fact]
        public void EncryptDecrypt_LongText_Succeeds()
        {
            var plaintext = new string('A', 10000);

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_UnicodeText_Succeeds()
        {
            var plaintext = "Hello, \u4e16\u754c! \ud83d\udd10";

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for binary data encryption/decryption using shared key pair.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BinaryEncryptionTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public BinaryEncryptionTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void EncryptDecrypt_BytesRoundTrip_Succeeds()
        {
            var plaintext = TestHelpers.RandomBytes(256);

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToBytes(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.False(envelope.IsText);
        }

        [Fact]
        public void EncryptDecrypt_LargeData_Succeeds()
        {
            var plaintext = TestHelpers.RandomBytes(100000);

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToBytes(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for associated data handling using shared key pair.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AssociatedDataTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public AssociatedDataTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void EncryptDecrypt_WithAssociatedData_Succeeds()
        {
            var plaintext = "Secret message";
            var aad = "metadata"u8.ToArray();

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey, aad);
            var decrypted = PgpBuilder.DecryptToString(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.NotNull(envelope.AssociatedData);
        }

        [Fact]
        public void Decrypt_WithoutAssociatedData_WhenRequired_Fails()
        {
            var plaintext = "Secret message";
            var aad = "metadata"u8.ToArray();

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey, aad);

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
                PgpBuilder.DecryptToString(tamperedEnvelope, fixture.KeyPair.PrivateKey));
        }
    }

    /// <summary>
    /// Tests for different encryption algorithms.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmSelectionTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public AlgorithmSelectionTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305)]
        public void EncryptDecrypt_DifferentAlgorithms_Succeed(EncryptionAlgorithm algorithm)
        {
            var builder = new PgpBuilder().WithEncryptionAlgorithm(algorithm);
            var plaintext = "Test with different algorithms";

            var envelope = builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
            var decrypted = PgpBuilder.DecryptToString(envelope, fixture.KeyPair.PrivateKey);

            Assert.Equal(plaintext, decrypted);
            Assert.Equal(algorithm.ToString(), envelope.Algorithm);
        }
    }

    /// <summary>
    /// Tests for envelope structure using shared key pair.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EnvelopeTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public EnvelopeTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void Envelope_ContainsAllRequiredFields()
        {
            var plaintext = "Test message";

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);

            Assert.NotEmpty(envelope.Ciphertext);
            Assert.NotEmpty(envelope.Nonce);
            Assert.NotEmpty(envelope.EncryptedKey);
            Assert.NotEmpty(envelope.Algorithm);
        }

        [Fact]
        public void Envelope_FieldsAreBase64Encoded()
        {
            var plaintext = "Test message";

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);

            // Should not throw
            Convert.FromBase64String(envelope.Ciphertext);
            Convert.FromBase64String(envelope.Nonce);
            Convert.FromBase64String(envelope.EncryptedKey);
        }
    }

    /// <summary>
    /// Tests for error handling using shared key pair.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ErrorHandlingTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public ErrorHandlingTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void Encrypt_NullPlaintext_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                fixture.Builder.Encrypt((string)null!, fixture.KeyPair.PublicKey));
        }

        [Fact]
        public void Encrypt_EmptyData_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                fixture.Builder.Encrypt([], fixture.KeyPair.PublicKey));
        }

        [Fact]
        public void Decrypt_NullEnvelope_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                PgpBuilder.DecryptToString(null!, fixture.KeyPair.PrivateKey));
        }

        [Fact]
        public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
        {
            var plaintext = "Secret message";

            var envelope = fixture.Builder.Encrypt(plaintext, fixture.KeyPair.PublicKey);
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
                PgpBuilder.DecryptToString(tamperedEnvelope, fixture.KeyPair.PrivateKey));
        }
    }

    /// <summary>
    /// Tests that require multiple key pairs (slow).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class MultiKeyTests
    {
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
    }

    /// <summary>
    /// Tests for fluent API chaining using shared key pair.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FluentApiTests : IClassFixture<PgpKeyFixture>
    {
        private readonly PgpKeyFixture fixture;

        public FluentApiTests(PgpKeyFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void FluentChaining_Works()
        {
            var builder = new PgpBuilder()
                .WithEncryptionAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305);

            var envelope = builder.Encrypt("Test", fixture.KeyPair.PublicKey);

            Assert.Equal("ChaCha20Poly1305", envelope.Algorithm);
        }
    }
}

#endif
