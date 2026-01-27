using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Comprehensive tests for decryption operations using HeroCryptBuilder.
/// Follows HeroCrypt testing conventions.
/// </summary>
/// <remarks>
/// <para><b>Platform Support Notes:</b></para>
/// <list type="bullet">
///   <item>
///     <term>AES-CCM on macOS</term>
///     <description>
///       AES-CCM is not supported on macOS. Tests using AES-CCM are automatically skipped
///       on macOS using <c>Assert.Skip()</c>.
///     </description>
///   </item>
///   <item>
///     <term>RSA Decryption</term>
///     <description>
///       Requires .NET 8.0 or later for key import APIs.
///     </description>
///   </item>
/// </list>
/// </remarks>
public class DecryptionBuilderTests
{
    public static IEnumerable<object[]> AeadCases =>
    [
        [EncryptionAlgorithm.ChaCha20Poly1305, 32],
        [EncryptionAlgorithm.XChaCha20Poly1305, 32],
        [EncryptionAlgorithm.AesGcm, 16],
        [EncryptionAlgorithm.AesGcm, 32],
        [EncryptionAlgorithm.AesCcm, 16],
        [EncryptionAlgorithm.AesCcm, 32],
        [EncryptionAlgorithm.AesOcb, 16],
        [EncryptionAlgorithm.AesOcb, 32],
        [EncryptionAlgorithm.AesSiv, 32],
        [EncryptionAlgorithm.AesSiv, 64]
    ];

    /// <summary>
    /// Tests for fluent API method coverage.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FluentApiTests
    {
        [Fact]
        public void WithAesGcm_SetsAlgorithm_SuccessfullyDecrypts()
        {
            var plaintext = "Test data for AES-GCM"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt().WithAesGcm().WithKey(key).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithAesGcm().WithKey(key).WithNonce(result.Nonce).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithAesCcm_SetsAlgorithm_SuccessfullyDecrypts()
        {
            if (OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test data for AES-CCM"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt().WithAesCcm().WithKey(key).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithAesCcm().WithKey(key).WithNonce(result.Nonce).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithAesOcb_SetsAlgorithm_SuccessfullyDecrypts()
        {
            var plaintext = "Test data for AES-OCB"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt().WithAesOcb().WithKey(key).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithAesOcb().WithKey(key).WithNonce(result.Nonce).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithAesSiv_SetsAlgorithm_SuccessfullyDecrypts()
        {
            var plaintext = "Test data for AES-SIV"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt().WithAesSiv().WithKey(key).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithAesSiv().WithKey(key).WithNonce(result.Nonce).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithChaCha20Poly1305_SetsAlgorithm_SuccessfullyDecrypts()
        {
            var plaintext = "Test data for ChaCha20-Poly1305"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt().WithChaCha20Poly1305().WithKey(key).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithChaCha20Poly1305().WithKey(key).WithNonce(result.Nonce).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithXChaCha20Poly1305_SetsAlgorithm_SuccessfullyDecrypts()
        {
            var plaintext = "Test data for XChaCha20-Poly1305"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt().WithXChaCha20Poly1305().WithKey(key).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithXChaCha20Poly1305().WithKey(key).WithNonce(result.Nonce).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for RSA decryption operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class RsaDecryptionTests
    {
        [Fact]
        public void WithRsaOaep_DecryptsSuccessfully()
        {
            var plaintext = "Test data for RSA-OAEP"u8.ToArray();

            using var rsa = RSA.Create(2048);
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var privateKey = rsa.ExportPkcs8PrivateKey();

            var result = HeroCryptBuilder.Encrypt().WithRsaOaep().WithKey(publicKey).Encrypt(plaintext);
            var decrypted = HeroCryptBuilder.Decrypt().WithRsaOaep().WithKey(privateKey).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void RsaDecrypt_WithWrongPrivateKey_ThrowsCryptographicException()
        {
            var plaintext = "Test data for RSA"u8.ToArray();

            using var rsa1 = RSA.Create(2048);
            using var rsa2 = RSA.Create(2048);
            var publicKey1 = rsa1.ExportSubjectPublicKeyInfo();
            var privateKey2 = rsa2.ExportPkcs8PrivateKey();

            var result = HeroCryptBuilder.Encrypt().WithRsaOaep().WithKey(publicKey1).Encrypt(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt().WithRsaOaep().WithKey(privateKey2).Decrypt(result.Ciphertext));
        }

        [Fact]
        public void RsaDecrypt_WithTamperedCiphertext_ThrowsCryptographicException()
        {
            var plaintext = "Test data for RSA"u8.ToArray();

            using var rsa = RSA.Create(2048);
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var privateKey = rsa.ExportPkcs8PrivateKey();

            var result = HeroCryptBuilder.Encrypt().WithRsaOaep().WithKey(publicKey).Encrypt(plaintext);
            var tampered = TestHelpers.TamperFirst(result.Ciphertext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt().WithRsaOaep().WithKey(privateKey).Decrypt(tampered));
        }

        [Fact]
        public void RsaDecrypt_DoesNotRequireNonce()
        {
            var plaintext = "RSA doesn't use nonces"u8.ToArray();

            using var rsa = RSA.Create(2048);
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var privateKey = rsa.ExportPkcs8PrivateKey();

            var result = HeroCryptBuilder.Encrypt().WithRsaOaep().WithKey(publicKey).Encrypt(plaintext);

            // RSA decryption should work without setting a nonce
            var decrypted = HeroCryptBuilder.Decrypt().WithRsaOaep().WithKey(privateKey).Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for X25519 hybrid encryption/decryption.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class X25519HybridDecryptionTests
    {
        [Fact]
        public void X25519ChaCha20Poly1305_DecryptsSuccessfully()
        {
            var plaintext = "Test data for X25519 + ChaCha20-Poly1305"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonce(result.Nonce)
                .WithEncapsulatedKey(result.EncapsulatedKey!)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void X25519XChaCha20Poly1305_DecryptsSuccessfully()
        {
            var plaintext = "Test data for X25519 + XChaCha20-Poly1305"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519XChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519XChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonce(result.Nonce)
                .WithEncapsulatedKey(result.EncapsulatedKey!)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void X25519AesGcm_DecryptsSuccessfully()
        {
            var plaintext = "Test data for X25519 + AES-GCM"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519AesGcm)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519AesGcm)
                .WithKey(privateKey)
                .WithNonce(result.Nonce)
                .WithEncapsulatedKey(result.EncapsulatedKey!)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void X25519Hybrid_WithWrongPrivateKey_FailsAuthentication()
        {
            var plaintext = "Test data"u8.ToArray();
            var privateKey1 = Curve25519Core.GeneratePrivateKey();
            var publicKey1 = Curve25519Core.DerivePublicKey(privateKey1);
            var privateKey2 = Curve25519Core.GeneratePrivateKey();

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey1)
                .Encrypt(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                    .WithKey(privateKey2)
                    .WithNonce(result.Nonce)
                    .WithEncapsulatedKey(result.EncapsulatedKey!)
                    .Decrypt(result.Ciphertext));
        }

        [Fact]
        public void X25519Hybrid_WithoutEncapsulatedKey_ThrowsInvalidOperationException()
        {
            var plaintext = "Test data"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                    .WithKey(privateKey)
                    .WithNonce(result.Nonce)
                    // Missing WithEncapsulatedKey
                    .Decrypt(result.Ciphertext));
        }
    }

    /// <summary>
    /// Tests for associated data handling in decryption.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AssociatedDataTests
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_WithMatchingAssociatedData_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test with AAD"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);
            var aad = "associated data"u8.ToArray();

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithAssociatedData(aad)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(aad)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_WithMissingAssociatedData_Fails(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test with AAD"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);
            var aad = "associated data"u8.ToArray();

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithAssociatedData(aad)
                .Encrypt(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithNonce(result.Nonce)
                    // Missing associated data
                    .Decrypt(result.Ciphertext));
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_WithEmptyAssociatedData_SucceedsWhenEncryptedWithEmpty(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test with empty AAD"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);
            var emptyAad = Array.Empty<byte>();

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithAssociatedData(emptyAad)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(emptyAad)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_SingleByte_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = new byte[] { 0x42 };
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_AllZeros_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = new byte[256]; // 256 bytes of zeros
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm, 32)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305, 32)]
        public void Decrypt_LargeData_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            var plaintext = TestHelpers.RandomBytes(64 * 1024); // 64KB
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptToString_EmptyString_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            var plaintext = string.Empty;

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptToString_SingleCharacter_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "X";

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptToString_UnicodeEmoji_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "\U0001F680\U0001F4BB\U0001F512"; // rocket, laptop, lock emojis

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptToString_MultiByteUnicode_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            // Mix of 1-byte, 2-byte, 3-byte, and 4-byte UTF-8 sequences
            var plaintext = "A\u00e9\u4e2d\U0001F600"; // A, é (2-byte), 中 (3-byte), 😀 (4-byte)

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_RepeatingPattern_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var pattern = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
            var plaintext = new byte[256];
            for (int i = 0; i < plaintext.Length; i++)
            {
                plaintext[i] = pattern[i % pattern.Length];
            }

            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_EmptyPlaintext_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = Array.Empty<byte>();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for parameter validation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidationTests
    {
        [Fact]
        public void Decrypt_WithoutKey_ThrowsInvalidOperationException()
        {
            var ciphertext = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithNonce(nonce)
                    .Decrypt(ciphertext));
        }

        [Fact]
        public void Decrypt_WithoutNonce_ThrowsInvalidOperationException()
        {
            var ciphertext = TestHelpers.RandomBytes(32);
            var key = TestHelpers.RandomBytes(16);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .Decrypt(ciphertext));
        }

        [Fact]
        public void Decrypt_WithNullCiphertext_ThrowsArgumentException()
        {
            var key = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(nonce)
                    .Decrypt(null!));
        }
    }

    /// <summary>
    /// Tests for security properties of decryption.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class SecurityTests
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_WithTamperedTag_FailsAuthentication(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test data"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            // Tamper the last bytes (where tag typically is)
            var tampered = TestHelpers.TamperLast(result.Ciphertext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithNonce(result.Nonce)
                    .Decrypt(tampered));
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void Decrypt_WithTruncatedCiphertext_FailsAuthentication(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test data with enough length"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            // Truncate the ciphertext
            var truncated = result.Ciphertext[..^5];

            Assert.ThrowsAny<Exception>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithNonce(result.Nonce)
                    .Decrypt(truncated));
        }
    }

    /// <summary>
    /// Tests for algorithm selection via WithAlgorithm method.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmSelectionTests
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void WithAlgorithm_SetsCorrectAlgorithm_SuccessfullyDecrypts(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test algorithm selection"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for FromEncryptionResult() convenience method.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FromEncryptionResultTests
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(DecryptionBuilderTests))]
        public void FromEncryptionResult_SetsNonce_SuccessfullyDecrypts(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Test FromEncryptionResult"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .FromEncryptionResult(result)
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void FromEncryptionResult_WithX25519Hybrid_SetsEncapsulatedKey()
        {
            var plaintext = "Test X25519 with FromEncryptionResult"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            // FromEncryptionResult should set both nonce and encapsulated key
            var decrypted = HeroCryptBuilder.Decrypt()
                .FromEncryptionResult(result)
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(privateKey)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void FromEncryptionResult_CanBeChainedWithOtherMethods()
        {
            var plaintext = "Test chaining"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);
            var aad = "additional data"u8.ToArray();

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithAssociatedData(aad)
                .Encrypt(plaintext);

            // Chain FromEncryptionResult with WithAssociatedData
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .FromEncryptionResult(result)
                .WithKey(key)
                .WithAssociatedData(aad)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for IDisposable implementation and secure memory clearing.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DisposalBehaviorTests
    {
        [Fact]
        public void Decrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(TestHelpers.RandomBytes(32))
                .WithNonce(TestHelpers.RandomBytes(12));
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.Decrypt(TestHelpers.RandomBytes(32)));
        }

        [Fact]
        public void WithKey_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithKey(TestHelpers.RandomBytes(32)));
        }

        [Fact]
        public void WithNonce_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithNonce(TestHelpers.RandomBytes(12)));
        }

        [Fact]
        public void FromEncryptionResult_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            var result = new EncryptionResult
            {
                Ciphertext = TestHelpers.RandomBytes(32),
                Nonce = TestHelpers.RandomBytes(12),
                EncapsulatedKey = null
            };

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.FromEncryptionResult(result));
        }

        [Fact]
        public void Dispose_MultipleTimes_DoesNotThrow()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();

            // Act & Assert - Should not throw
            builder.Dispose();
            builder.Dispose();
        }
    }

    /// <summary>
    /// Tests for ciphertext input format convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CiphertextInputFormatTests
    {
        [Fact]
        public void DecryptFromHex_Succeeds()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var hexCiphertext = Convert.ToHexString(result.Ciphertext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptFromHex(hexCiphertext);

            // Assert
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes(plaintext), decrypted);
        }

        [Fact]
        public void DecryptFromHexToString_Succeeds()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var hexCiphertext = Convert.ToHexString(result.Ciphertext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptFromHexToString(hexCiphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptFromBase64_Succeeds()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var base64Ciphertext = Convert.ToBase64String(result.Ciphertext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptFromBase64(base64Ciphertext);

            // Assert
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes(plaintext), decrypted);
        }

        [Fact]
        public void DecryptFromBase64ToString_Succeeds()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var base64Ciphertext = Convert.ToBase64String(result.Ciphertext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptFromBase64ToString(base64Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptFromBase64Url_Succeeds()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var base64UrlCiphertext = Convert.ToBase64String(result.Ciphertext)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptFromBase64Url(base64UrlCiphertext);

            // Assert
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes(plaintext), decrypted);
        }

        [Fact]
        public void DecryptFromBase64UrlToString_Succeeds()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var base64UrlCiphertext = Convert.ToBase64String(result.Ciphertext)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptFromBase64UrlToString(base64UrlCiphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void DecryptFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(nonce)
                    .DecryptFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void DecryptFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(nonce)
                    .DecryptFromBase64("not-valid-base64!@#$"));
        }
    }

    /// <summary>
    /// Tests for key and nonce input format convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyAndNonceInputFormatTests
    {
        [Fact]
        public void WithKeyFromHex_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithKeyFromBase64_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);
            var base64Key = Convert.ToBase64String(key);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromBase64(base64Key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithKeyFromBase64Url_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithNonceFromHex_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var hexNonce = Convert.ToHexString(result.Nonce).ToLowerInvariant();

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonceFromHex(hexNonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithNonceFromBase64_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var base64Nonce = Convert.ToBase64String(result.Nonce);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonceFromBase64(base64Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithNonceFromBase64Url_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Hello, World!";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var base64UrlNonce = Convert.ToBase64String(result.Nonce)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonceFromBase64Url(base64UrlNonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithKeyAndNonceFromHex_SuccessfullyDecrypts()
        {
            // Arrange - Test using both key and nonce from hex
            var plaintext = "Test complete hex workflow";
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var hexNonce = Convert.ToHexString(result.Nonce);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .WithNonceFromHex(hexNonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithKeyFromHex_InvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKeyFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64_InvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKeyFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithNonceFromHex_InvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithNonceFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithNonceFromBase64_InvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithNonceFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithKeyFromHex_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithKeyFromHex("abcd"));
        }

        [Fact]
        public void WithNonceFromHex_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithNonceFromHex("abcd"));
        }

        [Fact]
        public void EncryptWithRandomKey_DecryptWithKeyFromHex_RoundTrip()
        {
            // Arrange - Full workflow: generate key, get as hex, decrypt with hex key
            var plaintext = "Test encryption with random key and hex key decryption";

            using var encryptBuilder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var hexKey = encryptBuilder.GetKeyAsHex();
            var result = encryptBuilder.Encrypt(plaintext);

            // Act - Decrypt using hex key
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptWithRandomKey_DecryptWithKeyFromBase64_RoundTrip()
        {
            // Arrange
            var plaintext = "Test encryption with random key and base64 key decryption";

            using var encryptBuilder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var base64Key = encryptBuilder.GetKeyAsBase64();
            var result = encryptBuilder.Encrypt(plaintext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromBase64(base64Key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptWithRandomKey_DecryptWithKeyFromBase64Url_RoundTrip()
        {
            // Arrange
            var plaintext = "Test encryption with random key and URL-safe base64 key decryption";

            using var encryptBuilder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var base64UrlKey = encryptBuilder.GetKeyAsBase64Url();
            var result = encryptBuilder.Encrypt(plaintext);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for encapsulated key input format convenience methods (for hybrid encryption).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncapsulatedKeyInputFormatTests
    {
        [Fact]
        public void WithEncapsulatedKeyFromHex_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Test X25519 with hex encapsulated key"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            var hexEncapsulatedKey = Convert.ToHexString(result.EncapsulatedKey!);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonce(result.Nonce)
                .WithEncapsulatedKeyFromHex(hexEncapsulatedKey)
                .Decrypt(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithEncapsulatedKeyFromBase64_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Test X25519 with Base64 encapsulated key"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            var base64EncapsulatedKey = Convert.ToBase64String(result.EncapsulatedKey!);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonce(result.Nonce)
                .WithEncapsulatedKeyFromBase64(base64EncapsulatedKey)
                .Decrypt(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithEncapsulatedKeyFromBase64Url_SuccessfullyDecrypts()
        {
            // Arrange
            var plaintext = "Test X25519 with Base64Url encapsulated key"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            var base64UrlEncapsulatedKey = Convert.ToBase64String(result.EncapsulatedKey!)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonce(result.Nonce)
                .WithEncapsulatedKeyFromBase64Url(base64UrlEncapsulatedKey)
                .Decrypt(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithEncapsulatedKeyFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                    .WithEncapsulatedKeyFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithEncapsulatedKeyFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                    .WithEncapsulatedKeyFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithEncapsulatedKeyFromHex_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithEncapsulatedKeyFromHex("abcd"));
        }

        [Fact]
        public void WithEncapsulatedKeyFromBase64_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithEncapsulatedKeyFromBase64("dGVzdA=="));
        }

        [Fact]
        public void WithEncapsulatedKeyFromBase64Url_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Decrypt();
            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.WithEncapsulatedKeyFromBase64Url("dGVzdA"));
        }

        [Fact]
        public void EncryptionResultTextProperties_DecryptWithTextFormats_RoundTrip()
        {
            // Arrange - Full workflow: encrypt, get encapsulated key as hex, decrypt with hex
            var plaintext = "Test complete text format workflow for hybrid encryption"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            // Use text format properties from EncryptionResult
            var hexCiphertext = result.CiphertextAsHex;
            var hexNonce = result.NonceAsHex;
            var hexEncapsulatedKey = result.EncapsulatedKeyAsHex!;

            // Act - Decrypt using all hex inputs
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonceFromHex(hexNonce)
                .WithEncapsulatedKeyFromHex(hexEncapsulatedKey)
                .DecryptFromHex(hexCiphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptionResultTextProperties_DecryptWithBase64UrlFormats_RoundTrip()
        {
            // Arrange
            var plaintext = "Test Base64Url workflow"u8.ToArray();
            var privateKey = Curve25519Core.GeneratePrivateKey();
            var publicKey = Curve25519Core.DerivePublicKey(privateKey);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519XChaCha20Poly1305)
                .WithKey(publicKey)
                .Encrypt(plaintext);

            // Use URL-safe text format properties from EncryptionResult
            var base64UrlCiphertext = result.CiphertextAsBase64Url;
            var base64UrlNonce = result.NonceAsBase64Url;
            var base64UrlEncapsulatedKey = result.EncapsulatedKeyAsBase64Url!;

            // Act - Decrypt using all Base64Url inputs
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519XChaCha20Poly1305)
                .WithKey(privateKey)
                .WithNonceFromBase64Url(base64UrlNonce)
                .WithEncapsulatedKeyFromBase64Url(base64UrlEncapsulatedKey)
                .DecryptFromBase64Url(base64UrlCiphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for malformed input handling in DecryptionBuilder.
    /// </summary>
    [Trait("Category", TestCategories.INPUT_VALIDATION)]
    [Trait("Category", TestCategories.FAST)]
    public class InputValidation
    {
        public static TheoryData<string> InvalidHexStrings => new()
        {
            "not-valid-hex",
            "GHIJKL",
            "123",
            "0x1234",
            "!@#$%^&*()",
        };

        public static TheoryData<string> InvalidBase64Strings => new()
        {
            "not valid base64!",
            "!!!",
            "====",
            "a===",
        };

        [Theory]
        [MemberData(nameof(InvalidHexStrings))]
        public void WithKeyFromHex_InvalidHex_ThrowsFormatException(string invalidHex)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKeyFromHex(invalidHex));
        }

        [Theory]
        [MemberData(nameof(InvalidHexStrings))]
        public void WithNonceFromHex_InvalidHex_ThrowsFormatException(string invalidHex)
        {
            var key = TestHelpers.RandomBytes(32);
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonceFromHex(invalidHex));
        }

        [Theory]
        [MemberData(nameof(InvalidBase64Strings))]
        public void WithKeyFromBase64_InvalidBase64_ThrowsFormatException(string invalidBase64)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKeyFromBase64(invalidBase64));
        }

        [Theory]
        [MemberData(nameof(InvalidBase64Strings))]
        public void WithNonceFromBase64_InvalidBase64_ThrowsFormatException(string invalidBase64)
        {
            var key = TestHelpers.RandomBytes(32);
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonceFromBase64(invalidBase64));
        }

        [Fact]
        public void WithNullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(null!));
        }
    }

    /// <summary>
    /// Tests for concurrent disposal safety of DecryptionBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.FAST)]
    public class ConcurrentDisposal
    {
        [Fact]
        public void ConcurrentDispose_DoesNotThrow()
        {
            var key = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            var builder = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonce);

            var tasks = Enumerable.Range(0, 10)
                .Select(_ => Task.Run(() => builder.Dispose()))
                .ToArray();

            Task.WaitAll(tasks);
        }

        [Fact]
        public void RapidCreateDisposeLoop_NoIssues()
        {
            var key = TestHelpers.RandomBytes(32);

            for (int i = 0; i < 100; i++)
            {
                var encryptResult = HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .Encrypt("test data");

                var builder = HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(encryptResult.Nonce);

                builder.Decrypt(encryptResult.Ciphertext);
                builder.Dispose();
            }
        }
    }
}
