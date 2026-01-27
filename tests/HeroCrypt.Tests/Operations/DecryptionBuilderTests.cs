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
}
