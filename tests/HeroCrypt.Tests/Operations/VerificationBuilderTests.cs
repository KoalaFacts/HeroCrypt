using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Comprehensive tests for signature verification operations using HeroCryptBuilder.
/// Focuses on VerificationBuilder-specific functionality.
/// </summary>
/// <remarks>
/// For round-trip sign/verify tests, see SignatureBuilderTests.
/// This class tests VerificationBuilder fluent API and validation.
/// </remarks>
public class VerificationBuilderTests
{
    private static readonly byte[] TestMessage = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    /// <summary>
    /// Tests for fluent API method coverage.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FluentApiTests
    {
        [Fact]
        public void WithHmacSha256_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign().WithHmacSha256().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithHmacSha256().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithHmacSha384_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign().WithHmacSha384().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithHmacSha384().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithHmacSha512_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign().WithHmacSha512().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithHmacSha512().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithAesCmac128_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(16);
            var signature = HeroCryptBuilder.Sign().WithAesCmac128().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithAesCmac128().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithAesCmac192_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(24);
            var signature = HeroCryptBuilder.Sign().WithAesCmac192().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithAesCmac192().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithAesCmac256_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(32);
            var signature = HeroCryptBuilder.Sign().WithAesCmac256().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithAesCmac256().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithPoly1305_SetsAlgorithm_VerifiesSuccessfully()
        {
            var key = TestHelpers.RandomBytes(32);
            var signature = HeroCryptBuilder.Sign().WithPoly1305().WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithPoly1305().WithPublicKey(key).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithEd25519_SetsAlgorithm_VerifiesSuccessfully()
        {
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var signature = HeroCryptBuilder.Sign().WithEd25519().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithEd25519().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }
    }

    /// <summary>
    /// Tests for RSA signature verification via fluent API.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class RsaFluentApiTests
    {
        [Fact]
        public void WithRsaSha256_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithRsaSha256().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithRsaSha256().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithRsaSha384_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithRsaSha384().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithRsaSha384().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithRsaSha512_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithRsaSha512().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithRsaSha512().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithRsaPssSha256_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithRsaPssSha256().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithRsaPssSha256().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithRsaPssSha384_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithRsaPssSha384().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithRsaPssSha384().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithRsaPssSha512_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithRsaPssSha512().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithRsaPssSha512().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }
    }

    /// <summary>
    /// Tests for ECDSA signature verification via fluent API.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EcdsaFluentApiTests
    {
        [Fact]
        public void WithEcdsaP256_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKey = ecdsa.ExportECPrivateKey();
            var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithEcdsaP256().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithEcdsaP256().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithEcdsaP384_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var privateKey = ecdsa.ExportECPrivateKey();
            var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithEcdsaP384().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithEcdsaP384().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithEcdsaP521_SetsAlgorithm_VerifiesSuccessfully()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            var privateKey = ecdsa.ExportECPrivateKey();
            var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
            var signature = HeroCryptBuilder.Sign().WithEcdsaP521().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithEcdsaP521().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
        }

        [Fact]
        public void WithSecp256k1_SetsAlgorithm_VerifiesSuccessfully()
        {
            var (privateKey, publicKey) = HeroCrypt.Primitives.Secp256k1.Secp256k1Core.GenerateKeyPair();
            var signature = HeroCryptBuilder.Sign().WithSecp256k1().WithPrivateKey(privateKey).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify().WithSecp256k1().WithPublicKey(publicKey).WithSignature(signature).Verify(TestMessage);

            Assert.True(isValid);
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
        [InlineData(SignatureAlgorithm.HmacSha256)]
        [InlineData(SignatureAlgorithm.HmacSha384)]
        [InlineData(SignatureAlgorithm.HmacSha512)]
        public void Verify_SingleByte_Succeeds(SignatureAlgorithm algorithm)
        {
            var key = TestHelpers.RandomBytes(64);
            var data = new byte[] { 0x42 };
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256)]
        [InlineData(SignatureAlgorithm.HmacSha384)]
        [InlineData(SignatureAlgorithm.HmacSha512)]
        public void Verify_AllZeros_Succeeds(SignatureAlgorithm algorithm)
        {
            var key = TestHelpers.RandomBytes(64);
            var data = new byte[256];
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256)]
        [InlineData(SignatureAlgorithm.HmacSha384)]
        [InlineData(SignatureAlgorithm.HmacSha512)]
        public void Verify_LargeData_Succeeds(SignatureAlgorithm algorithm)
        {
            var key = TestHelpers.RandomBytes(64);
            var data = TestHelpers.RandomBytes(64 * 1024);
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_SingleCharacterString_Succeeds()
        {
            var key = TestHelpers.RandomBytes(64);
            var data = "X";
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_UnicodeString_Succeeds()
        {
            var key = TestHelpers.RandomBytes(64);
            var data = "\u4e2d\u6587\U0001F680"; // Chinese + rocket emoji
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_MultiByteUnicode_Succeeds()
        {
            var key = TestHelpers.RandomBytes(64);
            // Mix of 1-byte, 2-byte, 3-byte, and 4-byte UTF-8 sequences
            var data = "A\u00e9\u4e2d\U0001F600"; // A, é (2-byte), 中 (3-byte), 😀 (4-byte)
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_RepeatingPattern_Succeeds()
        {
            var key = TestHelpers.RandomBytes(64);
            var pattern = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
            var data = new byte[256];
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = pattern[i % pattern.Length];
            }

            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Ed25519_Verify_SingleByte_Succeeds()
        {
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var data = new byte[] { 0x42 };
            var signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Ed25519_Verify_AllZeros_Succeeds()
        {
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var data = new byte[256];
            var signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
        }

        [Fact]
        public void Ed25519_Verify_LargeData_Succeeds()
        {
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var data = TestHelpers.RandomBytes(64 * 1024);
            var signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .Sign(data);

            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(data);

            Assert.True(isValid);
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
        public void Verify_WithoutPublicKey_ThrowsInvalidOperationException()
        {
            var signature = TestHelpers.RandomBytes(32);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithSignature(signature)
                    .Verify(TestMessage));
        }

        [Fact]
        public void Verify_WithoutSignature_ThrowsInvalidOperationException()
        {
            var key = TestHelpers.RandomBytes(32);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithPublicKey(key)
                    .Verify(TestMessage));
        }

        [Fact]
        public void Verify_WithEmptyData_ThrowsArgumentException()
        {
            var key = TestHelpers.RandomBytes(32);
            var signature = TestHelpers.RandomBytes(32);

            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithPublicKey(key)
                    .WithSignature(signature)
                    .Verify([]));
        }

        [Fact]
        public void Verify_WithNullData_ThrowsArgumentException()
        {
            var key = TestHelpers.RandomBytes(32);
            var signature = TestHelpers.RandomBytes(32);

            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithPublicKey(key)
                    .WithSignature(signature)
                    .Verify((byte[])null!));
        }
    }

    /// <summary>
    /// Tests for verification failure scenarios.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class VerificationFailureTests
    {
        [Fact]
        public void Verify_WithTamperedSignature_ReturnsFalse()
        {
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign().WithHmacSha256().WithPrivateKey(key).Sign(TestMessage);
            var tamperedSignature = TestHelpers.TamperFirst(signature);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key)
                .WithSignature(tamperedSignature)
                .Verify(TestMessage);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WithTamperedData_ReturnsFalse()
        {
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign().WithHmacSha256().WithPrivateKey(key).Sign(TestMessage);
            var tamperedData = Encoding.UTF8.GetBytes("Tampered message");

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(tamperedData);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WithWrongAlgorithm_ReturnsFalse()
        {
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign().WithHmacSha256().WithPrivateKey(key).Sign(TestMessage);

            // Try to verify with SHA384 when signed with SHA256
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha384()
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WithRandomSignature_ReturnsFalse()
        {
            var key = TestHelpers.RandomBytes(64);
            var randomSignature = TestHelpers.RandomBytes(32);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key)
                .WithSignature(randomSignature)
                .Verify(TestMessage);

            Assert.False(isValid);
        }
    }

    /// <summary>
    /// Tests for WithAlgorithm method.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmSelectionTests
    {
        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256, 64)]
        [InlineData(SignatureAlgorithm.HmacSha384, 64)]
        [InlineData(SignatureAlgorithm.HmacSha512, 64)]
        public void WithAlgorithm_HmacVariants_VerifySuccessfully(SignatureAlgorithm algorithm, int keySize)
        {
            var key = TestHelpers.RandomBytes(keySize);
            var signature = HeroCryptBuilder.Sign().WithAlgorithm(algorithm).WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            Assert.True(isValid);
        }

        [Theory]
        [InlineData(SignatureAlgorithm.AesCmac128, 16)]
        [InlineData(SignatureAlgorithm.AesCmac192, 24)]
        [InlineData(SignatureAlgorithm.AesCmac256, 32)]
        public void WithAlgorithm_AesCmacVariants_VerifySuccessfully(SignatureAlgorithm algorithm, int keySize)
        {
            var key = TestHelpers.RandomBytes(keySize);
            var signature = HeroCryptBuilder.Sign().WithAlgorithm(algorithm).WithPrivateKey(key).Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            Assert.True(isValid);
        }
    }

    /// <summary>
    /// Tests for key input format convenience methods (WithKeyFromHex, WithKeyFromBase64, WithKeyFromBase64Url).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyInputFormatTests
    {
        [Fact]
        public void WithKeyFromHex_VerifiesCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key);
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsLowercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsUppercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key).ToUpperInvariant();
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Arrange
            var signature = TestHelpers.RandomBytes(32);

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithKeyFromHex("not-valid-hex!@#$")
                    .WithSignature(signature)
                    .Verify(TestMessage));
        }

        [Fact]
        public void WithKeyFromBase64_VerifiesCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64Key = Convert.ToBase64String(key);
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromBase64(base64Key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Arrange
            var signature = TestHelpers.RandomBytes(32);

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithKeyFromBase64("not-valid-base64!@#$")
                    .WithSignature(signature)
                    .Verify(TestMessage));
        }

        [Fact]
        public void WithKeyFromBase64Url_VerifiesCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromBase64Url_AcceptsPaddedInput()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64UrlKey = Convert.ToBase64String(key)
                .Replace('+', '-')
                .Replace('/', '_');
            // Keep padding
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256, 64)]
        [InlineData(SignatureAlgorithm.HmacSha384, 64)]
        [InlineData(SignatureAlgorithm.HmacSha512, 64)]
        public void WithKeyFromHex_WorksWithAllHmacAlgorithms(SignatureAlgorithm algorithm, int keySize)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(keySize);
            var hexKey = Convert.ToHexString(key);
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromHex_WorksWithAesCmac()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(16);
            var hexKey = Convert.ToHexString(key);
            var signature = HeroCryptBuilder.Sign()
                .WithAesCmac128()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithAesCmac128()
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithKeyFromHex_WorksWithPoly1305()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key);
            var signature = HeroCryptBuilder.Sign()
                .WithPoly1305()
                .WithKey(key)
                .Sign(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithPoly1305()
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void KeyFromHex_SignAndVerify_RoundTrip()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();

            // Act - Sign with hex key
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Act - Verify with same hex key
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }
    }

    /// <summary>
    /// Tests for signature input format convenience methods (WithSignatureFromHex, WithSignatureFromBase64).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SignatureInputFormatTests
    {
        [Fact]
        public void WithSignatureFromHex_VerifiesHexSignature_Successfully()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToHex(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromHex(hexSignature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithSignatureFromHex_AcceptsUppercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToHex(TestMessage);
            var uppercaseHex = hexSignature.ToUpperInvariant();

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromHex(uppercaseHex)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithSignatureFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithKey(key)
                    .WithSignatureFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithSignatureFromBase64_VerifiesBase64Signature_Successfully()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64Signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromBase64(base64Signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithSignatureFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Verify()
                    .WithHmacSha256()
                    .WithKey(key)
                    .WithSignatureFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithSignatureFromHex_WorksWithEd25519()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var hexSignature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .SignToHex(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignatureFromHex(hexSignature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithSignatureFromBase64_WorksWithEd25519()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var base64Signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .SignToBase64(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignatureFromBase64(base64Signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void SignToHex_And_WithSignatureFromHex_RoundTrip_AllHmacAlgorithms()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var algorithms = new[]
            {
                SignatureAlgorithm.HmacSha256,
                SignatureAlgorithm.HmacSha384,
                SignatureAlgorithm.HmacSha512
            };

            foreach (var algorithm in algorithms)
            {
                // Act
                var hexSignature = HeroCryptBuilder.Sign()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .SignToHex(TestMessage);

                var isValid = HeroCryptBuilder.Verify()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithSignatureFromHex(hexSignature)
                    .Verify(TestMessage);

                // Assert
                Assert.True(isValid, $"Failed for algorithm: {algorithm}");
            }
        }

        [Fact]
        public void SignToBase64_And_WithSignatureFromBase64_RoundTrip_AllHmacAlgorithms()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var algorithms = new[]
            {
                SignatureAlgorithm.HmacSha256,
                SignatureAlgorithm.HmacSha384,
                SignatureAlgorithm.HmacSha512
            };

            foreach (var algorithm in algorithms)
            {
                // Act
                var base64Signature = HeroCryptBuilder.Sign()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .SignToBase64(TestMessage);

                var isValid = HeroCryptBuilder.Verify()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithSignatureFromBase64(base64Signature)
                    .Verify(TestMessage);

                // Assert
                Assert.True(isValid, $"Failed for algorithm: {algorithm}");
            }
        }

        [Fact]
        public void WithSignatureFromHex_TamperedSignature_ReturnsFalse()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToHex(TestMessage);

            // Tamper with the hex signature (change first character)
            var tamperedHex = (hexSignature[0] == '0' ? '1' : '0') + hexSignature[1..];

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromHex(tamperedHex)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void WithSignatureFromBase64Url_VerifiesUrlSafeSignature_Successfully()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64UrlSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64Url(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromBase64Url(base64UrlSignature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithSignatureFromBase64Url_AcceptsPaddedInput()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Create padded URL-safe Base64
            var base64Url = Convert.ToBase64String(signature)
                .Replace('+', '-')
                .Replace('/', '_');
            // Keep the padding

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromBase64Url(base64Url)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void SignToBase64Url_And_WithSignatureFromBase64Url_RoundTrip()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act - Sign with URL-safe Base64 output
            var base64UrlSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64Url(TestMessage);

            // Act - Verify with URL-safe Base64 input
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignatureFromBase64Url(base64UrlSignature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void WithSignatureFromBase64Url_WithEd25519_Succeeds()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var base64UrlSignature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .SignToBase64Url(TestMessage);

            // Act
            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignatureFromBase64Url(base64UrlSignature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }
    }
}
