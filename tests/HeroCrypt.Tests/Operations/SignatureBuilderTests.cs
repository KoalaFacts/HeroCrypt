using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Tests.Infrastructure;
#if NET10_0_OR_GREATER
using HeroCrypt.Primitives.MLDsa;
#endif

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Comprehensive tests for digital signature operations using HeroCryptBuilder.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
/// <remarks>
/// Tests cover HMAC, RSA, ECDSA, Ed25519, and ML-DSA (post-quantum) signatures.
/// For Ed25519 low-level tests and RFC 8032 vectors, see Ed25519CoreTests.
/// </remarks>
public class SignatureBuilderTests
{
    private static readonly byte[] TestMessage = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    /// <summary>
    /// Tests for HMAC-based message authentication codes.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class HmacTests
    {
        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256, 32)]
        [InlineData(SignatureAlgorithm.HmacSha384, 48)]
        [InlineData(SignatureAlgorithm.HmacSha512, 64)]
        public void SignAndVerify_WithValidKey_Succeeds(SignatureAlgorithm algorithm, int expectedSignatureLength)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithPrivateKey(key)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.Equal(expectedSignatureLength, signature.Length);
            Assert.True(isValid);
        }

        [Fact]
        public void Verify_WithWrongKey_ReturnsFalse()
        {
            // Arrange
            var key1 = TestHelpers.RandomBytes(64);
            var key2 = TestHelpers.RandomBytes(64);

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithPrivateKey(key1)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key2)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WithTamperedData_ReturnsFalse()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var tamperedData = Encoding.UTF8.GetBytes("Tampered data");

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithPrivateKey(key)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(tamperedData);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void DifferentAlgorithms_ProduceDifferentSignatures()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act
            var sig256 = HeroCryptBuilder.Sign().WithHmacSha256().WithPrivateKey(key).Sign(TestMessage);
            var sig384 = HeroCryptBuilder.Sign().WithHmacSha384().WithPrivateKey(key).Sign(TestMessage);
            var sig512 = HeroCryptBuilder.Sign().WithHmacSha512().WithPrivateKey(key).Sign(TestMessage);

            // Assert
            Assert.NotEqual(sig256, sig384);
            Assert.NotEqual(sig256, sig512);
            Assert.NotEqual(sig384, sig512);
        }
    }

    /// <summary>
    /// Tests for RSA digital signatures.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class RsaTests
    {
        [Theory]
        [InlineData(SignatureAlgorithm.RsaSha256)]
        [InlineData(SignatureAlgorithm.RsaPssSha256)]
        public void SignAndVerify_WithValidKeyPair_Succeeds(SignatureAlgorithm algorithm)
        {
            // Arrange
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithPrivateKey(privateKey)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.True(isValid);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ReturnsFalse()
        {
            // Arrange
            using var rsa1 = RSA.Create(2048);
            using var rsa2 = RSA.Create(2048);
            var privateKey1 = rsa1.ExportPkcs8PrivateKey();
            var publicKey2 = rsa2.ExportSubjectPublicKeyInfo();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithRsaSha256()
                .WithPrivateKey(privateKey1)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithRsaSha256()
                .WithPublicKey(publicKey2)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WithTamperedSignature_ReturnsFalse()
        {
            // Arrange
            using var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var publicKey = rsa.ExportSubjectPublicKeyInfo();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithRsaSha256()
                .WithPrivateKey(privateKey)
                .Sign(TestMessage);

            var tamperedSignature = TestHelpers.TamperFirst(signature);

            var isValid = HeroCryptBuilder.Verify()
                .WithRsaSha256()
                .WithPublicKey(publicKey)
                .WithSignature(tamperedSignature)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }
    }

    /// <summary>
    /// Tests for ECDSA digital signatures.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EcdsaTests
    {
        [Theory]
        [InlineData(SignatureAlgorithm.EcdsaP256Sha256, 256)]
        [InlineData(SignatureAlgorithm.EcdsaP384Sha384, 384)]
        [InlineData(SignatureAlgorithm.EcdsaP521Sha512, 521)]
        public void SignAndVerify_WithValidKeyPair_Succeeds(SignatureAlgorithm algorithm, int curveSizeBits)
        {
            // Arrange
            var curve = curveSizeBits switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentException($"Unsupported curve size: {curveSizeBits}")
            };

            using var ecdsa = ECDsa.Create(curve);
            var privateKey = ecdsa.ExportECPrivateKey();
            var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithPrivateKey(privateKey)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.True(isValid);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ReturnsFalse()
        {
            // Arrange
            using var ecdsa1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var ecdsa2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKey1 = ecdsa1.ExportECPrivateKey();
            var publicKey2 = ecdsa2.ExportSubjectPublicKeyInfo();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithEcdsaP256()
                .WithPrivateKey(privateKey1)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithEcdsaP256()
                .WithPublicKey(publicKey2)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }
    }

    /// <summary>
    /// Tests for Ed25519 signatures via HeroCryptBuilder.
    /// Low-level Ed25519 tests and RFC 8032 vectors are in Ed25519CoreTests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class Ed25519Tests
    {
        private const int SIGNATURE_SIZE = 64;

        [Fact]
        public void SignAndVerify_WithValidKeyPair_Succeeds()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.Equal(SIGNATURE_SIZE, signature.Length);
            Assert.True(isValid);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ReturnsFalse()
        {
            // Arrange
            var (privateKey1, _) = Ed25519Core.GenerateKeyPair();
            var (_, publicKey2) = Ed25519Core.GenerateKeyPair();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey1)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey2)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Tests for ML-DSA (Module-Lattice Digital Signature Algorithm) post-quantum signatures.
    /// </summary>
    /// <remarks>
    /// ML-DSA is a post-quantum cryptographic signature algorithm standardized by NIST.
    ///
    /// Platform Requirements:
    /// - .NET 10 or later is required for ML-DSA support
    /// - Windows: Requires Windows CNG with PQC support (Windows 11 24H2+ or Windows Server 2025+)
    /// - Linux: Requires OpenSSL 3.5+ with PQC provider enabled
    /// - macOS: Not currently supported (no native PQC implementation)
    ///
    /// Tests are automatically skipped on unsupported platforms using MLDsaCore.IsSupported().
    /// </remarks>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class MlDsaTests
    {
        [Theory]
        [InlineData(SignatureAlgorithm.MLDsa65, MLDsaCore.SecurityLevel.MLDsa65)]
        [InlineData(SignatureAlgorithm.MLDsa87, MLDsaCore.SecurityLevel.MLDsa87)]
        public void SignAndVerify_WithValidKeyPair_Succeeds(SignatureAlgorithm algorithm, MLDsaCore.SecurityLevel securityLevel)
        {
            if (!MLDsaCore.IsSupported())
            {
                Assert.Skip("ML-DSA not supported on this platform");
                return;
            }

            // Arrange
            using var keyPair = MLDsaCore.GenerateKeyPair(securityLevel);
            var privateKey = Encoding.UTF8.GetBytes(keyPair.SecretKeyPem);
            var publicKey = Encoding.UTF8.GetBytes(keyPair.PublicKeyPem);

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithPrivateKey(privateKey)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithPublicKey(publicKey)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.True(isValid);
        }

        [Fact]
        public void MLDsa65_Verify_WithWrongPublicKey_ReturnsFalse()
        {
            if (!MLDsaCore.IsSupported())
            {
                Assert.Skip("ML-DSA not supported on this platform");
                return;
            }

            // Arrange
            using var keyPair1 = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);
            using var keyPair2 = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);
            var privateKey1 = Encoding.UTF8.GetBytes(keyPair1.SecretKeyPem);
            var publicKey2 = Encoding.UTF8.GetBytes(keyPair2.PublicKeyPem);

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithMLDsa65()
                .WithPrivateKey(privateKey1)
                .Sign(TestMessage);

            var isValid = HeroCryptBuilder.Verify()
                .WithMLDsa65()
                .WithPublicKey(publicKey2)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.False(isValid);
        }
    }
#endif

    /// <summary>
    /// Tests for HeroCryptBuilder fluent API patterns.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BuilderPatternTests
    {
        [Fact]
        public void SignAndVerify_UsingFluentApi_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act - Sign
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithPrivateKey(key)
                .Sign(TestMessage);

            // Act - Verify
            var isValid = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void Sign_WithByteArrayData_ProducesSignature()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var testData = Encoding.UTF8.GetBytes("test message");

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithPrivateKey(key)
                .Sign(testData);

            // Assert
            Assert.NotNull(signature);
            Assert.NotEmpty(signature);
        }
    }

    /// <summary>
    /// Tests for parameter validation and error handling.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        [Fact]
        public void Sign_WithEmptyData_ThrowsArgumentException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.Sign().WithHmacSha256().WithPrivateKey(key).Sign([]));
        }

        [Fact]
        public void Sign_WithoutKey_ThrowsInvalidOperationException()
        {
            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Sign().WithHmacSha256().Sign(TestMessage));
        }

        [Fact]
        public void Verify_WithEmptyData_ThrowsArgumentException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var signature = TestHelpers.RandomBytes(32);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.Verify().WithHmacSha256().WithPublicKey(key).WithSignature(signature).Verify([]));
        }

        [Fact]
        public void Verify_WithoutSignature_ThrowsInvalidOperationException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Verify().WithHmacSha256().WithPublicKey(key).Verify(TestMessage));
        }

        [Fact]
        public void Verify_WithoutKey_ThrowsInvalidOperationException()
        {
            // Arrange
            var signature = TestHelpers.RandomBytes(32);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Verify().WithHmacSha256().WithSignature(signature).Verify(TestMessage));
        }
    }

    /// <summary>
    /// Tests for the WithKey alias method for symmetric MAC algorithms.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SymmetricKeyAliasTests
    {
        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256)]
        [InlineData(SignatureAlgorithm.HmacSha384)]
        [InlineData(SignatureAlgorithm.HmacSha512)]
        public void SignAndVerify_UsingWithKey_Succeeds(SignatureAlgorithm algorithm)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act - Sign using WithKey (alias for WithPrivateKey)
            var signature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Sign(TestMessage);

            // Act - Verify using WithKey (alias for WithPublicKey)
            var isValid = HeroCryptBuilder.Verify()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.True(isValid);
        }

        [Fact]
        public void WithKey_IsSemanticallyEquivalentToWithPrivateKey()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);

            // Act - Sign using WithKey
            var signatureFromWithKey = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act - Sign using WithPrivateKey
            var signatureFromWithPrivateKey = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithPrivateKey(key)
                .Sign(TestMessage);

            // Assert - Both should produce identical signatures
            Assert.Equal(signatureFromWithKey, signatureFromWithPrivateKey);
        }

        [Fact]
        public void WithKey_OnVerificationBuilder_IsSemanticallyEquivalentToWithPublicKey()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            // Act - Verify using WithKey
            var isValidWithKey = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Act - Verify using WithPublicKey
            var isValidWithPublicKey = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithPublicKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert - Both should verify successfully
            Assert.True(isValidWithKey);
            Assert.True(isValidWithPublicKey);
        }

        [Fact]
        public void AesCmac_WithKey_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(16); // 128-bit key for AES-CMAC-128

            // Act - Sign using WithKey
            var signature = HeroCryptBuilder.Sign()
                .WithAesCmac128()
                .WithKey(key)
                .Sign(TestMessage);

            // Act - Verify using WithKey
            var isValid = HeroCryptBuilder.Verify()
                .WithAesCmac128()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.True(isValid);
        }

        [Fact]
        public void Poly1305_WithKey_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32); // 256-bit key for Poly1305

            // Act - Sign using WithKey
            var signature = HeroCryptBuilder.Sign()
                .WithPoly1305()
                .WithKey(key)
                .Sign(TestMessage);

            // Act - Verify using WithKey
            var isValid = HeroCryptBuilder.Verify()
                .WithPoly1305()
                .WithKey(key)
                .WithSignature(signature)
                .Verify(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.True(isValid);
        }
    }
}
