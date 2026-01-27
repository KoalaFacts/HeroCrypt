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
        public void SignAndVerify_SingleByte_Succeeds(SignatureAlgorithm algorithm)
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
        public void SignAndVerify_AllZeros_Succeeds(SignatureAlgorithm algorithm)
        {
            var key = TestHelpers.RandomBytes(64);
            var data = new byte[256]; // 256 bytes of zeros

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
        public void SignAndVerify_LargeData_Succeeds(SignatureAlgorithm algorithm)
        {
            var key = TestHelpers.RandomBytes(64);
            var data = TestHelpers.RandomBytes(64 * 1024); // 64KB

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
        public void SignAndVerify_SingleByteKey_HmacSucceeds()
        {
            // HMAC can work with any key size (though small keys are not recommended)
            var key = new byte[] { 0x42 };
            var data = Encoding.UTF8.GetBytes("test message");

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
        public void Sign_SingleCharacterString_Succeeds()
        {
            var key = TestHelpers.RandomBytes(64);
            var data = "X";

            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            Assert.NotNull(signature);
            Assert.Equal(32, signature.Length);
        }

        [Fact]
        public void SignAndVerify_UnicodeString_Succeeds()
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
        public void SignAndVerify_RepeatingPatternData_Succeeds()
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
        public void Ed25519_SignAndVerify_SingleByte_Succeeds()
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
        public void Ed25519_SignAndVerify_AllZeros_Succeeds()
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
        public void Ed25519_SignAndVerify_LargeData_Succeeds()
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

    /// <summary>
    /// Tests for key input format convenience methods (WithKeyFromHex, WithKeyFromBase64, WithKeyFromBase64Url).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyInputFormatTests
    {
        [Fact]
        public void WithKeyFromHex_SignsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key);

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromHex = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromHex);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsLowercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.Equal(32, signature.Length); // HMAC-SHA256
        }

        [Fact]
        public void WithKeyFromHex_AcceptsUppercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var hexKey = Convert.ToHexString(key).ToUpperInvariant();

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Assert
            Assert.NotNull(signature);
            Assert.Equal(32, signature.Length);
        }

        [Fact]
        public void WithKeyFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Sign()
                    .WithHmacSha256()
                    .WithKeyFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64_SignsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64Key = Convert.ToBase64String(key);

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromBase64 = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromBase64(base64Key)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromBase64);
        }

        [Fact]
        public void WithKeyFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Sign()
                    .WithHmacSha256()
                    .WithKeyFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64Url_SignsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromBase64Url = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromBase64Url(base64UrlKey)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromBase64Url);
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

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromBase64Url = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKeyFromBase64Url(base64UrlKey)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromBase64Url);
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

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromHex = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromHex);
        }

        [Fact]
        public void WithKeyFromHex_WorksWithAesCmac()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(16);
            var hexKey = Convert.ToHexString(key);

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithAesCmac128()
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromHex = HeroCryptBuilder.Sign()
                .WithAesCmac128()
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromHex);
        }

        [Fact]
        public void WithKeyFromHex_WorksWithPoly1305()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key);

            // Act
            var signatureFromBytes = HeroCryptBuilder.Sign()
                .WithPoly1305()
                .WithKey(key)
                .Sign(TestMessage);

            var signatureFromHex = HeroCryptBuilder.Sign()
                .WithPoly1305()
                .WithKeyFromHex(hexKey)
                .Sign(TestMessage);

            // Assert
            Assert.Equal(signatureFromBytes, signatureFromHex);
        }
    }

    /// <summary>
    /// Tests for signature output format convenience methods (SignToHex, SignToBase64).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class OutputFormatConvenienceMethods
    {
        [Fact]
        public void SignToHex_ReturnsLowercaseHexString()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var hexSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToHex(data);

            // Assert
            Assert.NotNull(hexSignature);
            Assert.Equal(64, hexSignature.Length); // HMAC-SHA256 = 32 bytes = 64 hex chars
            Assert.Equal(hexSignature.ToLowerInvariant(), hexSignature); // lowercase
            Assert.Matches("^[0-9a-f]+$", hexSignature); // valid hex
        }

        [Fact]
        public void SignToHex_ByteArray_ReturnsCorrectHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = Encoding.UTF8.GetBytes("test message");

            // Act
            var hexSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToHex(data);

            // Assert
            Assert.NotNull(hexSignature);
            Assert.Matches("^[0-9a-f]+$", hexSignature);
        }

        [Fact]
        public void SignToHex_MatchesManualConversion()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var signatureBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var hexSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToHex(data);

            var expectedHex = Convert.ToHexString(signatureBytes).ToLowerInvariant();

            // Assert
            Assert.Equal(expectedHex, hexSignature);
        }

        [Fact]
        public void SignToBase64_ReturnsValidBase64()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var base64Signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64(data);

            // Assert
            Assert.NotNull(base64Signature);
            Assert.DoesNotContain(" ", base64Signature);

            // Verify it's valid Base64 by decoding
            var decoded = Convert.FromBase64String(base64Signature);
            Assert.Equal(32, decoded.Length); // HMAC-SHA256 = 32 bytes
        }

        [Fact]
        public void SignToBase64_ByteArray_MatchesStringVersion()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var stringData = "test message";
            var byteData = Encoding.UTF8.GetBytes(stringData);

            // Act
            var base64FromString = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64(stringData);

            var base64FromBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64(byteData);

            // Assert
            Assert.Equal(base64FromString, base64FromBytes);
        }

        [Fact]
        public void SignToBase64_MatchesManualConversion()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var signatureBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var base64Signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64(data);

            var expectedBase64 = Convert.ToBase64String(signatureBytes);

            // Assert
            Assert.Equal(expectedBase64, base64Signature);
        }

        [Fact]
        public void SignToHex_WithEd25519_Succeeds()
        {
            // Arrange
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();
            var data = "test message";

            // Act
            var hexSignature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .SignToHex(data);

            // Assert
            Assert.NotNull(hexSignature);
            Assert.Equal(128, hexSignature.Length); // Ed25519 = 64 bytes = 128 hex chars
            Assert.Matches("^[0-9a-f]+$", hexSignature);
        }

        [Fact]
        public void SignToBase64_WithEd25519_Succeeds()
        {
            // Arrange
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();
            var data = "test message";

            // Act
            var base64Signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .SignToBase64(data);

            // Assert
            Assert.NotNull(base64Signature);
            var decoded = Convert.FromBase64String(base64Signature);
            Assert.Equal(64, decoded.Length); // Ed25519 = 64 bytes
        }

        [Theory]
        [InlineData(SignatureAlgorithm.HmacSha256, 64)]  // 32 bytes = 64 hex chars
        [InlineData(SignatureAlgorithm.HmacSha384, 96)]  // 48 bytes = 96 hex chars
        [InlineData(SignatureAlgorithm.HmacSha512, 128)] // 64 bytes = 128 hex chars
        public void SignToHex_AllHmacAlgorithms_ReturnsCorrectLength(SignatureAlgorithm algorithm, int expectedHexLength)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var hexSignature = HeroCryptBuilder.Sign()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .SignToHex(data);

            // Assert
            Assert.Equal(expectedHexLength, hexSignature.Length);
        }

        [Fact]
        public void SignToBase64Url_ReturnsUrlSafeString()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var base64UrlSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64Url(data);

            // Assert
            Assert.NotNull(base64UrlSignature);
            Assert.DoesNotContain("+", base64UrlSignature);
            Assert.DoesNotContain("/", base64UrlSignature);
            Assert.DoesNotContain("=", base64UrlSignature);
        }

        [Fact]
        public void SignToBase64Url_CanBeDecodedBack()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var data = "test message";

            // Act
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(data);

            var base64UrlSignature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64Url(data);

            // Convert back from URL-safe Base64
            var base64 = base64UrlSignature
                .Replace('-', '+')
                .Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 0: break;
                case 1: break;
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
                default: break;
            }
            var decoded = Convert.FromBase64String(base64);

            // Assert
            Assert.Equal(signature, decoded);
        }

        [Fact]
        public void SignToBase64Url_StringOverload_MatchesByteOverload()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var stringData = "test message";
            var byteData = Encoding.UTF8.GetBytes(stringData);

            // Act
            var fromString = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64Url(stringData);

            var fromBytes = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .SignToBase64Url(byteData);

            // Assert
            Assert.Equal(fromString, fromBytes);
        }
    }

    /// <summary>
    /// Tests for malformed input handling in SignatureBuilder.
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
                HeroCryptBuilder.Sign()
                    .WithHmacSha256()
                    .WithKeyFromHex(invalidHex));
        }

        [Theory]
        [MemberData(nameof(InvalidBase64Strings))]
        public void WithKeyFromBase64_InvalidBase64_ThrowsFormatException(string invalidBase64)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Sign()
                    .WithHmacSha256()
                    .WithKeyFromBase64(invalidBase64));
        }

        [Fact]
        public void WithNullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                HeroCryptBuilder.Sign()
                    .WithHmacSha256()
                    .WithKey(null!));
        }

        [Fact]
        public void Ed25519_WithWrongPrivateKeySize_ThrowsException()
        {
            var wrongSizeKey = TestHelpers.RandomBytes(16);

            Assert.ThrowsAny<Exception>(() =>
                HeroCryptBuilder.Sign()
                    .WithEd25519()
                    .WithPrivateKey(wrongSizeKey)
                    .Sign("test"));
        }
    }

    /// <summary>
    /// Tests for memory safety and secure disposal of SignatureBuilder.
    /// </summary>
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.FAST)]
    public class MemorySafety
    {
        [Fact]
        public void AfterDispose_Sign_ThrowsObjectDisposedException()
        {
            var builder = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(TestHelpers.RandomBytes(32));

            builder.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                builder.Sign("test"));
        }

        [Fact]
        public void AfterDispose_WithKey_ThrowsObjectDisposedException()
        {
            var builder = HeroCryptBuilder.Sign()
                .WithHmacSha256();

            builder.Dispose();

            Assert.Throws<ObjectDisposedException>(() =>
                builder.WithKey(TestHelpers.RandomBytes(32)));
        }

        [Fact]
        public void MultipleDispose_DoesNotThrow()
        {
            var builder = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(TestHelpers.RandomBytes(32));

            builder.Dispose();
            builder.Dispose();
            builder.Dispose();
        }
    }

    /// <summary>
    /// Tests for concurrent disposal safety of SignatureBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.FAST)]
    public class ConcurrentDisposal
    {
        [Fact]
        public void ConcurrentDispose_DoesNotThrow()
        {
            var builder = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(TestHelpers.RandomBytes(32));

            var tasks = Enumerable.Range(0, 10)
                .Select(_ => Task.Run(() => builder.Dispose()))
                .ToArray();

            Task.WaitAll(tasks);
        }

        [Fact]
        public void RapidCreateDisposeLoop_NoIssues()
        {
            for (int i = 0; i < 100; i++)
            {
                var builder = HeroCryptBuilder.Sign()
                    .WithHmacSha256()
                    .WithKey(TestHelpers.RandomBytes(32));

                builder.Sign("test data");
                builder.Dispose();
            }
        }
    }
}
