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
                    .Verify(null!));
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
}
