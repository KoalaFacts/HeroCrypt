using System.Security.Cryptography;
using HeroCrypt.Primitives.Ecdsa;

namespace HeroCrypt.Tests.Primitives.Ecdsa;

/// <summary>
/// Comprehensive tests for ECDSA implementation with NIST curves.
/// Tests P-256, P-384, and P-521 curves as used in OpenPGP (RFC 6637).
/// </summary>
public class EcdsaCoreTests
{
    private static readonly byte[] TestMessage = "Test message for ECDSA signing"u8.ToArray();

    /// <summary>
    /// Basic key generation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyGenerationTests
    {
        private readonly EcdsaCore core = new();

        [Theory]
        [InlineData(256)]
        [InlineData(384)]
        [InlineData(521)]
        public void GenerateKeyPair_SupportedCurves_Succeeds(int curveSizeBits)
        {
            var parameters = core.GenerateKeyPair(curveSizeBits);

            Assert.NotNull(parameters.D);
            Assert.NotNull(parameters.Q.X);
            Assert.NotNull(parameters.Q.Y);

            // Verify expected sizes
            var expectedCoordSize = core.GetCoordinateSize(curveSizeBits);
            Assert.Equal(expectedCoordSize, parameters.Q.X.Length);
            Assert.Equal(expectedCoordSize, parameters.Q.Y.Length);
        }

        [Fact]
        public void GenerateKeyPair_UnsupportedCurveSize_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => core.GenerateKeyPair(128));
        }

        [Fact]
        public void GenerateKeyPair_ProducesUniqueKeys()
        {
            var params1 = core.GenerateKeyPair(256);
            var params2 = core.GenerateKeyPair(256);

            Assert.NotEqual(params1.D, params2.D);
        }
    }

    /// <summary>
    /// Signing and verification tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SignAndVerifyTests
    {
        private readonly EcdsaCore core = new();

        [Theory]
        [InlineData(256)]
        [InlineData(384)]
        [InlineData(521)]
        public void SignAndVerifyData_AllCurves_RoundTrips(int curveSizeBits)
        {
            var keyParams = core.GenerateKeyPair(curveSizeBits);
            var hashAlgorithm = core.GetRecommendedHashAlgorithm(curveSizeBits);

            var signature = core.SignData(TestMessage, keyParams, hashAlgorithm);

            Assert.NotNull(signature);
            Assert.NotEmpty(signature);

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyData(TestMessage, signature, publicKeyParams, hashAlgorithm);

            Assert.True(isValid);
        }

        [Theory]
        [InlineData(256)]
        [InlineData(384)]
        [InlineData(521)]
        public void SignAndVerifyHash_AllCurves_RoundTrips(int curveSizeBits)
        {
            var keyParams = core.GenerateKeyPair(curveSizeBits);

            // Compute hash
            var hash = SHA256.HashData(TestMessage);

            var signature = core.SignHash(hash, keyParams);

            Assert.NotNull(signature);

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyHash(hash, signature, publicKeyParams);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_TamperedData_ReturnsFalse()
        {
            var keyParams = core.GenerateKeyPair(256);
            var signature = core.SignData(TestMessage, keyParams, HashAlgorithmName.SHA256);

            var tamperedMessage = "Tampered message"u8.ToArray();

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyData(tamperedMessage, signature, publicKeyParams, HashAlgorithmName.SHA256);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_TamperedSignature_ReturnsFalse()
        {
            var keyParams = core.GenerateKeyPair(256);
            var signature = core.SignData(TestMessage, keyParams, HashAlgorithmName.SHA256);

            // Tamper with signature
            signature[0] ^= 0xFF;

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyData(TestMessage, signature, publicKeyParams, HashAlgorithmName.SHA256);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WrongPublicKey_ReturnsFalse()
        {
            var keyParams1 = core.GenerateKeyPair(256);
            var keyParams2 = core.GenerateKeyPair(256);

            var signature = core.SignData(TestMessage, keyParams1, HashAlgorithmName.SHA256);

            var wrongPublicKey = core.ExtractPublicKey(keyParams2);
            var isValid = core.VerifyData(TestMessage, signature, wrongPublicKey, HashAlgorithmName.SHA256);

            Assert.False(isValid);
        }
    }

    /// <summary>
    /// Raw signature format tests (r, s components).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RawSignatureTests
    {
        private readonly EcdsaCore core = new();

        [Theory]
        [InlineData(256)]
        [InlineData(384)]
        [InlineData(521)]
        public void SignAndVerifyHashRaw_AllCurves_RoundTrips(int curveSizeBits)
        {
            var keyParams = core.GenerateKeyPair(curveSizeBits);
            var hash = SHA256.HashData(TestMessage);

            var (r, s) = core.SignHashRaw(hash, keyParams);

            Assert.NotNull(r);
            Assert.NotNull(s);

            var expectedComponentSize = core.GetSignatureComponentSize(curveSizeBits);
            Assert.Equal(expectedComponentSize, r.Length);
            Assert.Equal(expectedComponentSize, s.Length);

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyHashRaw(hash, r, s, publicKeyParams);

            Assert.True(isValid);
        }
    }

    /// <summary>
    /// Key parameter creation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyParameterTests
    {
        private readonly EcdsaCore core = new();

        [Fact]
        public void CreateParameters_WithPrivateKey_CanSign()
        {
            var generatedParams = core.GenerateKeyPair(256);

            var recreatedParams = core.CreateParameters(
                256,
                generatedParams.D,
                generatedParams.Q.X!,
                generatedParams.Q.Y!);

            var hash = SHA256.HashData(TestMessage);
            var signature = core.SignHash(hash, recreatedParams);

            var isValid = core.VerifyHash(hash, signature, recreatedParams);
            Assert.True(isValid);
        }

        [Fact]
        public void CreatePublicKeyParameters_CanVerify()
        {
            var keyParams = core.GenerateKeyPair(256);
            var hash = SHA256.HashData(TestMessage);
            var signature = core.SignHash(hash, keyParams);

            var publicKeyParams = core.CreatePublicKeyParameters(
                256,
                keyParams.Q.X!,
                keyParams.Q.Y!);

            var isValid = core.VerifyHash(hash, signature, publicKeyParams);
            Assert.True(isValid);
        }

        [Fact]
        public void ExtractPublicKey_RemovesPrivateKey()
        {
            var keyParams = core.GenerateKeyPair(256);

            Assert.NotNull(keyParams.D);

            var publicKeyParams = core.ExtractPublicKey(keyParams);

            Assert.Null(publicKeyParams.D);
            Assert.NotNull(publicKeyParams.Q.X);
            Assert.NotNull(publicKeyParams.Q.Y);
        }
    }

    /// <summary>
    /// Utility function tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class UtilityFunctionTests
    {
        private readonly EcdsaCore core = new();

        [Theory]
        [InlineData(256, 32)]
        [InlineData(384, 48)]
        [InlineData(521, 66)]
        public void GetCoordinateSize_ReturnsCorrectSize(int curveSizeBits, int expectedSize)
        {
            var size = core.GetCoordinateSize(curveSizeBits);
            Assert.Equal(expectedSize, size);
        }

        [Theory]
        [InlineData(256, 64)]
        [InlineData(384, 96)]
        [InlineData(521, 132)]
        public void GetSignatureSize_ReturnsCorrectSize(int curveSizeBits, int expectedSize)
        {
            var size = core.GetSignatureSize(curveSizeBits);
            Assert.Equal(expectedSize, size);
        }

        [Theory]
        [InlineData(256, "SHA256")]
        [InlineData(384, "SHA384")]
        [InlineData(521, "SHA512")]
        public void GetRecommendedHashAlgorithm_ReturnsCorrectAlgorithm(int curveSizeBits, string expectedName)
        {
            var algorithm = core.GetRecommendedHashAlgorithm(curveSizeBits);
            Assert.Equal(expectedName, algorithm.Name);
        }
    }

    /// <summary>
    /// Builder API tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BuilderApiTests
    {
        [Fact]
        public void Builder_SignAndVerify_Works()
        {
            using var builder = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256);

            var keyParams = builder.GenerateKeyPair();

            var signature = builder
                .WithData(TestMessage)
                .Sign();

            var publicKey = builder.ExtractPublicKey();

            using var verifier = EcdsaBuilder.Create()
                .WithKeyParameters(publicKey)
                .WithData(TestMessage)
                .WithSignature(signature);

            Assert.True(verifier.Verify());
        }

        [Fact]
        public void Builder_WithRawKey_Works()
        {
            var core = new EcdsaCore();
            var keyParams = core.GenerateKeyPair(256);
            var hash = SHA256.HashData(TestMessage);

            using var builder = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256)
                .WithRawKey(keyParams.D, keyParams.Q.X!, keyParams.Q.Y!)
                .WithHash(hash);

            var signature = builder.Sign();

            using var verifier = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256)
                .WithPublicKey(keyParams.Q.X!, keyParams.Q.Y!)
                .WithHash(hash)
                .WithSignature(signature);

            Assert.True(verifier.Verify());
        }

        [Fact]
        public void Builder_SignRaw_ReturnsComponents()
        {
            using var builder = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256);

            builder.GenerateKeyPair();

            var (r, s) = builder
                .WithData(TestMessage)
                .SignRaw();

            Assert.NotNull(r);
            Assert.NotNull(s);
            Assert.Equal(32, r.Length);
            Assert.Equal(32, s.Length);
        }

        [Fact]
        public void Builder_WithSignatureRaw_Works()
        {
            using var builder = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256);

            var keyParams = builder.GenerateKeyPair();

            var (r, s) = builder
                .WithData(TestMessage)
                .SignRaw();

            var publicKey = builder.ExtractPublicKey();

            using var verifier = EcdsaBuilder.Create()
                .WithKeyParameters(publicKey)
                .WithData(TestMessage)
                .WithSignatureRaw(r, s);

            Assert.True(verifier.Verify());
        }

        [Fact]
        public void Builder_VerifyRaw_Works()
        {
            using var builder = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256);

            var keyParams = builder.GenerateKeyPair();

            var (r, s) = builder
                .WithData(TestMessage)
                .SignRaw();

            var publicKey = builder.ExtractPublicKey();

            using var verifier = EcdsaBuilder.Create()
                .WithKeyParameters(publicKey)
                .WithData(TestMessage);

            Assert.True(verifier.VerifyRaw(r, s));
        }

        [Fact]
        public void Builder_WithoutKeyParameters_ThrowsInvalidOperationException()
        {
            using var builder = EcdsaBuilder.Create()
                .WithData(TestMessage);

            Assert.Throws<InvalidOperationException>(builder.Sign);
        }

        [Fact]
        public void Builder_SignWithoutData_ThrowsInvalidOperationException()
        {
            using var builder = EcdsaBuilder.Create()
                .WithCurve(EcdsaCurve.P256);

            builder.GenerateKeyPair();

            Assert.Throws<InvalidOperationException>(builder.Sign);
        }

        [Fact]
        public void HeroCryptBuilder_Ecdsa_CreatesBuilder()
        {
            using var builder = HeroCryptBuilder.Ecdsa();

            Assert.NotNull(builder);
            Assert.IsType<EcdsaBuilder>(builder);
        }
    }

    /// <summary>
    /// Curve-specific tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class CurveSpecificTests
    {
        [Theory]
        [InlineData(EcdsaCurve.P256)]
        [InlineData(EcdsaCurve.P384)]
        [InlineData(EcdsaCurve.P521)]
        public void Builder_AllCurves_Work(EcdsaCurve curve)
        {
            using var builder = EcdsaBuilder.Create()
                .WithCurve(curve);

            var keyParams = builder.GenerateKeyPair();

            var signature = builder
                .WithData(TestMessage)
                .Sign();

            var publicKey = builder.ExtractPublicKey();

            using var verifier = EcdsaBuilder.Create()
                .WithCurve(curve)
                .WithKeyParameters(publicKey)
                .WithData(TestMessage)
                .WithSignature(signature);

            Assert.True(verifier.Verify());
        }
    }

    /// <summary>
    /// Edge case tests.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly EcdsaCore core = new();

        [Fact]
        public void Sign_EmptyData_Succeeds()
        {
            var keyParams = core.GenerateKeyPair(256);
            var emptyData = Array.Empty<byte>();

            var signature = core.SignData(emptyData, keyParams, HashAlgorithmName.SHA256);

            Assert.NotNull(signature);

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyData(emptyData, signature, publicKeyParams, HashAlgorithmName.SHA256);

            Assert.True(isValid);
        }

        [Fact]
        public void Sign_LargeData_Succeeds()
        {
            var keyParams = core.GenerateKeyPair(256);
            var largeData = new byte[1024 * 1024]; // 1 MB
            new Random(42).NextBytes(largeData);

            var signature = core.SignData(largeData, keyParams, HashAlgorithmName.SHA256);

            Assert.NotNull(signature);

            var publicKeyParams = core.ExtractPublicKey(keyParams);
            var isValid = core.VerifyData(largeData, signature, publicKeyParams, HashAlgorithmName.SHA256);

            Assert.True(isValid);
        }
    }
}
