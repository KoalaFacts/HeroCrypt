using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PgpSignatureSigner and PgpSignatureVerifier.
/// </summary>
public class PgpSignatureSignerTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // Helper Methods for Test Key Generation
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates an RSA key pair for testing.
    /// </summary>
    private static (PgpPublicKeyPacket PublicKey, PgpSecretKeyPacket SecretKey) CreateRsaKeyPair(int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        var rsaParams = rsa.ExportParameters(true);

        var n = new BigInteger(rsaParams.Modulus!, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(rsaParams.Exponent!, isUnsigned: true, isBigEndian: true);
        var d = new BigInteger(rsaParams.D!, isUnsigned: true, isBigEndian: true);
        var p = new BigInteger(rsaParams.P!, isUnsigned: true, isBigEndian: true);
        var q = new BigInteger(rsaParams.Q!, isUnsigned: true, isBigEndian: true);

        // Compute u = p^-1 mod q (required by PGP format)
        var u = BigInteger.ModPow(p, q - 2, q);

        // Build the secret key material as MPI-encoded values: d, p, q, u
        var secretMaterial = BuildRsaSecretMaterial(d, p, q, u);

        var publicKey = PgpPublicKeyPacket.CreateRsa(4, DateTimeOffset.UtcNow, n, e);
        var secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);

        return (publicKey, secretKey);
    }

    /// <summary>
    /// Builds RSA secret key material as MPI-encoded values.
    /// </summary>
    private static byte[] BuildRsaSecretMaterial(BigInteger d, BigInteger p, BigInteger q, BigInteger u)
    {
        // Calculate total size needed
        int dLen = Mpi.GetEncodedLength(d);
        int pLen = Mpi.GetEncodedLength(p);
        int qLen = Mpi.GetEncodedLength(q);
        int uLen = Mpi.GetEncodedLength(u);

        var result = new byte[dLen + pLen + qLen + uLen];
        var span = result.AsSpan();

        int offset = 0;
        offset += Mpi.Write(d, span.Slice(offset));
        offset += Mpi.Write(p, span.Slice(offset));
        offset += Mpi.Write(q, span.Slice(offset));
        Mpi.Write(u, span.Slice(offset));

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Basic Signing Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class BasicSigningTests
    {
        [Fact]
        public void Sign_WithRsaKey_ProducesValidSignature()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(100);

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey)
                .WithSha256();
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.Equal(data.Length, signedMessage.Data.Length);
            Assert.Equal(PgpSignatureType.BinaryDocument, signedMessage.Signature.SignatureType);
            Assert.Equal(4, signedMessage.Signature.Version);
        }

        [Fact]
        public void Sign_CreatesCorrectOnePassSignaturePacket()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = "Hello, World!"u8.ToArray();

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.True(signedMessage.OnePassSignature.HasValue);
            Assert.Equal(PgpSignatureType.BinaryDocument, signedMessage.OnePassSignature.Value.SignatureType);
        }

        [Fact]
        public void Sign_WithEmptyData_Succeeds()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = Array.Empty<byte>();

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.Equal(0, signedMessage.Data.Length);
            Assert.False(signedMessage.Signature.SignatureData.IsEmpty);
        }

        [Fact]
        public void CreateDetachedSignature_ReturnsSignatureOnly()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(50);

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signature = signer.CreateDetachedSignature(data);

            // Assert
            Assert.Equal(PgpSignatureType.BinaryDocument, signature.SignatureType);
            Assert.Equal(4, signature.Version);
            Assert.False(signature.SignatureData.IsEmpty);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Verification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class VerificationTests
    {
        [Fact]
        public void Verify_ValidSignature_ReturnsValid()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = "Test message for signing"u8.ToArray();

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(data, signedMessage.Signature);

            // Assert
            Assert.True(result.IsValid);
            Assert.Equal(PgpSignatureType.BinaryDocument, result.SignatureType);
            Assert.Equal(PgpHashAlgorithmId.Sha256, result.HashAlgorithm);
            Assert.Null(result.ErrorMessage);
        }

        [Fact]
        public void Verify_SignedMessage_ReturnsValid()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(256);

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(signedMessage);

            // Assert
            Assert.True(result.IsValid);
        }

        [Fact]
        public void Verify_TamperedData_ReturnsInvalid()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(100);

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Tamper with the data
            var tamperedData = TestHelpers.TamperFirst(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(tamperedData, signedMessage.Signature);

            // Assert
            Assert.False(result.IsValid);
            Assert.NotNull(result.ErrorMessage);
        }

        [Fact]
        public void Verify_WrongKey_ReturnsInvalid()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var (wrongPublicKey, _) = CreateRsaKeyPair();
            var data = "Secret message"u8.ToArray();

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(wrongPublicKey);
            var result = verifier.Verify(data, signedMessage.Signature);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Verify_NoPublicKeys_ReturnsInvalid()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = "Test"u8.ToArray();

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create();
            var result = verifier.Verify(data, signedMessage.Signature);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("No public keys", result.ErrorMessage);
        }

        [Fact]
        public void TryVerify_ReturnsExpectedResult()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = "Test data"u8.ToArray();

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var success = verifier.TryVerify(data, signedMessage.Signature, out var result, out var error);

            // Assert
            Assert.True(success);
            Assert.True(result.IsValid);
            Assert.Null(error);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Hash Algorithm Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class HashAlgorithmTests
    {
        [Theory]
        [InlineData(PgpHashAlgorithmId.Sha256)]
        [InlineData(PgpHashAlgorithmId.Sha384)]
        [InlineData(PgpHashAlgorithmId.Sha512)]
        public void Sign_WithDifferentHashAlgorithms_ProducesValidSignatures(PgpHashAlgorithmId hashAlg)
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(64);

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey)
                .WithHashAlgorithm(hashAlg);
            var signedMessage = signer.Sign(data);

            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(data, signedMessage.Signature);

            // Assert
            Assert.True(result.IsValid);
            Assert.Equal(hashAlg, result.HashAlgorithm);
        }

        [Fact]
        public void WithSha256_SetsCorrectHashAlgorithm()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = "Test"u8.ToArray();

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey)
                .WithSha256();
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.Equal((byte)PgpHashAlgorithmId.Sha256, signedMessage.Signature.HashAlgorithm);
        }

        [Fact]
        public void WithSha384_SetsCorrectHashAlgorithm()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = "Test"u8.ToArray();

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey)
                .WithSha384();
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.Equal((byte)PgpHashAlgorithmId.Sha384, signedMessage.Signature.HashAlgorithm);
        }

        [Fact]
        public void WithSha512_SetsCorrectHashAlgorithm()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = "Test"u8.ToArray();

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey)
                .WithSha512();
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.Equal((byte)PgpHashAlgorithmId.Sha512, signedMessage.Signature.HashAlgorithm);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Text Signing Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class TextSigningTests
    {
        [Fact]
        public void SignText_SetsCanonicalTextType()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var text = "Hello, World!";

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.SignText(text);

            // Assert
            Assert.Equal(PgpSignatureType.CanonicalTextDocument, signedMessage.Signature.SignatureType);
        }

        [Fact]
        public void SignText_CanonicalizesCRLF()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var text = "Line 1\nLine 2\rLine 3\r\nLine 4";

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.SignText(text);

            // Assert - the data should be canonicalized with CRLF
            var dataString = signedMessage.GetDataAsString();
            Assert.Contains("\r\n", dataString);
            Assert.DoesNotContain("\r\r", dataString); // No double CR
        }

        [Fact]
        public void SignText_NullText_ThrowsArgumentNullException()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();

            // Act & Assert
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            Assert.Throws<ArgumentNullException>(() => signer.SignText(null!));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Error Cases
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ErrorCaseTests
    {
        [Fact]
        public void Sign_WithoutSecretKey_ThrowsInvalidOperationException()
        {
            // Arrange
            var data = "Test"u8.ToArray();

            // Act & Assert
            using var signer = PgpSignatureSigner.Create();
            Assert.Throws<InvalidOperationException>(() => signer.Sign(data));
        }

        [Fact]
        public void CreateDetachedSignature_WithoutSecretKey_ThrowsInvalidOperationException()
        {
            // Arrange
            var data = "Test"u8.ToArray();

            // Act & Assert
            using var signer = PgpSignatureSigner.Create();
            Assert.Throws<InvalidOperationException>(() => signer.CreateDetachedSignature(data));
        }

        [Fact]
        public void Dispose_PreventsSubsequentUse()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);

            // Act
            signer.Dispose();

            // Assert
            Assert.Throws<ObjectDisposedException>(() => signer.Sign("Test"u8));
        }

        [Fact]
        public void Verifier_Dispose_PreventsSubsequentUse()
        {
            // Arrange
            var (publicKey, _) = CreateRsaKeyPair();
            var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);

            // Act
            verifier.Dispose();

            // Assert
            Assert.Throws<ObjectDisposedException>(() =>
                verifier.Verify("Test"u8, PgpSignaturePacket.CreateV4(
                    PgpSignatureType.BinaryDocument, 1, 8, [], [], 0, Array.Empty<byte>())));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class RoundTripTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(256)]
        [InlineData(1024)]
        public void SignAndVerify_VariousDataSizes_Succeeds(int dataSize)
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = dataSize > 0 ? TestHelpers.RandomBytes(dataSize) : [];

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(data, signedMessage.Signature);

            // Assert
            Assert.True(result.IsValid);
        }

        [Fact]
        public void SignedMessage_Serialization_RoundTrips()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = "Important document content"u8.ToArray();

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act - serialize and deserialize
            var serialized = signedMessage.ToArray();
            var deserialized = PgpSignedMessage.Read(serialized);

            // Assert
            Assert.Equal(signedMessage.Data.Length, deserialized.Data.Length);
            Assert.True(signedMessage.Data.Span.SequenceEqual(deserialized.Data.Span));

            // Verify the deserialized message
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(deserialized);
            Assert.True(result.IsValid);
        }

        [Fact]
        public void DetachedSignature_Verification_Works()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(128);

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signature = signer.CreateDetachedSignature(data);

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(data, signature);

            // Assert
            Assert.True(result.IsValid);
        }

        [Fact]
        public void SignatureResult_ContainsExpectedMetadata()
        {
            // Arrange
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var data = "Metadata test"u8.ToArray();
            var beforeSign = DateTimeOffset.UtcNow;

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey)
                .WithSha384();
            var signedMessage = signer.Sign(data);

            var afterSign = DateTimeOffset.UtcNow;

            // Act
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(publicKey);
            var result = verifier.Verify(data, signedMessage.Signature);

            // Assert
            Assert.True(result.IsValid);
            Assert.Equal(PgpSignatureType.BinaryDocument, result.SignatureType);
            Assert.Equal(PgpHashAlgorithmId.Sha384, result.HashAlgorithm);
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, result.PublicKeyAlgorithm);
            Assert.Equal(4, result.SignatureVersion);

            Assert.NotNull(result.SignatureTime);
            Assert.True(result.SignatureTime >= beforeSign.AddSeconds(-1));
            Assert.True(result.SignatureTime <= afterSign.AddSeconds(1));

            Assert.NotNull(result.SignerKeyId);
            Assert.Equal(8, result.SignerKeyId.Length);
            Assert.NotNull(result.GetKeyIdHex());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSignatureResult Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SignatureResultTests
    {
        [Fact]
        public void Valid_CreatesValidResult()
        {
            var result = PgpSignatureResult.Valid(
                PgpSignatureType.BinaryDocument,
                DateTimeOffset.UtcNow,
                new byte[8],
                new byte[20],
                PgpHashAlgorithmId.Sha256,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                4);

            Assert.True(result.IsValid);
            Assert.Null(result.ErrorMessage);
        }

        [Fact]
        public void Invalid_CreatesInvalidResult()
        {
            var result = PgpSignatureResult.Invalid("Test error message");

            Assert.False(result.IsValid);
            Assert.Equal("Test error message", result.ErrorMessage);
        }

        [Fact]
        public void GetKeyIdHex_ReturnsHexString()
        {
            var keyId = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            var result = PgpSignatureResult.Valid(
                PgpSignatureType.BinaryDocument,
                DateTimeOffset.UtcNow,
                keyId,
                null,
                PgpHashAlgorithmId.Sha256,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                4);

            Assert.Equal("0123456789ABCDEF", result.GetKeyIdHex());
        }

        [Fact]
        public void GetFingerprintHex_ReturnsHexString()
        {
            var fingerprint = new byte[20];
            fingerprint[0] = 0xAB;
            fingerprint[19] = 0xCD;

            var result = PgpSignatureResult.Valid(
                PgpSignatureType.BinaryDocument,
                DateTimeOffset.UtcNow,
                null,
                fingerprint,
                PgpHashAlgorithmId.Sha256,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                4);

            var hex = result.GetFingerprintHex();
            Assert.NotNull(hex);
            Assert.StartsWith("AB", hex);
            Assert.EndsWith("CD", hex);
        }

        [Fact]
        public void ToString_ValidResult_ContainsExpectedInfo()
        {
            var result = PgpSignatureResult.Valid(
                PgpSignatureType.BinaryDocument,
                DateTimeOffset.UtcNow,
                new byte[8],
                null,
                PgpHashAlgorithmId.Sha256,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                4);

            var str = result.ToString();
            Assert.Contains("Valid", str);
            Assert.Contains("BinaryDocument", str);
            Assert.Contains("Sha256", str);
        }

        [Fact]
        public void ToString_InvalidResult_ContainsErrorMessage()
        {
            var result = PgpSignatureResult.Invalid("Signature failed");

            var str = result.ToString();
            Assert.Contains("Invalid", str);
            Assert.Contains("Signature failed", str);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpHashAlgorithmId Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class HashAlgorithmIdTests
    {
        [Theory]
        [InlineData(PgpHashAlgorithmId.Sha256, 32)]
        [InlineData(PgpHashAlgorithmId.Sha384, 48)]
        [InlineData(PgpHashAlgorithmId.Sha512, 64)]
        [InlineData(PgpHashAlgorithmId.Sha224, 28)]
        public void GetHashSize_ReturnsCorrectSize(PgpHashAlgorithmId alg, int expectedSize)
        {
            Assert.Equal(expectedSize, alg.GetHashSize());
        }

        [Theory]
        [InlineData(PgpHashAlgorithmId.Sha256)]
        [InlineData(PgpHashAlgorithmId.Sha384)]
        [InlineData(PgpHashAlgorithmId.Sha512)]
        public void ComputeHash_ProducesCorrectSizeOutput(PgpHashAlgorithmId alg)
        {
            var data = TestHelpers.RandomBytes(100);
            var hash = alg.ComputeHash(data);

            Assert.Equal(alg.GetHashSize(), hash.Length);
        }

        [Fact]
        public void ComputeHash_SameInput_ProducesSameOutput()
        {
            var data = "Test data for hashing"u8.ToArray();

            var hash1 = PgpHashAlgorithmId.Sha256.ComputeHash(data);
            var hash2 = PgpHashAlgorithmId.Sha256.ComputeHash(data);

            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void ComputeHash_DifferentInput_ProducesDifferentOutput()
        {
            var data1 = "Data 1"u8.ToArray();
            var data2 = "Data 2"u8.ToArray();

            var hash1 = PgpHashAlgorithmId.Sha256.ComputeHash(data1);
            var hash2 = PgpHashAlgorithmId.Sha256.ComputeHash(data2);

            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void CreateIncrementalHash_AllowsStreamingHash()
        {
            var data = TestHelpers.RandomBytes(200);

            // Compute hash in one go
            var hash1 = PgpHashAlgorithmId.Sha256.ComputeHash(data);

            // Compute hash incrementally
            using var incremental = PgpHashAlgorithmId.Sha256.CreateIncrementalHash();
            incremental.AppendData(data.AsSpan(0, 100).ToArray());
            incremental.AppendData(data.AsSpan(100, 100).ToArray());
            var hash2 = incremental.GetHashAndReset();

            Assert.Equal(hash1, hash2);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSignedMessage Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SignedMessageTests
    {
        [Fact]
        public void GetDataAsString_ReturnsUtf8String()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var text = "Hello, UTF-8 World!";
            var data = System.Text.Encoding.UTF8.GetBytes(text);

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            var result = signedMessage.GetDataAsString();

            // Assert
            Assert.Equal(text, result);
        }

        [Fact]
        public void TryGetDataAsString_WithValidUtf8_ReturnsTrue()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = "Valid UTF-8"u8.ToArray();

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            var success = signedMessage.TryGetDataAsString(out var result);

            // Assert
            Assert.True(success);
            Assert.Equal("Valid UTF-8", result);
        }

        [Fact]
        public void GetDetachedSignature_ReturnsSerializedSignature()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(50);

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            var detached = signedMessage.GetDetachedSignature();

            // Assert
            Assert.NotEmpty(detached);

            // Should be a valid PGP packet
            Assert.True(detached[0] == 0xC2 || (detached[0] & 0x80) != 0); // New or old format packet
        }

        [Fact]
        public void ToString_ReturnsDescriptiveString()
        {
            // Arrange
            var (_, secretKey) = CreateRsaKeyPair();
            var data = TestHelpers.RandomBytes(100);

            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(secretKey);
            var signedMessage = signer.Sign(data);

            // Act
            var str = signedMessage.ToString();

            // Assert
            Assert.Contains("SignedMessage", str);
            Assert.Contains("100 bytes", str);
        }
    }
}
