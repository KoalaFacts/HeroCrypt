using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Signature.Ecc;
using HeroCrypt.Signatures;
#if NET10_0_OR_GREATER
using HeroCrypt.Cryptography.Primitives.PostQuantum.Signature;
#endif

namespace HeroCrypt.Tests.Signatures;

public class DigitalSignatureTests
{
    private readonly byte[] testData = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    #region HMAC Tests

    [Theory]
    [InlineData(SignatureAlgorithm.HmacSha256, 32)]
    [InlineData(SignatureAlgorithm.HmacSha384, 48)]
    [InlineData(SignatureAlgorithm.HmacSha512, 64)]
    public void HMAC_Sign_And_Verify_Success(SignatureAlgorithm algorithm, int expectedSignatureLength)
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);

        // Act
        var signature = DigitalSignature.Sign(testData, key, algorithm);

        var isValid = DigitalSignature.Verify(testData, signature, key, algorithm);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(expectedSignatureLength, signature.Length);
        Assert.True(isValid);
    }

    [Fact]
    public void HMAC_Verify_With_Wrong_Key_Returns_False()
    {
        // Arrange
        var key1 = new byte[64];
        var key2 = new byte[64];
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);

        // Act
        var signature = DigitalSignature.Sign(testData, key1, SignatureAlgorithm.HmacSha256);
        var isValid = DigitalSignature.Verify(testData, signature, key2, SignatureAlgorithm.HmacSha256);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void HMAC_Verify_With_Tampered_Data_Returns_False()
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);
        var tamperedData = Encoding.UTF8.GetBytes("Tampered data");

        // Act
        var signature = DigitalSignature.Sign(testData, key, SignatureAlgorithm.HmacSha256);
        var isValid = DigitalSignature.Verify(tamperedData, signature, key, SignatureAlgorithm.HmacSha256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region RSA Tests

    [Theory]
    [InlineData(SignatureAlgorithm.RsaSha256)]
    [InlineData(SignatureAlgorithm.RsaPssSha256)]
    public void RSA_Sign_And_Verify_Success(SignatureAlgorithm algorithm)
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey, algorithm);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey, algorithm);

        // Assert
        Assert.NotNull(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void RSA_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var privateKey1 = rsa1.ExportPkcs8PrivateKey();
        var publicKey2 = rsa2.ExportSubjectPublicKeyInfo();

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey1, SignatureAlgorithm.RsaSha256);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey2, SignatureAlgorithm.RsaSha256);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void RSA_Verify_With_Tampered_Signature_Returns_False()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey, SignatureAlgorithm.RsaSha256);
        signature[0] ^= 0xFF; // Tamper with signature
        var isValid = DigitalSignature.Verify(testData, signature, publicKey, SignatureAlgorithm.RsaSha256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region ECDSA Tests

    [Theory]
    [InlineData(SignatureAlgorithm.EcdsaP256Sha256, 256)]
    [InlineData(SignatureAlgorithm.EcdsaP384Sha384, 384)]
    [InlineData(SignatureAlgorithm.EcdsaP521Sha512, 521)]
    public void ECDSA_Sign_And_Verify_Success(SignatureAlgorithm algorithm, int curveSizeBits)
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
        var signature = DigitalSignature.Sign(testData, privateKey, algorithm);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey, algorithm);

        // Assert
        Assert.NotNull(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void ECDSA_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange
        using var ecdsa1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecdsa2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey1 = ecdsa1.ExportECPrivateKey();
        var publicKey2 = ecdsa2.ExportSubjectPublicKeyInfo();

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey1, SignatureAlgorithm.EcdsaP256Sha256);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey2, SignatureAlgorithm.EcdsaP256Sha256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region EdDSA Tests

    [Fact]
    public void Ed25519_Sign_And_Verify_Success()
    {
        // Arrange - Using HeroCrypt's custom Ed25519Core implementation
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey, SignatureAlgorithm.Ed25519);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey, SignatureAlgorithm.Ed25519);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
        Assert.True(isValid);
    }

    [Fact]
    public void Ed25519_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange - Using HeroCrypt's custom Ed25519Core implementation
        var (privateKey1, _) = Ed25519Core.GenerateKeyPair();
        var (_, publicKey2) = Ed25519Core.GenerateKeyPair();

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey1, SignatureAlgorithm.Ed25519);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey2, SignatureAlgorithm.Ed25519);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void Ed25519_RFC8032_TestVector1()
    {
        // RFC 8032 Section 7.1 Test Vector 1 (empty message)
        var privateKey = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var expectedPublicKey = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        var message = Array.Empty<byte>();
        var expectedSignature = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        // Test public key derivation
        var publicKey = Ed25519Core.DerivePublicKey(privateKey);
        Assert.Equal(expectedPublicKey, publicKey);

        // Test signature
        var signature = Ed25519Core.Sign(message, privateKey);
        Assert.Equal(expectedSignature, signature);

        // Test verification
        Assert.True(Ed25519Core.Verify(message, signature, publicKey));
    }

    [Fact]
    public void Ed25519_RFC8032_TestVector2()
    {
        // RFC 8032 Section 7.1 Test Vector 2 (single byte message)
        var privateKey = Convert.FromHexString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        var expectedPublicKey = Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        var message = "r"u8.ToArray();
        var expectedSignature = Convert.FromHexString(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

        // Test public key derivation
        var publicKey = Ed25519Core.DerivePublicKey(privateKey);
        Assert.Equal(expectedPublicKey, publicKey);

        // Test signature
        var signature = Ed25519Core.Sign(message, privateKey);
        Assert.Equal(expectedSignature, signature);

        // Test verification
        Assert.True(Ed25519Core.Verify(message, signature, publicKey));
    }

    [Fact]
    public void Ed25519_RFC8032_TestVector3()
    {
        // RFC 8032 Section 7.1 Test Vector 3 (two byte message)
        var privateKey = Convert.FromHexString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        var expectedPublicKey = Convert.FromHexString("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        var message = new byte[] { 0xaf, 0x82 };
        var expectedSignature = Convert.FromHexString(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

        // Test public key derivation
        var publicKey = Ed25519Core.DerivePublicKey(privateKey);
        Assert.Equal(expectedPublicKey, publicKey);

        // Test signature
        var signature = Ed25519Core.Sign(message, privateKey);
        Assert.Equal(expectedSignature, signature);

        // Test verification
        Assert.True(Ed25519Core.Verify(message, signature, publicKey));
    }

    [Fact]
    public void Ed25519_Signature_Is_Deterministic()
    {
        // Ed25519 signatures should be deterministic - same input produces same output
        var (privateKey, _) = Ed25519Core.GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("Test message for determinism check");

        var signature1 = Ed25519Core.Sign(message, privateKey);
        var signature2 = Ed25519Core.Sign(message, privateKey);

        Assert.Equal(signature1, signature2);
    }

    [Fact]
    public void Ed25519_Tampered_Signature_Rejected()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("Original message");

        var signature = Ed25519Core.Sign(message, privateKey);

        // Tamper with signature
        var tamperedSignature = (byte[])signature.Clone();
        tamperedSignature[0] ^= 0xFF;

        Assert.False(Ed25519Core.Verify(message, tamperedSignature, publicKey));
    }

    [Fact]
    public void Ed25519_Tampered_Message_Rejected()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
        var message = Encoding.UTF8.GetBytes("Original message");

        var signature = Ed25519Core.Sign(message, privateKey);

        // Tamper with message
        var tamperedMessage = Encoding.UTF8.GetBytes("Tampered message");

        Assert.False(Ed25519Core.Verify(tamperedMessage, signature, publicKey));
    }

    [Fact]
    public void Ed25519_Empty_Message_Signing()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
        var emptyMessage = Array.Empty<byte>();

        var signature = Ed25519Core.Sign(emptyMessage, privateKey);

        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
        Assert.True(Ed25519Core.Verify(emptyMessage, signature, publicKey));
    }

    [Fact]
    public void Ed25519_Large_Message_Signing()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
        var largeMessage = new byte[100_000];
        new Random(42).NextBytes(largeMessage);

        var signature = Ed25519Core.Sign(largeMessage, privateKey);

        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
        Assert.True(Ed25519Core.Verify(largeMessage, signature, publicKey));
    }

    [Fact]
    public void Ed25519_KeyPair_Has_Correct_Sizes()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

        Assert.Equal(32, privateKey.Length);
        Assert.Equal(32, publicKey.Length);
    }

    [Fact]
    public void Ed25519_DerivePublicKey_Is_Consistent()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

        var derivedPublicKey = Ed25519Core.DerivePublicKey(privateKey);

        Assert.Equal(publicKey, derivedPublicKey);
    }

    [Fact]
    public void Ed25519_Invalid_PrivateKey_Size_Throws()
    {
        var invalidKey = new byte[31]; // Should be 32

        Assert.Throws<ArgumentException>(() => Ed25519Core.DerivePublicKey(invalidKey));
        Assert.Throws<ArgumentException>(() => Ed25519Core.Sign(testData, invalidKey));
    }

    [Fact]
    public void Ed25519_Invalid_PublicKey_Size_Throws()
    {
        var invalidPublicKey = new byte[31]; // Should be 32
        var validSignature = new byte[64];

        Assert.Throws<ArgumentException>(() => Ed25519Core.Verify(testData, validSignature, invalidPublicKey));
    }

    [Fact]
    public void Ed25519_Invalid_Signature_Size_Throws()
    {
        var validPublicKey = new byte[32];
        var invalidSignature = new byte[63]; // Should be 64

        Assert.Throws<ArgumentException>(() => Ed25519Core.Verify(testData, invalidSignature, validPublicKey));
    }

    [Fact]
    public void Ed25519_Null_Parameters_Throw()
    {
        var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
        var signature = new byte[64];

        Assert.Throws<ArgumentNullException>(() => Ed25519Core.Sign(null!, privateKey));
        Assert.Throws<ArgumentNullException>(() => Ed25519Core.Sign(testData, null!));
        Assert.Throws<ArgumentNullException>(() => Ed25519Core.DerivePublicKey(null!));
        Assert.Throws<ArgumentNullException>(() => Ed25519Core.Verify(null!, signature, publicKey));
        Assert.Throws<ArgumentNullException>(() => Ed25519Core.Verify(testData, null!, publicKey));
        Assert.Throws<ArgumentNullException>(() => Ed25519Core.Verify(testData, signature, null!));
    }

    [Fact]
    public void Ed25519_Multiple_KeyPairs_Are_Different()
    {
        var (privateKey1, publicKey1) = Ed25519Core.GenerateKeyPair();
        var (privateKey2, publicKey2) = Ed25519Core.GenerateKeyPair();

        Assert.NotEqual(privateKey1, privateKey2);
        Assert.NotEqual(publicKey1, publicKey2);
    }

    #endregion

    #region ML-DSA Tests (Post-Quantum)

    // =====================================================================================
    // ML-DSA (Module-Lattice Digital Signature Algorithm) Platform Support
    // =====================================================================================
    // ML-DSA is a post-quantum cryptographic signature algorithm standardized by NIST.
    //
    // Platform Requirements:
    // - .NET 10 or later is required for ML-DSA support
    // - Windows: Requires Windows CNG (Cryptography Next Generation) with PQC support
    //   (available in Windows 11 24H2+ or Windows Server 2025+)
    // - Linux: Requires OpenSSL 3.5+ with PQC provider enabled
    // - macOS: Not currently supported (no native PQC implementation)
    //
    // Tests are automatically skipped on unsupported platforms using MLDsaWrapper.IsSupported()
    // which checks for runtime availability of the underlying cryptographic primitives.
    // =====================================================================================

#if NET10_0_OR_GREATER
    [Theory]
    [InlineData(SignatureAlgorithm.MLDsa65, MLDsaWrapper.SecurityLevel.MLDsa65)]
    [InlineData(SignatureAlgorithm.MLDsa87, MLDsaWrapper.SecurityLevel.MLDsa87)]
    public void MLDsa_Sign_And_Verify_Success(SignatureAlgorithm algorithm, MLDsaWrapper.SecurityLevel securityLevel)
    {
        if (!MLDsaWrapper.IsSupported())
        {
            Assert.Skip("ML-DSA not supported on this platform");
            return;
        }

        // Arrange
        using var keyPair = MLDsaWrapper.GenerateKeyPair(securityLevel);
        var privateKey = Encoding.UTF8.GetBytes(keyPair.SecretKeyPem);
        var publicKey = Encoding.UTF8.GetBytes(keyPair.PublicKeyPem);

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey, algorithm);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey, algorithm);

        // Assert
        Assert.NotNull(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void MLDsa65_Verify_With_Wrong_PublicKey_Returns_False()
    {
        if (!MLDsaWrapper.IsSupported())
        {
            Assert.Skip("ML-DSA not supported on this platform");
            return;
        }

        // Arrange
        using var keyPair1 = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);
        using var keyPair2 = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);
        var privateKey1 = Encoding.UTF8.GetBytes(keyPair1.SecretKeyPem);
        var publicKey2 = Encoding.UTF8.GetBytes(keyPair2.PublicKeyPem);

        // Act
        var signature = DigitalSignature.Sign(testData, privateKey1, SignatureAlgorithm.MLDsa65);
        var isValid = DigitalSignature.Verify(testData, signature, publicKey2, SignatureAlgorithm.MLDsa65);

        // Assert
        Assert.False(isValid);
    }
#endif

    #endregion

    #region Builder Pattern Tests

    [Fact]
    public void Builder_Sign_And_Verify_Success()
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);

        // Act - Sign
        var signature = DigitalSignature.Sign(testData, key, SignatureAlgorithm.HmacSha256);

        // Act - Verify
        var isValid = DigitalSignature.Verify(testData, signature, key, SignatureAlgorithm.HmacSha256);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void Builder_WithData_String_Works()
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);

        // Act
        var testData = Encoding.UTF8.GetBytes("test message");
        var signature = DigitalSignature.Sign(testData, key, SignatureAlgorithm.HmacSha256);

        // Assert
        Assert.NotNull(signature);
        Assert.NotEmpty(signature);
    }

    #endregion

    #region Error Handling Tests

    [Fact]
    public void Sign_With_Null_Data_Throws_ArgumentNullException()
    {
        // Arrange
        var key = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Sign(null!, key, SignatureAlgorithm.HmacSha256));
    }

    [Fact]
    public void Sign_With_Null_Key_Throws_ArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Sign(testData, null!, SignatureAlgorithm.HmacSha256));
    }

    [Fact]
    public void Verify_With_Null_Data_Throws_ArgumentNullException()
    {
        // Arrange
        var key = new byte[32];
        var signature = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Verify(null!, signature, key, SignatureAlgorithm.HmacSha256));
    }

    [Fact]
    public void Verify_With_Null_Signature_Throws_ArgumentNullException()
    {
        // Arrange
        var key = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Verify(testData, null!, key, SignatureAlgorithm.HmacSha256));
    }

    [Fact]
    public void Verify_With_Null_Key_Throws_ArgumentNullException()
    {
        // Arrange
        var signature = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Verify(testData, signature, null!, SignatureAlgorithm.HmacSha256));
    }

    #endregion

    #region Cross-Algorithm Tests

    [Fact]
    public void Different_HMAC_Algorithms_Produce_Different_Signatures()
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);

        // Act
        var sig256 = DigitalSignature.Sign(testData, key, SignatureAlgorithm.HmacSha256);
        var sig384 = DigitalSignature.Sign(testData, key, SignatureAlgorithm.HmacSha384);
        var sig512 = DigitalSignature.Sign(testData, key, SignatureAlgorithm.HmacSha512);

        // Assert
        Assert.NotEqual(sig256, sig384);
        Assert.NotEqual(sig256, sig512);
        Assert.NotEqual(sig384, sig512);
    }

    #endregion
}
