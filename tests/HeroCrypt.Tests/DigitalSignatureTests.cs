using HeroCrypt.Cryptography.DigitalSignatures;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace HeroCrypt.Tests;

public class DigitalSignatureTests
{
    private readonly byte[] _testData = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

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
        var signature = DigitalSignature.Sign(_testData, key, algorithm);
        var isValid = DigitalSignature.Verify(_testData, signature, key, algorithm);

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
        var signature = DigitalSignature.Sign(_testData, key1, SignatureAlgorithm.HmacSha256);
        var isValid = DigitalSignature.Verify(_testData, signature, key2, SignatureAlgorithm.HmacSha256);

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
        var signature = DigitalSignature.Sign(_testData, key, SignatureAlgorithm.HmacSha256);
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
        var signature = DigitalSignature.Sign(_testData, privateKey, algorithm);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey, algorithm);

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
        var signature = DigitalSignature.Sign(_testData, privateKey1, SignatureAlgorithm.RsaSha256);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey2, SignatureAlgorithm.RsaSha256);

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
        var signature = DigitalSignature.Sign(_testData, privateKey, SignatureAlgorithm.RsaSha256);
        signature[0] ^= 0xFF; // Tamper with signature
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey, SignatureAlgorithm.RsaSha256);

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
        var signature = DigitalSignature.Sign(_testData, privateKey, algorithm);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey, algorithm);

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
        var signature = DigitalSignature.Sign(_testData, privateKey1, SignatureAlgorithm.EcdsaP256Sha256);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey2, SignatureAlgorithm.EcdsaP256Sha256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region EdDSA Tests

#if NET7_0_OR_GREATER
    [Fact]
    public void Ed25519_Sign_And_Verify_Success()
    {
        // Arrange
        using var ed25519 = System.Security.Cryptography.Ed25519.Create();
        var privateKey = ed25519.ExportPkcs8PrivateKey();
        var publicKey = ed25519.ExportSubjectPublicKeyInfo();

        // Act
        var signature = DigitalSignature.Sign(_testData, privateKey, SignatureAlgorithm.Ed25519);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey, SignatureAlgorithm.Ed25519);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
        Assert.True(isValid);
    }

    [Fact]
    public void Ed25519_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange
        using var ed1 = System.Security.Cryptography.Ed25519.Create();
        using var ed2 = System.Security.Cryptography.Ed25519.Create();
        var privateKey1 = ed1.ExportPkcs8PrivateKey();
        var publicKey2 = ed2.ExportSubjectPublicKeyInfo();

        // Act
        var signature = DigitalSignature.Sign(_testData, privateKey1, SignatureAlgorithm.Ed25519);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey2, SignatureAlgorithm.Ed25519);

        // Assert
        Assert.False(isValid);
    }
#endif

    #endregion

    #region ML-DSA Tests (Post-Quantum)

#if NET10_0_OR_GREATER
    [Theory]
    [InlineData(SignatureAlgorithm.MLDsa65, 192)]
    [InlineData(SignatureAlgorithm.MLDsa87, 256)]
    public void MLDsa_Sign_And_Verify_Success(SignatureAlgorithm algorithm, int securityBits)
    {
        // Arrange
        using var keyPair = HeroCrypt.Cryptography.PostQuantum.Dilithium.MLDsaWrapper.GenerateKeyPair(securityBits);
        var privateKey = Encoding.UTF8.GetBytes(keyPair.SecretKeyPem);
        var publicKey = Encoding.UTF8.GetBytes(keyPair.PublicKeyPem);

        // Act
        var signature = DigitalSignature.Sign(_testData, privateKey, algorithm);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey, algorithm);

        // Assert
        Assert.NotNull(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void MLDsa65_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange
        using var keyPair1 = HeroCrypt.Cryptography.PostQuantum.Dilithium.MLDsaWrapper.GenerateKeyPair(192);
        using var keyPair2 = HeroCrypt.Cryptography.PostQuantum.Dilithium.MLDsaWrapper.GenerateKeyPair(192);
        var privateKey1 = Encoding.UTF8.GetBytes(keyPair1.SecretKeyPem);
        var publicKey2 = Encoding.UTF8.GetBytes(keyPair2.PublicKeyPem);

        // Act
        var signature = DigitalSignature.Sign(_testData, privateKey1, SignatureAlgorithm.MLDsa65);
        var isValid = DigitalSignature.Verify(_testData, signature, publicKey2, SignatureAlgorithm.MLDsa65);

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
        var signature = SignatureBuilder.Create()
            .WithData(_testData)
            .WithKey(key)
            .WithAlgorithm(SignatureAlgorithm.HmacSha256)
            .Sign();

        // Act - Verify
        var isValid = SignatureBuilder.Create()
            .WithData(_testData)
            .WithSignature(signature)
            .WithKey(key)
            .WithAlgorithm(SignatureAlgorithm.HmacSha256)
            .Verify();

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
        var signature = SignatureBuilder.Create()
            .WithData("test message")
            .WithKey(key)
            .WithAlgorithm(SignatureAlgorithm.HmacSha256)
            .Sign();

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
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Sign(_testData, null!, SignatureAlgorithm.HmacSha256));
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
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Verify(_testData, null!, key, SignatureAlgorithm.HmacSha256));
    }

    [Fact]
    public void Verify_With_Null_Key_Throws_ArgumentNullException()
    {
        // Arrange
        var signature = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DigitalSignature.Verify(_testData, signature, null!, SignatureAlgorithm.HmacSha256));
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
        var sig256 = DigitalSignature.Sign(_testData, key, SignatureAlgorithm.HmacSha256);
        var sig384 = DigitalSignature.Sign(_testData, key, SignatureAlgorithm.HmacSha384);
        var sig512 = DigitalSignature.Sign(_testData, key, SignatureAlgorithm.HmacSha512);

        // Assert
        Assert.NotEqual(sig256, sig384);
        Assert.NotEqual(sig256, sig512);
        Assert.NotEqual(sig384, sig512);
    }

    #endregion
}
