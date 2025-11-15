using HeroCrypt.Cryptography.JWT;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace HeroCrypt.Tests;

public class JwsSignerTests
{
    private readonly byte[] _testData = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

    #region HMAC Tests

    [Theory]
    [InlineData(JwsAlgorithm.HS256, 32)]
    [InlineData(JwsAlgorithm.HS384, 48)]
    [InlineData(JwsAlgorithm.HS512, 64)]
    public void HMAC_Sign_And_Verify_Success(JwsAlgorithm algorithm, int expectedSignatureLength)
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);

        // Act
        var signature = JwsSigner.Sign(_testData, key, algorithm);
        var isValid = JwsSigner.Verify(_testData, signature, key, algorithm);

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
        var signature = JwsSigner.Sign(_testData, key1, JwsAlgorithm.HS256);
        var isValid = JwsSigner.Verify(_testData, signature, key2, JwsAlgorithm.HS256);

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
        var signature = JwsSigner.Sign(_testData, key, JwsAlgorithm.HS256);
        var isValid = JwsSigner.Verify(tamperedData, signature, key, JwsAlgorithm.HS256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region RSA Tests

    [Theory]
    [InlineData(JwsAlgorithm.RS256)]
    [InlineData(JwsAlgorithm.PS256)]
    public void RSA_Sign_And_Verify_Success(JwsAlgorithm algorithm)
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        // Act
        var signature = JwsSigner.Sign(_testData, privateKey, algorithm);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey, algorithm);

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
        var signature = JwsSigner.Sign(_testData, privateKey1, JwsAlgorithm.RS256);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey2, JwsAlgorithm.RS256);

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
        var signature = JwsSigner.Sign(_testData, privateKey, JwsAlgorithm.RS256);
        signature[0] ^= 0xFF; // Tamper with signature
        var isValid = JwsSigner.Verify(_testData, signature, publicKey, JwsAlgorithm.RS256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region ECDSA Tests

    [Theory]
    [InlineData(JwsAlgorithm.ES256, 256)]
    [InlineData(JwsAlgorithm.ES384, 384)]
    [InlineData(JwsAlgorithm.ES512, 521)]
    public void ECDSA_Sign_And_Verify_Success(JwsAlgorithm algorithm, int curveSizeBits)
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
        var signature = JwsSigner.Sign(_testData, privateKey, algorithm);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey, algorithm);

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
        var signature = JwsSigner.Sign(_testData, privateKey1, JwsAlgorithm.ES256);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey2, JwsAlgorithm.ES256);

        // Assert
        Assert.False(isValid);
    }

    #endregion

    #region EdDSA Tests

#if NET7_0_OR_GREATER
    [Fact]
    public void EdDSA_Sign_And_Verify_Success()
    {
        // Arrange
        using var ed25519 = System.Security.Cryptography.Ed25519.Create();
        var privateKey = ed25519.ExportPkcs8PrivateKey();
        var publicKey = ed25519.ExportSubjectPublicKeyInfo();

        // Act
        var signature = JwsSigner.Sign(_testData, privateKey, JwsAlgorithm.EdDSA);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey, JwsAlgorithm.EdDSA);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(64, signature.Length);
        Assert.True(isValid);
    }

    [Fact]
    public void EdDSA_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange
        using var ed1 = System.Security.Cryptography.Ed25519.Create();
        using var ed2 = System.Security.Cryptography.Ed25519.Create();
        var privateKey1 = ed1.ExportPkcs8PrivateKey();
        var publicKey2 = ed2.ExportSubjectPublicKeyInfo();

        // Act
        var signature = JwsSigner.Sign(_testData, privateKey1, JwsAlgorithm.EdDSA);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey2, JwsAlgorithm.EdDSA);

        // Assert
        Assert.False(isValid);
    }
#endif

    #endregion

    #region ML-DSA Tests (Post-Quantum)

#if NET10_0_OR_GREATER
    [Theory]
    [InlineData(JwsAlgorithm.MLDSA65, 192)]
    [InlineData(JwsAlgorithm.MLDSA87, 256)]
    public void MLDSA_Sign_And_Verify_Success(JwsAlgorithm algorithm, int securityBits)
    {
        // Arrange
        using var keyPair = HeroCrypt.Cryptography.PostQuantum.Dilithium.MLDsaWrapper.GenerateKeyPair(securityBits);
        var privateKey = Encoding.UTF8.GetBytes(keyPair.SecretKeyPem);
        var publicKey = Encoding.UTF8.GetBytes(keyPair.PublicKeyPem);

        // Act
        var signature = JwsSigner.Sign(_testData, privateKey, algorithm);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey, algorithm);

        // Assert
        Assert.NotNull(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void MLDSA65_Verify_With_Wrong_PublicKey_Returns_False()
    {
        // Arrange
        using var keyPair1 = HeroCrypt.Cryptography.PostQuantum.Dilithium.MLDsaWrapper.GenerateKeyPair(192);
        using var keyPair2 = HeroCrypt.Cryptography.PostQuantum.Dilithium.MLDsaWrapper.GenerateKeyPair(192);
        var privateKey1 = Encoding.UTF8.GetBytes(keyPair1.SecretKeyPem);
        var publicKey2 = Encoding.UTF8.GetBytes(keyPair2.PublicKeyPem);

        // Act
        var signature = JwsSigner.Sign(_testData, privateKey1, JwsAlgorithm.MLDSA65);
        var isValid = JwsSigner.Verify(_testData, signature, publicKey2, JwsAlgorithm.MLDSA65);

        // Assert
        Assert.False(isValid);
    }
#endif

    #endregion

    #region Error Handling Tests

    [Fact]
    public void Sign_With_Null_Data_Throws_ArgumentNullException()
    {
        // Arrange
        var key = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => JwsSigner.Sign(null!, key, JwsAlgorithm.HS256));
    }

    [Fact]
    public void Sign_With_Null_Key_Throws_ArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => JwsSigner.Sign(_testData, null!, JwsAlgorithm.HS256));
    }

    [Fact]
    public void Verify_With_Null_Data_Throws_ArgumentNullException()
    {
        // Arrange
        var key = new byte[32];
        var signature = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => JwsSigner.Verify(null!, signature, key, JwsAlgorithm.HS256));
    }

    [Fact]
    public void Verify_With_Null_Signature_Throws_ArgumentNullException()
    {
        // Arrange
        var key = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => JwsSigner.Verify(_testData, null!, key, JwsAlgorithm.HS256));
    }

    [Fact]
    public void Verify_With_Null_Key_Throws_ArgumentNullException()
    {
        // Arrange
        var signature = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => JwsSigner.Verify(_testData, signature, null!, JwsAlgorithm.HS256));
    }

    #endregion

    #region Cross-Algorithm Tests

    [Fact]
    public void Different_Algorithms_Produce_Different_Signatures()
    {
        // Arrange
        var key = new byte[64];
        RandomNumberGenerator.Fill(key);

        // Act
        var sig256 = JwsSigner.Sign(_testData, key, JwsAlgorithm.HS256);
        var sig384 = JwsSigner.Sign(_testData, key, JwsAlgorithm.HS384);
        var sig512 = JwsSigner.Sign(_testData, key, JwsAlgorithm.HS512);

        // Assert
        Assert.NotEqual(sig256, sig384);
        Assert.NotEqual(sig256, sig512);
        Assert.NotEqual(sig384, sig512);
    }

    #endregion
}
