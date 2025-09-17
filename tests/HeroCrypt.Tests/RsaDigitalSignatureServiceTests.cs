using System;
using System.Text;
using System.Threading.Tasks;
using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using Xunit.v3;

namespace HeroCrypt.Tests;

/// <summary>
/// Unit tests for RSA Digital Signature Service functionality
/// </summary>
public class RsaDigitalSignatureServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Constructor_WithValidKeySize_InitializesCorrectly()
    {
        var service = new RsaDigitalSignatureService(2048);

        Assert.Equal("RSA-SHA256", service.AlgorithmName);
        Assert.Equal(2048, service.KeySizeBits);
        Assert.Equal(256, service.SignatureSize); // 2048 bits = 256 bytes
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Constructor_WithInvalidKeySize_ThrowsException()
    {
        var ex = Assert.Throws<ArgumentException>(() => new RsaDigitalSignatureService(512));
        Assert.Contains("RSA key size must be at least 1024 bits", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Constructor_WithNonMultipleOf8_ThrowsException()
    {
        var ex = Assert.Throws<ArgumentException>(() => new RsaDigitalSignatureService(2049));
        Assert.Contains("RSA key size must be a multiple of 8", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void GenerateKeyPair_ReturnsValidKeyPair()
    {
        var service = new RsaDigitalSignatureService(1024); // Smaller key for faster tests

        var (privateKey, publicKey) = service.GenerateKeyPair();

        Assert.NotNull(privateKey);
        Assert.NotNull(publicKey);
        Assert.True(privateKey.Length > 0);
        Assert.True(publicKey.Length > 0);
        Assert.NotEqual(privateKey, publicKey);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void DerivePublicKey_FromPrivateKey_ReturnsConsistentResult()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, originalPublicKey) = service.GenerateKeyPair();

        var derivedPublicKey = service.DerivePublicKey(privateKey);

        Assert.Equal(originalPublicKey, derivedPublicKey);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void DerivePublicKey_WithNullPrivateKey_ThrowsException()
    {
        var service = new RsaDigitalSignatureService();

        var ex = Assert.Throws<ArgumentNullException>(() => service.DerivePublicKey(null!));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Sign_WithValidInputs_ReturnsSignature()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, _) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message for signing");

        var signature = service.Sign(data, privateKey);

        Assert.NotNull(signature);
        Assert.Equal(128, signature.Length); // 1024 bits = 128 bytes
        Assert.NotEqual(new byte[128], signature);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Sign_WithNullData_ThrowsException()
    {
        var service = new RsaDigitalSignatureService();
        var (privateKey, _) = service.GenerateKeyPair();

        var ex = Assert.Throws<ArgumentNullException>(() => service.Sign(null!, privateKey));
        Assert.Equal("data", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Sign_WithNullPrivateKey_ThrowsException()
    {
        var service = new RsaDigitalSignatureService();
        var data = Encoding.UTF8.GetBytes("test");

        var ex = Assert.Throws<ArgumentNullException>(() => service.Sign(data, null!));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Verify_WithValidSignature_ReturnsTrue()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message for verification");

        var signature = service.Sign(data, privateKey);
        var isValid = service.Verify(signature, data, publicKey);

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Verify_WithInvalidSignature_ReturnsFalse()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message");
        var wrongData = Encoding.UTF8.GetBytes("Different message");

        var signature = service.Sign(data, privateKey);
        var isValid = service.Verify(signature, wrongData, publicKey);

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Verify_WithTamperedSignature_ReturnsFalse()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message");

        var signature = service.Sign(data, privateKey);
        signature[0] ^= 0xFF; // Tamper with the signature

        var isValid = service.Verify(signature, data, publicKey);

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Verify_WithWrongPublicKey_ReturnsFalse()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey1, _) = service.GenerateKeyPair();
        var (_, publicKey2) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Test message");

        var signature = service.Sign(data, privateKey1);
        var isValid = service.Verify(signature, data, publicKey2);

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Verify_WithNullInputs_ThrowsException()
    {
        var service = new RsaDigitalSignatureService();
        var (_, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("test");
        var signature = new byte[256];

        Assert.Throws<ArgumentNullException>(() => service.Verify(null!, data, publicKey));
        Assert.Throws<ArgumentNullException>(() => service.Verify(signature, null!, publicKey));
        Assert.Throws<ArgumentNullException>(() => service.Verify(signature, data, null!));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Sign_IsDeterministic_WithSameInputs()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, _) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Deterministic test message");

        var signature1 = service.Sign(data, privateKey);
        var signature2 = service.Sign(data, privateKey);

        // RSA signatures should be the same for the same input and key
        Assert.Equal(signature1, signature2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Sign_DifferentMessages_ProduceDifferentSignatures()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, _) = service.GenerateKeyPair();
        var message1 = Encoding.UTF8.GetBytes("First message");
        var message2 = Encoding.UTF8.GetBytes("Second message");

        var signature1 = service.Sign(message1, privateKey);
        var signature2 = service.Sign(message2, privateKey);

        Assert.NotEqual(signature1, signature2);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void KeyPairGeneration_ProducesUniqueKeys()
    {
        var service = new RsaDigitalSignatureService(1024);

        var (privateKey1, publicKey1) = service.GenerateKeyPair();
        var (privateKey2, publicKey2) = service.GenerateKeyPair();

        Assert.NotEqual(privateKey1, privateKey2);
        Assert.NotEqual(publicKey1, publicKey2);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public async Task SignAsync_WorksCorrectly()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Async signing test");

        var signature = await service.SignAsync(data, privateKey);
        var isValid = service.Verify(signature, data, publicKey);

        Assert.True(isValid);
        Assert.Equal(128, signature.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public async Task VerifyAsync_WorksCorrectly()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Async verification test");

        var signature = service.Sign(data, privateKey);
        var isValid = await service.VerifyAsync(signature, data, publicKey);

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public async Task AsyncOperations_ProduceSameResultsAsSyncOperations()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Sync vs Async test");

        var syncSignature = service.Sign(data, privateKey);
        var asyncSignature = await service.SignAsync(data, privateKey);

        Assert.Equal(syncSignature, asyncSignature);

        var syncVerification = service.Verify(syncSignature, data, publicKey);
        var asyncVerification = await service.VerifyAsync(asyncSignature, data, publicKey);

        Assert.Equal(syncVerification, asyncVerification);
        Assert.True(syncVerification);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_HandlesLargeData()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();

        // Create 1MB of test data
        var largeData = new byte[1024 * 1024];
        new Random(42).NextBytes(largeData);

        var signature = service.Sign(largeData, privateKey);
        var isValid = service.Verify(signature, largeData, publicKey);

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_HandlesEmptyData()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var emptyData = Array.Empty<byte>();

        var signature = service.Sign(emptyData, privateKey);
        var isValid = service.Verify(signature, emptyData, publicKey);

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_PerformanceTest_MultipleOperations()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Performance test message");

        // Perform multiple sign/verify operations
        for (var i = 0; i < 10; i++)
        {
            var signature = service.Sign(data, privateKey);
            var isValid = service.Verify(signature, data, publicKey);
            Assert.True(isValid);
        }
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_SecurityTest_DifferentKeysDontWork()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey1, _) = service.GenerateKeyPair();
        var (_, publicKey2) = service.GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("Security test message");

        var signature = service.Sign(data, privateKey1);
        var isValid = service.Verify(signature, data, publicKey2);

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Service_SecurityTest_ModifiedDataDetected()
    {
        var service = new RsaDigitalSignatureService(1024);
        var (privateKey, publicKey) = service.GenerateKeyPair();
        var originalData = Encoding.UTF8.GetBytes("Original message");
        var modifiedData = Encoding.UTF8.GetBytes("Modified message");

        var signature = service.Sign(originalData, privateKey);
        var isValid = service.Verify(signature, modifiedData, publicKey);

        Assert.False(isValid);
    }
}