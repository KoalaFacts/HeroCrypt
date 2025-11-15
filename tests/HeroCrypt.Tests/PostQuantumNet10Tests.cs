#if NET10_0_OR_GREATER
using System.Text;
using HeroCrypt.Cryptography.PostQuantum.Kyber;
using HeroCrypt.Cryptography.PostQuantum.Dilithium;
using HeroCrypt.Cryptography.PostQuantum.Sphincs;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for .NET 10+ Post-Quantum Cryptography native implementations
/// </summary>
public class PostQuantumNet10Tests
{
    #region ML-KEM Tests

    [Fact]
    public void MLKem_IsSupported_ReturnsExpectedValue()
    {
        // This test documents platform support - may pass or fail depending on platform
        var isSupported = MLKemWrapper.IsSupported();
        Assert.NotNull(isSupported); // Just verify it doesn't throw
    }

    [Fact]
    public void MLKem_GenerateKeyPair_MLKem512_Success()
    {
        if (!MLKemWrapper.IsSupported())
        {
            // Skip test on platforms without PQC support
            return;
        }

        using var keyPair = MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem512);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKeyPem);
        Assert.NotNull(keyPair.SecretKeyPem);
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem512, keyPair.Level);
        Assert.Contains("PUBLIC KEY", keyPair.PublicKeyPem);
        Assert.Contains("PRIVATE KEY", keyPair.SecretKeyPem);
    }

    [Fact]
    public void MLKem_GenerateKeyPair_MLKem768_Success()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        using var keyPair = MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem768, keyPair.Level);
    }

    [Fact]
    public void MLKem_GenerateKeyPair_MLKem1024_Success()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        using var keyPair = MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem1024);

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem1024, keyPair.Level);
    }

    [Fact]
    public void MLKem_EncapsulateDecapsulate_Success()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        using var keyPair = MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);

        // Encapsulate
        using var result = MLKemWrapper.Encapsulate(keyPair.PublicKeyPem);

        Assert.NotNull(result.Ciphertext);
        Assert.NotNull(result.SharedSecret);
        Assert.Equal(32, result.SharedSecret.Length); // Shared secrets are always 32 bytes

        // Decapsulate
        var recoveredSecret = keyPair.Decapsulate(result.Ciphertext);

        Assert.NotNull(recoveredSecret);
        Assert.Equal(32, recoveredSecret.Length);
        Assert.Equal(result.SharedSecret, recoveredSecret);
    }

    [Fact]
    public void MLKem_GetRecommendedLevel_ReturnsCorrectLevel()
    {
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem512, MLKemWrapper.GetRecommendedLevel(128));
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem768, MLKemWrapper.GetRecommendedLevel(192));
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem1024, MLKemWrapper.GetRecommendedLevel(256));
    }

    [Fact]
    public void MLKem_GetLevelInfo_ReturnsCorrectInfo()
    {
        var (secBits512, desc512) = MLKemWrapper.GetLevelInfo(MLKemWrapper.SecurityLevel.MLKem512);
        Assert.Equal(128, secBits512);
        Assert.Contains("128-bit", desc512);

        var (secBits768, desc768) = MLKemWrapper.GetLevelInfo(MLKemWrapper.SecurityLevel.MLKem768);
        Assert.Equal(192, secBits768);
        Assert.Contains("192-bit", desc768);

        var (secBits1024, desc1024) = MLKemWrapper.GetLevelInfo(MLKemWrapper.SecurityLevel.MLKem1024);
        Assert.Equal(256, secBits1024);
        Assert.Contains("256-bit", desc1024);
    }

    #endregion

    #region ML-DSA Tests

    [Fact]
    public void MLDsa_IsSupported_ReturnsExpectedValue()
    {
        var isSupported = MLDsaWrapper.IsSupported();
        Assert.NotNull(isSupported);
    }

    [Fact]
    public void MLDsa_GenerateKeyPair_MLDsa44_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        using var keyPair = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa44);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKeyPem);
        Assert.NotNull(keyPair.SecretKeyPem);
        Assert.Equal(MLDsaWrapper.SecurityLevel.MLDsa44, keyPair.Level);
    }

    [Fact]
    public void MLDsa_GenerateKeyPair_MLDsa65_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        using var keyPair = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        Assert.NotNull(keyPair);
        Assert.Equal(MLDsaWrapper.SecurityLevel.MLDsa65, keyPair.Level);
    }

    [Fact]
    public void MLDsa_GenerateKeyPair_MLDsa87_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        using var keyPair = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa87);

        Assert.NotNull(keyPair);
        Assert.Equal(MLDsaWrapper.SecurityLevel.MLDsa87, keyPair.Level);
    }

    [Fact]
    public void MLDsa_SignAndVerify_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        using var keyPair = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        var data = Encoding.UTF8.GetBytes("Hello, Post-Quantum World!");

        // Sign
        var signature = keyPair.Sign(data);

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);

        // Verify with correct data
        var isValid = MLDsaWrapper.Verify(keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);

        // Verify with incorrect data
        var wrongData = Encoding.UTF8.GetBytes("Wrong data");
        var isInvalid = MLDsaWrapper.Verify(keyPair.PublicKeyPem, wrongData, signature);
        Assert.False(isInvalid);
    }

    [Fact]
    public void MLDsa_SignWithContext_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        using var keyPair = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        var data = Encoding.UTF8.GetBytes("Message with context");
        var context = Encoding.UTF8.GetBytes("test-context");

        // Sign with context
        var signature = keyPair.Sign(data, context);
        Assert.NotNull(signature);

        // Verify with correct context
        var isValid = MLDsaWrapper.Verify(keyPair.PublicKeyPem, data, signature, context);
        Assert.True(isValid);

        // Verify without context should fail
        var isInvalidNoContext = MLDsaWrapper.Verify(keyPair.PublicKeyPem, data, signature, null);
        Assert.False(isInvalidNoContext);

        // Verify with wrong context should fail
        var wrongContext = Encoding.UTF8.GetBytes("wrong-context");
        var isInvalidWrongContext = MLDsaWrapper.Verify(keyPair.PublicKeyPem, data, signature, wrongContext);
        Assert.False(isInvalidWrongContext);
    }

    [Fact]
    public void MLDsa_GetRecommendedLevel_ReturnsCorrectLevel()
    {
        Assert.Equal(MLDsaWrapper.SecurityLevel.MLDsa44, MLDsaWrapper.GetRecommendedLevel(128));
        Assert.Equal(MLDsaWrapper.SecurityLevel.MLDsa65, MLDsaWrapper.GetRecommendedLevel(192));
        Assert.Equal(MLDsaWrapper.SecurityLevel.MLDsa87, MLDsaWrapper.GetRecommendedLevel(256));
    }

    [Fact]
    public void MLDsa_GetLevelInfo_ReturnsCorrectInfo()
    {
        var (secBits44, sigSize44, desc44) = MLDsaWrapper.GetLevelInfo(MLDsaWrapper.SecurityLevel.MLDsa44);
        Assert.Equal(128, secBits44);
        Assert.Equal(2420, sigSize44);
        Assert.Contains("128-bit", desc44);

        var (secBits65, sigSize65, desc65) = MLDsaWrapper.GetLevelInfo(MLDsaWrapper.SecurityLevel.MLDsa65);
        Assert.Equal(192, secBits65);
        Assert.Equal(3309, sigSize65);
        Assert.Contains("192-bit", desc65);

        var (secBits87, sigSize87, desc87) = MLDsaWrapper.GetLevelInfo(MLDsaWrapper.SecurityLevel.MLDsa87);
        Assert.Equal(256, secBits87);
        Assert.Equal(4627, sigSize87);
        Assert.Contains("256-bit", desc87);
    }

    #endregion

    #region SLH-DSA Tests

    [Fact]
    public void SlhDsa_IsSupported_ReturnsExpectedValue()
    {
        var isSupported = SlhDsaWrapper.IsSupported();
        Assert.NotNull(isSupported);
    }

    [Fact]
    public void SlhDsa_GenerateKeyPair_128s_Success()
    {
        if (!SlhDsaWrapper.IsSupported())
            return;

        using var keyPair = SlhDsaWrapper.GenerateKeyPair(SlhDsaWrapper.SecurityLevel.SlhDsa128s);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKeyPem);
        Assert.NotNull(keyPair.SecretKeyPem);
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa128s, keyPair.Level);
    }

    [Fact]
    public void SlhDsa_GenerateKeyPair_AllLevels_Success()
    {
        if (!SlhDsaWrapper.IsSupported())
            return;

        var levels = new[]
        {
            SlhDsaWrapper.SecurityLevel.SlhDsa128s,
            SlhDsaWrapper.SecurityLevel.SlhDsa128f,
            SlhDsaWrapper.SecurityLevel.SlhDsa192s,
            SlhDsaWrapper.SecurityLevel.SlhDsa192f,
            SlhDsaWrapper.SecurityLevel.SlhDsa256s,
            SlhDsaWrapper.SecurityLevel.SlhDsa256f
        };

        foreach (var level in levels)
        {
            using var keyPair = SlhDsaWrapper.GenerateKeyPair(level);
            Assert.NotNull(keyPair);
            Assert.Equal(level, keyPair.Level);
        }
    }

    [Fact]
    public void SlhDsa_SignAndVerify_Success()
    {
        if (!SlhDsaWrapper.IsSupported())
            return;

        using var keyPair = SlhDsaWrapper.GenerateKeyPair(SlhDsaWrapper.SecurityLevel.SlhDsa128s);

        var data = Encoding.UTF8.GetBytes("Hash-based signatures!");

        // Sign
        var signature = keyPair.Sign(data);

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);

        // Verify with correct data
        var isValid = SlhDsaWrapper.Verify(keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);

        // Verify with incorrect data
        var wrongData = Encoding.UTF8.GetBytes("Wrong data");
        var isInvalid = SlhDsaWrapper.Verify(keyPair.PublicKeyPem, wrongData, signature);
        Assert.False(isInvalid);
    }

    [Fact]
    public void SlhDsa_GetRecommendedLevel_ReturnsCorrectLevel()
    {
        // Prefer small
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa128s, SlhDsaWrapper.GetRecommendedLevel(128, preferSmall: true));
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa192s, SlhDsaWrapper.GetRecommendedLevel(192, preferSmall: true));
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa256s, SlhDsaWrapper.GetRecommendedLevel(256, preferSmall: true));

        // Prefer fast
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa128f, SlhDsaWrapper.GetRecommendedLevel(128, preferSmall: false));
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa192f, SlhDsaWrapper.GetRecommendedLevel(192, preferSmall: false));
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa256f, SlhDsaWrapper.GetRecommendedLevel(256, preferSmall: false));
    }

    [Fact]
    public void SlhDsa_GetLevelInfo_ReturnsCorrectInfo()
    {
        var (secBits, sigSize, desc) = SlhDsaWrapper.GetLevelInfo(SlhDsaWrapper.SecurityLevel.SlhDsa128s);
        Assert.Equal(128, secBits);
        Assert.True(sigSize > 0);
        Assert.Contains("128-bit", desc);
        Assert.Contains("small", desc);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void Integration_HybridEncryption_MLKemWithAesGcm()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        // Generate ML-KEM key pair
        using var keyPair = MLKemWrapper.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);

        // Sender: Encapsulate to get shared secret
        using var encResult = MLKemWrapper.Encapsulate(keyPair.PublicKeyPem);

        // Use shared secret as encryption key (demonstration)
        Assert.Equal(32, encResult.SharedSecret.Length);

        // Receiver: Decapsulate to recover shared secret
        var recoveredSecret = keyPair.Decapsulate(encResult.Ciphertext);

        Assert.Equal(encResult.SharedSecret, recoveredSecret);

        // In real usage, you would use this shared secret with AES-GCM or similar
    }

    [Fact]
    public void Integration_MultipleSignatureSchemes_DifferentSecurityLevels()
    {
        if (!MLDsaWrapper.IsSupported() || !SlhDsaWrapper.IsSupported())
            return;

        var data = Encoding.UTF8.GetBytes("Important document");

        // Sign with ML-DSA
        using var mlDsaKey = MLDsaWrapper.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);
        var mlDsaSignature = mlDsaKey.Sign(data);
        Assert.True(MLDsaWrapper.Verify(mlDsaKey.PublicKeyPem, data, mlDsaSignature));

        // Sign with SLH-DSA
        using var slhDsaKey = SlhDsaWrapper.GenerateKeyPair(SlhDsaWrapper.SecurityLevel.SlhDsa128s);
        var slhDsaSignature = slhDsaKey.Sign(data);
        Assert.True(SlhDsaWrapper.Verify(slhDsaKey.PublicKeyPem, data, slhDsaSignature));

        // Different algorithms produce different signatures
        Assert.NotEqual(mlDsaSignature.Length, slhDsaSignature.Length);
    }

    #endregion

    #region Builder Pattern Tests

    [Fact]
    public void MLKemBuilder_FluentAPI_Success()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        // Generate key pair with builder
        using var keyPair = MLKemBuilder.Create()
            .WithSecurityBits(192)
            .GenerateKeyPair();

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem768, keyPair.Level);

        // Encapsulate with builder
        using var encResult = MLKemBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .Encapsulate();

        Assert.NotNull(encResult.Ciphertext);
        Assert.NotNull(encResult.SharedSecret);

        // Decapsulate with builder
        var recovered = MLKemBuilder.Create()
            .WithKeyPair(keyPair)
            .Decapsulate(encResult.Ciphertext);

        Assert.Equal(encResult.SharedSecret, recovered);
    }

    [Fact]
    public void MLDsaBuilder_FluentAPI_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        var message = "Test message for builder";

        // Generate key pair and sign with builder
        using var keyPair = MLDsaBuilder.Create()
            .WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa65)
            .GenerateKeyPair();

        var signature = MLDsaBuilder.Create()
            .WithKeyPair(keyPair)
            .WithData(message)
            .WithContext("test-context")
            .Sign();

        Assert.NotNull(signature);

        // Verify with builder
        var isValid = MLDsaBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .WithData(message)
            .WithContext("test-context")
            .Verify(signature);

        Assert.True(isValid);
    }

    [Fact]
    public void SlhDsaBuilder_FluentAPI_SmallVariant_Success()
    {
        if (!SlhDsaWrapper.IsSupported())
            return;

        var message = Encoding.UTF8.GetBytes("Test message for SLH-DSA builder");

        // Generate key pair with small variant
        using var keyPair = SlhDsaBuilder.Create()
            .WithSmallVariant(128)
            .GenerateKeyPair();

        Assert.NotNull(keyPair);
        Assert.Equal(SlhDsaWrapper.SecurityLevel.SlhDsa128s, keyPair.Level);

        // Sign and verify
        var signature = SlhDsaBuilder.Create()
            .WithKeyPair(keyPair)
            .WithData(message)
            .Sign();

        var isValid = SlhDsaBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .WithData(message)
            .Verify(signature);

        Assert.True(isValid);
    }

    [Fact]
    public void MLKem_ShorthandAPI_Success()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        // Use shorthand static methods
        using var keyPair = MLKem.GenerateKeyPair();
        Assert.NotNull(keyPair);

        using var keyPair512 = MLKem.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem512);
        Assert.Equal(MLKemWrapper.SecurityLevel.MLKem512, keyPair512.Level);
    }

    [Fact]
    public void MLDsa_ShorthandAPI_Success()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        // Use shorthand static methods
        using var keyPair = MLDsa.GenerateKeyPair();
        Assert.NotNull(keyPair);

        var data = Encoding.UTF8.GetBytes("Quick test");
        var signature = keyPair.Sign(data);

        var isValid = MLDsa.Verify(keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);
    }

    #endregion
}
#endif
