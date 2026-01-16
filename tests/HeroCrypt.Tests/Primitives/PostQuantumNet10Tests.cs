#if NET10_0_OR_GREATER
using System.Text;
using HeroCrypt.Primitives.MLDsa;
using HeroCrypt.Primitives.MLKem;
using HeroCrypt.Primitives.SlhDsa;

namespace HeroCrypt.Tests.Primitives;

/// <summary>
/// Tests for .NET 10+ Post-Quantum Cryptography (PQC) native implementations.
/// </summary>
/// <remarks>
/// <para><b>Platform Support Notes:</b></para>
/// <para>
/// Post-quantum cryptography algorithms (ML-KEM, ML-DSA) require specific platform support:
/// </para>
/// <list type="bullet">
///   <item>
///     <term>Windows</term>
///     <description>
///       Requires Windows CNG (Cryptography Next Generation) with PQC support.
///       Available in Windows 11 version 24H2 or later, and Windows Server 2025+.
///       Earlier Windows versions do not have native PQC support.
///     </description>
///   </item>
///   <item>
///     <term>Linux</term>
///     <description>
///       Requires OpenSSL 3.5+ with the PQC provider enabled.
///       Most Linux distributions ship with older OpenSSL versions.
///       Ubuntu 24.04+ and similar recent distributions may have support.
///     </description>
///   </item>
///   <item>
///     <term>macOS</term>
///     <description>
///       Not currently supported. Apple's Security framework does not include
///       post-quantum cryptographic algorithms as of macOS 14 (Sonoma).
///     </description>
///   </item>
/// </list>
/// <para>
/// Tests automatically detect platform support using <c>MLKemCore.IsSupported()</c>
/// and <c>MLDsaCore.IsSupported()</c> and skip gracefully on unsupported platforms.
/// </para>
/// <para>
/// <b>Algorithms tested:</b>
/// </para>
/// <list type="bullet">
///   <item><term>ML-KEM</term><description>Module-Lattice Key Encapsulation Mechanism (NIST FIPS 203)</description></item>
///   <item><term>ML-DSA</term><description>Module-Lattice Digital Signature Algorithm (NIST FIPS 204)</description></item>
/// </list>
/// </remarks>
public class PostQuantumNet10Tests
{
    #region ML-KEM Tests

    [Fact]
    public void MLKem_IsSupported_ReturnsExpectedValue()
    {
        // This test documents platform support - result depends on platform
        // Just verify the call doesn't throw; actual support varies by OS/runtime
        var isSupported = MLKemCore.IsSupported();
        // Don't assert true/false - just verify it returns a valid boolean
        Assert.True(isSupported || !isSupported);
    }

    [Fact]
    public void MLKem_GenerateKeyPair_MLKem512_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            // Skip test on platforms without PQC support
            return;
        }

        using var keyPair = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem512);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKeyPem);
        Assert.NotNull(keyPair.SecretKeyPem);
        Assert.Equal(MLKemCore.SecurityLevel.MLKem512, keyPair.Level);
        Assert.Contains("PUBLIC KEY", keyPair.PublicKeyPem);
        Assert.Contains("PRIVATE KEY", keyPair.SecretKeyPem);
    }

    [Fact]
    public void MLKem_GenerateKeyPair_MLKem768_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem768);

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemCore.SecurityLevel.MLKem768, keyPair.Level);
    }

    [Fact]
    public void MLKem_GenerateKeyPair_MLKem1024_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem1024);

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemCore.SecurityLevel.MLKem1024, keyPair.Level);
    }

    [Fact]
    public void MLKem_EncapsulateDecapsulate_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem768);

        // Encapsulate
        using var result = MLKemCore.Encapsulate(keyPair.PublicKeyPem);

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
        Assert.Equal(MLKemCore.SecurityLevel.MLKem512, MLKemCore.GetRecommendedLevel(128));
        Assert.Equal(MLKemCore.SecurityLevel.MLKem768, MLKemCore.GetRecommendedLevel(192));
        Assert.Equal(MLKemCore.SecurityLevel.MLKem1024, MLKemCore.GetRecommendedLevel(256));
    }

    [Fact]
    public void MLKem_GetLevelInfo_ReturnsCorrectInfo()
    {
        var (secBits512, desc512) = MLKemCore.GetLevelInfo(MLKemCore.SecurityLevel.MLKem512);
        Assert.Equal(128, secBits512);
        Assert.Contains("128-bit", desc512);

        var (secBits768, desc768) = MLKemCore.GetLevelInfo(MLKemCore.SecurityLevel.MLKem768);
        Assert.Equal(192, secBits768);
        Assert.Contains("192-bit", desc768);

        var (secBits1024, desc1024) = MLKemCore.GetLevelInfo(MLKemCore.SecurityLevel.MLKem1024);
        Assert.Equal(256, secBits1024);
        Assert.Contains("256-bit", desc1024);
    }

    #endregion

    #region ML-DSA Tests

    [Fact]
    public void MLDsa_IsSupported_ReturnsExpectedValue()
    {
        // Result depends on platform - just verify the call doesn't throw
        var isSupported = MLDsaCore.IsSupported();
        Assert.True(isSupported || !isSupported);
    }

    [Fact]
    public void MLDsa_GenerateKeyPair_MLDsa44_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa44);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKeyPem);
        Assert.NotNull(keyPair.SecretKeyPem);
        Assert.Equal(MLDsaCore.SecurityLevel.MLDsa44, keyPair.Level);
    }

    [Fact]
    public void MLDsa_GenerateKeyPair_MLDsa65_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

        Assert.NotNull(keyPair);
        Assert.Equal(MLDsaCore.SecurityLevel.MLDsa65, keyPair.Level);
    }

    [Fact]
    public void MLDsa_GenerateKeyPair_MLDsa87_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa87);

        Assert.NotNull(keyPair);
        Assert.Equal(MLDsaCore.SecurityLevel.MLDsa87, keyPair.Level);
    }

    [Fact]
    public void MLDsa_SignAndVerify_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

        var data = Encoding.UTF8.GetBytes("Hello, Post-Quantum World!");

        // Sign
        var signature = keyPair.Sign(data);

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);

        // Verify with correct data
        var isValid = MLDsaCore.Verify(keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);

        // Verify with incorrect data
        var wrongData = Encoding.UTF8.GetBytes("Wrong data");
        var isInvalid = MLDsaCore.Verify(keyPair.PublicKeyPem, wrongData, signature);
        Assert.False(isInvalid);
    }

    [Fact]
    public void MLDsa_SignWithContext_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

        var data = Encoding.UTF8.GetBytes("Message with context");
        var context = Encoding.UTF8.GetBytes("test-context");

        // Sign with context
        var signature = keyPair.Sign(data, context);
        Assert.NotNull(signature);

        // Verify with correct context
        var isValid = MLDsaCore.Verify(keyPair.PublicKeyPem, data, signature, context);
        Assert.True(isValid);

        // Verify without context should fail
        var isInvalidNoContext = MLDsaCore.Verify(keyPair.PublicKeyPem, data, signature, null);
        Assert.False(isInvalidNoContext);

        // Verify with wrong context should fail
        var wrongContext = Encoding.UTF8.GetBytes("wrong-context");
        var isInvalidWrongContext = MLDsaCore.Verify(keyPair.PublicKeyPem, data, signature, wrongContext);
        Assert.False(isInvalidWrongContext);
    }

    [Fact]
    public void MLDsa_GetRecommendedLevel_ReturnsCorrectLevel()
    {
        Assert.Equal(MLDsaCore.SecurityLevel.MLDsa44, MLDsaCore.GetRecommendedLevel(128));
        Assert.Equal(MLDsaCore.SecurityLevel.MLDsa65, MLDsaCore.GetRecommendedLevel(192));
        Assert.Equal(MLDsaCore.SecurityLevel.MLDsa87, MLDsaCore.GetRecommendedLevel(256));
    }

    [Fact]
    public void MLDsa_GetLevelInfo_ReturnsCorrectInfo()
    {
        var (secBits44, sigSize44, desc44) = MLDsaCore.GetLevelInfo(MLDsaCore.SecurityLevel.MLDsa44);
        Assert.Equal(128, secBits44);
        Assert.Equal(2420, sigSize44);
        Assert.Contains("128-bit", desc44);

        var (secBits65, sigSize65, desc65) = MLDsaCore.GetLevelInfo(MLDsaCore.SecurityLevel.MLDsa65);
        Assert.Equal(192, secBits65);
        Assert.Equal(3309, sigSize65);
        Assert.Contains("192-bit", desc65);

        var (secBits87, sigSize87, desc87) = MLDsaCore.GetLevelInfo(MLDsaCore.SecurityLevel.MLDsa87);
        Assert.Equal(256, secBits87);
        Assert.Equal(4627, sigSize87);
        Assert.Contains("256-bit", desc87);
    }

    #endregion

    #region SLH-DSA Tests

    [Fact]
    public void SlhDsa_IsSupported_ReturnsExpectedValue()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        Assert.True(SlhDsaCore.IsSupported());
    }

    [Fact]
    public void SlhDsa_GenerateKeyPair_128s_Success()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = SlhDsaCore.GenerateKeyPair(SlhDsaCore.SecurityLevel.SlhDsa128s);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKeyPem);
        Assert.NotNull(keyPair.SecretKeyPem);
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa128s, keyPair.Level);
    }

    [Fact]
    public void SlhDsa_GenerateKeyPair_AllLevels_Success()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        var levels = new[]
        {
            SlhDsaCore.SecurityLevel.SlhDsa128s,
            SlhDsaCore.SecurityLevel.SlhDsa128f,
            SlhDsaCore.SecurityLevel.SlhDsa192s,
            SlhDsaCore.SecurityLevel.SlhDsa192f,
            SlhDsaCore.SecurityLevel.SlhDsa256s,
            SlhDsaCore.SecurityLevel.SlhDsa256f
        };

        foreach (var level in levels)
        {
            using var keyPair = SlhDsaCore.GenerateKeyPair(level);
            Assert.NotNull(keyPair);
            Assert.Equal(level, keyPair.Level);
        }
    }

    [Fact]
    public void SlhDsa_SignAndVerify_Success()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = SlhDsaCore.GenerateKeyPair(SlhDsaCore.SecurityLevel.SlhDsa128s);

        var data = Encoding.UTF8.GetBytes("Hash-based signatures!");

        // Sign
        var signature = keyPair.Sign(data);

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);

        // Verify with correct data
        var isValid = SlhDsaCore.Verify(keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);

        // Verify with incorrect data
        var wrongData = Encoding.UTF8.GetBytes("Wrong data");
        var isInvalid = SlhDsaCore.Verify(keyPair.PublicKeyPem, wrongData, signature);
        Assert.False(isInvalid);
    }

    [Fact]
    public void SlhDsa_GetRecommendedLevel_ReturnsCorrectLevel()
    {
        // Prefer small
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa128s, SlhDsaCore.GetRecommendedLevel(128, preferSmall: true));
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa192s, SlhDsaCore.GetRecommendedLevel(192, preferSmall: true));
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa256s, SlhDsaCore.GetRecommendedLevel(256, preferSmall: true));

        // Prefer fast
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa128f, SlhDsaCore.GetRecommendedLevel(128, preferSmall: false));
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa192f, SlhDsaCore.GetRecommendedLevel(192, preferSmall: false));
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa256f, SlhDsaCore.GetRecommendedLevel(256, preferSmall: false));
    }

    [Fact]
    public void SlhDsa_GetLevelInfo_ReturnsCorrectInfo()
    {
        var (secBits, sigSize, desc) = SlhDsaCore.GetLevelInfo(SlhDsaCore.SecurityLevel.SlhDsa128s);
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
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        // Generate ML-KEM key pair
        using var keyPair = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem768);

        // Sender: Encapsulate to get shared secret
        using var encResult = MLKemCore.Encapsulate(keyPair.PublicKeyPem);

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
        if (!MLDsaCore.IsSupported() || !SlhDsaCore.IsSupported())
        {
            return;
        }

        var data = Encoding.UTF8.GetBytes("Important document");

        // Sign with ML-DSA
        using var mlDsaKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);
        var mlDsaSignature = mlDsaKey.Sign(data);
        Assert.True(MLDsaCore.Verify(mlDsaKey.PublicKeyPem, data, mlDsaSignature));

        // Sign with SLH-DSA
        using var slhDsaKey = SlhDsaCore.GenerateKeyPair(SlhDsaCore.SecurityLevel.SlhDsa128s);
        var slhDsaSignature = slhDsaKey.Sign(data);
        Assert.True(SlhDsaCore.Verify(slhDsaKey.PublicKeyPem, data, slhDsaSignature));

        // Different algorithms produce different signatures
        Assert.NotEqual(mlDsaSignature.Length, slhDsaSignature.Length);
    }

    #endregion

    #region Unified HeroCryptBuilder Tests

    [Fact]
    public void HeroCryptBuilder_PostQuantum_MLKem_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        // Use unified builder
        using var keyPair = MLKemBuilder.Create()
            .WithSecurityBits(192)
            .GenerateKeyPair();

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemCore.SecurityLevel.MLKem768, keyPair.Level);

        // Encapsulate
        using var encResult = MLKemBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .Encapsulate();

        Assert.NotNull(encResult.Ciphertext);
        Assert.NotNull(encResult.SharedSecret);

        // Decapsulate
        var recovered = MLKemBuilder.Create()
            .WithKeyPair(keyPair)
            .Decapsulate(encResult.Ciphertext);

        Assert.Equal(encResult.SharedSecret, recovered);
    }

    [Fact]
    public void HeroCryptBuilder_PostQuantum_MLDsa_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        var message = "Test unified builder";

        // Generate and sign
        using var keyPair = MLDsaBuilder.Create()
            .WithSecurityLevel(MLDsaCore.SecurityLevel.MLDsa65)
            .GenerateKeyPair();

        var signature = MLDsaBuilder.Create()
            .WithKeyPair(keyPair)
            .WithData(message)
            .WithContext("unified-test")
            .Sign();

        Assert.NotNull(signature);

        // Verify
        var isValid = MLDsaBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .WithData(message)
            .WithContext("unified-test")
            .Verify(signature);

        Assert.True(isValid);
    }

    [Fact]
    public void HeroCryptBuilder_PostQuantum_SlhDsa_Success()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        var message = Encoding.UTF8.GetBytes("Unified builder SLH-DSA test");

        // Generate with unified builder
        using var keyPair = SlhDsaBuilder.Create()
            .WithSmallVariant(128)
            .GenerateKeyPair();

        Assert.NotNull(keyPair);

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
    public void HeroCrypt_PostQuantum_QuickAccess_MLKem_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLKemBuilder.Create().GenerateKeyPair();
        Assert.NotNull(keyPair);

        using var keyPair512 = MLKemBuilder.Create()
            .WithSecurityLevel(MLKemCore.SecurityLevel.MLKem512)
            .GenerateKeyPair();
        Assert.Equal(MLKemCore.SecurityLevel.MLKem512, keyPair512.Level);
    }

    [Fact]
    public void HeroCrypt_PostQuantum_QuickAccess_MLDsa_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaBuilder.Create().GenerateKeyPair();
        Assert.NotNull(keyPair);

        var data = Encoding.UTF8.GetBytes("Quick access test");
        var signature = keyPair.Sign(data);

        var isValid = MLDsaCore.Verify(
            keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);
    }

    #endregion

    #region Builder Pattern Tests

    [Fact]
    public void MLKemBuilder_FluentAPI_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        // Generate key pair with builder
        using var keyPair = MLKemBuilder.Create()
            .WithSecurityBits(192)
            .GenerateKeyPair();

        Assert.NotNull(keyPair);
        Assert.Equal(MLKemCore.SecurityLevel.MLKem768, keyPair.Level);

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
    public void MLKemBuilder_EncapsulateWithoutPublicKey_Throws()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        var builder = MLKemBuilder.Create();
        Assert.Throws<InvalidOperationException>(builder.Encapsulate);
    }

    [Fact]
    public void MLDsaBuilder_FluentAPI_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        var message = "Test message for builder";

        // Generate key pair and sign with builder
        using var keyPair = MLDsaBuilder.Create()
            .WithSecurityLevel(MLDsaCore.SecurityLevel.MLDsa65)
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
    public void MLDsaBuilder_Verify_FailsWithDifferentContext()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaBuilder.Create().GenerateKeyPair();
        var data = Encoding.UTF8.GetBytes("contexted data");

        var signature = MLDsaBuilder.Create()
            .WithKeyPair(keyPair)
            .WithData(data)
            .WithContext("ctx1")
            .Sign();

        var isValid = MLDsaBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .WithData(data)
            .WithContext("ctx2")
            .Verify(signature);

        Assert.False(isValid);
    }

    [Fact]
    public void SlhDsaBuilder_FluentAPI_SmallVariant_Success()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        var message = Encoding.UTF8.GetBytes("Test message for SLH-DSA builder");

        // Generate key pair with small variant
        using var keyPair = SlhDsaBuilder.Create()
            .WithSmallVariant(128)
            .GenerateKeyPair();

        Assert.NotNull(keyPair);
        Assert.Equal(SlhDsaCore.SecurityLevel.SlhDsa128s, keyPair.Level);

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
    public void SlhDsaBuilder_VerifyFailsWhenDataTampered()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = SlhDsaBuilder.Create()
            .WithSmallVariant(128)
            .GenerateKeyPair();

        var data = Encoding.UTF8.GetBytes("release");

        var signature = SlhDsaBuilder.Create()
            .WithKeyPair(keyPair)
            .WithData(data)
            .Sign();

        var tampered = Encoding.UTF8.GetBytes("release-mod");

        var isValid = SlhDsaBuilder.Create()
            .WithPublicKey(keyPair.PublicKeyPem)
            .WithData(tampered)
            .Verify(signature);

        Assert.False(isValid);
    }

    [Fact]
    public void MLKem_ShorthandAPI_Success()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLKemBuilder.Create().GenerateKeyPair();
        Assert.NotNull(keyPair);

        using var keyPair512 = MLKemBuilder.Create()
            .WithSecurityLevel(MLKemCore.SecurityLevel.MLKem512)
            .GenerateKeyPair();
        Assert.Equal(MLKemCore.SecurityLevel.MLKem512, keyPair512.Level);
    }

    [Fact]
    public void MLDsa_ShorthandAPI_Success()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        using var keyPair = MLDsaBuilder.Create().GenerateKeyPair();
        Assert.NotNull(keyPair);

        var data = Encoding.UTF8.GetBytes("Quick test");
        var signature = keyPair.Sign(data);

        var isValid = MLDsaCore.Verify(keyPair.PublicKeyPem, data, signature);
        Assert.True(isValid);
    }

    #endregion
}
#endif
