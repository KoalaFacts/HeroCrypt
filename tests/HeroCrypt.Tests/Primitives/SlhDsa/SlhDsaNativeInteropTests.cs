#if NET10_0_OR_GREATER
using HeroCrypt.Primitives.SlhDsa;

namespace HeroCrypt.Tests.Primitives.SlhDsa;

[Trait("Category", TestCategories.COMPLIANCE)]
public class SlhDsaNativeInteropTests
{
    [Theory]
    [InlineData(SlhDsaCore.SecurityLevel.SlhDsa128s, "SLH-DSA-SHA2-128s", 32, 7856)]
    [InlineData(SlhDsaCore.SecurityLevel.SlhDsa128f, "SLH-DSA-SHA2-128f", 32, 17088)]
    [InlineData(SlhDsaCore.SecurityLevel.SlhDsa192s, "SLH-DSA-SHA2-192s", 48, 16224)]
    [InlineData(SlhDsaCore.SecurityLevel.SlhDsa192f, "SLH-DSA-SHA2-192f", 48, 35664)]
    [InlineData(SlhDsaCore.SecurityLevel.SlhDsa256s, "SLH-DSA-SHA2-256s", 64, 29792)]
    [InlineData(SlhDsaCore.SecurityLevel.SlhDsa256f, "SLH-DSA-SHA2-256f", 64, 49856)]
    public void GeneratedKeysAndSignatures_InteroperateWithNativeSha2Profile(
        SlhDsaCore.SecurityLevel level, string algorithmName, int publicKeySize, int signatureSize)
    {
        RequireSupport();
        var core = new SlhDsaCore();
        using var keyPair = core.GenerateKeyPair(level);
        using var nativePrivate = System.Security.Cryptography.SlhDsa.ImportFromPem(keyPair.SecretKeyPem);
        using var nativePublic = System.Security.Cryptography.SlhDsa.ImportFromPem(keyPair.PublicKeyPem);
        Assert.Equal(algorithmName, nativePrivate.Algorithm.Name);
        Assert.Equal(algorithmName, nativePublic.Algorithm.Name);
        Assert.Equal(publicKeySize, nativePublic.Algorithm.PublicKeySizeInBytes);
        Assert.Equal(signatureSize, nativePublic.Algorithm.SignatureSizeInBytes);
        var data = "SLH-DSA native interoperability regression"u8.ToArray();
        var context = "profile-context"u8.ToArray();
        var signature = keyPair.Sign(data, context);
        Assert.Equal(signatureSize, signature.Length);
        Assert.True(nativePublic.VerifyData(data, signature, context));
        var nativeSignature = nativePrivate.SignData(data, context);
        Assert.True(core.Verify(keyPair.PublicKeyPem, data, nativeSignature, context));
        Assert.False(core.Verify(keyPair.PublicKeyPem, data, nativeSignature, "different-context"u8.ToArray()));
        Assert.False(nativePublic.VerifyData("tampered"u8.ToArray(), signature, context));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(6)]
    [InlineData(int.MaxValue)]
    public void KeyGeneration_RejectsUnknownSecurityLevels(int level)
    {
        RequireSupport();
        Assert.Throws<ArgumentOutOfRangeException>(() => new SlhDsaCore().GenerateKeyPair((SlhDsaCore.SecurityLevel)level));
    }

    private static void RequireSupport()
    {
        if (!System.Security.Cryptography.SlhDsa.IsSupported)
            Assert.Skip("The native platform does not provide SLH-DSA.");
    }
}
#endif
