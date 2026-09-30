using HeroCrypt.Protocols.SecretSharing;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class ThresholdSignatureBuilderTests
{
    [Fact]
    public void ConfiguredBuilder_AllOperations_AreUnsupported()
    {
        var scheme = ThresholdSignatures.SignatureScheme.Schnorr;
        var keyShare = new ThresholdSignatures.KeyShare(0, 1, new byte[32], new byte[32], [], 2, 3, scheme);
        var partial = new ThresholdSignatures.PartialSignature(0, 1, new byte[32], new byte[32]);
        var signature = new ThresholdSignatures.ThresholdSignature(new byte[32], new byte[64], [0, 1, 2], scheme);
        var builder = HeroCryptBuilder.ThresholdSignature()
            .WithParties(3)
            .WithThreshold(2)
            .WithScheme(scheme)
            .WithMessage([1])
            .WithKeyShare(keyShare)
            .WithSigners([0, 1, 2])
            .WithPartialSignatures([partial])
            .WithPublicKey(new byte[32]);

        Assert.Throws<NotSupportedException>(builder.GenerateKeys);
        Assert.Throws<NotSupportedException>(builder.SignPartial);
        Assert.Throws<NotSupportedException>(builder.CombineSignatures);
        Assert.Throws<NotSupportedException>(() => builder.VerifySignature(signature));
    }
}
