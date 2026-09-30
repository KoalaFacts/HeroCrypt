using System.Security.Cryptography;
using HeroCrypt.Protocols.SecretSharing;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class ThresholdSignaturesTests
{
    [Fact]
    public void VerifySignature_PubliclyComputedForgery_IsRejected()
    {
        byte[] message = [1, 2, 3];
        var publicKey = RandomNumberGenerator.GetBytes(32);
        var r = RandomNumberGenerator.GetBytes(32);
        var baseS = RandomNumberGenerator.GetBytes(32);
        var challenge = SHA256.HashData([.. r, .. publicKey, .. message]);
        var tag = SHA256.HashData([.. baseS, .. challenge]);
        var forgery = new ThresholdSignatures.ThresholdSignature(
            r, [.. baseS, .. tag], [0, 1, 2], ThresholdSignatures.SignatureScheme.Schnorr);

        Assert.Throws<NotSupportedException>(() =>
            new ThresholdSignatures().VerifySignature(message, forgery, publicKey));
    }

    [Theory]
    [InlineData(ThresholdSignatures.SignatureScheme.Schnorr)]
    [InlineData(ThresholdSignatures.SignatureScheme.ECDSA)]
    [InlineData(ThresholdSignatures.SignatureScheme.EdDSA)]
    [InlineData(ThresholdSignatures.SignatureScheme.BLS)]
    public void Operations_AllSchemes_AreUnsupported(ThresholdSignatures.SignatureScheme scheme)
    {
        var core = new ThresholdSignatures();
        var keyShare = new ThresholdSignatures.KeyShare(0, 1, new byte[32], new byte[32], [], 2, 3, scheme);
        var partial = new ThresholdSignatures.PartialSignature(0, 1, new byte[32], new byte[32]);
        var signature = new ThresholdSignatures.ThresholdSignature(new byte[32], new byte[64], [0, 1, 2], scheme);

        Assert.Throws<NotSupportedException>(() => core.GenerateKeys(3, 2, scheme));
        Assert.Throws<NotSupportedException>(() => core.SignPartial([1], keyShare, [0, 1, 2]));
        Assert.Throws<NotSupportedException>(() => core.CombineSignatures([1], [partial], new byte[32], scheme));
        Assert.Throws<NotSupportedException>(() => core.VerifySignature([1], signature, new byte[32]));
    }

    [Fact]
    public void TestingPolicy_CannotEnableThresholdSignatures()
    {
        Assert.Throws<NotSupportedException>(() =>
            new ThresholdSignatures(SecurityPolicyOptions.Testing).GenerateKeys(3, 2));
    }
}
