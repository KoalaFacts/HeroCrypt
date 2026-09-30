using HeroCrypt.Protocols.SecretSharing;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class SecureMpcTests
{
    [Theory]
    [InlineData(SecureMpc.SecurityModel.SemiHonest)]
    [InlineData(SecureMpc.SecurityModel.Malicious)]
    [InlineData(SecureMpc.SecurityModel.Covert)]
    [InlineData((SecureMpc.SecurityModel)0)]
    public void SecurityModel_CannotEnableSum(SecureMpc.SecurityModel model)
    {
        var mpc = new SecureMpc();

        Assert.Throws<NotSupportedException>(() => mpc.SecureSum([[1], [2], [3]], 2, model));
    }

    [Theory]
    [InlineData(SecureMpc.SecurityModel.SemiHonest)]
    [InlineData(SecureMpc.SecurityModel.Malicious)]
    [InlineData(SecureMpc.SecurityModel.Covert)]
    [InlineData((SecureMpc.SecurityModel)0)]
    public void SecurityModel_CannotEnablePrivateIntersection(SecureMpc.SecurityModel model)
    {
        Assert.Throws<NotSupportedException>(() =>
            new SecureMpc().PrivateSetIntersection([[1], [2]], [[2], [3]], model));
    }

    [Fact]
    public void SecureSum_UnequalInputLengths_CannotReportTruncatedSuccess()
    {
        Assert.Throws<NotSupportedException>(() =>
            new SecureMpc().SecureSum([[1], [2, 99], [3, 100]], 2));
    }

    [Theory]
    [InlineData(2, true)]
    [InlineData(-1, false)]
    [InlineData(4, false)]
    public void SecureMultiply_TamperedTripleOrInvalidThreshold_IsRejected(int threshold, bool tamper)
    {
        var x = new SecureMpc.MpcShare[3];
        var y = new SecureMpc.MpcShare[3];
        var triples = new SecureMpc.BeaverTriple[3];
        for (var party = 0; party < 3; party++)
        {
            var index = (byte)(party + 1);
            x[party] = new SecureMpc.MpcShare(party, [2], index);
            y[party] = new SecureMpc.MpcShare(party, [3], index);
            triples[party] = new SecureMpc.BeaverTriple(
                new SecureMpc.MpcShare(party, [1], index),
                new SecureMpc.MpcShare(party, [1], index),
                new SecureMpc.MpcShare(party, [1], index));
        }

        // Corrupt c = a*b for one participant. The former simulation consumed it
        // without authenticating the triple or detecting participant tampering.
        if (tamper)
        {
            triples[0].C.Value[0] = 0;
        }

        Assert.Throws<NotSupportedException>(() => new SecureMpc().SecureMultiply(x, y, triples, threshold));
    }

    [Theory]
    [InlineData(SecurityLevel.None)]
    [InlineData(SecurityLevel.Standard)]
    [InlineData(SecurityLevel.Strict)]
    [InlineData(SecurityLevel.Compliance)]
    public void SecurityPolicy_CannotEnableMpcOperations(SecurityLevel level)
    {
        var mpc = new SecureMpc(new SecurityPolicyOptions(level, AllowDeterministicNonSiv: true));

        Assert.Throws<NotSupportedException>(() => mpc.SecureSum([[1], [2], [3]], 2));
        Assert.Throws<NotSupportedException>(() => mpc.PrivateSetIntersection([[1]], [[1]]));
        Assert.Throws<NotSupportedException>(() => mpc.GenerateBeaverTriples(3, 2, 1));
        Assert.Throws<NotSupportedException>(() => mpc.SecureMultiply([], [], [], 2));
    }

    [Fact]
    public void BeaverTripleGeneration_CannotProduceUnsupportedProtocolMaterial()
    {
        Assert.Throws<NotSupportedException>(() => new SecureMpc().GenerateBeaverTriples(3, 2, 32));
    }
}
