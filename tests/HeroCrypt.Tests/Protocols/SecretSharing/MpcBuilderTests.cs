using HeroCrypt.Protocols.SecretSharing;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class MpcBuilderTests
{
    [Theory]
    [InlineData(SecureMpc.SecurityModel.SemiHonest)]
    [InlineData(SecureMpc.SecurityModel.Malicious)]
    [InlineData(SecureMpc.SecurityModel.Covert)]
    [InlineData((SecureMpc.SecurityModel)0)]
    public void PublicFactory_ConfiguredOperations_CannotBypassUnsupportedCore(SecureMpc.SecurityModel model)
    {
        byte[][] inputs = [[1], [2], [3]];
        byte[][] set1 = [[1], [2]];
        byte[][] set2 = [[2], [3]];
        var builder = HeroCryptBuilder.Mpc()
            .WithThreshold(2)
            .WithSecurityModel(model)
            .WithPartyInputs(inputs)
            .WithParty1Set(set1)
            .WithParty2Set(set2);

        Assert.Throws<NotSupportedException>(builder.ComputeSum);
        Assert.Throws<NotSupportedException>(() => builder.ComputeSum(inputs));
        Assert.Throws<NotSupportedException>(builder.ComputeIntersection);
        Assert.Throws<NotSupportedException>(() => builder.ComputeIntersection(set1, set2));
        Assert.Throws<NotSupportedException>(() => builder.GenerateBeaverTriples(3, 32));
    }

    [Fact]
    public void ComputeSum_MissingInputs_ReportsConfigurationError()
    {
        Assert.Throws<InvalidOperationException>(HeroCryptBuilder.Mpc().ComputeSum);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void ComputeIntersection_MissingSet_ReportsConfigurationError(bool hasFirst, bool hasSecond)
    {
        var builder = HeroCryptBuilder.Mpc();
        if (hasFirst)
        {
            builder.WithParty1Set([[1]]);
        }
        if (hasSecond)
        {
            builder.WithParty2Set([[1]]);
        }

        Assert.Throws<InvalidOperationException>(builder.ComputeIntersection);
    }
}
