using System.Reflection;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

[Trait("Category", TestCategories.UNIT)]
public class PgpFeatureFlagSecurityTests
{
    [Fact]
    public void FeatureFlags_Rfc9580SeipdV2_HasNamedPublicValue()
    {
        // RFC 9580 section 5.2.3.32 assigns 0x08 to SEIPD version 2.
        Assert.True(Enum.IsDefined(typeof(PgpFeatures), (byte)0x08));
    }

    [Theory]
    [InlineData("AeadEncryptedData", 0x02)]
    [InlineData("Version6Keys", 0x04)]
    public void FeatureFlags_ReservedLegacyMembers_PreserveValueAndWarnCallers(string name, byte wireValue)
    {
        // Preserve published numeric values for binary/source compatibility,
        // but do not advertise these reserved draft bits as RFC 9580 features.
        var field = typeof(PgpFeatures).GetField(name);
        Assert.NotNull(field);
        Assert.Equal(wireValue, (byte)(PgpFeatures)field.GetValue(null)!);
        var obsolete = field.GetCustomAttribute<ObsoleteAttribute>();
        Assert.NotNull(obsolete);
        Assert.False(obsolete.IsError);
        Assert.Contains("reserved", obsolete.Message!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FeatureFlags_Rfc9580SeipdV2_PreservesExactWireOctet()
    {
        var packet = PgpSignatureSubpacket.CreateFeatures((PgpFeatures)0x08);
        Assert.Equal(PgpSignatureSubpacketType.Features, packet.Type);
        Assert.Equal(new byte[] { 0x08 }, packet.Data.ToArray());
    }
}
