using HeroCrypt.Cryptography.Blake2b;
using HeroCrypt.Services;
using System.Text;

namespace HeroCrypt.Tests;

/// <summary>
/// Unit tests for Blake2b functionality
/// </summary>
public class Blake2bServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bCore_ComputeHash_ReturnsCorrectLength()
    {
        var data = Encoding.UTF8.GetBytes("Hello Blake2b");
        var hash = Blake2bCore.ComputeHash(data, 32);

        Assert.Equal(32, hash.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bCore_ComputeHash_IsDeterministic()
    {
        var data = Encoding.UTF8.GetBytes("Test data");
        var hash1 = Blake2bCore.ComputeHash(data, 32);
        var hash2 = Blake2bCore.ComputeHash(data, 32);

        Assert.True(hash1.AsSpan().SequenceEqual(hash2));
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bCore_ComputeLongHash_HandlesLargeSizes()
    {
        var data = Encoding.UTF8.GetBytes("Test data for long hash");
        var hash = Blake2bCore.ComputeLongHash(data, 128);

        Assert.Equal(128, hash.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bService_ComputeHash_ReturnsValidHash()
    {
        var service = new Blake2bHashingService();
        var data = Encoding.UTF8.GetBytes("Test Blake2b Service");

        var hash = service.ComputeHash(data, 64);

        Assert.Equal(64, hash.Length);
        Assert.NotEqual(new byte[64], hash);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bService_VerifyHash_ValidatesCorrectly()
    {
        var service = new Blake2bHashingService();
        var data = Encoding.UTF8.GetBytes("Test data for verification");

        var hash = service.ComputeHash(data, 32);
        var isValid = service.VerifyHash(data, hash);

        Assert.True(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bService_VerifyHash_RejectsInvalidHash()
    {
        var service = new Blake2bHashingService();
        var data = Encoding.UTF8.GetBytes("Test data");
        var wrongData = Encoding.UTF8.GetBytes("Wrong data");

        var hash = service.ComputeHash(data, 32);
        var isValid = service.VerifyHash(wrongData, hash);

        Assert.False(isValid);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bService_ComputeLongHash_WorksCorrectly()
    {
        var service = new Blake2bHashingService();
        var data = Encoding.UTF8.GetBytes("Long hash test data");

        var hash = service.ComputeLongHash(data, 256);

        Assert.Equal(256, hash.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bCore_ThrowsOnInvalidOutputLength()
    {
        var data = Encoding.UTF8.GetBytes("Test data");

        var ex = Assert.Throws<ArgumentException>(() =>
            Blake2bCore.ComputeHash(data, 0));

        Assert.Contains("Output length must be", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Unit)]
    public void Blake2bCore_ThrowsOnInvalidLongHashLength()
    {
        var data = Encoding.UTF8.GetBytes("Test data");

        var ex = Assert.Throws<ArgumentException>(() =>
            Blake2bCore.ComputeLongHash(data, 0));

        Assert.Contains("Output length must be positive", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.Compliance)]
    public void Blake2bCore_ProducesKnownTestVector()
    {
        // RFC 7693 test vector: empty input
        var emptyInput = new byte[0];
        var hash = Blake2bCore.ComputeHash(emptyInput, 64);

        // Blake2b-512 of empty string
        var expectedPrefix = "786A02F742015903C6C6FD852552D272";
        var actualHex = Convert.ToHexString(hash);

        Assert.StartsWith(expectedPrefix, actualHex);
    }
}


