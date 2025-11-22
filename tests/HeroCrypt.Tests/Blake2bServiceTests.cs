using System.Text;
using HeroCrypt.Cryptography.Primitives.Hash;

namespace HeroCrypt.Tests;

/// <summary>
/// Unit tests for Blake2b functionality
/// </summary>
public class Blake2bServiceTests
{
    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Blake2bCore_ComputeHash_ReturnsCorrectLength()
    {
        var data = Encoding.UTF8.GetBytes("Hello Blake2b");
        var hash = Blake2bCore.ComputeHash(data, 32);

        Assert.Equal(32, hash.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Blake2bCore_ComputeHash_IsDeterministic()
    {
        var data = Encoding.UTF8.GetBytes("Test data");
        var hash1 = Blake2bCore.ComputeHash(data, 32);
        var hash2 = Blake2bCore.ComputeHash(data, 32);

        Assert.True(hash1.AsSpan().SequenceEqual(hash2));
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Blake2bCore_ComputeLongHash_HandlesLargeSizes()
    {
        var data = Encoding.UTF8.GetBytes("Test data for long hash");
        var hash = Blake2bCore.ComputeLongHash(data, 128);

        Assert.Equal(128, hash.Length);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Blake2bCore_ThrowsOnInvalidOutputLength()
    {
        var data = Encoding.UTF8.GetBytes("Test data");

        var ex = Assert.Throws<ArgumentException>(() =>
            Blake2bCore.ComputeHash(data, 0));

        Assert.Contains("Output length must be", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void Blake2bCore_ThrowsOnInvalidLongHashLength()
    {
        var data = Encoding.UTF8.GetBytes("Test data");

        var ex = Assert.Throws<ArgumentException>(() =>
            Blake2bCore.ComputeLongHash(data, 0));

        Assert.Contains("Output length must be positive", ex.Message);
    }

    [Fact]
    [Trait("Category", TestCategories.COMPLIANCE)]
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


