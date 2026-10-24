using HeroCrypt.Security;

namespace HeroCrypt.Tests.Security;

[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.MEMORY)]
public class SecureMemoryOperationsTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(1024)]
    [InlineData(16384)]
    public void SecureClear_ArrayWipesAllBytesAndPreservesCallerOwnership(int length)
    {
        var sensitive = Enumerable.Repeat((byte)0xA5, length).ToArray();
        var independent = sensitive.ToArray();

        SecureMemoryOperations.SecureClear(sensitive);

        Assert.All(sensitive, value => Assert.Equal((byte)0, value));
        Assert.All(independent, value => Assert.Equal((byte)0xA5, value));
    }

    [Fact]
    public void SecureClear_SpanOnlyWipesTheRequestedSlice()
    {
        var bytes = Enumerable.Repeat((byte)0x5A, 21).ToArray();

        SecureMemoryOperations.SecureClear(bytes.AsSpan(5, 11));

        Assert.All(bytes[..5], value => Assert.Equal((byte)0x5A, value));
        Assert.All(bytes[5..16], value => Assert.Equal((byte)0, value));
        Assert.All(bytes[16..], value => Assert.Equal((byte)0x5A, value));
    }

    [Fact]
    public void SecureClear_MultipleArraysAndEmptyInputsAreSupported()
    {
        byte[] first = [1, 2, 3];
        byte[] second = [4, 5];
        SecureMemoryOperations.SecureClear(first, second);
        SecureMemoryOperations.SecureClear((byte[])null!);
        SecureMemoryOperations.SecureClear(Array.Empty<byte>());

        Assert.Equal(new byte[3], first);
        Assert.Equal(new byte[2], second);
    }

    [Fact]
    public void SecureByteArray_DisposeClearsOwnedStorage()
    {
        var secure = SecureMemoryOperations.CreateSecureCopy([1, 2, 3, 4]);
        byte[]? observation = null;
        secure.WithBytes(bytes => observation = bytes);
        secure.Dispose();

        Assert.NotNull(observation);
        Assert.Equal(new byte[4], observation);
    }
}
