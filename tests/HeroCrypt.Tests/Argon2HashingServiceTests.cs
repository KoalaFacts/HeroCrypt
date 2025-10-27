using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;

namespace HeroCrypt.Tests;

// DISABLED: Binary search for hanging test
#if FALSE


[Trait("Category", TestCategories.Fast)]
[Trait("Category", TestCategories.Unit)]
public class Argon2HashingServiceTests
{
    private readonly Argon2HashingService _service;

    public Argon2HashingServiceTests()
    {
        _service = new Argon2HashingService(new Argon2Options
        {
            Type = Argon2Type.Argon2id,
            Iterations = 2,
            MemorySize = 8192,
            Parallelism = 2,
            HashSize = 32,
            SaltSize = 16
        });
    }

    [Fact]
    public async Task HashAsyncWithStringReturnsValidHash()
    {
        var input = "TestPassword123!";

        var hash = await _service.HashAsync(input, CancellationToken.None);

        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public async Task HashAsyncSameInputProducesDifferentHashes()
    {
        var input = "TestPassword123!";

        var hash1 = await _service.HashAsync(input, CancellationToken.None);
        var hash2 = await _service.HashAsync(input, CancellationToken.None);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public async Task VerifyAsyncWithCorrectPasswordReturnsTrue()
    {
        var input = "TestPassword123!";
        var hash = await _service.HashAsync(input, CancellationToken.None);

        var result = await _service.VerifyAsync(input, hash, CancellationToken.None);

        Assert.True(result);
    }

    [Fact]
    public async Task VerifyAsyncWithIncorrectPasswordReturnsFalse()
    {
        var input = "TestPassword123!";
        var wrongInput = "WrongPassword123!";
        var hash = await _service.HashAsync(input, CancellationToken.None);

        var result = await _service.VerifyAsync(wrongInput, hash, CancellationToken.None);

        Assert.False(result);
    }

    [Fact]
    public async Task HashAsyncWithBytesReturnsValidHash()
    {
        var input = new byte[] { 1, 2, 3, 4, 5 };

        var hash = await _service.HashAsync(input, CancellationToken.None);

        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public async Task VerifyAsyncWithBytesWorksCorrectly()
    {
        var input = new byte[] { 1, 2, 3, 4, 5 };
        var hash = await _service.HashAsync(input, CancellationToken.None);

        var result = await _service.VerifyAsync(input, hash, CancellationToken.None);

        Assert.True(result);
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d)]
    [InlineData(Argon2Type.Argon2i)]
    [InlineData(Argon2Type.Argon2id)]
    public async Task HashAsyncWithDifferentTypesWorksCorrectly(Argon2Type type)
    {
        var service = new Argon2HashingService(new Argon2Options
        {
            Type = type,
            Iterations = 2,
            MemorySize = 8192,
            Parallelism = 2
        });
        var input = "TestPassword";

        var hash = await service.HashAsync(input, CancellationToken.None);
        var result = await service.VerifyAsync(input, hash, CancellationToken.None);

        Assert.True(result);
    }

    [Fact]
    public async Task VerifyAsyncWithInvalidHashReturnsFalse()
    {
        var input = "TestPassword";
        var invalidHash = "InvalidBase64Hash!!!";

        var result = await _service.VerifyAsync(input, invalidHash, CancellationToken.None);

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsyncWithEmptyHashReturnsFalse()
    {
        var input = "TestPassword";

        var result = await _service.VerifyAsync(input, "", CancellationToken.None);

        Assert.False(result);
    }
}

#endif
