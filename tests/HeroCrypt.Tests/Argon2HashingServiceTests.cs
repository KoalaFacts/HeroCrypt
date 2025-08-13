using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;

namespace HeroCrypt.Tests;

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
    public async Task HashAsync_WithString_ReturnsValidHash()
    {
        var input = "TestPassword123!";
        
        var hash = await _service.HashAsync(input);
        
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public async Task HashAsync_SameInput_ProducesDifferentHashes()
    {
        var input = "TestPassword123!";
        
        var hash1 = await _service.HashAsync(input);
        var hash2 = await _service.HashAsync(input);
        
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public async Task VerifyAsync_WithCorrectPassword_ReturnsTrue()
    {
        var input = "TestPassword123!";
        var hash = await _service.HashAsync(input);
        
        var result = await _service.VerifyAsync(input, hash);
        
        Assert.True(result);
    }

    [Fact]
    public async Task VerifyAsync_WithIncorrectPassword_ReturnsFalse()
    {
        var input = "TestPassword123!";
        var wrongInput = "WrongPassword123!";
        var hash = await _service.HashAsync(input);
        
        var result = await _service.VerifyAsync(wrongInput, hash);
        
        Assert.False(result);
    }

    [Fact]
    public async Task HashAsync_WithBytes_ReturnsValidHash()
    {
        var input = new byte[] { 1, 2, 3, 4, 5 };
        
        var hash = await _service.HashAsync(input);
        
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public async Task VerifyAsync_WithBytes_WorksCorrectly()
    {
        var input = new byte[] { 1, 2, 3, 4, 5 };
        var hash = await _service.HashAsync(input);
        
        var result = await _service.VerifyAsync(input, hash);
        
        Assert.True(result);
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d)]
    [InlineData(Argon2Type.Argon2i)]
    [InlineData(Argon2Type.Argon2id)]
    public async Task HashAsync_WithDifferentTypes_WorksCorrectly(Argon2Type type)
    {
        var service = new Argon2HashingService(new Argon2Options
        {
            Type = type,
            Iterations = 2,
            MemorySize = 8192,
            Parallelism = 2
        });
        var input = "TestPassword";
        
        var hash = await service.HashAsync(input);
        var result = await service.VerifyAsync(input, hash);
        
        Assert.True(result);
    }

    [Fact]
    public async Task VerifyAsync_WithInvalidHash_ReturnsFalse()
    {
        var input = "TestPassword";
        var invalidHash = "InvalidBase64Hash!!!";
        
        var result = await _service.VerifyAsync(input, invalidHash);
        
        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_WithEmptyHash_ReturnsFalse()
    {
        var input = "TestPassword";
        
        var result = await _service.VerifyAsync(input, "");
        
        Assert.False(result);
    }
}