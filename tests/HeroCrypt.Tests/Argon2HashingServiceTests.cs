using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Security;

namespace HeroCrypt.Tests;

[Trait("Category", TestCategories.FAST)]
[Trait("Category", TestCategories.UNIT)]
public class Argon2HashingServiceTests
{
    private static readonly Argon2Parameters defaultParams = new(
        Iterations: 2,
        MemorySizeKb: 8192,
        Parallelism: 2,
        HashLength: 32,
        Type: Argon2Type.Argon2id);

    [Fact]
    public void Hash_WithSameSalt_IsDeterministic()
    {
        var password = Encoding.UTF8.GetBytes("TestPassword123!");
        var salt = RandomNumberGenerator.GetBytes(16);

        var hash1 = Hash(password, salt, defaultParams);
        var hash2 = Hash(password, salt, defaultParams);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void Hash_WithDifferentSalt_ProducesDifferentHashes()
    {
        var password = Encoding.UTF8.GetBytes("TestPassword123!");

        var hash1 = Hash(password, RandomNumberGenerator.GetBytes(16), defaultParams);
        var hash2 = Hash(password, RandomNumberGenerator.GetBytes(16), defaultParams);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Verify_WithCorrectPassword_Succeeds()
    {
        var password = Encoding.UTF8.GetBytes("TestPassword123!");
        var salt = RandomNumberGenerator.GetBytes(16);

        var expected = Hash(password, salt, defaultParams);
        var actual = Hash(password, salt, defaultParams);

        Assert.True(SecureMemoryOperations.ConstantTimeEquals(expected, actual));
    }

    [Fact]
    public void Verify_WithWrongPassword_Fails()
    {
        var password = Encoding.UTF8.GetBytes("TestPassword123!");
        var wrongPassword = Encoding.UTF8.GetBytes("WrongPassword!");
        var salt = RandomNumberGenerator.GetBytes(16);

        var expected = Hash(password, salt, defaultParams);
        var actual = Hash(wrongPassword, salt, defaultParams);

        Assert.False(SecureMemoryOperations.ConstantTimeEquals(expected, actual));
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d)]
    [InlineData(Argon2Type.Argon2i)]
    [InlineData(Argon2Type.Argon2id)]
    public void Hash_AllVariants_Work(Argon2Type type)
    {
        var parameters = defaultParams with { Type = type };
        var password = Encoding.UTF8.GetBytes("TestPassword");
        var salt = RandomNumberGenerator.GetBytes(16);

        var hash = Hash(password, salt, parameters);

        Assert.Equal(parameters.HashLength, hash.Length);
    }

    [Fact]
    public void Hash_WithInvalidParams_Throws()
    {
        var password = Encoding.UTF8.GetBytes("TestPassword");
        var salt = RandomNumberGenerator.GetBytes(16);

        Assert.Throws<ArgumentException>(() => Hash(password, salt, defaultParams with { Iterations = 0 }));
        Assert.Throws<ArgumentException>(() => Hash(password, salt, defaultParams with { MemorySizeKb = 0 }));
        Assert.Throws<ArgumentException>(() => Hash(password, salt, defaultParams with { Parallelism = 0 }));
        Assert.Throws<ArgumentException>(() => Hash(password, salt, defaultParams with { HashLength = 0 }));
    }

    private static byte[] Hash(byte[] password, byte[] salt, Argon2Parameters parameters) =>
        Argon2Core.Hash(
            password,
            salt,
            parameters.Iterations,
            parameters.MemorySizeKb,
            parameters.Parallelism,
            parameters.HashLength,
            parameters.Type);

    private readonly record struct Argon2Parameters(
        int Iterations,
        int MemorySizeKb,
        int Parallelism,
        int HashLength,
        Argon2Type Type);
}
