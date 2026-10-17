using System.Security.Cryptography;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Security;
using Org.BouncyCastle.Crypto.Generators;
using BcArgon2Parameters = Org.BouncyCastle.Crypto.Parameters.Argon2Parameters;

namespace HeroCrypt.Tests.Primitives.S2K;

public class Argon2S2KSecurityTests
{
    private static readonly byte[] Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    [Theory]
    [InlineData(35)]
    [InlineData(67)]
    [InlineData(99)]
    public void Parse_RejectsShiftAliases(byte exponent)
    {
        Assert.ThrowsAny<ArgumentException>(() => S2KParameters.Parse(Encoded(exponent)));
    }

    [Theory]
    [InlineData(35)]
    [InlineData(67)]
    [InlineData(99)]
    public void Factory_RejectsShiftAliases(byte exponent)
    {
        Assert.ThrowsAny<ArgumentException>(() => S2KParameters.CreateArgon2(1, 1, exponent));
    }

    [Theory]
    [InlineData(35)]
    [InlineData(67)]
    [InlineData(99)]
    public void Derive_RejectsManuallyConstructedShiftAliases(byte exponent)
    {
        // Before the fix all three aliases allocate only 8 KiB and produce the m=3 key.
        var parameters = Parameters(exponent);
        Assert.ThrowsAny<ArgumentException>(() => parameters.DeriveKey("public fixture"u8, 16));
    }

    [Fact]
    public void Derive_ValidMinimum_PreservesKnownKey()
    {
        Assert.Equal("066E0A199E3EC18B11204A3ABFD42523",
            Convert.ToHexString(S2KParameters.Parse(Encoded(3)).DeriveKey("public fixture"u8, 16)));
    }

    [Fact]
    public void SecretKeySpecifier_RejectsMemoryBelowEightBlocksPerLane()
    {
        Assert.ThrowsAny<ArgumentException>(() => PgpS2KSpecifier.CreateArgon2(8, Salt, 1, 3, 4));
    }

    [Theory]
    [InlineData(7, 16)]
    [InlineData(8, 15)]
    public void Derive_RejectsCustomBudgetBeforeComputing(long memory, long work)
    {
        // Even without enforcement this fixture uses only 8 KiB and two passes.
        var policy = SecurityPolicyOptions.Testing with
        {
            S2KLimits = new S2KResourceLimits { MaxArgon2MemoryKiB = memory, MaxArgon2WorkKiB = work }
        };
        var exception = Assert.Throws<CryptographicException>(() => Parameters(3, 2).DeriveKey("public fixture"u8, 16, policy));
        Assert.Contains("limit", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    [InlineData(255)]
    public void ParsersAndFactories_ValidateEveryExponentWithoutDeriving(byte lanes)
    {
        for (int exponent = 0; exponent <= byte.MaxValue; exponent++)
        {
            bool valid = exponent >= 3 && exponent <= 31 && (1L << exponent) >= 8L * lanes;
            byte[] secretSpecifier = [4, 8, .. Salt, (byte)exponent, 1, lanes];
            Assert.Equal(valid, PgpS2KSpecifier.TryRead(secretSpecifier, out _, out _, out _));
            if (valid)
            {
                var parsed = S2KParameters.Parse(Encoded((byte)exponent, lanes: lanes), out int consumed);
                Assert.Equal(20, consumed);
                Assert.Equal((byte)exponent, parsed.Argon2MemoryExponent);
                Assert.Equal((byte)exponent, S2KParameters.CreateArgon2(1, lanes, (byte)exponent).Argon2MemoryExponent);
                PgpS2KSpecifier.ValidateArgon2Parameters(1, lanes, (byte)exponent);
            }
            else
            {
                Assert.ThrowsAny<ArgumentException>(() => S2KParameters.Parse(Encoded((byte)exponent, lanes: lanes)));
                Assert.ThrowsAny<ArgumentException>(() => S2KParameters.CreateArgon2(1, lanes, (byte)exponent));
                Assert.ThrowsAny<ArgumentException>(() => PgpS2KSpecifier.CreateArgon2(8, Salt, 1, lanes, (byte)exponent));
            }
        }
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    public void ZeroPassesOrLanes_RejectAcrossEntrypoints(byte passes, byte lanes)
    {
        Assert.ThrowsAny<ArgumentException>(() => S2KParameters.Parse(Encoded(3, passes, lanes)));
        Assert.ThrowsAny<ArgumentException>(() => S2KParameters.CreateArgon2(passes, lanes, 3));
        Assert.ThrowsAny<ArgumentException>(() => Parameters(3, passes, lanes).DeriveKey("public fixture"u8, 16));
        Assert.ThrowsAny<ArgumentException>(() => PgpS2KSpecifier.CreateArgon2(8, Salt, passes, lanes, 3));
    }

    [Theory]
    [InlineData(1, 1, 3)]
    [InlineData(2, 1, 3)]
    [InlineData(3, 2, 4)]
    [InlineData(1, 4, 5)]
    public void Derive_AtExactBudget_MatchesIndependentArgon2(byte passes, byte lanes, byte exponent)
    {
        var expected = new byte[16];
        var reference = new Argon2BytesGenerator();
        reference.Init(new BcArgon2Parameters.Builder(BcArgon2Parameters.Argon2id)
            .WithVersion(BcArgon2Parameters.Version13).WithSalt(Salt)
            .WithIterations(passes).WithParallelism(lanes).WithMemoryAsKB(1 << exponent).Build());
        reference.GenerateBytes("public fixture"u8.ToArray(), expected);
        var policy = SecurityPolicyOptions.Default with
        {
            S2KLimits = new S2KResourceLimits
            {
                MaxArgon2MemoryKiB = 1L << exponent,
                MaxArgon2WorkKiB = (1L << exponent) * passes
            }
        };
        Assert.Equal(expected, Parameters(exponent, passes, lanes).DeriveKey("public fixture"u8, 16, policy));
        using var builder = S2KBuilder.Create(policy).WithArgon2Parameters(passes, lanes, exponent).WithSalt(Salt);
        Assert.Equal(expected, builder.DeriveKey("public fixture", 16));
    }

    [Fact]
    public void Derive_Exponent31_IsValidEncodingButExplicitlyUnsupported()
    {
        var parsed = S2KParameters.Parse(Encoded(31));
        var policy = SecurityPolicyOptions.Testing with
        {
            S2KLimits = new S2KResourceLimits { MaxArgon2MemoryKiB = long.MaxValue, MaxArgon2WorkKiB = long.MaxValue }
        };
        Assert.Throws<NotSupportedException>(() => parsed.DeriveKey("public fixture"u8, 16, policy));
    }

    [Fact]
    public void DefaultLimits_CoverExistingGenerationDefaultsAndRejectHigherCostsWithoutDeriving()
    {
        S2KResourceLimits.Default.ValidateArgon2(1L << 19, 3);
        Assert.Throws<CryptographicException>(() => S2KResourceLimits.Default.ValidateArgon2(1L << 20, 1));
        Assert.Throws<CryptographicException>(() => S2KResourceLimits.Default.ValidateArgon2(1L << 19, 4));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Limits_RejectNonpositiveConfiguration(long value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new S2KResourceLimits { MaxArgon2MemoryKiB = value });
        Assert.Throws<ArgumentOutOfRangeException>(() => new S2KResourceLimits { MaxArgon2WorkKiB = value });
    }

    [Fact]
    public void Policy_RejectsNullLimits()
    {
        Assert.Throws<ArgumentNullException>(() => SecurityPolicyOptions.Testing with { S2KLimits = null! });
    }

    private static byte[] Encoded(byte exponent, byte passes = 1, byte lanes = 1)
        => [4, .. Salt, passes, lanes, exponent];

    private static S2KParameters Parameters(byte exponent, byte passes = 1, byte lanes = 1)
        => new()
        {
            Type = S2KType.Argon2,
            Salt = Salt,
            Argon2TimePasses = passes,
            Argon2Parallelism = lanes,
            Argon2MemoryExponent = exponent
        };
}
