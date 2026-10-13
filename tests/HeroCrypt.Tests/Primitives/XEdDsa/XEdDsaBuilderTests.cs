using HeroCrypt.Primitives.XEdDsa;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Primitives.XEdDsa;

public class XEdDsaBuilderTests
{
    [Fact]
    public void Builder_OwnsKeysAndSignsEmptyMessage()
    {
        using var generator = XEdDsaBuilder.Create();
        var (key, publicKey) = generator.GenerateKeyPair();
        var original = key.ToArray();
        using var signer = XEdDsaBuilder.Create().WithPrivateKey(key).WithMessage([]);
        Array.Clear(key);
        var signature = signer.Sign();
        Assert.Equal(publicKey, signer.DerivePublicKey());
        using var verifier = XEdDsaBuilder.Create().WithPublicKey(publicKey).WithMessage([]).WithSignature(signature);
        Array.Clear(publicKey); Array.Clear(signature);
        Assert.True(verifier.Verify());
        using var clamped = XEdDsaBuilder.Create().WithPrivateKey(original.AsSpan()).WithMessage(original.AsSpan(0, 0));
        Assert.Equal(signer.DerivePublicKey(), clamped.DerivePublicKey());
    }

    [Fact]
    public void Builder_RejectsIncompleteDisposedAndInvalidInput()
    {
        var builder = XEdDsaBuilder.Create();
        Assert.Throws<InvalidOperationException>(builder.Sign);
        Assert.Throws<ArgumentException>(() => builder.WithPrivateKey(new byte[31]));
        Assert.Throws<ArgumentException>(() => builder.WithSignature(new byte[63]));
        builder.Dispose(); builder.Dispose();
        Assert.Throws<ObjectDisposedException>(() => builder.GenerateKeyPair());
        Assert.Throws<ObjectDisposedException>(() => builder.WithMessage("late"u8));
        Assert.Throws<SecurityPolicyException>(() => XEdDsaBuilder.Create(SecurityPolicyOptions.Compliance).GenerateKeyPair());
        Assert.Throws<SecurityPolicyException>(() => SecurityPolicyOptions.Compliance.ValidateSignature("XEDDSA"));
    }
}
