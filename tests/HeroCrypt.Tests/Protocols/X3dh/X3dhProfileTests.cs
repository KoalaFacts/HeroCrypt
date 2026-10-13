using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Protocols.X3dh;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Protocols.X3dh;

public class X3dhProfileTests
{
    [Theory]
    [InlineData(false, "128262ae19685198a46556b9882e0586b6aac0967cfc5db54d3a63fe9a217b5e")]
    [InlineData(true, "7c9f19834f2972a847b334fff823a56d6ce4b77921234018749f6ab910e2170d")]
    public void ThreeAndFourDh_MatchPinnedPythonAndIndependentBcReference(bool opk, string expected)
    {
        // Pinned using independent Python RFC 7748 ladder + hashlib/hmac HKDF.
        var a = X3dhReference.Key("Alice identity"); var b = X3dhReference.Key("Bob identity");
        var e = X3dhReference.Key("Alice ephemeral"); var s = X3dhReference.Key("signed prekey");
        var o = X3dhReference.Key("one time");
        var bundle = X3dhPreKeyBundle.Create(X3dhReference.Public(b), 1, X3dhReference.Public(s), new byte[64],
            opk ? 1u : null, opk ? X3dhReference.Public(o) : null);
        var initial = X3dhInitialMessage.Create(X3dhReference.Public(a), X3dhReference.Public(e), 1, opk ? 1u : null, X3dhEncodingTests.Ratchet());
        var sk = X3dhKdf.DeriveInitiator(a, e, bundle, SecurityPolicyOptions.Default);
        Assert.Equal(Convert.FromHexString(expected), sk); Assert.Equal(X3dhReference.Secret(opk), sk);
        Assert.Equal(sk, X3dhKdf.DeriveResponder(b, s, opk ? o : null, initial, SecurityPolicyOptions.Default));
        if (opk) Assert.Throws<CryptographicException>(() => X3dhKdf.DeriveResponder(b, s, null, initial, SecurityPolicyOptions.Default));
    }

    [Fact]
    public void Transcript_AndAssociatedDataMatchIndependentFraming()
    {
        var a = X3dhReference.Public(X3dhReference.Key("Alice identity"));
        var b = X3dhReference.Public(X3dhReference.Key("Bob identity"));
        var e = X3dhReference.Public(X3dhReference.Key("Alice ephemeral"));
        var s = X3dhReference.Public(X3dhReference.Key("signed prekey"));
        var o = X3dhReference.Public(X3dhReference.Key("one time"));
        var bundle = X3dhPreKeyBundle.Create(b, 1, s, new byte[64], 2, o);
        using var stream = new MemoryStream(); stream.Write("HeroCrypt.X3DH.DoubleRatchet.v1"u8);
        var length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, 3); stream.Write(length); stream.Write("ctx"u8);
        foreach (var key in new[] { a, b, e, s }) { stream.WriteByte(5); stream.Write(key); }
        BinaryPrimitives.WriteUInt32BigEndian(length, 1); stream.Write(length); stream.WriteByte(1);
        BinaryPrimitives.WriteUInt32BigEndian(length, 2); stream.Write(length); stream.WriteByte(5); stream.Write(o);
        var context = X3dhKdf.SessionContext(a, b, e, bundle, "ctx"u8.ToArray());
        Assert.Equal(SHA256.HashData(stream.ToArray()), context);
        Assert.NotEqual(context, X3dhKdf.SessionContext(a, b, e, bundle, "other"u8.ToArray()));
        byte[] expectedAd = [5, .. a, 5, .. b, 0, 0, 0, 1, 9];
        Assert.Equal(expectedAd, X3dhKdf.FirstAssociatedData(a, b, [9]));
        var changed = X3dhPreKeyBundle.Create(b, 2, s, new byte[64], 2, o);
        Assert.NotEqual(context, X3dhKdf.SessionContext(a, b, e, changed, "ctx"u8.ToArray()));
    }

    [Fact]
    public void InputAndTrustBounds_RejectWithoutCryptoMutation()
    {
        var valid = X3dhEncodingTests.Key();
        Assert.Throws<CryptographicException>(() => X3dhValidation.RequireIdentity(valid, X3dhEncodingTests.Key(10)));
        Assert.Throws<ArgumentException>(() => X3dhValidation.RequireIdentity(new byte[31], valid));
        Assert.Throws<ArgumentException>(() => X3dhValidation.ValidateContext([]));
        X3dhValidation.ValidateContext(new byte[4096]);
        Assert.Throws<ArgumentException>(() => X3dhValidation.ValidateContext(new byte[4097]));
        X3dhValidation.ValidatePayloadAndMetadata([], new byte[16 * 1024 * 1024 - 70]);
        Assert.Throws<ArgumentException>(() => X3dhValidation.ValidatePayloadAndMetadata([], new byte[16 * 1024 * 1024 - 69]));
        Assert.Throws<ArgumentException>(() => X3dhValidation.ValidatePayloadAndMetadata(new byte[16 * 1024 * 1024 + 1], []));
        Assert.Throws<SecurityPolicyException>(() => X3dhValidation.ValidatePolicy(SecurityPolicyOptions.Compliance));
    }
}
