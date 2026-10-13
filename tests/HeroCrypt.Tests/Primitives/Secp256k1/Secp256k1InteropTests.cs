using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Secp256k1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace HeroCrypt.Tests.Primitives.Secp256k1;

[Trait("Category", TestCategories.COMPLIANCE)]
public class Secp256k1InteropTests
{
    private static readonly ECDomainParameters Domain = CreateDomain();
    private readonly Secp256k1Core core = new();

    [Fact]
    [RequiresUnreferencedCode("This test inspects references of the untrimmed production assembly.")]
    public void ProductionAssembly_DoesNotReferenceBouncyCastle()
    {
        Assert.DoesNotContain(typeof(Secp256k1Builder).Assembly.GetReferencedAssemblies(),
            reference => reference.Name!.Contains("BouncyCastle", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(16)]
    public void PublicKeysAndDeterministicSignatures_MatchIndependentImplementation(int keyValue)
    {
        var key = new byte[32];
        key[31] = (byte)keyValue;
        AssertMatchesReference(key, SHA256.HashData(Encoding.UTF8.GetBytes("secp256k1 independent comparison")));
    }

    [Fact]
    public void BoundaryScalarsAndHashes_MatchIndependentImplementation()
    {
        var keys = new[] { Scalar(BigInteger.One), Scalar(Domain.N.Subtract(BigInteger.One)) };
        var hashes = new[] { new byte[32], Scalar(Domain.N), Enumerable.Repeat((byte)255, 32).ToArray() };
        foreach (var key in keys)
        {
            foreach (var hash in hashes)
                AssertMatchesReference(key, hash);
        }
    }

    [Fact]
    public void RandomKeysAndHashes_MatchIndependentImplementation()
    {
        for (var i = 0; i < 12; i++)
        {
            var key = SHA256.HashData(Encoding.UTF8.GetBytes($"key comparison {i}"));
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"hash comparison {i}"));
            AssertMatchesReference(key, hash);
        }
    }

    [Fact]
    public void Verify_AcceptsBothStandardSRepresentations()
    {
        var key = Scalar(BigInteger.One);
        var hash = SHA256.HashData("high-S interoperability"u8);
        var signature = core.Sign(hash, key);
        var highS = Domain.N.Subtract(new BigInteger(1, signature.AsSpan(32).ToArray()));
        Scalar(highS).CopyTo(signature, 32);
        Assert.True(core.Verify(hash, signature, core.DerivePublicKey(key)));
    }

    [Fact]
    public void Verify_RejectsVerificationPointAtInfinity()
    {
        var one = Scalar(BigInteger.One);
        var signature = new byte[64];
        one.CopyTo(signature, 0);
        one.CopyTo(signature, 32);
        Assert.False(core.Verify(Scalar(Domain.N.Subtract(BigInteger.One)), signature, core.DerivePublicKey(one)));
    }

    [Fact]
    public void Verify_AcceptsRareVerificationPointWithXAboveOrder()
    {
        // Construct R.x = n + r, s = 1, e = 0 and Q = r^-1 R. Then the
        // verification point is R and its x coordinate MUST be reduced mod n.
        // Random signatures hit this branch with negligible probability.
        var r = BigInteger.Two;
        var point = Domain.Curve.DecodePoint(Convert.FromHexString(
            "03fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143"));
        Assert.Equal(Domain.N.Add(r), point.Normalize().AffineXCoord.ToBigInteger());
        var publicPoint = point.Multiply(r.ModInverse(Domain.N)).Normalize();
        var signature = new byte[64];
        Scalar(r).CopyTo(signature, 0);
        Scalar(BigInteger.One).CopyTo(signature, 32);
        var verifier = new ECDsaSigner();
        verifier.Init(false, new ECPublicKeyParameters(publicPoint, Domain));
        Assert.True(verifier.VerifySignature(new byte[32], r, BigInteger.One));
        Assert.True(core.Verify(new byte[32], signature, publicPoint.GetEncoded(true)));
        Assert.True(core.Verify(new byte[32], signature, publicPoint.GetEncoded(false)));
    }

    [Fact]
    public void NonceRetry_FollowsRfc6979RejectionUpdate()
    {
        var key = Scalar(BigInteger.One);
        var hash = SHA256.HashData("nonce retry"u8);
        using var nonces = new Secp256k1NonceGenerator(key, hash);
        // Independently calculated with Python hmac/hashlib using RFC 6979 section 3.2.
        Assert.Equal(Convert.FromHexString("43a4179ed08c153e1def84b19afa69630acd50524a397c843a050de59662b9c2"),
            Secp256k1Math.EncodeScalar(nonces.Next()));
        nonces.Reject();
        Assert.Equal(Convert.FromHexString("08cbf5c63ce3db37b670579e41694e13ae5cc83cfc123ee71cd2ceb0e51f04dc"),
            Secp256k1Math.EncodeScalar(nonces.Next()));
    }

    [Fact]
    public void PrivateScalarBoundaries_AreRejected()
    {
        foreach (var key in new[] { new byte[32], Scalar(Domain.N), Enumerable.Repeat((byte)255, 32).ToArray() })
        {
            Assert.Throws<ArgumentException>(() => core.DerivePublicKey(key));
            Assert.Throws<ArgumentException>(() => core.Sign(new byte[32], key));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void Verify_RejectsNoncanonicalPublicKeyPrefixes(byte prefix)
    {
        var key = Scalar(BigInteger.One);
        var hash = new byte[32];
        var signature = core.Sign(hash, key);
        var publicKey = core.DerivePublicKey(key);
        publicKey[0] = prefix;
        Assert.Throws<ArgumentException>(() => core.Verify(hash, signature, publicKey));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Verify_RejectsZeroOrOutOfRangeScalars(int component)
    {
        var key = Scalar(BigInteger.One);
        var hash = SHA256.HashData("invalid scalars"u8);
        foreach (var invalid in new[] { new byte[32], Scalar(Domain.N) })
        {
            var signature = core.Sign(hash, key);
            invalid.CopyTo(signature, component * 32);
            Assert.False(core.Verify(hash, signature, core.DerivePublicKey(key)));
        }
    }

    [Fact]
    public void Decompress_RejectsCoordinatesOutsideFieldAndNonCurvePoints()
    {
        var fieldPrime = Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        Assert.Throws<ArgumentException>(() => core.DecompressPublicKey([2, .. fieldPrime]));
        Assert.Throws<ArgumentException>(() => core.DecompressPublicKey([2, .. new byte[32]]));
        Assert.Throws<ArgumentException>(() => core.CompressPublicKey([4, .. new byte[64]]));
        var generator = core.DerivePublicKey(Scalar(BigInteger.One));
        fieldPrime.CopyTo(generator, 1);
        Assert.Throws<ArgumentException>(() => core.CompressPublicKey(generator));
        generator = core.DerivePublicKey(Scalar(BigInteger.One));
        fieldPrime.CopyTo(generator, 33);
        Assert.Throws<ArgumentException>(() => core.CompressPublicKey(generator));
    }

    private void AssertMatchesReference(byte[] key, byte[] hash)
    {
        var scalar = new BigInteger(1, key);
        var publicPoint = Domain.G.Multiply(scalar).Normalize();
        Assert.Equal(publicPoint.GetEncoded(false), core.DerivePublicKey(key));
        Assert.Equal(publicPoint.GetEncoded(true), core.DerivePublicKey(key, compressed: true));
        Assert.Equal(publicPoint.GetEncoded(false), core.DecompressPublicKey(publicPoint.GetEncoded(true)));

        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, new ECPrivateKeyParameters(scalar, Domain));
        var components = signer.GenerateSignature(hash);
        var s = components[1];
        if (s.CompareTo(Domain.N.ShiftRight(1)) > 0) s = Domain.N.Subtract(s);
        var expected = new byte[64];
        Scalar(components[0]).CopyTo(expected, 0);
        Scalar(s).CopyTo(expected, 32);
        var actual = core.Sign(hash, key);
        Assert.Equal(expected, actual);
        Assert.True(core.Verify(hash, actual, publicPoint.GetEncoded(true)));
        var verifier = new ECDsaSigner();
        verifier.Init(false, new ECPublicKeyParameters(publicPoint, Domain));
        Assert.True(verifier.VerifySignature(hash, new BigInteger(1, actual.AsSpan(0, 32).ToArray()),
            new BigInteger(1, actual.AsSpan(32).ToArray())));
    }

    private static byte[] Scalar(BigInteger value)
    {
        var result = new byte[32];
        var encoded = value.ToByteArrayUnsigned();
        encoded.CopyTo(result, 32 - encoded.Length);
        return result;
    }

    private static ECDomainParameters CreateDomain()
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        return new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
    }
}
