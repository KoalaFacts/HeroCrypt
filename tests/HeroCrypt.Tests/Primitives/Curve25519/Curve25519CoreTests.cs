using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Curve25519;

/// <summary>
/// Comprehensive tests for Curve25519 (X25519) implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Curve25519CoreTests
{
    private const int KEY_SIZE = 32;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void GeneratePrivateKey_ReturnsCorrectLength()
        {
            var privateKey = Curve25519Core.GeneratePrivateKey();
            Assert.Equal(KEY_SIZE, privateKey.Length);
        }

        [Fact]
        public void Connect_AliceAndBob_Success()
        {
            // Arrange
            var alicePrivate = Curve25519Core.GeneratePrivateKey();
            var bobPrivate = Curve25519Core.GeneratePrivateKey();

            var alicePublic = Curve25519Core.DerivePublicKey(alicePrivate);
            var bobPublic = Curve25519Core.DerivePublicKey(bobPrivate);

            // Act
            var sharedSecret1 = Curve25519Core.ComputeSharedSecret(alicePrivate, bobPublic);
            var sharedSecret2 = Curve25519Core.ComputeSharedSecret(bobPrivate, alicePublic);

            // Assert
            Assert.Equal(KEY_SIZE, sharedSecret1.Length);
            CryptoAssertions.AssertBytesEqual(sharedSecret1, sharedSecret2);
        }

        [Fact]
        public void DerivePublicKey_IsDeterministic()
        {
            var privateKey = Curve25519Core.GeneratePrivateKey();

            var pub1 = Curve25519Core.DerivePublicKey(privateKey);
            var pub2 = Curve25519Core.DerivePublicKey(privateKey);

            CryptoAssertions.AssertBytesEqual(pub1, pub2);
        }

        [Fact]
        public void DerivePublicKey_DifferentKeys_ProduceDifferentPublicKeys()
        {
            var p1 = Curve25519Core.GeneratePrivateKey();
            var p2 = Curve25519Core.GeneratePrivateKey();

            // Very small chance of collision, practically zero
            while (p1.AsSpan().SequenceEqual(p2)) p2 = Curve25519Core.GeneratePrivateKey();

            var pub1 = Curve25519Core.DerivePublicKey(p1);
            var pub2 = Curve25519Core.DerivePublicKey(p2);

            Assert.NotEqual(pub1, pub2);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        [Fact]
        public void ComputeSharedSecret_NullKeys_ThrowsArgumentNullException()
        {
            var key = new byte[KEY_SIZE];

            Assert.Throws<ArgumentNullException>(() => Curve25519Core.ComputeSharedSecret(null!, key));
            Assert.Throws<ArgumentNullException>(() => Curve25519Core.ComputeSharedSecret(key, null!));
        }

        [Fact]
        public void ComputeSharedSecret_InvalidLength_ThrowsArgumentException()
        {
            var valid = new byte[KEY_SIZE];
            var invalid = new byte[KEY_SIZE - 1];

            Assert.Throws<ArgumentException>(() => Curve25519Core.ComputeSharedSecret(invalid, valid));
            Assert.Throws<ArgumentException>(() => Curve25519Core.ComputeSharedSecret(valid, invalid));
        }

        [Fact]
        public void DerivePublicKey_NullOrInvalid_ThrowsException()
        {
            Assert.Throws<ArgumentNullException>(() => Curve25519Core.DerivePublicKey(null!));
            Assert.Throws<ArgumentException>(() => Curve25519Core.DerivePublicKey(new byte[10]));
        }
    }

    /// <summary>
    /// Known Answer Tests using official vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void RFC7748_TestVector1_Alice()
        {
            // Alice's private key (scalar)
            var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            // Alice's public key (expected)
            var alicePublicExpected = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

            var alicePublic = Curve25519Core.DerivePublicKey(alicePrivate);
            Assert.Equal(alicePublicExpected, alicePublic);
        }

        [Fact]
        public void RFC7748_TestVector1_Bob()
        {
            // Bob's private key (scalar)
            var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            // Bob's public key (expected)
            var bobPublicExpected = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

            var bobPublic = Curve25519Core.DerivePublicKey(bobPrivate);
            Assert.Equal(bobPublicExpected, bobPublic);
        }

        [Fact]
        public void RFC7748_TestVector1_SharedSecret()
        {
            var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

            var alicePublic = Curve25519Core.DerivePublicKey(alicePrivate);
            var bobPublic = Curve25519Core.DerivePublicKey(bobPrivate);

            var expectedSharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            var sharedSecret1 = Curve25519Core.ComputeSharedSecret(alicePrivate, bobPublic);
            var sharedSecret2 = Curve25519Core.ComputeSharedSecret(bobPrivate, alicePublic);

            Assert.Equal(expectedSharedSecret, sharedSecret1);
            Assert.Equal(sharedSecret1, sharedSecret2);
        }

        [Fact]
        public void RFC7748_Section6_1_DiffieHellman()
        {
            var scalar = new byte[32];
            scalar[0] = 9;
            var uCoordinate = new byte[32];
            uCoordinate[0] = 9;

            var expected = Convert.FromHexString("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

            var result = Curve25519Core.ComputeSharedSecret(scalar, uCoordinate);
            Assert.Equal(expected, result);
        }

        [Fact]
        public void RFC7748_Iterated_1000()
        {
            var k = new byte[32];
            k[0] = 9;
            var u = new byte[32];
            u[0] = 9;

            var expected = Convert.FromHexString("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

            for (var i = 0; i < 1000; i++)
            {
                var result = Curve25519Core.ComputeSharedSecret(k, u);
                Array.Copy(k, u, 32);      // u = old k
                Array.Copy(result, k, 32); // k = new result
            }

            Assert.Equal(expected, k);
        }
    }
}
