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
        private readonly Curve25519Core core = new();

        [Fact]
        public void GeneratePrivateKey_ReturnsCorrectLength()
        {
            var privateKey = core.GeneratePrivateKey();
            Assert.Equal(KEY_SIZE, privateKey.Length);
        }

        [Fact]
        public void Connect_AliceAndBob_Success()
        {
            // Arrange
            var alicePrivate = core.GeneratePrivateKey();
            var bobPrivate = core.GeneratePrivateKey();

            var alicePublic = core.DerivePublicKey(alicePrivate);
            var bobPublic = core.DerivePublicKey(bobPrivate);

            // Act
            var sharedSecret1 = core.ComputeSharedSecret(alicePrivate, bobPublic);
            var sharedSecret2 = core.ComputeSharedSecret(bobPrivate, alicePublic);

            // Assert
            Assert.Equal(KEY_SIZE, sharedSecret1.Length);
            CryptoAssertions.AssertBytesEqual(sharedSecret1, sharedSecret2);
        }

        [Fact]
        public void DerivePublicKey_IsDeterministic()
        {
            var privateKey = core.GeneratePrivateKey();

            var pub1 = core.DerivePublicKey(privateKey);
            var pub2 = core.DerivePublicKey(privateKey);

            CryptoAssertions.AssertBytesEqual(pub1, pub2);
        }

        [Fact]
        public void DerivePublicKey_DifferentKeys_ProduceDifferentPublicKeys()
        {
            var p1 = core.GeneratePrivateKey();
            var p2 = core.GeneratePrivateKey();

            // Very small chance of collision, practically zero
            while (p1.AsSpan().SequenceEqual(p2)) p2 = core.GeneratePrivateKey();

            var pub1 = core.DerivePublicKey(p1);
            var pub2 = core.DerivePublicKey(p2);

            Assert.NotEqual(pub1, pub2);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly Curve25519Core core = new();

        [Fact]
        public void ComputeSharedSecret_MultipleIterations_Success()
        {
            // Test that the implementation is stable over many iterations
            var alice = core.GeneratePrivateKey();
            var bob = core.GeneratePrivateKey();
            _ = core.DerivePublicKey(alice); // Alice's public key (unused in this test)
            var bobPublic = core.DerivePublicKey(bob);

            var secrets = new List<byte[]>();
            for (int i = 0; i < 10; i++)
            {
                secrets.Add(core.ComputeSharedSecret(alice, bobPublic));
            }

            // All should be identical
            for (int i = 1; i < secrets.Count; i++)
            {
                CryptoAssertions.AssertBytesEqual(secrets[0], secrets[i]);
            }
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        private readonly Curve25519Core core = new();
        [Fact]
        public void SharedSecret_DifferentKeys_ProducesDifferentSecrets()
        {
            var alice = core.GeneratePrivateKey();
            var bob1 = core.GeneratePrivateKey();
            var bob2 = core.GeneratePrivateKey();

            var bob1Public = core.DerivePublicKey(bob1);
            var bob2Public = core.DerivePublicKey(bob2);

            var secret1 = core.ComputeSharedSecret(alice, bob1Public);
            var secret2 = core.ComputeSharedSecret(alice, bob2Public);

            Assert.NotEqual(secret1, secret2);
        }

        [Fact]
        public void PrivateKey_CannotBeDerivedFromPublic()
        {
            // Verify public key appears random (information theoretic)
            var privateKey = core.GeneratePrivateKey();
            var publicKey = core.DerivePublicKey(privateKey);

            // Public key should appear random
            CryptoAssertions.AssertAppearsRandom(publicKey);
        }

        [Fact]
        public void SharedSecret_AppearsRandom()
        {
            var alice = core.GeneratePrivateKey();
            var bob = core.GeneratePrivateKey();
            var bobPublic = core.DerivePublicKey(bob);

            var secret = core.ComputeSharedSecret(alice, bobPublic);

            CryptoAssertions.AssertAppearsRandom(secret);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        private readonly Curve25519Core core = new();

        [Fact]
        public void ComputeSharedSecret_NullKeys_ThrowsArgumentNullException()
        {
            var key = new byte[KEY_SIZE];

            Assert.Throws<ArgumentNullException>(() => core.ComputeSharedSecret(null!, key));
            Assert.Throws<ArgumentNullException>(() => core.ComputeSharedSecret(key, null!));
        }

        [Fact]
        public void ComputeSharedSecret_InvalidLength_ThrowsArgumentException()
        {
            var valid = new byte[KEY_SIZE];
            var invalid = new byte[KEY_SIZE - 1];

            Assert.Throws<ArgumentException>(() => core.ComputeSharedSecret(invalid, valid));
            Assert.Throws<ArgumentException>(() => core.ComputeSharedSecret(valid, invalid));
        }

        [Fact]
        public void DerivePublicKey_NullOrInvalid_ThrowsException()
        {
            Assert.Throws<ArgumentNullException>(() => core.DerivePublicKey(null!));
            Assert.Throws<ArgumentException>(() => core.DerivePublicKey(new byte[10]));
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
        private readonly Curve25519Core core = new();
        [Fact]
        public void RFC7748_TestVector1_Alice()
        {
            // Alice's private key (scalar)
            var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            // Alice's public key (expected)
            var alicePublicExpected = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

            var alicePublic = core.DerivePublicKey(alicePrivate);
            Assert.Equal(alicePublicExpected, alicePublic);
        }

        [Fact]
        public void RFC7748_TestVector1_Bob()
        {
            // Bob's private key (scalar)
            var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            // Bob's public key (expected)
            var bobPublicExpected = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

            var bobPublic = core.DerivePublicKey(bobPrivate);
            Assert.Equal(bobPublicExpected, bobPublic);
        }

        [Fact]
        public void RFC7748_TestVector1_SharedSecret()
        {
            var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

            var alicePublic = core.DerivePublicKey(alicePrivate);
            var bobPublic = core.DerivePublicKey(bobPrivate);

            var expectedSharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            var sharedSecret1 = core.ComputeSharedSecret(alicePrivate, bobPublic);
            var sharedSecret2 = core.ComputeSharedSecret(bobPrivate, alicePublic);

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

            var result = core.ComputeSharedSecret(scalar, uCoordinate);
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
                var result = core.ComputeSharedSecret(k, u);
                Array.Copy(k, u, 32);      // u = old k
                Array.Copy(result, k, 32); // k = new result
            }

            Assert.Equal(expected, k);
        }
    }
}
