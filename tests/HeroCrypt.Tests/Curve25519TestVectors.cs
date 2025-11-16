using HeroCrypt.Cryptography.Primitives.Signature.Ecc;

namespace HeroCrypt.Tests;

/// <summary>
/// RFC 7748 test vectors for Curve25519 (X25519)
/// </summary>
public class Curve25519TestVectors
{
    /// <summary>
    /// RFC 7748 Section 5.2 - Test Vector 1
    /// </summary>
    [Fact]
    public void X25519_RFC7748_TestVector1()
    {
        // Arrange - Alice's private key (scalar)
        var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

        // Alice's public key (expected)
        var alicePublicExpected = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        // Act
        var alicePublic = Curve25519Core.DerivePublicKey(alicePrivate);

        // Assert
        Assert.Equal(alicePublicExpected, alicePublic);
    }

    /// <summary>
    /// RFC 7748 Section 5.2 - Test Vector 1 (Bob's keys)
    /// </summary>
    [Fact]
    public void X25519_RFC7748_TestVector1_Bob()
    {
        // Arrange - Bob's private key (scalar)
        var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        // Bob's public key (expected)
        var bobPublicExpected = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        // Act
        var bobPublic = Curve25519Core.DerivePublicKey(bobPrivate);

        // Assert
        Assert.Equal(bobPublicExpected, bobPublic);
    }

    /// <summary>
    /// RFC 7748 Section 5.2 - Test Vector 1 (Shared Secret)
    /// Alice and Bob should compute the same shared secret
    /// </summary>
    [Fact]
    public void X25519_RFC7748_TestVector1_SharedSecret()
    {
        // Arrange
        var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        var alicePublic = Curve25519Core.DerivePublicKey(alicePrivate);
        var bobPublic = Curve25519Core.DerivePublicKey(bobPrivate);

        // Expected shared secret from RFC 7748
        var expectedSharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        // Act
        var sharedSecret1 = Curve25519Core.ComputeSharedSecret(alicePrivate, bobPublic);
        var sharedSecret2 = Curve25519Core.ComputeSharedSecret(bobPrivate, alicePublic);

        // Assert
        Assert.Equal(expectedSharedSecret, sharedSecret1);
        Assert.Equal(expectedSharedSecret, sharedSecret2);
        Assert.Equal(sharedSecret1, sharedSecret2);
    }

    /// <summary>
    /// RFC 7748 Section 6.1 - Diffie-Hellman Test Vector
    /// </summary>
    [Fact]
    public void X25519_RFC7748_Section6_1()
    {
        // Arrange
        var scalar = new byte[32];
        scalar[0] = 9; // Input scalar = 9

        var uCoordinate = new byte[32];
        uCoordinate[0] = 9; // Input u-coordinate = 9

        // Expected output
        var expected = Convert.FromHexString("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

        // Act
        var result = Curve25519Core.ComputeSharedSecret(scalar, uCoordinate);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// RFC 7748 Section 6.1 - Iterated Diffie-Hellman (1 iteration)
    /// </summary>
    [Fact]
    public void X25519_RFC7748_Iterated_1()
    {
        // Arrange
        var k = new byte[32];
        k[0] = 9;

        var u = new byte[32];
        u[0] = 9;

        // Expected after 1 iteration
        var expected = Convert.FromHexString("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

        // Act
        var result = Curve25519Core.ComputeSharedSecret(k, u);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// RFC 7748 Section 6.1 - Iterated Diffie-Hellman (1000 iterations)
    /// Note: This test may be slow
    /// </summary>
    [Fact]
    public void X25519_RFC7748_Iterated_1000()
    {
        // Arrange
        var k = new byte[32];
        k[0] = 9;

        var u = new byte[32];
        u[0] = 9;

        // Expected after 1000 iterations
        var expected = Convert.FromHexString("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

        // Act - Perform 1000 iterations
        // RFC 7748: For each iteration, set k to be the result of calling the function
        // and u to be the old value of k.
        for (var i = 0; i < 1000; i++)
        {
            var result = Curve25519Core.ComputeSharedSecret(k, u);
            Array.Copy(k, u, 32);      // u = old k
            Array.Copy(result, k, 32); // k = new result
        }

        // Assert
        Assert.Equal(expected, k);
    }

    /// <summary>
    /// Test that public key derivation is deterministic
    /// </summary>
    [Fact]
    public void DerivePublicKey_SamePrivateKey_ProducesSamePublicKey()
    {
        // Arrange
        var privateKey = new byte[32];
        new Random(42).NextBytes(privateKey);

        // Act
        var publicKey1 = Curve25519Core.DerivePublicKey(privateKey);
        var publicKey2 = Curve25519Core.DerivePublicKey(privateKey);

        // Assert
        Assert.Equal(publicKey1, publicKey2);
    }

    /// <summary>
    /// Test that different private keys produce different public keys
    /// </summary>
    [Fact]
    public void DerivePublicKey_DifferentPrivateKeys_ProduceDifferentPublicKeys()
    {
        // Arrange
        var privateKey1 = new byte[32];
        var privateKey2 = new byte[32];
        new Random(42).NextBytes(privateKey1);
        new Random(43).NextBytes(privateKey2);

        // Act
        var publicKey1 = Curve25519Core.DerivePublicKey(privateKey1);
        var publicKey2 = Curve25519Core.DerivePublicKey(privateKey2);

        // Assert
        Assert.NotEqual(publicKey1, publicKey2);
    }

    /// <summary>
    /// Test shared secret symmetry
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_AliceAndBob_ProduceSameSecret()
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
        Assert.Equal(sharedSecret1, sharedSecret2);
    }

    /// <summary>
    /// Test that shared secrets are 32 bytes
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_ReturnsCorrectLength()
    {
        // Arrange
        var privateKey1 = Curve25519Core.GeneratePrivateKey();
        var privateKey2 = Curve25519Core.GeneratePrivateKey();
        var publicKey2 = Curve25519Core.DerivePublicKey(privateKey2);

        // Act
        var sharedSecret = Curve25519Core.ComputeSharedSecret(privateKey1, publicKey2);

        // Assert
        Assert.Equal(32, sharedSecret.Length);
    }

    /// <summary>
    /// Test with null private key
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_NullPrivateKey_ThrowsArgumentNullException()
    {
        // Arrange
        var publicKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Curve25519Core.ComputeSharedSecret(null!, publicKey));
    }

    /// <summary>
    /// Test with null public key
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_NullPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var privateKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Curve25519Core.ComputeSharedSecret(privateKey, null!));
    }

    /// <summary>
    /// Test with invalid private key length
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_InvalidPrivateKeyLength_ThrowsArgumentException()
    {
        // Arrange
        var privateKey = new byte[31]; // Wrong length
        var publicKey = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Curve25519Core.ComputeSharedSecret(privateKey, publicKey));
    }

    /// <summary>
    /// Test with invalid public key length
    /// </summary>
    [Fact]
    public void ComputeSharedSecret_InvalidPublicKeyLength_ThrowsArgumentException()
    {
        // Arrange
        var privateKey = new byte[32];
        var publicKey = new byte[31]; // Wrong length

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Curve25519Core.ComputeSharedSecret(privateKey, publicKey));
    }
}
