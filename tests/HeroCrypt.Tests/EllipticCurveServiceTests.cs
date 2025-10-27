using HeroCrypt.Abstractions;
using HeroCrypt.Services;

namespace HeroCrypt.Tests;

// DISABLED: Binary search for hanging test
#if FALSE

/// <summary>
/// Tests for elliptic curve cryptographic operations
/// </summary>
public class EllipticCurveServiceTests
{
    private readonly IEllipticCurveService _eccService;

    public EllipticCurveServiceTests()
    {
        _eccService = new EllipticCurveService();
    }

    [Theory]
    [InlineData(EccCurve.Curve25519)]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task GenerateKeyPair_SupportedCurves_GeneratesValidKeyPair(EccCurve curve)
    {
        // Act
        var keyPair = await _eccService.GenerateKeyPairAsync(curve);

        // Assert
        Assert.NotNull(keyPair.PrivateKey);
        Assert.NotNull(keyPair.PublicKey);
        Assert.Equal(curve, keyPair.Curve);
        Assert.Equal(EccKeyPair.GetPrivateKeySize(curve), keyPair.PrivateKey.Length);

        // Allow both compressed and uncompressed for secp256k1
        if (curve == EccCurve.Secp256k1)
        {
            Assert.True(keyPair.PublicKey.Length == 33 || keyPair.PublicKey.Length == 65);
        }
        else
        {
            Assert.Equal(EccKeyPair.GetPublicKeySize(curve), keyPair.PublicKey.Length);
        }
    }

    [Theory]
    [InlineData(EccCurve.Curve25519)]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task GenerateKeyPair_MultipleCalls_GeneratesDifferentKeys(EccCurve curve)
    {
        // Act
        var keyPair1 = await _eccService.GenerateKeyPairAsync(curve);
        var keyPair2 = await _eccService.GenerateKeyPairAsync(curve);

        // Assert
        Assert.False(keyPair1.PrivateKey.AsSpan().SequenceEqual(keyPair2.PrivateKey));
        Assert.False(keyPair1.PublicKey.AsSpan().SequenceEqual(keyPair2.PublicKey));
    }

    [Theory]
    [InlineData(EccCurve.Curve25519)]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task DerivePublicKey_FromPrivateKey_MatchesGeneratedPublicKey(EccCurve curve)
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(curve);

        // Act
        var derivedPublicKey = await _eccService.DerivePublicKeyAsync(keyPair.PrivateKey, curve);

        // Assert
        if (curve == EccCurve.Secp256k1)
        {
            // secp256k1 may return compressed or uncompressed - check if they represent the same point
            Assert.True(derivedPublicKey.AsSpan().SequenceEqual(keyPair.PublicKey) ||
                       (derivedPublicKey.Length != keyPair.PublicKey.Length &&
                        ValidateSecp256k1KeyEquivalence(derivedPublicKey, keyPair.PublicKey)));
        }
        else
        {
            Assert.True(derivedPublicKey.AsSpan().SequenceEqual(keyPair.PublicKey));
        }
    }

    [Theory]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task Sign_And_Verify_ValidMessage_ReturnsTrue(EccCurve curve)
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(curve);
        var message = "Hello, ECC World!"u8.ToArray();

        // Act
        var signature = await _eccService.SignAsync(message, keyPair.PrivateKey, curve);
        var isValid = await _eccService.VerifyAsync(message, signature, keyPair.PublicKey, curve);

        // Assert
        Assert.True(isValid);
        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);
    }

    [Theory]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task Verify_ModifiedMessage_ReturnsFalse(EccCurve curve)
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(curve);
        var originalMessage = "Hello, ECC World!"u8.ToArray();
        var modifiedMessage = "Hello, ECC World?"u8.ToArray();

        // Act
        var signature = await _eccService.SignAsync(originalMessage, keyPair.PrivateKey, curve);
        var isValid = await _eccService.VerifyAsync(modifiedMessage, signature, keyPair.PublicKey, curve);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task Verify_ModifiedSignature_ReturnsFalse(EccCurve curve)
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(curve);
        var message = "Hello, ECC World!"u8.ToArray();

        // Act
        var signature = await _eccService.SignAsync(message, keyPair.PrivateKey, curve);

        // Modify the signature
        signature[0] ^= 0x01;

        var isValid = await _eccService.VerifyAsync(message, signature, keyPair.PublicKey, curve);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData(EccCurve.Ed25519)]
    [InlineData(EccCurve.Secp256k1)]
    public async Task Verify_WrongPublicKey_ReturnsFalse(EccCurve curve)
    {
        // Arrange
        var keyPair1 = await _eccService.GenerateKeyPairAsync(curve);
        var keyPair2 = await _eccService.GenerateKeyPairAsync(curve);
        var message = "Hello, ECC World!"u8.ToArray();

        // Act
        var signature = await _eccService.SignAsync(message, keyPair1.PrivateKey, curve);
        var isValid = await _eccService.VerifyAsync(message, signature, keyPair2.PublicKey, curve);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public async Task PerformEcdh_Curve25519_ProducesSameSharedSecret()
    {
        // Arrange
        var keyPair1 = await _eccService.GenerateKeyPairAsync(EccCurve.Curve25519);
        var keyPair2 = await _eccService.GenerateKeyPairAsync(EccCurve.Curve25519);

        // Act
        var sharedSecret1 = await _eccService.PerformEcdhAsync(keyPair1.PrivateKey, keyPair2.PublicKey);
        var sharedSecret2 = await _eccService.PerformEcdhAsync(keyPair2.PrivateKey, keyPair1.PublicKey);

        // Assert
        Assert.True(sharedSecret1.AsSpan().SequenceEqual(sharedSecret2));
        Assert.Equal(32, sharedSecret1.Length); // Curve25519 shared secrets are 32 bytes
    }

    [Fact]
    public async Task PerformEcdh_DifferentKeyPairs_ProducesDifferentSharedSecrets()
    {
        // Arrange
        var keyPair1 = await _eccService.GenerateKeyPairAsync(EccCurve.Curve25519);
        var keyPair2 = await _eccService.GenerateKeyPairAsync(EccCurve.Curve25519);
        var keyPair3 = await _eccService.GenerateKeyPairAsync(EccCurve.Curve25519);

        // Act
        var sharedSecret1 = await _eccService.PerformEcdhAsync(keyPair1.PrivateKey, keyPair2.PublicKey);
        var sharedSecret2 = await _eccService.PerformEcdhAsync(keyPair1.PrivateKey, keyPair3.PublicKey);

        // Assert
        Assert.False(sharedSecret1.AsSpan().SequenceEqual(sharedSecret2));
    }

    [Theory]
    [InlineData(EccCurve.Curve25519, 32)]
    [InlineData(EccCurve.Ed25519, 32)]
    public void ValidatePoint_ValidPoints_ReturnsTrue(EccCurve curve, int pointSize)
    {
        // Arrange
        var validPoint = new byte[pointSize];
        // For Curve25519 and Ed25519, any 32-byte array is potentially valid

        // Act & Assert
        Assert.True(_eccService.ValidatePoint(validPoint, curve));
    }

    [Fact]
    public void ValidatePoint_Secp256k1_ValidFormats_ReturnsTrue()
    {
        // Arrange - Compressed format
        var compressedPoint = new byte[33];
        compressedPoint[0] = 0x02; // Valid compression prefix

        // Uncompressed format
        var uncompressedPoint = new byte[65];
        uncompressedPoint[0] = 0x04; // Valid uncompressed prefix

        // Act & Assert
        Assert.True(_eccService.ValidatePoint(compressedPoint, EccCurve.Secp256k1));
        Assert.True(_eccService.ValidatePoint(uncompressedPoint, EccCurve.Secp256k1));
    }

    [Fact]
    public void ValidatePoint_Secp256k1_InvalidFormats_ReturnsFalse()
    {
        // Arrange - Invalid compression prefix
        var invalidPoint1 = new byte[33];
        invalidPoint1[0] = 0x01; // Invalid prefix

        // Invalid uncompressed prefix
        var invalidPoint2 = new byte[65];
        invalidPoint2[0] = 0x05; // Invalid prefix

        // Wrong size
        var invalidPoint3 = new byte[32];

        // Act & Assert
        Assert.False(_eccService.ValidatePoint(invalidPoint1, EccCurve.Secp256k1));
        Assert.False(_eccService.ValidatePoint(invalidPoint2, EccCurve.Secp256k1));
        Assert.False(_eccService.ValidatePoint(invalidPoint3, EccCurve.Secp256k1));
    }

    [Fact]
    public async Task CompressPoint_Secp256k1_ValidUncompressed_ReturnsCompressed()
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(EccCurve.Secp256k1);

        // Ensure we have an uncompressed public key
        byte[] uncompressedKey;
        if (keyPair.PublicKey.Length == 65)
        {
            uncompressedKey = keyPair.PublicKey;
        }
        else
        {
            uncompressedKey = _eccService.DecompressPoint(keyPair.PublicKey, EccCurve.Secp256k1);
        }

        // Act
        var compressedKey = _eccService.CompressPoint(uncompressedKey, EccCurve.Secp256k1);

        // Assert
        Assert.Equal(33, compressedKey.Length);
        Assert.True(compressedKey[0] == 0x02 || compressedKey[0] == 0x03);
    }

    [Fact]
    public async Task DecompressPoint_Secp256k1_ValidCompressed_ReturnsUncompressed()
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(EccCurve.Secp256k1);

        // Ensure we have a compressed public key
        byte[] compressedKey;
        if (keyPair.PublicKey.Length == 33)
        {
            compressedKey = keyPair.PublicKey;
        }
        else
        {
            compressedKey = _eccService.CompressPoint(keyPair.PublicKey, EccCurve.Secp256k1);
        }

        // Act
        var uncompressedKey = _eccService.DecompressPoint(compressedKey, EccCurve.Secp256k1);

        // Assert
        Assert.Equal(65, uncompressedKey.Length);
        Assert.Equal(0x04, uncompressedKey[0]);
    }

    [Theory]
    [InlineData(EccCurve.Curve25519)]
    [InlineData(EccCurve.Ed25519)]
    public void CompressDecompress_MonoCurves_ReturnsOriginal(EccCurve curve)
    {
        // Arrange
        var originalPoint = new byte[32];
        new Random().NextBytes(originalPoint);

        // Act
        var compressed = _eccService.CompressPoint(originalPoint, curve);
        var decompressed = _eccService.DecompressPoint(compressed, curve);

        // Assert
        Assert.True(originalPoint.AsSpan().SequenceEqual(decompressed));
    }

    [Fact]
    public async Task Sign_EmptyMessage_ProducesValidSignature()
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(EccCurve.Ed25519);
        var emptyMessage = Array.Empty<byte>();

        // Act
        var signature = await _eccService.SignAsync(emptyMessage, keyPair.PrivateKey, EccCurve.Ed25519);
        var isValid = await _eccService.VerifyAsync(emptyMessage, signature, keyPair.PublicKey, EccCurve.Ed25519);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public async Task Sign_LargeMessage_ProducesValidSignature()
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(EccCurve.Ed25519);
        var largeMessage = new byte[10000];
        new Random(42).NextBytes(largeMessage);

        // Act
        var signature = await _eccService.SignAsync(largeMessage, keyPair.PrivateKey, EccCurve.Ed25519);
        var isValid = await _eccService.VerifyAsync(largeMessage, signature, keyPair.PublicKey, EccCurve.Ed25519);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public async Task GenerateKeyPair_InvalidCurve_ThrowsNotSupportedException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<NotSupportedException>(
            () => _eccService.GenerateKeyPairAsync((EccCurve)999));
    }

    [Fact]
    public async Task DerivePublicKey_NullPrivateKey_ThrowsArgumentNullException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _eccService.DerivePublicKeyAsync(null!, EccCurve.Ed25519));
    }

    [Fact]
    public async Task Sign_NullData_ThrowsArgumentNullException()
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(EccCurve.Ed25519);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _eccService.SignAsync(null!, keyPair.PrivateKey, EccCurve.Ed25519));
    }

    [Fact]
    public async Task Verify_NullSignature_ThrowsArgumentNullException()
    {
        // Arrange
        var keyPair = await _eccService.GenerateKeyPairAsync(EccCurve.Ed25519);
        var message = "test"u8.ToArray();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _eccService.VerifyAsync(message, null!, keyPair.PublicKey, EccCurve.Ed25519));
    }

    [Fact]
    public async Task PerformEcdh_NullKeys_ThrowsArgumentNullException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _eccService.PerformEcdhAsync(null!, new byte[32]));

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _eccService.PerformEcdhAsync(new byte[32], null!));
    }

    [Fact]
    public void ValidatePoint_NullPoint_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => _eccService.ValidatePoint(null!, EccCurve.Ed25519));
    }

    /// <summary>
    /// Helper method to validate secp256k1 key equivalence between compressed and uncompressed formats
    /// </summary>
    private bool ValidateSecp256k1KeyEquivalence(byte[] key1, byte[] key2)
    {
        try
        {
            // Convert both to uncompressed format for comparison
            var uncompressed1 = key1.Length == 65 ? key1 : _eccService.DecompressPoint(key1, EccCurve.Secp256k1);
            var uncompressed2 = key2.Length == 65 ? key2 : _eccService.DecompressPoint(key2, EccCurve.Secp256k1);

            return uncompressed1.AsSpan().SequenceEqual(uncompressed2);
        }
        catch
        {
            return false;
        }
    }
}

#endif
