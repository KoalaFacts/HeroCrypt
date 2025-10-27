using HeroCrypt.Cryptography.SecretSharing;
using System.Text;

namespace HeroCrypt.Tests;

// DISABLED: Systematically disabling all advanced tests to isolate crash
#if !NETSTANDARD2_0

/// <summary>
/// Tests for Shamir's Secret Sharing
/// </summary>
public class ShamirSecretSharingTests
{
    [Fact]
    public void Split_And_Reconstruct_SimpleSecret_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Hello, World!");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, threshold));

        // Assert
        Assert.Equal(shareCount, shares.Length);
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Split_GeneratesUniqueShares()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test secret");
        var threshold = 2;
        var shareCount = 4;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);

        // Assert - All shares should have different indices
        var indices = shares.Select(s => s.Index).ToList();
        Assert.Equal(shareCount, indices.Distinct().Count());

        // Assert - All shares should have different data
        for (var i = 0; i < shares.Length; i++)
        {
            for (var j = i + 1; j < shares.Length; j++)
            {
                Assert.NotEqual(shares[i].Data, shares[j].Data);
            }
        }
    }

    [Fact]
    public void Reconstruct_WithExactThreshold_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Secret message");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, threshold));

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Reconstruct_WithMoreThanThreshold_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Secret message");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 4)); // Use 4 shares

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Reconstruct_WithAllShares_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Secret message");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares);

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Reconstruct_WithDifferentShareCombinations_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test secret for combinations");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);

        // Test different combinations of shares
        var combinations = new[]
        {
            new[] { shares[0], shares[1], shares[2] },
            new[] { shares[0], shares[2], shares[4] },
            new[] { shares[1], shares[3], shares[4] },
            new[] { shares[2], shares[3], shares[4] }
        };

        // Assert - All combinations should reconstruct the same secret
        foreach (var combination in combinations)
        {
            var reconstructed = ShamirSecretSharing.Reconstruct(combination);
            Assert.Equal(secret, reconstructed);
        }
    }

    [Fact]
    public void Reconstruct_WithLessThanThreshold_FailsOrProducesWrongSecret()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Secret message");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2)); // Only 2 shares, need 3

        // Assert - Should NOT reconstruct correct secret
        Assert.NotEqual(secret, reconstructed);
    }

    [Fact]
    public void Split_ThresholdOf2_MinimumThreshold_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Minimum threshold test");
        var threshold = 2; // Minimum allowed
        var shareCount = 3;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2));

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Split_MaximumShares_Success()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Max shares test");
        var threshold = 128;
        var shareCount = 255; // Maximum allowed

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, threshold));

        // Assert
        Assert.Equal(shareCount, shares.Length);
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Split_SingleByteSecret_Success()
    {
        // Arrange
        var secret = new byte[] { 0x42 };
        var threshold = 2;
        var shareCount = 3;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2));

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Split_LargeSecret_Success()
    {
        // Arrange - 1KB secret
        var secret = new byte[1024];
        new Random(42).NextBytes(secret);
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 3));

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Split_AllZeroSecret_Success()
    {
        // Arrange
        var secret = new byte[32]; // All zeros
        var threshold = 2;
        var shareCount = 4;

        // Act
        var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2));

        // Assert
        Assert.Equal(secret, reconstructed);
    }

    [Fact]
    public void Split_EmptySecret_ThrowsException()
    {
        // Arrange
        var secret = Array.Empty<byte>();
        var threshold = 2;
        var shareCount = 3;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(secret, threshold, shareCount));
    }

    [Fact]
    public void Split_ThresholdTooLow_ThrowsException()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test");
        var threshold = 1; // Below minimum
        var shareCount = 3;

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(secret, threshold, shareCount));
    }

    [Fact]
    public void Split_ThresholdGreaterThanShareCount_ThrowsException()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test");
        var threshold = 5;
        var shareCount = 3; // Less than threshold

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(secret, threshold, shareCount));
    }

    [Fact]
    public void Split_ShareCountTooHigh_ThrowsException()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test");
        var threshold = 2;
        var shareCount = 256; // Above maximum

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(secret, threshold, shareCount));
    }

    [Fact]
    public void Reconstruct_LessThanMinimumShares_ThrowsException()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test");
        var shares = ShamirSecretSharing.Split(secret, 2, 3);

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 1))); // Only 1 share
    }

    [Fact]
    public void Reconstruct_MismatchedShareLengths_ThrowsException()
    {
        // Arrange
        var shares = new[]
        {
            new ShamirSecretSharing.Share(1, new byte[] { 1, 2, 3 }),
            new ShamirSecretSharing.Share(2, new byte[] { 4, 5 }) // Different length
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Reconstruct(shares));
    }

    [Fact]
    public void Reconstruct_DuplicateShareIndices_ThrowsException()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test");
        var shares = ShamirSecretSharing.Split(secret, 2, 3);

        var duplicateShares = new[]
        {
            shares[0],
            shares[0].Clone() // Duplicate index
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Reconstruct(duplicateShares));
    }

    [Fact]
    public void Verify_CorrectShares_ReturnsTrue()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test secret");
        var shares = ShamirSecretSharing.Split(secret, 3, 5);

        // Act
        var result = ShamirSecretSharing.Verify(shares.AsSpan(0, 3), secret);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Verify_WrongSecret_ReturnsFalse()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test secret");
        var wrongSecret = Encoding.UTF8.GetBytes("Wrong secret");
        var shares = ShamirSecretSharing.Split(secret, 3, 5);

        // Act
        var result = ShamirSecretSharing.Verify(shares.AsSpan(0, 3), wrongSecret);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_InsufficientShares_ReturnsFalse()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Test secret");
        var shares = ShamirSecretSharing.Split(secret, 3, 5);

        // Act
        var result = ShamirSecretSharing.Verify(shares.AsSpan(0, 2), secret); // Only 2 shares, need 3

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Share_Construction_WithValidParameters_Success()
    {
        // Arrange
        var index = (byte)5;
        var data = new byte[] { 1, 2, 3, 4 };

        // Act
        var share = new ShamirSecretSharing.Share(index, data);

        // Assert
        Assert.Equal(index, share.Index);
        Assert.Equal(data, share.Data);
    }

    [Fact]
    public void Share_Construction_WithZeroIndex_ThrowsException()
    {
        // Arrange
        var index = (byte)0;
        var data = new byte[] { 1, 2, 3 };

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new ShamirSecretSharing.Share(index, data));
    }

    [Fact]
    public void Share_Clone_CreatesIndependentCopy()
    {
        // Arrange
        var original = new ShamirSecretSharing.Share(1, new byte[] { 1, 2, 3 });

        // Act
        var clone = original.Clone();
        clone.Data[0] = 99; // Modify clone

        // Assert
        Assert.Equal(original.Index, clone.Index);
        Assert.NotEqual(original.Data[0], clone.Data[0]); // Changes should not affect original
    }

    [Fact]
    public void GetInfo_ReturnsDescription()
    {
        // Act
        var info = ShamirSecretSharing.GetInfo();

        // Assert
        Assert.Contains("Shamir", info);
        Assert.Contains("255", info); // Max shares
        Assert.Contains("GF(256)", info);
    }

    [Fact]
    public void Split_DeterministicWithSameInput_ProducesDifferentShares()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("Determinism test");
        var threshold = 3;
        var shareCount = 5;

        // Act - Split the same secret twice
        var shares1 = ShamirSecretSharing.Split(secret, threshold, shareCount);
        var shares2 = ShamirSecretSharing.Split(secret, threshold, shareCount);

        // Assert - Shares should be different (due to random coefficients)
        // but both should reconstruct to the same secret
        Assert.NotEqual(shares1[0].Data, shares2[0].Data);

        var reconstructed1 = ShamirSecretSharing.Reconstruct(shares1.AsSpan(0, threshold));
        var reconstructed2 = ShamirSecretSharing.Reconstruct(shares2.AsSpan(0, threshold));

        Assert.Equal(secret, reconstructed1);
        Assert.Equal(secret, reconstructed2);
    }

    [Fact]
    public void PerfectSecrecy_ThresholdMinusOne_RevealsNothing()
    {
        // Arrange - Test that K-1 shares reveal no information
        var secret1 = Encoding.UTF8.GetBytes("Secret One");
        var secret2 = Encoding.UTF8.GetBytes("Secret Two");
        var threshold = 3;
        var shareCount = 5;

        // Act
        var shares1 = ShamirSecretSharing.Split(secret1, threshold, shareCount);
        var shares2 = ShamirSecretSharing.Split(secret2, threshold, shareCount);

        // Attempt reconstruction with K-1 shares
        var partial1 = ShamirSecretSharing.Reconstruct(shares1.AsSpan(0, 2)); // Need 3, have 2
        var partial2 = ShamirSecretSharing.Reconstruct(shares2.AsSpan(0, 2)); // Need 3, have 2

        // Assert - Neither partial reconstruction should match the actual secrets
        Assert.NotEqual(secret1, partial1);
        Assert.NotEqual(secret2, partial2);
    }
}
#endif
