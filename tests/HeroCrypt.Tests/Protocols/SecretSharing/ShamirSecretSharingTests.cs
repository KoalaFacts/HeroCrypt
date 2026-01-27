using System.Text;
using HeroCrypt.Protocols.SecretSharing;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Tests for Shamir's Secret Sharing scheme.
/// </summary>
[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class ShamirSecretSharingTests
{
    /// <summary>
    /// Tests for basic split and reconstruct functionality.
    /// </summary>
    public class BasicFunctionality
    {
        [Fact]
        public void Split_And_Reconstruct_SimpleSecret_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Hello, World!");
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, threshold));

            Assert.Equal(shareCount, shares.Length);
            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_GeneratesUniqueShares()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var threshold = 2;
            var shareCount = 4;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);

            // All shares should have different indices
            var indices = shares.Select(s => s.Index).ToList();
            Assert.Equal(shareCount, indices.Distinct().Count());

            // All shares should have different data
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
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, threshold));

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithMoreThanThreshold_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 4)); // Use 4 shares

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithAllShares_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares);

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithDifferentShareCombinations_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret for combinations");
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);

            // Test different combinations of shares
            var combinations = new[]
            {
                new[] { shares[0], shares[1], shares[2] },
                [shares[0], shares[2], shares[4]],
                [shares[1], shares[3], shares[4]],
                [shares[2], shares[3], shares[4]]
            };

            // All combinations should reconstruct the same secret
            foreach (var combination in combinations)
            {
                var reconstructed = ShamirSecretSharing.Reconstruct(combination);
                Assert.Equal(secret, reconstructed);
            }
        }
    }

    /// <summary>
    /// Tests for threshold-related behavior.
    /// </summary>
    public class ThresholdBehavior
    {
        [Fact]
        public void Reconstruct_WithLessThanThreshold_FailsOrProducesWrongSecret()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2)); // Only 2 shares, need 3

            // Should NOT reconstruct correct secret
            Assert.NotEqual(secret, reconstructed);
        }

        [Fact]
        public void Split_ThresholdOf2_MinimumThreshold_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Minimum threshold test");
            var threshold = 2; // Minimum allowed
            var shareCount = 3;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2));

            Assert.Equal(secret, reconstructed);
        }
    }

    /// <summary>
    /// Tests for boundary conditions and various secret sizes.
    /// </summary>
    public class BoundaryConditions
    {
        [Fact]
        public void Split_MaximumShares_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Max shares test");
            var threshold = 128;
            var shareCount = 255; // Maximum allowed

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, threshold));

            Assert.Equal(shareCount, shares.Length);
            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_SingleByteSecret_Success()
        {
            var secret = "B"u8.ToArray();
            var threshold = 2;
            var shareCount = 3;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2));

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_LargeSecret_Success()
        {
            // 1KB secret
            var secret = new byte[1024];
            new Random(42).NextBytes(secret);
            var threshold = 3;
            var shareCount = 5;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 3));

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_AllZeroSecret_Success()
        {
            var secret = new byte[32]; // All zeros
            var threshold = 2;
            var shareCount = 4;

            var shares = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var reconstructed = ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 2));

            Assert.Equal(secret, reconstructed);
        }
    }

    /// <summary>
    /// Tests for parameter validation and error handling.
    /// </summary>
    [Trait("Category", TestCategories.INPUT_VALIDATION)]
    public class ParameterValidation
    {
        [Fact]
        public void Split_EmptySecret_ThrowsException()
        {
            var secret = Array.Empty<byte>();
            var threshold = 2;
            var shareCount = 3;

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Split_ThresholdTooLow_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var threshold = 1; // Below minimum
            var shareCount = 3;

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Split_ThresholdGreaterThanShareCount_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var threshold = 5;
            var shareCount = 3; // Less than threshold

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Split_ShareCountTooHigh_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var threshold = 2;
            var shareCount = 256; // Above maximum

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Reconstruct_LessThanMinimumShares_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var shares = ShamirSecretSharing.Split(secret, 2, 3);

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Reconstruct(shares.AsSpan(0, 1))); // Only 1 share
        }

        [Fact]
        public void Reconstruct_MismatchedShareLengths_ThrowsException()
        {
            var shares = new[]
            {
                new ShamirSecretSharing.Share(1, [1, 2, 3]),
                new ShamirSecretSharing.Share(2, [4, 5]) // Different length
            };

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Reconstruct(shares));
        }

        [Fact]
        public void Reconstruct_DuplicateShareIndices_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var shares = ShamirSecretSharing.Split(secret, 2, 3);

            var duplicateShares = new[]
            {
                shares[0],
                shares[0].Clone() // Duplicate index
            };

            Assert.Throws<ArgumentException>(() =>
                ShamirSecretSharing.Reconstruct(duplicateShares));
        }
    }

    /// <summary>
    /// Tests for share verification functionality.
    /// </summary>
    public class VerificationTests
    {
        [Fact]
        public void Verify_CorrectShares_ReturnsTrue()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var shares = ShamirSecretSharing.Split(secret, 3, 5);

            var result = ShamirSecretSharing.Verify(shares.AsSpan(0, 3), secret);

            Assert.True(result);
        }

        [Fact]
        public void Verify_WrongSecret_ReturnsFalse()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var wrongSecret = Encoding.UTF8.GetBytes("Wrong secret");
            var shares = ShamirSecretSharing.Split(secret, 3, 5);

            var result = ShamirSecretSharing.Verify(shares.AsSpan(0, 3), wrongSecret);

            Assert.False(result);
        }

        [Fact]
        public void Verify_InsufficientShares_ReturnsFalse()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var shares = ShamirSecretSharing.Split(secret, 3, 5);

            var result = ShamirSecretSharing.Verify(shares.AsSpan(0, 2), secret); // Only 2 shares, need 3

            Assert.False(result);
        }
    }

    /// <summary>
    /// Tests for the Share class.
    /// </summary>
    public class ShareTests
    {
        [Fact]
        public void Share_Construction_WithValidParameters_Success()
        {
            var index = (byte)5;
            var data = new byte[] { 1, 2, 3, 4 };

            var share = new ShamirSecretSharing.Share(index, data);

            Assert.Equal(index, share.Index);
            Assert.Equal(data, share.Data);
        }

        [Fact]
        public void Share_Construction_WithZeroIndex_ThrowsException()
        {
            var index = (byte)0;
            var data = new byte[] { 1, 2, 3 };

            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing.Share(index, data));
        }

        [Fact]
        public void Share_Clone_CreatesIndependentCopy()
        {
            var original = new ShamirSecretSharing.Share(1, [1, 2, 3]);

            var clone = original.Clone();
            clone.Data[0] = 99; // Modify clone

            Assert.Equal(original.Index, clone.Index);
            Assert.NotEqual(original.Data[0], clone.Data[0]); // Changes should not affect original
        }
    }

    /// <summary>
    /// Tests for security properties of the secret sharing scheme.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    public class SecurityProperties
    {
        [Fact]
        public void Split_DeterministicWithSameInput_ProducesDifferentShares()
        {
            var secret = Encoding.UTF8.GetBytes("Determinism test");
            var threshold = 3;
            var shareCount = 5;

            // Split the same secret twice
            var shares1 = ShamirSecretSharing.Split(secret, threshold, shareCount);
            var shares2 = ShamirSecretSharing.Split(secret, threshold, shareCount);

            // Shares should be different (due to random coefficients)
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
            // Test that K-1 shares reveal no information
            var secret1 = Encoding.UTF8.GetBytes("Secret One");
            var secret2 = Encoding.UTF8.GetBytes("Secret Two");
            var threshold = 3;
            var shareCount = 5;

            var shares1 = ShamirSecretSharing.Split(secret1, threshold, shareCount);
            var shares2 = ShamirSecretSharing.Split(secret2, threshold, shareCount);

            // Attempt reconstruction with K-1 shares
            var partial1 = ShamirSecretSharing.Reconstruct(shares1.AsSpan(0, 2)); // Need 3, have 2
            var partial2 = ShamirSecretSharing.Reconstruct(shares2.AsSpan(0, 2)); // Need 3, have 2

            // Neither partial reconstruction should match the actual secrets
            Assert.NotEqual(secret1, partial1);
            Assert.NotEqual(secret2, partial2);
        }
    }
}
#endif
