using HeroCrypt.Protocols.SecretSharing;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Comprehensive tests for SecretSharingBuilder fluent API.
/// </summary>
public class SecretSharingBuilderTests
{
    /// <summary>
    /// Tests for basic split and reconstruct operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicOperationsTests
    {
        [Fact]
        public void SplitAndReconstruct_DefaultThreshold_Succeeds()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(3)
                .Split(secret);

            var reconstructed = new SecretSharingBuilder()
                .WithShares(shares)
                .Reconstruct();

            Assert.Equal(secret, reconstructed);
        }

        [Theory]
        [InlineData(2, 3)]
        [InlineData(3, 5)]
        [InlineData(5, 10)]
        [InlineData(10, 20)]
        public void SplitAndReconstruct_VariousThresholds_Succeeds(int threshold, int shareCount)
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(threshold)
                .WithShareCount(shareCount)
                .Split(secret);

            Assert.Equal(shareCount, shares.Length);

            var selectedShares = shares.Take(threshold).ToArray();
            var reconstructed = new SecretSharingBuilder()
                .WithShares(selectedShares)
                .Reconstruct();

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_ReturnsCorrectNumberOfShares()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(3)
                .WithShareCount(5)
                .Split(secret);

            Assert.Equal(5, shares.Length);
        }
    }

    /// <summary>
    /// Tests for threshold behavior.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ThresholdBehaviorTests
    {
        [Fact]
        public void Reconstruct_WithExactThreshold_Succeeds()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(3)
                .WithShareCount(5)
                .Split(secret);

            var selectedShares = shares.Take(3).ToArray();
            var reconstructed = new SecretSharingBuilder()
                .WithShares(selectedShares)
                .Reconstruct();

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithMoreThanThreshold_Succeeds()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(5)
                .Split(secret);

            var selectedShares = shares.Take(4).ToArray();
            var reconstructed = new SecretSharingBuilder()
                .WithShares(selectedShares)
                .Reconstruct();

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithAllShares_Succeeds()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(5)
                .Split(secret);

            var reconstructed = new SecretSharingBuilder()
                .WithShares(shares)
                .Reconstruct();

            Assert.Equal(secret, reconstructed);
        }
    }

    /// <summary>
    /// Tests for verification.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class VerificationTests
    {
        [Fact]
        public void Verify_CorrectShares_ReturnsTrue()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(3)
                .Split(secret);

            var isValid = new SecretSharingBuilder()
                .WithShares(shares)
                .Verify(secret);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_WrongSecret_ReturnsFalse()
        {
            var secret = TestHelpers.RandomBytes(32);
            var wrongSecret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(3)
                .Split(secret);

            var isValid = new SecretSharingBuilder()
                .WithShares(shares)
                .Verify(wrongSecret);

            Assert.False(isValid);
        }
    }

    /// <summary>
    /// Tests for parameter validation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidationTests
    {
        [Fact]
        public void Reconstruct_WithoutShares_ThrowsInvalidOperationException()
        {
            var builder = new SecretSharingBuilder();

            Assert.Throws<InvalidOperationException>(builder.Reconstruct);
        }

        [Fact]
        public void Verify_WithoutShares_ThrowsInvalidOperationException()
        {
            var secret = TestHelpers.RandomBytes(32);
            var builder = new SecretSharingBuilder();

            Assert.Throws<InvalidOperationException>(() => builder.Verify(secret));
        }
    }

    /// <summary>
    /// Tests for different secret sizes.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecretSizeTests
    {
        [Theory]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        [InlineData(256)]
        public void SplitAndReconstruct_VariousSecretSizes_Succeeds(int size)
        {
            var secret = TestHelpers.RandomBytes(size);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(3)
                .Split(secret);

            var reconstructed = new SecretSharingBuilder()
                .WithShares(shares)
                .Reconstruct();

            Assert.Equal(secret, reconstructed);
        }
    }

    /// <summary>
    /// Tests for fluent API.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FluentApiTests
    {
        [Fact]
        public void FluentChaining_Works()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(3)
                .WithShareCount(7)
                .Split(secret);

            Assert.Equal(7, shares.Length);
        }

        [Fact]
        public void Reconstruct_WithSharesParameter_Works()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(3)
                .Split(secret);

            var reconstructed = new SecretSharingBuilder()
                .Reconstruct(shares);

            Assert.Equal(secret, reconstructed);
        }
    }

    /// <summary>
    /// Tests for share independence.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class ShareIndependenceTests
    {
        [Fact]
        public void Shares_AreUnique()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(5)
                .Split(secret);

            var shareData = shares.Select(s => Convert.ToHexString(s.Data)).ToList();
            Assert.Equal(5, shareData.Distinct().Count());
        }

        [Fact]
        public void Shares_HaveUniqueIndices()
        {
            var secret = TestHelpers.RandomBytes(32);

            var shares = new SecretSharingBuilder()
                .WithThreshold(2)
                .WithShareCount(5)
                .Split(secret);

            var indices = shares.Select(s => s.Index).ToList();
            Assert.Equal(5, indices.Distinct().Count());
        }
    }
}

#endif
