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

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, threshold));

            Assert.Equal(shareCount, shares.Length);
            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_GeneratesUniqueIndicesAndIndependentBuffers()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var threshold = 2;
            var shareCount = 4;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);

            // All shares should have different indices
            var indices = shares.Select(s => s.Index).ToList();
            Assert.Equal(shareCount, indices.Distinct().Count());

            // Equal values are possible; buffers must still be independent.
            for (var i = 0; i < shares.Length; i++)
            {
                for (var j = i + 1; j < shares.Length; j++)
                {
                    Assert.NotSame(shares[i].Data, shares[j].Data);
                }
            }
        }

        [Fact]
        public void Reconstruct_WithExactThreshold_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, threshold));

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithMoreThanThreshold_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 4)); // Use 4 shares

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithAllShares_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares);

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Reconstruct_WithDifferentShareCombinations_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret for combinations");
            var threshold = 3;
            var shareCount = 5;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);

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
                var reconstructed = new ShamirSecretSharing().Reconstruct(combination);
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
        public void Reconstruct_WithLessThanExplicitThreshold_IsRejected()
        {
            var secret = Encoding.UTF8.GetBytes("Secret message");
            var threshold = 3;
            var shareCount = 5;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 2), threshold));
        }

        [Fact]
        public void Split_ThresholdOf2_MinimumThreshold_Success()
        {
            var secret = Encoding.UTF8.GetBytes("Minimum threshold test");
            var threshold = 2; // Minimum allowed
            var shareCount = 3;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 2));

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

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, threshold));

            Assert.Equal(shareCount, shares.Length);
            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_SingleByteSecret_Success()
        {
            var secret = "B"u8.ToArray();
            var threshold = 2;
            var shareCount = 3;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 2));

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

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 3));

            Assert.Equal(secret, reconstructed);
        }

        [Fact]
        public void Split_AllZeroSecret_Success()
        {
            var secret = new byte[32]; // All zeros
            var threshold = 2;
            var shareCount = 4;

            var shares = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var reconstructed = new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 2));

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
                new ShamirSecretSharing().Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Split_ThresholdTooLow_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var threshold = 1; // Below minimum
            var shareCount = 3;

            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing().Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Split_ThresholdGreaterThanShareCount_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var threshold = 5;
            var shareCount = 3; // Less than threshold

            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing().Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Split_ShareCountTooHigh_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var threshold = 2;
            var shareCount = 256; // Above maximum

            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing().Split(secret, threshold, shareCount));
        }

        [Fact]
        public void Reconstruct_LessThanMinimumShares_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var shares = new ShamirSecretSharing().Split(secret, 2, 3);

            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing().Reconstruct(shares.AsSpan(0, 1))); // Only 1 share
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
                new ShamirSecretSharing().Reconstruct(shares));
        }

        [Fact]
        public void Reconstruct_DuplicateShareIndices_ThrowsException()
        {
            var secret = Encoding.UTF8.GetBytes("Test");
            var shares = new ShamirSecretSharing().Split(secret, 2, 3);

            var duplicateShares = new[]
            {
                shares[0],
                shares[0].Clone() // Duplicate index
            };

            Assert.Throws<ArgumentException>(() =>
                new ShamirSecretSharing().Reconstruct(duplicateShares));
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
            var shares = new ShamirSecretSharing().Split(secret, 3, 5);

            var result = new ShamirSecretSharing().Verify(shares.AsSpan(0, 3), secret);

            Assert.True(result);
        }

        [Fact]
        public void Verify_WrongSecret_ReturnsFalse()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var wrongSecret = Encoding.UTF8.GetBytes("Wrong secret");
            var shares = new ShamirSecretSharing().Split(secret, 3, 5);

            var result = new ShamirSecretSharing().Verify(shares.AsSpan(0, 3), wrongSecret);

            Assert.False(result);
        }

        [Fact]
        public void Verify_InsufficientShares_ReturnsFalse()
        {
            var secret = Encoding.UTF8.GetBytes("Test secret");
            var shares = new ShamirSecretSharing().Split(secret, 3, 5);

            var result = new ShamirSecretSharing().Verify(shares.AsSpan(0, 2), secret, 3);

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
        public void Split_RepeatedCalls_ReconstructAndUseIndependentBuffers()
        {
            var secret = Encoding.UTF8.GetBytes("Determinism test");
            var threshold = 3;
            var shareCount = 5;

            // Split the same secret twice
            var shares1 = new ShamirSecretSharing().Split(secret, threshold, shareCount);
            var shares2 = new ShamirSecretSharing().Split(secret, threshold, shareCount);

            // Random outputs can coincide; storage must be independent.
            Assert.NotSame(shares1[0].Data, shares2[0].Data);

            var reconstructed1 = new ShamirSecretSharing().Reconstruct(shares1.AsSpan(0, threshold));
            var reconstructed2 = new ShamirSecretSharing().Reconstruct(shares2.AsSpan(0, threshold));

            Assert.Equal(secret, reconstructed1);
            Assert.Equal(secret, reconstructed2);
        }

        [Fact]
        public void SingleShare_IsCompatibleWithEverySecretByte()
        {
            // Fix f(1)=0x42. For each possible constant term s there is exactly
            // one linear coefficient c=s XOR 0x42, including c=0.
            // This checks algebraic compatibility, not RNG quality or side channels.
            var shamir = new ShamirSecretSharing();
            for (var secret = 0; secret < 256; secret++)
            {
                var coefficient = secret ^ 0x42;
                var doubled = ((coefficient << 1) & 0xFF) ^ ((coefficient & 0x80) != 0 ? 0x1B : 0);
                ShamirSecretSharing.Share[] shares =
                    [new(1, [0x42]), new(2, [(byte)(secret ^ doubled)])];

                Assert.Equal(new byte[] { (byte)secret }, shamir.Reconstruct(shares, 2));
            }
        }
    }

    public class AuditRegressions
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Reconstruct_DefaultShare_ReportsInvalidInput(bool first)
        {
            var valid = new ShamirSecretSharing.Share(1, [0x42]);
            ShamirSecretSharing.Share[] shares = first ? [default, valid] : [valid, default];

            Assert.Throws<ArgumentException>(() => new ShamirSecretSharing().Reconstruct(shares));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Verify_DefaultShare_ReturnsFalse(bool first)
        {
            var valid = new ShamirSecretSharing.Share(1, [0x42]);
            ShamirSecretSharing.Share[] shares = first ? [default, valid] : [valid, default];

            Assert.False(new ShamirSecretSharing().Verify(shares, [0x42]));
        }

        [Fact]
        public void Reconstruct_EmptyShareData_IsRejected()
        {
            ShamirSecretSharing.Share[] shares = [new(1, []), new(2, [])];

            Assert.Throws<ArgumentException>(() => new ShamirSecretSharing().Reconstruct(shares));
        }

        [Fact]
        public void Verify_EmptyShares_CannotVerifyEmptySecret()
        {
            ShamirSecretSharing.Share[] shares = [new(1, []), new(2, [])];

            Assert.False(new ShamirSecretSharing().Verify(shares, []));
        }

        [Fact]
        public void Clone_DefaultShare_ReportsUninitializedValue()
        {
            var share = default(ShamirSecretSharing.Share);

            Assert.Throws<InvalidOperationException>(() => { share.Clone(); });
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Builder_Reconstruct_EnforcesConfiguredThreshold(bool stored)
        {
            // Zero random coefficients are legitimate field values. These two
            // shares can happen to interpolate to the expected byte even when
            // the caller requires three shares. A wrong-value check is insufficient.
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42])];
            var builder = HeroCryptBuilder.SecretSharing().WithThreshold(3);

            if (stored)
            {
                builder.WithShares(shares);
                Assert.Throws<ArgumentException>(builder.Reconstruct);
            }
            else
            {
                Assert.Throws<ArgumentException>(() => builder.Reconstruct(shares));
            }
        }

        [Fact]
        public void Builder_Verify_EnforcesConfiguredThreshold()
        {
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42])];
            var builder = HeroCryptBuilder.SecretSharing().WithThreshold(3).WithShares(shares);

            Assert.False(builder.Verify([0x42]));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(256)]
        public void Builder_Reconstruct_RejectsInvalidThreshold(int threshold)
        {
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42])];

            Assert.Throws<ArgumentException>(() =>
                HeroCryptBuilder.SecretSharing().WithThreshold(threshold).Reconstruct(shares));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(256)]
        public void Builder_Verify_RejectsInvalidThreshold(int threshold)
        {
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42])];

            Assert.False(HeroCryptBuilder.SecretSharing().WithThreshold(threshold).WithShares(shares).Verify([0x42]));
        }

        [Fact]
        public void FieldMultiplication_MatchesIndependentPolynomialReduction()
        {
            var method = typeof(ShamirSecretSharing).GetMethod("GF256Multiply",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
            var multiply = method.CreateDelegate<Func<byte, byte, byte>>();

            // Independent carryless polynomial multiplication and long division,
            // rather than the production routine's shift-and-reduce algorithm.
            for (var a = 0; a < 256; a++)
            {
                for (var b = 0; b < 256; b++)
                {
                    var product = 0;
                    for (var bit = 0; bit < 8; bit++)
                    {
                        if ((b & (1 << bit)) != 0)
                            product ^= a << bit;
                    }
                    for (var degree = 14; degree >= 8; degree--)
                    {
                        if ((product & (1 << degree)) != 0)
                            product ^= 0x11B << (degree - 8);
                    }

                    Assert.Equal((byte)product, multiply((byte)a, (byte)b));
                }
            }

            // NIST FIPS 197, section 4.2 examples.
            Assert.Equal((byte)0xC1, multiply(0x57, 0x83));
            Assert.Equal((byte)0xFE, multiply(0x57, 0x13));
        }

        [Fact]
        public void Reconstruct_KnownLinearPolynomial_WithHighAndReorderedIndices()
        {
            // f(x) = 0x42 + 0x57*x in the AES field. Values for x=0x13 and
            // x=0x83 follow the published FIPS multiplication examples above.
            ShamirSecretSharing.Share[] shares = [new(0x83, [0x83]), new(0x13, [0xBC])];

            Assert.Equal(new byte[] { 0x42 }, new ShamirSecretSharing().Reconstruct(shares));
            Array.Reverse(shares);
            Assert.Equal(new byte[] { 0x42 }, new ShamirSecretSharing().Reconstruct(shares));
        }

        [Fact]
        public void SplitAndReconstruct_MaximumThreshold_RetainsCorrectness()
        {
            var shamir = new ShamirSecretSharing();
            var shares = shamir.Split([0x42], 255, 255);
            Array.Reverse(shares);

            Assert.Equal(new byte[] { 0x42 }, shamir.Reconstruct(shares));
            Assert.Equal(new byte[] { 0x42 }, shamir.Reconstruct(shares, 255));
            Assert.True(shamir.Verify(shares, [0x42], 255));
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(256)]
        public void ExplicitThreshold_InvalidValue_IsRejected(int threshold)
        {
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42])];
            var shamir = new ShamirSecretSharing();

            Assert.Throws<ArgumentException>(() => shamir.Reconstruct(shares, threshold));
            Assert.False(shamir.Verify(shares, [0x42], threshold));
        }

        [Fact]
        public void ExplicitThreshold_InsufficientShares_IsRejectedEvenIfValueMatches()
        {
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42])];
            var shamir = new ShamirSecretSharing();

            Assert.Throws<ArgumentException>(() => shamir.Reconstruct(shares, 3));
            Assert.False(shamir.Verify(shares, [0x42], 3));
        }

        [Fact]
        public void ZeroCoefficients_EqualPayloads_AreValidWithEnoughDistinctIndices()
        {
            // Uniform field sampling includes zero coefficients. A valid sharing
            // polynomial may be constant; rejecting equal payloads would bias it.
            ShamirSecretSharing.Share[] shares = [new(1, [0x42]), new(2, [0x42]), new(255, [0x42])];

            Assert.Equal(new byte[] { 0x42 }, new ShamirSecretSharing().Reconstruct(shares, 3));
            Assert.True(HeroCryptBuilder.SecretSharing().WithThreshold(3).WithShares(shares).Verify([0x42]));
        }

        [Fact]
        public void Verify_MismatchedLengthsAndDuplicateIndices_ReturnsFalse()
        {
            var shamir = new ShamirSecretSharing();

            Assert.False(shamir.Verify([new(1, [0x42]), new(2, [0x42, 0x42])], [0x42]));
            Assert.False(shamir.Verify([new(1, [0x42]), new(1, [0x42])], [0x42]));
        }

        [Theory]
        [InlineData(HeroCrypt.Security.SecurityLevel.None)]
        [InlineData(HeroCrypt.Security.SecurityLevel.Standard)]
        [InlineData(HeroCrypt.Security.SecurityLevel.Strict)]
        [InlineData(HeroCrypt.Security.SecurityLevel.Compliance)]
        public void Verify_IsValueComparison_NotShareProvenanceAuthentication(HeroCrypt.Security.SecurityLevel level)
        {
            // The first point can belong to f(x)=0x10+0x52*x, and the second
            // to g(x)=0x20+0x31*x. Mixing them interpolates to 0x42. No origin
            // information is present, so matching an expected value cannot
            // authenticate a dealer, a sharing session, or a participant.
            ShamirSecretSharing.Share[] mixed = [new(1, [0x42]), new(2, [0x42])];
            var shamir = new ShamirSecretSharing(new HeroCrypt.Security.SecurityPolicyOptions(level));

            Assert.True(shamir.Verify(mixed, [0x42]));
        }
    }
}
#endif
