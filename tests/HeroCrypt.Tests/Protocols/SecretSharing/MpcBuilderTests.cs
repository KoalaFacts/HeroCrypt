using HeroCrypt.Protocols.SecretSharing;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Comprehensive tests for MpcBuilder fluent API.
/// </summary>
public class MpcBuilderTests
{
    /// <summary>
    /// Tests for secure sum computation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecureSumTests
    {
        [Fact]
        public void ComputeSum_ValidInputs_Succeeds()
        {
            var input1 = new byte[] { 10 };
            var input2 = new byte[] { 20 };
            var input3 = new byte[] { 30 };

            var result = new MpcBuilder()
                .WithThreshold(2)
                .WithPartyInputs([input1, input2, input3])
                .ComputeSum();

            Assert.NotNull(result);
            Assert.NotNull(result.Result);
        }

        [Fact]
        public void ComputeSum_WithParameterOverload_Succeeds()
        {
            var input1 = new byte[] { 10 };
            var input2 = new byte[] { 20 };
            var input3 = new byte[] { 30 };

            var result = new MpcBuilder()
                .WithThreshold(2)
                .ComputeSum([input1, input2, input3]);

            Assert.NotNull(result);
        }

        [Fact]
        public void ComputeSum_WithoutInputs_ThrowsInvalidOperationException()
        {
            var builder = new MpcBuilder()
                .WithThreshold(2);

            Assert.Throws<InvalidOperationException>(() => builder.ComputeSum());
        }

        [Theory]
        [InlineData(SecureMpc.SecurityModel.SemiHonest)]
        [InlineData(SecureMpc.SecurityModel.Malicious)]
        public void ComputeSum_DifferentSecurityModels_Succeeds(SecureMpc.SecurityModel model)
        {
            var inputs = new[] { new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 } };

            var result = new MpcBuilder()
                .WithThreshold(2)
                .WithSecurityModel(model)
                .WithPartyInputs(inputs)
                .ComputeSum();

            Assert.NotNull(result);
        }
    }

    /// <summary>
    /// Tests for private set intersection.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PrivateSetIntersectionTests
    {
        [Fact]
        public void ComputeIntersection_OverlappingSets_ReturnsCommonElements()
        {
            var set1 = new[]
            {
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 }
            };
            var set2 = new[]
            {
                new byte[] { 4, 5, 6 },
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 }
            };

            var intersection = new MpcBuilder()
                .WithParty1Set(set1)
                .WithParty2Set(set2)
                .ComputeIntersection();

            Assert.NotNull(intersection);
            Assert.Equal(2, intersection.Length);
        }

        [Fact]
        public void ComputeIntersection_DisjointSets_ReturnsEmpty()
        {
            var set1 = new[]
            {
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 }
            };
            var set2 = new[]
            {
                new byte[] { 7, 8, 9 },
                new byte[] { 10, 11, 12 }
            };

            var intersection = new MpcBuilder()
                .WithParty1Set(set1)
                .WithParty2Set(set2)
                .ComputeIntersection();

            Assert.Empty(intersection);
        }

        [Fact]
        public void ComputeIntersection_IdenticalSets_ReturnsAll()
        {
            var set = new[]
            {
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5, 6 }
            };

            var intersection = new MpcBuilder()
                .WithParty1Set(set)
                .WithParty2Set(set)
                .ComputeIntersection();

            Assert.Equal(2, intersection.Length);
        }

        [Fact]
        public void ComputeIntersection_WithParameterOverload_Succeeds()
        {
            var set1 = new[] { new byte[] { 1 } };
            var set2 = new[] { new byte[] { 1 } };

            var intersection = new MpcBuilder()
                .ComputeIntersection(set1, set2);

            Assert.Single(intersection);
        }

        [Fact]
        public void ComputeIntersection_WithoutParty1Set_ThrowsInvalidOperationException()
        {
            var set2 = new[] { new byte[] { 1 } };

            var builder = new MpcBuilder()
                .WithParty2Set(set2);

            Assert.Throws<InvalidOperationException>(() => builder.ComputeIntersection());
        }

        [Fact]
        public void ComputeIntersection_WithoutParty2Set_ThrowsInvalidOperationException()
        {
            var set1 = new[] { new byte[] { 1 } };

            var builder = new MpcBuilder()
                .WithParty1Set(set1);

            Assert.Throws<InvalidOperationException>(() => builder.ComputeIntersection());
        }
    }

    /// <summary>
    /// Tests for Beaver triple generation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BeaverTripleTests
    {
        [Fact]
        public void GenerateBeaverTriples_ValidParameters_Succeeds()
        {
            var triples = new MpcBuilder()
                .WithThreshold(2)
                .GenerateBeaverTriples(numParties: 3, valueLength: 32);

            Assert.NotNull(triples);
            Assert.Equal(3, triples.Length);
        }

        [Theory]
        [InlineData(3, 16)]
        [InlineData(5, 32)]
        [InlineData(7, 64)]
        public void GenerateBeaverTriples_VariousConfigurations_Succeeds(int numParties, int valueLength)
        {
            var triples = new MpcBuilder()
                .WithThreshold(2)
                .GenerateBeaverTriples(numParties, valueLength);

            Assert.Equal(numParties, triples.Length);
            foreach (var triple in triples)
            {
                Assert.Equal(valueLength, triple.A.Value.Length);
                Assert.Equal(valueLength, triple.B.Value.Length);
                Assert.Equal(valueLength, triple.C.Value.Length);
            }
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
        public void FluentChaining_SecureSum_Works()
        {
            var inputs = new[]
            {
                new byte[] { 1 },
                new byte[] { 2 },
                new byte[] { 3 }
            };

            var result = new MpcBuilder()
                .WithThreshold(2)
                .WithSecurityModel(SecureMpc.SecurityModel.SemiHonest)
                .WithPartyInputs(inputs)
                .ComputeSum();

            Assert.NotNull(result);
        }

        [Fact]
        public void FluentChaining_Intersection_Works()
        {
            var set1 = new[] { new byte[] { 1, 2 } };
            var set2 = new[] { new byte[] { 1, 2 } };

            var result = new MpcBuilder()
                .WithSecurityModel(SecureMpc.SecurityModel.Malicious)
                .WithParty1Set(set1)
                .WithParty2Set(set2)
                .ComputeIntersection();

            Assert.NotNull(result);
        }
    }

    /// <summary>
    /// Tests for security model settings.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecurityModelTests
    {
        [Fact]
        public void WithSecurityModel_SemiHonest_IsDefault()
        {
            var inputs = new[] { new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 } };

            // Default should work without explicitly setting security model
            var result = new MpcBuilder()
                .WithThreshold(2)
                .WithPartyInputs(inputs)
                .ComputeSum();

            Assert.NotNull(result);
        }

        [Fact]
        public void WithSecurityModel_Malicious_Succeeds()
        {
            var inputs = new[] { new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 } };

            var result = new MpcBuilder()
                .WithThreshold(2)
                .WithSecurityModel(SecureMpc.SecurityModel.Malicious)
                .WithPartyInputs(inputs)
                .ComputeSum();

            Assert.NotNull(result);
        }
    }

    /// <summary>
    /// Tests for threshold settings.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ThresholdTests
    {
        [Theory]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(5)]
        public void WithThreshold_VariousValues_Succeeds(int threshold)
        {
            var inputs = Enumerable.Range(0, threshold + 1)
                .Select(i => new byte[] { (byte)i })
                .ToArray();

            var result = new MpcBuilder()
                .WithThreshold(threshold)
                .WithPartyInputs(inputs)
                .ComputeSum();

            Assert.NotNull(result);
        }
    }
}

#endif
