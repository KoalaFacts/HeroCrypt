using HeroCrypt.Security;

namespace HeroCrypt.Tests.Security;

/// <summary>
/// Tests for SIMD-optimized constant-time operations
/// </summary>
public class SimdConstantTimeOperationsTests
{
    #region ConstantTimeArrayEquals Tests

    [Fact]
    public void ConstantTimeArrayEquals_EmptyArrays_ReturnsTrue()
    {
        var a = Array.Empty<byte>();
        var b = Array.Empty<byte>();

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.True(result);
    }

    [Fact]
    public void ConstantTimeArrayEquals_DifferentLengths_ReturnsFalse()
    {
        var a = new byte[] { 1, 2, 3 };
        var b = new byte[] { 1, 2, 3, 4 };

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.False(result);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]  // Exactly one SSE2 chunk
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]  // Exactly one AVX2 chunk
    [InlineData(33)]
    [InlineData(40)]  // One AVX2 chunk + partial SSE2
    [InlineData(48)]  // One AVX2 chunk + one SSE2 chunk
    [InlineData(50)]  // One AVX2 chunk + one SSE2 chunk + remainder
    [InlineData(64)]  // Two AVX2 chunks
    [InlineData(100)]
    [InlineData(256)]
    public void ConstantTimeArrayEquals_EqualArrays_ReturnsTrue(int size)
    {
        var a = new byte[size];
        var b = new byte[size];

        // Fill with same pattern
        for (var i = 0; i < size; i++)
        {
            a[i] = (byte)(i % 256);
            b[i] = (byte)(i % 256);
        }

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.True(result);
    }

    [Theory]
    [InlineData(1, 0)]    // Single byte, differ at start
    [InlineData(16, 0)]   // SSE2 chunk, differ at start
    [InlineData(16, 15)]  // SSE2 chunk, differ at end
    [InlineData(32, 0)]   // AVX2 chunk, differ at start
    [InlineData(32, 31)]  // AVX2 chunk, differ at end
    [InlineData(40, 32)]  // AVX2+SSE2, differ in SSE2 portion
    [InlineData(40, 38)]  // AVX2+SSE2, differ in scalar remainder
    [InlineData(48, 40)]  // AVX2+SSE2, differ in SSE2 chunk
    [InlineData(50, 48)]  // AVX2+SSE2+scalar, differ in scalar portion
    public void ConstantTimeArrayEquals_DifferentArrays_ReturnsFalse(int size, int diffPosition)
    {
        var a = new byte[size];
        var b = new byte[size];

        // Fill with same pattern
        for (var i = 0; i < size; i++)
        {
            a[i] = (byte)(i % 256);
            b[i] = (byte)(i % 256);
        }

        // Make one byte different
        b[diffPosition] = (byte)(~b[diffPosition]);

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.False(result);
    }

    [Fact]
    public void ConstantTimeArrayEquals_AllZeros_ReturnsTrue()
    {
        var a = new byte[64];
        var b = new byte[64];

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.True(result);
    }

    [Fact]
    public void ConstantTimeArrayEquals_AllOnes_ReturnsTrue()
    {
        var a = Enumerable.Repeat((byte)0xFF, 64).ToArray();
        var b = Enumerable.Repeat((byte)0xFF, 64).ToArray();

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.True(result);
    }

    #endregion

    #region ConditionalCopy Tests

    [Fact]
    public void ConditionalCopy_ConditionOne_CopiesData()
    {
        var source = new byte[] { 1, 2, 3, 4, 5 };
        var destination = new byte[] { 10, 20, 30, 40, 50 };

        SimdConstantTimeOperations.ConditionalCopy(1, source, destination, source.Length);

        Assert.Equal(source, destination);
    }

    [Fact]
    public void ConditionalCopy_ConditionZero_DoesNotCopy()
    {
        var source = new byte[] { 1, 2, 3, 4, 5 };
        var destination = new byte[] { 10, 20, 30, 40, 50 };
        var original = destination.ToArray();

        SimdConstantTimeOperations.ConditionalCopy(0, source, destination, source.Length);

        Assert.Equal(original, destination);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(48)]
    [InlineData(64)]
    [InlineData(100)]
    public void ConditionalCopy_ConditionOne_VariousSizes_CopiesData(int size)
    {
        var source = new byte[size];
        var destination = new byte[size];

        // Fill source with pattern
        for (var i = 0; i < size; i++)
        {
            source[i] = (byte)((i + 1) % 256);
            destination[i] = 0;
        }

        SimdConstantTimeOperations.ConditionalCopy(1, source, destination, size);

        Assert.Equal(source, destination);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(48)]
    [InlineData(64)]
    public void ConditionalCopy_ConditionZero_VariousSizes_PreservesDestination(int size)
    {
        var source = new byte[size];
        var destination = new byte[size];

        // Fill with different patterns
        for (var i = 0; i < size; i++)
        {
            source[i] = (byte)((i + 1) % 256);
            destination[i] = (byte)((255 - i) % 256);
        }

        var original = destination.ToArray();

        SimdConstantTimeOperations.ConditionalCopy(0, source, destination, size);

        Assert.Equal(original, destination);
    }

    [Fact]
    public void ConditionalCopy_PartialLength_OnlyCopiesSpecifiedBytes()
    {
        var source = new byte[] { 1, 2, 3, 4, 5 };
        var destination = new byte[] { 10, 20, 30, 40, 50 };

        SimdConstantTimeOperations.ConditionalCopy(1, source, destination, 3);

        Assert.Equal(new byte[] { 1, 2, 3, 40, 50 }, destination);
    }

    [Fact]
    public void ConditionalCopy_NegativeLength_ThrowsArgumentException()
    {
        var source = new byte[] { 1, 2, 3 };
        var destination = new byte[] { 1, 2, 3 };

        Assert.Throws<ArgumentException>(() =>
            SimdConstantTimeOperations.ConditionalCopy(1, source, destination, -1));
    }

    [Fact]
    public void ConditionalCopy_LengthExceedsSource_ThrowsArgumentException()
    {
        var source = new byte[] { 1, 2, 3 };
        var destination = new byte[] { 1, 2, 3, 4, 5 };

        Assert.Throws<ArgumentException>(() =>
            SimdConstantTimeOperations.ConditionalCopy(1, source, destination, 5));
    }

    [Fact]
    public void ConditionalCopy_ConditionNormalized_TreatsNonZeroAsOne()
    {
        var source = new byte[] { 1, 2, 3, 4, 5 };
        var destination = new byte[] { 10, 20, 30, 40, 50 };

        // Pass condition value > 1, should be normalized to 1
        SimdConstantTimeOperations.ConditionalCopy(255, source, destination, source.Length);

        Assert.Equal(source, destination);
    }

    #endregion

    #region SecureClear Tests

    [Fact]
    public void SecureClear_EmptySpan_DoesNotThrow()
    {
        var data = Array.Empty<byte>();

        var exception = Record.Exception(() => SimdConstantTimeOperations.SecureClear(data));

        Assert.Null(exception);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(48)]
    [InlineData(64)]
    [InlineData(100)]
    public void SecureClear_VariousSizes_ClearsAllBytes(int size)
    {
        var data = new byte[size];

        // Fill with non-zero pattern
        for (var i = 0; i < size; i++)
        {
            data[i] = (byte)((i + 1) % 256);
        }

        SimdConstantTimeOperations.SecureClear(data);

        Assert.All(data, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SecureClear_AlreadyZero_RemainsZero()
    {
        var data = new byte[64];

        SimdConstantTimeOperations.SecureClear(data);

        Assert.All(data, b => Assert.Equal(0, b));
    }

    #endregion

    #region XorArrays Tests

    [Fact]
    public void XorArrays_EmptyArrays_DoesNotThrow()
    {
        var a = Array.Empty<byte>();
        var b = Array.Empty<byte>();
        var result = Array.Empty<byte>();

        var exception = Record.Exception(() => SimdConstantTimeOperations.XorArrays(a, b, result));

        Assert.Null(exception);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(48)]
    [InlineData(64)]
    [InlineData(100)]
    public void XorArrays_VariousSizes_ComputesCorrectXor(int size)
    {
        var a = new byte[size];
        var b = new byte[size];
        var result = new byte[size];
        var expected = new byte[size];

        // Fill with patterns
        for (var i = 0; i < size; i++)
        {
            a[i] = (byte)(i % 256);
            b[i] = (byte)((255 - i) % 256);
            expected[i] = (byte)(a[i] ^ b[i]);
        }

        SimdConstantTimeOperations.XorArrays(a, b, result);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void XorArrays_SameArray_ProducesZeros()
    {
        var a = new byte[] { 1, 2, 3, 4, 5 };
        var result = new byte[5];

        SimdConstantTimeOperations.XorArrays(a, a, result);

        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public void XorArrays_WithZeros_ReturnsOtherArray()
    {
        var a = new byte[] { 1, 2, 3, 4, 5 };
        var zeros = new byte[5];
        var result = new byte[5];

        SimdConstantTimeOperations.XorArrays(a, zeros, result);

        Assert.Equal(a, result);
    }

    [Fact]
    public void XorArrays_InPlace_WorksCorrectly()
    {
        var a = new byte[] { 1, 2, 3, 4, 5 };
        var b = new byte[] { 5, 4, 3, 2, 1 };
        var expected = new byte[] { 4, 6, 0, 6, 4 };

        // XOR in place (result is same as a)
        SimdConstantTimeOperations.XorArrays(a, b, a);

        Assert.Equal(expected, a);
    }

    [Fact]
    public void XorArrays_DifferentLengths_ThrowsArgumentException()
    {
        var a = new byte[] { 1, 2, 3 };
        var b = new byte[] { 1, 2, 3, 4 };
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => SimdConstantTimeOperations.XorArrays(a, b, result));
    }

    [Fact]
    public void XorArrays_ResultTooSmall_ThrowsArgumentException()
    {
        var a = new byte[] { 1, 2, 3, 4, 5 };
        var b = new byte[] { 1, 2, 3, 4, 5 };
        var result = new byte[3];

        Assert.Throws<ArgumentException>(() => SimdConstantTimeOperations.XorArrays(a, b, result));
    }

    #endregion

    #region IsAvailable Tests

    [Fact]
    public void IsAvailable_ReturnsConsistentValue()
    {
        // Call multiple times to ensure consistency
        var result1 = SimdConstantTimeOperations.IsAvailable;
        var result2 = SimdConstantTimeOperations.IsAvailable;

        Assert.Equal(result1, result2);
    }

    #endregion

    #region Regression Tests for Fixed Bugs

    /// <summary>
    /// Regression test: ConditionalCopy fallback was not modifying the destination
    /// because it called ToArray() which created a copy
    /// </summary>
    [Fact]
    public void ConditionalCopy_Regression_FallbackActuallyModifiesDestination()
    {
        // Use a small array that won't use SIMD path on platforms where SIMD is available
        // but will test the scalar fallback on platforms where SIMD is not available
        var source = new byte[] { 0xAA, 0xBB, 0xCC };
        var destination = new byte[] { 0x11, 0x22, 0x33 };

        SimdConstantTimeOperations.ConditionalCopy(1, source, destination, 3);

        // This would have failed before the fix because destination wasn't modified
        Assert.Equal(0xAA, destination[0]);
        Assert.Equal(0xBB, destination[1]);
        Assert.Equal(0xCC, destination[2]);
    }

    /// <summary>
    /// Regression test: ConstantTimeArrayEquals was not combining SSE2 accumulator
    /// when AVX2 was also used, causing incorrect results for arrays 32-47 bytes
    /// </summary>
    [Theory]
    [InlineData(33)]  // 32 bytes AVX2 + 1 byte scalar
    [InlineData(40)]  // 32 bytes AVX2 + 8 bytes scalar
    [InlineData(47)]  // 32 bytes AVX2 + 15 bytes scalar
    [InlineData(48)]  // 32 bytes AVX2 + 16 bytes SSE2
    [InlineData(49)]  // 32 bytes AVX2 + 16 bytes SSE2 + 1 byte scalar
    public void ConstantTimeArrayEquals_Regression_DetectsDifferenceInSse2Range(int size)
    {
        var a = new byte[size];
        var b = new byte[size];

        // Fill with same pattern
        for (var i = 0; i < size; i++)
        {
            a[i] = (byte)(i % 256);
            b[i] = (byte)(i % 256);
        }

        // Make a difference in the SSE2/scalar range (after the first 32 bytes)
        var diffPosition = 35;
        if (diffPosition < size)
        {
            b[diffPosition] = (byte)~b[diffPosition];

            var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

            // This would have incorrectly returned true before the fix
            Assert.False(result);
        }
    }

    /// <summary>
    /// Regression test: Ensure difference at position 32-47 is detected
    /// This specifically tests the SSE2 accumulator combination bug
    /// </summary>
    [Fact]
    public void ConstantTimeArrayEquals_Regression_DifferenceAtByte40_Detected()
    {
        var a = new byte[48];
        var b = new byte[48];

        // Fill with same values
        for (var i = 0; i < 48; i++)
        {
            a[i] = (byte)i;
            b[i] = (byte)i;
        }

        // Change byte 40 (in the SSE2 range after AVX2 processing)
        b[40] = 0xFF;

        var result = SimdConstantTimeOperations.ConstantTimeArrayEquals(a, b);

        Assert.False(result);
    }

    #endregion
}
