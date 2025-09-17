using System;
using System.Runtime.CompilerServices;

#if NET5_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace HeroCrypt.Security;

/// <summary>
/// SIMD-optimized constant-time operations for enhanced performance while maintaining security
/// These operations use vectorized instructions to process multiple values simultaneously
/// while preserving constant-time execution characteristics
/// </summary>
public static class SimdConstantTimeOperations
{
    /// <summary>
    /// Checks if SIMD acceleration is available
    /// </summary>
#if NET5_0_OR_GREATER
    public static bool IsAvailable => Avx2.IsSupported || Sse2.IsSupported;
#else
    public static bool IsAvailable => false;
#endif

    /// <summary>
    /// SIMD-optimized constant-time array comparison
    /// Processes 32 bytes at a time using AVX2 or 16 bytes using SSE2
    /// </summary>
    /// <param name="a">First array</param>
    /// <param name="b">Second array</param>
    /// <returns>True if arrays are equal, false otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool ConstantTimeArrayEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
            return false;

        if (a.Length == 0)
            return true;

#if NET5_0_OR_GREATER
        if (IsAvailable)
        {
            return ConstantTimeArrayEqualsSimd(a, b);
        }
#endif

        // Fallback to scalar implementation
        return ConstantTimeOperations.ConstantTimeArrayEquals(a.ToArray(), b.ToArray()) == 1;
    }

#if NET5_0_OR_GREATER
    /// <summary>
    /// SIMD implementation of constant-time array comparison
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static unsafe bool ConstantTimeArrayEqualsSimd(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var length = a.Length;
        var offset = 0;

        fixed (byte* ptrA = a)
        fixed (byte* ptrB = b)
        {
            Vector256<byte> accumulator256 = Vector256<byte>.Zero;
            Vector128<byte> accumulator128 = Vector128<byte>.Zero;

            // Process 32-byte chunks with AVX2 if available
            if (Avx2.IsSupported && length >= 32)
            {
                var chunks = length / 32;
                for (var i = 0; i < chunks; i++)
                {
                    var vecA = Avx.LoadVector256(ptrA + offset);
                    var vecB = Avx.LoadVector256(ptrB + offset);
                    var diff = Avx2.Xor(vecA, vecB);
                    accumulator256 = Avx2.Or(accumulator256, diff);
                    offset += 32;
                }
            }

            // Process 16-byte chunks with SSE2
            if (Sse2.IsSupported && (length - offset) >= 16)
            {
                var chunks = (length - offset) / 16;
                for (var i = 0; i < chunks; i++)
                {
                    var vecA = Sse2.LoadVector128(ptrA + offset);
                    var vecB = Sse2.LoadVector128(ptrB + offset);
                    var diff = Sse2.Xor(vecA, vecB);
                    accumulator128 = Sse2.Or(accumulator128, diff);
                    offset += 16;
                }
            }

            // Process remaining bytes
            byte scalarAccumulator = 0;
            for (var i = offset; i < length; i++)
            {
                scalarAccumulator |= (byte)(ptrA[i] ^ ptrB[i]);
            }

            // Combine all accumulators
            var result256 = Vector256<byte>.Zero;
            var result128 = Vector128<byte>.Zero;

            if (Avx2.IsSupported)
            {
                result256 = accumulator256;
                // Extract high and low 128-bit parts and combine
                var high = Avx2.ExtractVector128(result256, 1);
                var low = Avx2.ExtractVector128(result256, 0);
                result128 = Sse2.Or(high, low);
            }
            else
            {
                result128 = accumulator128;
            }

            // Reduce 128-bit result to scalar
            if (Sse2.IsSupported)
            {
                // Horizontal OR reduction
                var temp = Sse2.Or(result128, Sse2.ShiftRightLogical128BitLane(result128, 8));
                temp = Sse2.Or(temp, Sse2.ShiftRightLogical128BitLane(temp, 4));
                temp = Sse2.Or(temp, Sse2.ShiftRightLogical128BitLane(temp, 2));
                temp = Sse2.Or(temp, Sse2.ShiftRightLogical128BitLane(temp, 1));

                var finalResult = Sse2.Extract(temp.AsUInt16(), 0);
                return (finalResult | scalarAccumulator) == 0;
            }

            return scalarAccumulator == 0;
        }
    }
#endif

    /// <summary>
    /// SIMD-optimized constant-time conditional copy
    /// Copies data from source to destination if condition is true (1), does nothing if false (0)
    /// </summary>
    /// <param name="condition">Condition mask (0 or 1)</param>
    /// <param name="source">Source array</param>
    /// <param name="destination">Destination array</param>
    /// <param name="length">Number of bytes to potentially copy</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ConditionalCopy(byte condition, ReadOnlySpan<byte> source, Span<byte> destination, int length)
    {
        if (length < 0)
            throw new ArgumentException("Length cannot be negative", nameof(length));
        if (source.Length < length || destination.Length < length)
            throw new ArgumentException("Arrays are too small for the specified length");

        // Ensure condition is 0 or 1
        condition = (byte)(condition & 1);

#if NET5_0_OR_GREATER
        if (IsAvailable && length >= 16)
        {
            ConditionalCopySimd(condition, source, destination, length);
            return;
        }
#endif

        // Fallback to scalar implementation
        ConstantTimeOperations.ConditionalCopy(condition, source.ToArray(), destination.ToArray(), length);
    }

#if NET5_0_OR_GREATER
    /// <summary>
    /// SIMD implementation of conditional copy
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static unsafe void ConditionalCopySimd(byte condition, ReadOnlySpan<byte> source, Span<byte> destination, int length)
    {
        var offset = 0;

        // Create condition mask for SIMD operations
        var conditionMask256 = Vector256.Create((byte)(-(sbyte)condition));
        var conditionMask128 = Vector128.Create((byte)(-(sbyte)condition));

        fixed (byte* ptrSrc = source)
        fixed (byte* ptrDst = destination)
        {
            // Process 32-byte chunks with AVX2
            if (Avx2.IsSupported && length >= 32)
            {
                var chunks = length / 32;
                for (var i = 0; i < chunks; i++)
                {
                    var srcVec = Avx.LoadVector256(ptrSrc + offset);
                    var dstVec = Avx.LoadVector256(ptrDst + offset);

                    // Conditional select: (condition & src) | (~condition & dst)
                    var selected = Avx2.Or(
                        Avx2.And(conditionMask256, srcVec),
                        Avx2.AndNot(conditionMask256, dstVec)
                    );

                    Avx.Store(ptrDst + offset, selected);
                    offset += 32;
                }
            }

            // Process 16-byte chunks with SSE2
            if (Sse2.IsSupported && (length - offset) >= 16)
            {
                var chunks = (length - offset) / 16;
                for (var i = 0; i < chunks; i++)
                {
                    var srcVec = Sse2.LoadVector128(ptrSrc + offset);
                    var dstVec = Sse2.LoadVector128(ptrDst + offset);

                    // Conditional select: (condition & src) | (~condition & dst)
                    var selected = Sse2.Or(
                        Sse2.And(conditionMask128, srcVec),
                        Sse2.AndNot(conditionMask128, dstVec)
                    );

                    Sse2.Store(ptrDst + offset, selected);
                    offset += 16;
                }
            }

            // Process remaining bytes with scalar operations
            var mask = (byte)(-(sbyte)condition);
            for (var i = offset; i < length; i++)
            {
                ptrDst[i] = (byte)((ptrSrc[i] & mask) | (ptrDst[i] & ~mask));
            }
        }
    }
#endif

    /// <summary>
    /// SIMD-optimized constant-time memory clearing
    /// Securely clears memory using vectorized operations
    /// </summary>
    /// <param name="data">Memory span to clear</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void SecureClear(Span<byte> data)
    {
        if (data.Length == 0)
            return;

#if NET5_0_OR_GREATER
        if (IsAvailable && data.Length >= 16)
        {
            SecureClearSimd(data);
            return;
        }
#endif

        // Fallback to scalar clearing
        SecureMemoryOperations.SecureClear(data);
    }

#if NET5_0_OR_GREATER
    /// <summary>
    /// SIMD implementation of secure memory clearing
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static unsafe void SecureClearSimd(Span<byte> data)
    {
        var length = data.Length;
        var offset = 0;

        var zero256 = Vector256<byte>.Zero;
        var zero128 = Vector128<byte>.Zero;

        fixed (byte* ptr = data)
        {
            // Clear 32-byte chunks with AVX2
            if (Avx2.IsSupported && length >= 32)
            {
                var chunks = length / 32;
                for (var i = 0; i < chunks; i++)
                {
                    Avx.Store(ptr + offset, zero256);
                    offset += 32;
                }
            }

            // Clear 16-byte chunks with SSE2
            if (Sse2.IsSupported && (length - offset) >= 16)
            {
                var chunks = (length - offset) / 16;
                for (var i = 0; i < chunks; i++)
                {
                    Sse2.Store(ptr + offset, zero128);
                    offset += 16;
                }
            }

            // Clear remaining bytes
            for (var i = offset; i < length; i++)
            {
                ptr[i] = 0;
            }
        }

        // Memory barrier to prevent compiler optimization
        System.Threading.Thread.MemoryBarrier();
    }
#endif

    /// <summary>
    /// SIMD-optimized XOR operation for large arrays
    /// Performs constant-time XOR of two arrays using vectorized instructions
    /// </summary>
    /// <param name="a">First array</param>
    /// <param name="b">Second array</param>
    /// <param name="result">Result array (can be same as input arrays)</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void XorArrays(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        if (a.Length != b.Length || a.Length != result.Length)
            throw new ArgumentException("All arrays must have the same length");

        if (a.Length == 0)
            return;

#if NET5_0_OR_GREATER
        if (IsAvailable && a.Length >= 16)
        {
            XorArraysSimd(a, b, result);
            return;
        }
#endif

        // Fallback to scalar XOR
        for (var i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
    }

#if NET5_0_OR_GREATER
    /// <summary>
    /// SIMD implementation of array XOR
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static unsafe void XorArraysSimd(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        var length = a.Length;
        var offset = 0;

        fixed (byte* ptrA = a)
        fixed (byte* ptrB = b)
        fixed (byte* ptrResult = result)
        {
            // Process 32-byte chunks with AVX2
            if (Avx2.IsSupported && length >= 32)
            {
                var chunks = length / 32;
                for (var i = 0; i < chunks; i++)
                {
                    var vecA = Avx.LoadVector256(ptrA + offset);
                    var vecB = Avx.LoadVector256(ptrB + offset);
                    var xorResult = Avx2.Xor(vecA, vecB);
                    Avx.Store(ptrResult + offset, xorResult);
                    offset += 32;
                }
            }

            // Process 16-byte chunks with SSE2
            if (Sse2.IsSupported && (length - offset) >= 16)
            {
                var chunks = (length - offset) / 16;
                for (var i = 0; i < chunks; i++)
                {
                    var vecA = Sse2.LoadVector128(ptrA + offset);
                    var vecB = Sse2.LoadVector128(ptrB + offset);
                    var xorResult = Sse2.Xor(vecA, vecB);
                    Sse2.Store(ptrResult + offset, xorResult);
                    offset += 16;
                }
            }

            // Process remaining bytes
            for (var i = offset; i < length; i++)
            {
                ptrResult[i] = (byte)(ptrA[i] ^ ptrB[i]);
            }
        }
    }
#endif
}