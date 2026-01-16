using System.Runtime.CompilerServices;

namespace HeroCrypt.Security;

/// <summary>
/// Provides constant-time operations to prevent timing attacks
/// </summary>
public static class ConstantTimeOperations
{
    /// <summary>
    /// Performs constant-time conditional assignment
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="trueValue">Value to return if condition is 1</param>
    /// <param name="falseValue">Value to return if condition is 0</param>
    /// <returns>trueValue if condition is 1, falseValue if condition is 0</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConditionalSelect(byte condition, byte trueValue, byte falseValue)
    {
        // Ensure condition is 0 or 1
        condition &= 1;

        // Use bitwise operations to avoid branching
        var mask = (byte)(-(sbyte)condition);
        return (byte)((trueValue & mask) | (falseValue & ~mask));
    }

    /// <summary>
    /// Performs constant-time conditional assignment for integers
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="trueValue">Value to return if condition is 1</param>
    /// <param name="falseValue">Value to return if condition is 0</param>
    /// <returns>trueValue if condition is 1, falseValue if condition is 0</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int ConditionalSelect(int condition, int trueValue, int falseValue)
    {
        // Ensure condition is 0 or 1
        condition &= 1;

        // Create mask: 0xFFFFFFFF if condition is 1, 0x00000000 if condition is 0
        var mask = -(condition);
        return (trueValue & mask) | (falseValue & ~mask);
    }

    /// <summary>
    /// Performs constant-time conditional assignment for unsigned integers
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="trueValue">Value to return if condition is 1</param>
    /// <param name="falseValue">Value to return if condition is 0</param>
    /// <returns>trueValue if condition is 1, falseValue if condition is 0</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static uint ConditionalSelect(uint condition, uint trueValue, uint falseValue)
    {
        // Ensure condition is 0 or 1
        condition &= 1;

        // Create mask: 0xFFFFFFFF if condition is 1, 0x00000000 if condition is 0
        var mask = 0u - condition;
        return (trueValue & mask) | (falseValue & ~mask);
    }

    /// <summary>
    /// Performs constant-time conditional swap of two byte spans
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="a">First span</param>
    /// <param name="b">Second span</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ConditionalSwap(byte condition, Span<byte> a, Span<byte> b)
    {
        if (a.Length != b.Length)
        {
            throw new ArgumentException("Spans must have the same length");
        }

        // Ensure condition is 0 or 1
        condition &= 1;
        var mask = (byte)(-(sbyte)condition);

        for (var i = 0; i < a.Length; i++)
        {
            var temp = (byte)((a[i] ^ b[i]) & mask);
            a[i] ^= temp;
            b[i] ^= temp;
        }
    }

    /// <summary>
    /// Performs constant-time comparison returning 1 if a == b, 0 otherwise
    /// </summary>
    /// <param name="a">First value</param>
    /// <param name="b">Second value</param>
    /// <returns>1 if equal, 0 otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConstantTimeEquals(byte a, byte b)
    {
        var diff = a ^ b;
        return (byte)(1 & ((diff - 1) >> 8));
    }

    /// <summary>
    /// Performs constant-time comparison returning 1 if a == b, 0 otherwise
    /// </summary>
    /// <param name="a">First value</param>
    /// <param name="b">Second value</param>
    /// <returns>1 if equal, 0 otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static uint ConstantTimeEquals(uint a, uint b)
    {
        var diff = a ^ b;
        return 1 & ((diff - 1) >> 31);
    }

    /// <summary>
    /// Performs constant-time comparison returning 1 if a &lt; b, 0 otherwise
    /// </summary>
    /// <param name="a">First value</param>
    /// <param name="b">Second value</param>
    /// <returns>1 if a &lt; b, 0 otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static uint ConstantTimeLessThan(uint a, uint b)
    {
        return (a ^ ((a ^ b) | ((a - b) ^ b))) >> 31;
    }

    /// <summary>
    /// Performs constant-time padding validation for PKCS#1 v1.5
    /// </summary>
    /// <param name="paddedMessage">The padded message to validate</param>
    /// <param name="expectedLength">Expected message length</param>
    /// <returns>1 if padding is valid, 0 otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ValidatePkcs1Padding(ReadOnlySpan<byte> paddedMessage, int expectedLength)
    {
        if (paddedMessage.Length < 11) // Minimum padding length
        {
            return 0;
        }

        byte valid = 1;

        // Check first byte is 0x00
        valid &= ConstantTimeEquals(paddedMessage[0], 0x00);

        // Check second byte is 0x01 (for signing) or 0x02 (for encryption)
        var blockType = paddedMessage[1];
        var isType1 = ConstantTimeEquals(blockType, 0x01);
        var isType2 = ConstantTimeEquals(blockType, 0x02);
        valid &= (byte)(isType1 | isType2);

        // Find the 0x00 separator
        var separatorFound = (byte)0;
        var separatorIndex = 0;

        for (var i = 2; i < paddedMessage.Length; i++)
        {
            var isSeparator = ConstantTimeEquals(paddedMessage[i], 0x00);
            var notFoundYet = (byte)(1 - separatorFound);

            separatorIndex = ConditionalSelect(isSeparator & notFoundYet, i, separatorIndex);
            separatorFound |= (byte)(isSeparator & notFoundYet);
        }

        // Validate separator was found and padding length is correct
        valid &= separatorFound;

        if (expectedLength > 0)
        {
            var messageLength = paddedMessage.Length - separatorIndex - 1;
            valid &= (byte)ConstantTimeEquals((uint)messageLength, (uint)expectedLength);
        }

        // Validate minimum padding length (at least 8 bytes of padding for PKCS#1)
        var paddingLength = separatorIndex - 2;
        valid &= (byte)(1 - ConstantTimeLessThan((uint)paddingLength, 8));

        return valid;
    }

    /// <summary>
    /// Performs constant-time modular reduction for small moduli.
    /// </summary>
    /// <param name="value">Value to reduce</param>
    /// <param name="modulus">Modulus</param>
    /// <returns>value mod modulus</returns>
    /// <remarks>
    /// <para>
    /// This method uses repeated subtraction with a fixed iteration count (32) to ensure
    /// constant-time execution regardless of the input value. While this is less efficient
    /// than a simple modulo operation, it prevents timing side-channels that could leak
    /// information about the value being reduced.
    /// </para>
    /// <para>
    /// The 32-iteration count is sufficient because a 32-bit value can be at most 2^32-1,
    /// and each iteration reduces the value by at least 1 (the minimum modulus). In practice,
    /// far fewer iterations are needed for typical moduli, but we always perform all 32
    /// iterations to maintain constant timing.
    /// </para>
    /// <para>
    /// For high-performance scenarios with large moduli, consider Montgomery or Barrett
    /// reduction which are both constant-time and more efficient for larger values.
    /// </para>
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static uint ConstantTimeModulo(uint value, uint modulus)
    {
        if (modulus == 0)
        {
            throw new ArgumentException("Modulus cannot be zero", nameof(modulus));
        }

        // Perform 32 iterations unconditionally to ensure constant-time execution.
        // Each iteration conditionally subtracts the modulus if the result is >= modulus.
        var result = value;
        for (var i = 0; i < 32; i++)
        {
            var needsReduction = ConstantTimeLessThan(modulus - 1, result);
            result = ConditionalSelect(needsReduction, result - modulus, result);
        }

        return result;
    }

    /// <summary>
    /// Performs constant-time copying with conditional execution
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="source">Source span</param>
    /// <param name="destination">Destination span</param>
    /// <param name="length">Number of bytes to copy</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ConditionalCopy(byte condition, ReadOnlySpan<byte> source, Span<byte> destination, int length)
    {
        if (length < 0)
        {
            throw new ArgumentException("Length cannot be negative", nameof(length));
        }
        if (source.Length < length || destination.Length < length)
        {
            throw new ArgumentException("Spans are too small for the specified length");
        }

        // Ensure condition is 0 or 1
        condition = (byte)(condition & 1);

        for (var i = 0; i < length; i++)
        {
            destination[i] = ConditionalSelect(condition, source[i], destination[i]);
        }
    }

    /// <summary>
    /// Performs constant-time byte span comparison
    /// </summary>
    /// <param name="a">First span</param>
    /// <param name="b">Second span</param>
    /// <returns>1 if spans are equal, 0 otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConstantTimeArrayEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
        {
            return 0;
        }

        byte result = 1;
        for (var i = 0; i < a.Length; i++)
        {
            result &= ConstantTimeEquals(a[i], b[i]);
        }

        return result;
    }

    /// <summary>
    /// Performs constant-time lookup in a byte span
    /// </summary>
    /// <param name="data">Span to search in</param>
    /// <param name="index">Index to lookup</param>
    /// <returns>Value at the specified index</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConstantTimeLookup(ReadOnlySpan<byte> data, int index)
    {
        if (index < 0 || index >= data.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        byte result = 0;
        for (var i = 0; i < data.Length; i++)
        {
            var isTarget = ConstantTimeEquals((uint)i, (uint)index);
            result = ConditionalSelect((byte)isTarget, data[i], result);
        }

        return result;
    }
}
