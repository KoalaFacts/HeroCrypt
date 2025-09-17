using System;
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
        condition = (byte)(condition & 1);

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
        condition = condition & 1;

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
        condition = condition & 1;

        // Create mask: 0xFFFFFFFF if condition is 1, 0x00000000 if condition is 0
        var mask = (uint)(-(int)condition);
        return (trueValue & mask) | (falseValue & ~mask);
    }

    /// <summary>
    /// Performs constant-time conditional swap of two byte arrays
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="a">First array</param>
    /// <param name="b">Second array</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ConditionalSwap(byte condition, byte[] a, byte[] b)
    {
        if (a == null)
            throw new ArgumentNullException(nameof(a));
        if (b == null)
            throw new ArgumentNullException(nameof(b));
        if (a.Length != b.Length)
            throw new ArgumentException("Arrays must have the same length");

        // Ensure condition is 0 or 1
        condition = (byte)(condition & 1);
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
        return (uint)(1 & ((diff - 1) >> 31));
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
    public static byte ValidatePkcs1Padding(byte[] paddedMessage, int expectedLength)
    {
        if (paddedMessage == null)
            return 0;

        if (paddedMessage.Length < 11) // Minimum padding length
            return 0;

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
    /// Performs constant-time modular reduction for small moduli
    /// </summary>
    /// <param name="value">Value to reduce</param>
    /// <param name="modulus">Modulus</param>
    /// <returns>value mod modulus</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static uint ConstantTimeModulo(uint value, uint modulus)
    {
        if (modulus == 0)
            throw new ArgumentException("Modulus cannot be zero", nameof(modulus));

        // Simple constant-time modular reduction for small values
        // For larger values, use Montgomery reduction or Barrett reduction

        var result = value;
        for (var i = 0; i < 32; i++) // Maximum iterations for 32-bit values
        {
            var needsReduction = ConstantTimeLessThan(modulus - 1, result);
            result = ConditionalSelect(needsReduction, result - modulus, result);
        }

        return result;
    }

    /// <summary>
    /// Performs constant-time array copying with conditional execution
    /// </summary>
    /// <param name="condition">Condition value (0 or 1)</param>
    /// <param name="source">Source array</param>
    /// <param name="destination">Destination array</param>
    /// <param name="length">Number of bytes to copy</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void ConditionalCopy(byte condition, byte[] source, byte[] destination, int length)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));
        if (destination == null)
            throw new ArgumentNullException(nameof(destination));
        if (length < 0)
            throw new ArgumentException("Length cannot be negative", nameof(length));
        if (source.Length < length || destination.Length < length)
            throw new ArgumentException("Arrays are too small for the specified length");

        // Ensure condition is 0 or 1
        condition = (byte)(condition & 1);
        var mask = (byte)(-(sbyte)condition);

        for (var i = 0; i < length; i++)
        {
            destination[i] = ConditionalSelect(condition, source[i], destination[i]);
        }
    }

    /// <summary>
    /// Performs constant-time byte array comparison
    /// </summary>
    /// <param name="a">First array</param>
    /// <param name="b">Second array</param>
    /// <returns>1 if arrays are equal, 0 otherwise</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConstantTimeArrayEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null)
            return (byte)(a == b ? 1 : 0);

        if (a.Length != b.Length)
            return 0;

        byte result = 1;
        for (var i = 0; i < a.Length; i++)
        {
            result &= ConstantTimeEquals(a[i], b[i]);
        }

        return result;
    }

    /// <summary>
    /// Performs constant-time lookup in a byte array
    /// </summary>
    /// <param name="array">Array to search in</param>
    /// <param name="index">Index to lookup</param>
    /// <returns>Value at the specified index</returns>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte ConstantTimeLookup(byte[] array, int index)
    {
        if (array == null)
            throw new ArgumentNullException(nameof(array));
        if (index < 0 || index >= array.Length)
            throw new ArgumentOutOfRangeException(nameof(index));

        byte result = 0;
        for (var i = 0; i < array.Length; i++)
        {
            var isTarget = ConstantTimeEquals((uint)i, (uint)index);
            result = ConditionalSelect((byte)isTarget, array[i], result);
        }

        return result;
    }
}