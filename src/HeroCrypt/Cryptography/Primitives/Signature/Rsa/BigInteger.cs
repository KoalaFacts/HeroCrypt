using System.Buffers;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;

namespace HeroCrypt.Cryptography.Primitives.Signature.Rsa;

internal sealed class BigInteger : IComparable<BigInteger>
{
    private uint[] dataWords;

    /// <summary>
    /// Represents the value zero.
    /// </summary>
    public static readonly BigInteger Zero = new(0);

    /// <summary>
    /// Represents the value one.
    /// </summary>
    public static readonly BigInteger One = new(1);

    /// <summary>
    /// Initializes a new instance of the <see cref="BigInteger"/> class from a 64-bit signed integer.
    /// </summary>
    /// <param name="value">The 64-bit signed integer value.</param>
    public BigInteger(long value)
    {
        if (value == 0)
        {
            dataWords = [0];
            Sign = 0;
        }
        else if (value > 0)
        {
            dataWords = [(uint)value, (uint)(value >> 32)];
            Sign = 1;
        }
        else
        {
            value = -value;
            dataWords = [(uint)value, (uint)(value >> 32)];
            Sign = -1;
        }

        Normalize();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BigInteger"/> class from a byte array in big-endian format.
    /// </summary>
    /// <param name="bytes">The byte array representing the value in big-endian format.</param>
    public BigInteger(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0)
        {
            dataWords = [0];
            Sign = 0;
            return;
        }

        int wordCount = (bytes.Length + 3) / 4;
        dataWords = new uint[wordCount];

        for (int i = 0; i < bytes.Length; i++)
        {
            dataWords[i / 4] |= (uint)(bytes[bytes.Length - 1 - i] << (i % 4 * 8));
        }

        Sign = 1;
        Normalize();
    }

    private BigInteger(uint[] data, int sign)
    {
        dataWords = data;
        Sign = sign;
        Normalize();
    }

    /// <summary>
    /// Gets a value indicating whether this instance represents zero.
    /// </summary>
    public bool IsZero => Sign == 0;

    /// <summary>
    /// Gets a value indicating whether this instance represents one.
    /// </summary>
    public bool IsOne => Sign == 1 && dataWords.Length == 1 && dataWords[0] == 1;

    /// <summary>
    /// Gets the sign of the value: -1 for negative, 0 for zero, 1 for positive.
    /// </summary>
    public int Sign { get; private set; }

    /// <summary>
    /// Converts this <see cref="BigInteger"/> to a byte array in big-endian format.
    /// </summary>
    /// <returns>A byte array representing the value in big-endian format.</returns>
    public byte[] ToByteArray()
    {
        if (IsZero)
        {
            return [0];
        }

        var bytes = new List<byte>();
        uint[] data = (uint[])dataWords.Clone();

        for (int i = 0; i < data.Length; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                bytes.Add((byte)(data[i] & 0xFF));
                data[i] >>= 8;
            }
        }

        while (bytes.Count > 1 && bytes[^1] == 0)
        {
            bytes.RemoveAt(bytes.Count - 1);
        }

        bytes.Reverse();
        return [.. bytes];
    }

    /// <summary>
    /// Adds two <see cref="BigInteger"/> values.
    /// </summary>
    /// <param name="left">The first value to add.</param>
    /// <param name="right">The second value to add.</param>
    /// <returns>The sum of the two values.</returns>
    public static BigInteger operator +(BigInteger left, BigInteger right)
    {
        if (left.IsZero)
        {
            return right;
        }
        if (right.IsZero)
        {
            return left;
        }

        if (left.Sign == right.Sign)
        {
            return new BigInteger(Add(left.dataWords, right.dataWords), left.Sign);
        }

        int cmp = CompareAbs(left.dataWords, right.dataWords);
        return cmp == 0
            ? Zero
            : cmp > 0
            ? new BigInteger(Subtract(left.dataWords, right.dataWords), left.Sign)
            : new BigInteger(Subtract(right.dataWords, left.dataWords), right.Sign);
    }

    /// <summary>
    /// Subtracts one <see cref="BigInteger"/> value from another.
    /// </summary>
    /// <param name="left">The value to subtract from.</param>
    /// <param name="right">The value to subtract.</param>
    /// <returns>The result of the subtraction.</returns>
    public static BigInteger operator -(BigInteger left, BigInteger right)
    {
        return left + new BigInteger(right.dataWords, -right.Sign);
    }

    /// <summary>
    /// Multiplies two <see cref="BigInteger"/> values.
    /// </summary>
    /// <param name="left">The first value to multiply.</param>
    /// <param name="right">The second value to multiply.</param>
    /// <returns>The product of the two values.</returns>
    public static BigInteger operator *(BigInteger left, BigInteger right)
    {
        if (left.IsZero || right.IsZero)
        {
            return Zero;
        }

        uint[] result = Multiply(left.dataWords, right.dataWords);
        return new BigInteger(result, left.Sign * right.Sign);
    }

    /// <summary>
    /// Divides one <see cref="BigInteger"/> value by another.
    /// </summary>
    /// <param name="dividend">The value to be divided.</param>
    /// <param name="divisor">The value to divide by.</param>
    /// <returns>The quotient of the division.</returns>
    /// <exception cref="DivideByZeroException">Thrown when divisor is zero.</exception>
    public static BigInteger operator /(BigInteger dividend, BigInteger divisor)
    {
        if (divisor.IsZero)
        {
            throw new DivideByZeroException();
        }
        if (dividend.IsZero)
        {
            return Zero;
        }

        (uint[]? quotient, uint[] _) = DivideWithRemainder(dividend.dataWords, divisor.dataWords);
        return new BigInteger(quotient, dividend.Sign * divisor.Sign);
    }

    /// <summary>
    /// Computes the remainder when dividing one <see cref="BigInteger"/> value by another.
    /// </summary>
    /// <param name="dividend">The value to be divided.</param>
    /// <param name="divisor">The value to divide by.</param>
    /// <returns>The remainder of the division.</returns>
    /// <exception cref="DivideByZeroException">Thrown when divisor is zero.</exception>
    public static BigInteger operator %(BigInteger dividend, BigInteger divisor)
    {
        if (divisor.IsZero)
        {
            throw new DivideByZeroException();
        }
        if (dividend.IsZero)
        {
            return Zero;
        }

        (uint[] _, uint[]? remainder) = DivideWithRemainder(dividend.dataWords, divisor.dataWords);
        return new BigInteger(remainder, dividend.Sign);
    }

    /// <summary>
    /// Determines whether two <see cref="BigInteger"/> values are equal.
    /// </summary>
    /// <param name="left">The first value to compare.</param>
    /// <param name="right">The second value to compare.</param>
    /// <returns>true if the values are equal; otherwise, false.</returns>
    public static bool operator ==(BigInteger left, BigInteger right)
    {
        return ReferenceEquals(left, right) || (left is not null && right is not null && left.Sign == right.Sign && CompareAbs(left.dataWords, right.dataWords) == 0);
    }

    /// <summary>
    /// Determines whether two <see cref="BigInteger"/> values are not equal.
    /// </summary>
    /// <param name="left">The first value to compare.</param>
    /// <param name="right">The second value to compare.</param>
    /// <returns>true if the values are not equal; otherwise, false.</returns>
    public static bool operator !=(BigInteger left, BigInteger right)
    {
        return !(left == right);
    }

    /// <summary>
    /// Determines whether one <see cref="BigInteger"/> value is less than another.
    /// </summary>
    /// <param name="left">The first value to compare.</param>
    /// <param name="right">The second value to compare.</param>
    /// <returns>true if left is less than right; otherwise, false.</returns>
    public static bool operator <(BigInteger left, BigInteger right)
    {
        return left.CompareTo(right) < 0;
    }

    /// <summary>
    /// Determines whether one <see cref="BigInteger"/> value is greater than another.
    /// </summary>
    /// <param name="left">The first value to compare.</param>
    /// <param name="right">The second value to compare.</param>
    /// <returns>true if left is greater than right; otherwise, false.</returns>
    public static bool operator >(BigInteger left, BigInteger right)
    {
        return left.CompareTo(right) > 0;
    }

    /// <summary>
    /// Determines whether one <see cref="BigInteger"/> value is less than or equal to another.
    /// </summary>
    /// <param name="left">The first value to compare.</param>
    /// <param name="right">The second value to compare.</param>
    /// <returns>true if left is less than or equal to right; otherwise, false.</returns>
    public static bool operator <=(BigInteger left, BigInteger right)
    {
        return left.CompareTo(right) <= 0;
    }

    /// <summary>
    /// Determines whether one <see cref="BigInteger"/> value is greater than or equal to another.
    /// </summary>
    /// <param name="left">The first value to compare.</param>
    /// <param name="right">The second value to compare.</param>
    /// <returns>true if left is greater than or equal to right; otherwise, false.</returns>
    public static bool operator >=(BigInteger left, BigInteger right)
    {
        return left.CompareTo(right) >= 0;
    }

    /// <summary>
    /// Compares this instance to another <see cref="BigInteger"/> and returns an indication of their relative values.
    /// </summary>
    /// <param name="other">The value to compare to this instance.</param>
    /// <returns>A value less than 0 if this instance is less than other; 0 if equal; greater than 0 if greater.</returns>
    public int CompareTo(BigInteger? other)
    {
        if (other is null)
        {
            return 1;
        }
        if (Sign != other.Sign)
        {
            return Sign.CompareTo(other.Sign);
        }
        if (Sign == 0)
        {
            return 0;
        }

        int cmp = CompareAbs(dataWords, other.dataWords);
        return Sign > 0 ? cmp : -cmp;
    }

    /// <summary>
    /// Performs modular exponentiation: (this ^ exponent) mod modulus.
    /// </summary>
    /// <param name="exponent">The exponent.</param>
    /// <param name="modulus">The modulus.</param>
    /// <returns>The result of the modular exponentiation.</returns>
    /// <exception cref="DivideByZeroException">Thrown when modulus is zero.</exception>
    /// <exception cref="ArgumentException">Thrown when exponent is negative.</exception>
    public BigInteger ModPow(BigInteger exponent, BigInteger modulus)
    {
        if (modulus.IsZero)
        {
            throw new DivideByZeroException();
        }
        if (exponent.Sign < 0)
        {
            throw new ArgumentException("Negative exponent not supported");
        }

        BigInteger result = One;
        BigInteger baseValue = this % modulus;
        BigInteger exp = exponent;

        while (!exp.IsZero)
        {
            if ((exp.dataWords[0] & 1) == 1)
            {
                result = result * baseValue % modulus;
            }

            baseValue = baseValue * baseValue % modulus;
            exp >>= 1;
        }

        return result;
    }

    /// <summary>
    /// Computes the modular multiplicative inverse of this value modulo the specified modulus using the extended Euclidean algorithm.
    /// </summary>
    /// <param name="modulus">The modulus.</param>
    /// <returns>The modular multiplicative inverse.</returns>
    /// <exception cref="DivideByZeroException">Thrown when modulus is zero.</exception>
    /// <exception cref="ArgumentException">Thrown when the value and modulus are not coprime.</exception>
    public BigInteger ModInverse(BigInteger modulus)
    {
        if (modulus.IsZero)
        {
            throw new DivideByZeroException();
        }

        BigInteger m0 = modulus;
        BigInteger a = this % modulus;

        if (a.IsZero)
        {
            throw new ArgumentException("Value and modulus are not coprime", nameof(modulus));
        }

        BigInteger x0 = Zero;
        BigInteger x1 = One;

        while (!modulus.IsZero)
        {
            BigInteger quotient = a / modulus;
            BigInteger remainder = a % modulus;

            a = modulus;
            modulus = remainder;

            BigInteger temp = x0;
            x0 = x1 - (quotient * x0);
            x1 = temp;
        }

        if (a != One)
        {
            throw new ArgumentException("Value and modulus are not coprime", nameof(modulus));
        }

        if (x1 < Zero)
        {
            x1 += m0;
        }

        return x1;
    }

    /// <summary>
    /// Performs a left bit shift on a <see cref="BigInteger"/> value.
    /// </summary>
    /// <param name="value">The value to shift.</param>
    /// <param name="shift">The number of bits to shift left.</param>
    /// <returns>The result of shifting the value left by the specified number of bits.</returns>
    /// <exception cref="ArgumentException">Thrown when shift is negative.</exception>
    public static BigInteger operator <<(BigInteger value, int shift)
    {
        if (shift < 0)
        {
            throw new ArgumentException("Negative shift");
        }
        if (shift == 0 || value.IsZero)
        {
            return value;
        }

        int wordShift = shift / 32;
        int bitShift = shift % 32;

        int newLength = value.dataWords.Length + wordShift + (bitShift > 0 ? 1 : 0);
        uint[] result = new uint[newLength];

        if (bitShift == 0)
        {
            Array.Copy(value.dataWords, 0, result, wordShift, value.dataWords.Length);
        }
        else
        {
            ulong carry = 0;
            for (int i = 0; i < value.dataWords.Length; i++)
            {
                carry |= (ulong)value.dataWords[i] << bitShift;
                result[i + wordShift] = (uint)carry;
                carry >>= 32;
            }
            if (carry != 0)
            {
                result[value.dataWords.Length + wordShift] = (uint)carry;
            }
        }

        return new BigInteger(result, value.Sign);
    }

    /// <summary>
    /// Performs a right bit shift on a <see cref="BigInteger"/> value.
    /// </summary>
    /// <param name="value">The value to shift.</param>
    /// <param name="shift">The number of bits to shift right.</param>
    /// <returns>The result of shifting the value right by the specified number of bits.</returns>
    /// <exception cref="ArgumentException">Thrown when shift is negative.</exception>
    public static BigInteger operator >>(BigInteger value, int shift)
    {
        if (shift < 0)
        {
            throw new ArgumentException("Negative shift");
        }
        if (shift == 0 || value.IsZero)
        {
            return value;
        }

        int wordShift = shift / 32;
        int bitShift = shift % 32;

        if (wordShift >= value.dataWords.Length)
        {
            return Zero;
        }

        int newLength = value.dataWords.Length - wordShift;
        uint[] result = new uint[newLength];

        if (bitShift == 0)
        {
            Array.Copy(value.dataWords, wordShift, result, 0, newLength);
        }
        else
        {
            ulong carry = 0;
            for (int i = value.dataWords.Length - 1; i >= wordShift; i--)
            {
                carry = ((ulong)value.dataWords[i] << (32 - bitShift)) | (carry >> 32);
                if (i - wordShift < result.Length)
                {
                    result[i - wordShift] = (value.dataWords[i] >> bitShift) | (uint)(carry >> (32 - bitShift));
                }
            }
        }

        return new BigInteger(result, value.Sign);
    }

    private static uint[] Add(uint[] left, uint[] right)
    {
        int maxLength = Math.Max(left.Length, right.Length);
        ArrayPool<uint> pool = ArrayPool<uint>.Shared;
        uint[] result = pool.Rent(maxLength + 1);

        try
        {
            Array.Clear(result, 0, maxLength + 1);
            ulong carry = 0;

            for (int i = 0; i < maxLength; i++)
            {
                uint a = i < left.Length ? left[i] : 0u;
                uint b = i < right.Length ? right[i] : 0u;

                carry += a + (ulong)b;
                result[i] = (uint)carry;
                carry >>= 32;
            }

            if (carry != 0)
            {
                result[maxLength] = (uint)carry;
            }

            int actualLength = carry != 0 ? maxLength + 1 : maxLength;
            uint[] finalResult = new uint[actualLength];
            Array.Copy(result, finalResult, actualLength);
            return finalResult;
        }
        finally
        {
            pool.Return(result);
        }
    }

    private static uint[] Subtract(uint[] left, uint[] right)
    {
        ArrayPool<uint> pool = ArrayPool<uint>.Shared;
        uint[] result = pool.Rent(left.Length);

        try
        {
            Array.Clear(result, 0, left.Length);
            long borrow = 0;

            for (int i = 0; i < left.Length; i++)
            {
                uint a = left[i];
                uint b = i < right.Length ? right[i] : 0u;

                long diff = a - b - borrow;
                if (diff < 0)
                {
                    diff += 0x100000000L;
                    borrow = 1;
                }
                else
                {
                    borrow = 0;
                }

                result[i] = (uint)diff;
            }

            uint[] finalResult = new uint[left.Length];
            Array.Copy(result, finalResult, left.Length);
            return finalResult;
        }
        finally
        {
            pool.Return(result);
        }
    }

    private static uint[] Multiply(uint[] left, uint[] right)
    {
        // Use Karatsuba algorithm for large numbers
        if (left.Length > 32 && right.Length > 32)
        {
            return MultiplyKaratsuba(left, right);
        }

        ArrayPool<uint> pool = ArrayPool<uint>.Shared;
        uint[] result = pool.Rent(left.Length + right.Length);

        try
        {
            Array.Clear(result, 0, left.Length + right.Length);

            for (int i = 0; i < left.Length; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < right.Length; j++)
                {
                    carry += ((ulong)left[i] * right[j]) + result[i + j];
                    result[i + j] = (uint)carry;
                    carry >>= 32;
                }
                result[i + right.Length] = (uint)carry;
            }

            uint[] finalResult = new uint[left.Length + right.Length];
            Array.Copy(result, finalResult, left.Length + right.Length);
            return finalResult;
        }
        finally
        {
            pool.Return(result);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint[] MultiplyKaratsuba(uint[] left, uint[] right)
    {
        // Karatsuba multiplication for better performance with large numbers
        int n = Math.Max(left.Length, right.Length);
        if (n <= 32)
        {
            return Multiply(left, right);
        }

        int half = n / 2;

        // Split the numbers
        uint[] leftLow = new uint[Math.Min(half, left.Length)];
        uint[] leftHigh = new uint[Math.Max(0, left.Length - half)];
        uint[] rightLow = new uint[Math.Min(half, right.Length)];
        uint[] rightHigh = new uint[Math.Max(0, right.Length - half)];

        if (left.Length > 0)
        {
            Array.Copy(left, 0, leftLow, 0, leftLow.Length);
            if (left.Length > half)
            {
                Array.Copy(left, half, leftHigh, 0, leftHigh.Length);
            }
        }

        if (right.Length > 0)
        {
            Array.Copy(right, 0, rightLow, 0, rightLow.Length);
            if (right.Length > half)
            {
                Array.Copy(right, half, rightHigh, 0, rightHigh.Length);
            }
        }

        // Compute three products
        uint[] z0 = Multiply(leftLow, rightLow);
        uint[] z2 = Multiply(leftHigh, rightHigh);

        uint[] leftSum = Add(leftLow, leftHigh);
        uint[] rightSum = Add(rightLow, rightHigh);
        uint[] z1 = Multiply(leftSum, rightSum);
        z1 = Subtract(z1, z0);
        z1 = Subtract(z1, z2);

        // Combine results
        uint[] result = new uint[left.Length + right.Length];
        AddShifted(result, z0, 0);
        AddShifted(result, z1, half);
        AddShifted(result, z2, 2 * half);

        return result;
    }

    private static void AddShifted(uint[] result, uint[] value, int shift)
    {
        ulong carry = 0;
        for (int i = 0; i < value.Length; i++)
        {
            if (i + shift < result.Length)
            {
                carry += result[i + shift] + (ulong)value[i];
                result[i + shift] = (uint)carry;
                carry >>= 32;
            }
        }

        for (int i = value.Length + shift; i < result.Length && carry != 0; i++)
        {
            carry += result[i];
            result[i] = (uint)carry;
            carry >>= 32;
        }
    }

    private static (uint[] quotient, uint[] remainder) DivideWithRemainder(uint[] dividend, uint[] divisor)
    {
        if (CompareAbs(dividend, divisor) < 0)
        {
            return ([0], dividend);
        }

        var quotient = new List<uint>();
        uint[] remainder = (uint[])dividend.Clone();

        int divisorBits = GetBitLength(divisor);

        while (CompareAbs(remainder, divisor) >= 0)
        {
            int remainderBits = GetBitLength(remainder);
            int shift = remainderBits - divisorBits;

            uint[] shiftedDivisor = ShiftLeft(divisor, shift);

            if (CompareAbs(remainder, shiftedDivisor) < 0)
            {
                shift--;
                shiftedDivisor = ShiftLeft(divisor, shift);
            }

            remainder = Subtract(remainder, shiftedDivisor);

            if (shift / 32 >= quotient.Count)
            {
                while (quotient.Count <= shift / 32)
                {
                    quotient.Add(0);
                }
            }

            quotient[shift / 32] |= 1u << (shift % 32);
        }

        if (quotient.Count == 0)
        {
            quotient.Add(0);
        }

        return (quotient.ToArray(), remainder);
    }

    private static uint[] ShiftLeft(uint[] value, int shift)
    {
        if (shift < 0)
        {
            return value;
        }

        int wordShift = shift / 32;
        int bitShift = shift % 32;

        uint[] result = new uint[value.Length + wordShift + 1];

        if (bitShift == 0)
        {
            Array.Copy(value, 0, result, wordShift, value.Length);
        }
        else
        {
            ulong carry = 0;
            for (int i = 0; i < value.Length; i++)
            {
                carry |= (ulong)value[i] << bitShift;
                result[i + wordShift] = (uint)carry;
                carry >>= 32;
            }
            if (carry != 0)
            {
                result[value.Length + wordShift] = (uint)carry;
            }
        }

        return result;
    }

    private static int GetBitLength(uint[] value)
    {
        for (int i = value.Length - 1; i >= 0; i--)
        {
            if (value[i] != 0)
            {
                int bits = 0;
                uint n = value[i];
                while (n != 0)
                {
                    bits++;
                    n >>= 1;
                }
                return (i * 32) + bits;
            }
        }
        return 0;
    }

    private static int CompareAbs(uint[] left, uint[] right)
    {
        int leftLen = GetActualLength(left);
        int rightLen = GetActualLength(right);

        if (leftLen != rightLen)
        {
            return leftLen.CompareTo(rightLen);
        }

        for (int i = leftLen - 1; i >= 0; i--)
        {
            uint leftVal = i < left.Length ? left[i] : 0u;
            uint rightVal = i < right.Length ? right[i] : 0u;

            if (leftVal != rightVal)
            {
                return leftVal.CompareTo(rightVal);
            }
        }

        return 0;
    }

    private static int GetActualLength(uint[] data)
    {
        for (int i = data.Length - 1; i >= 0; i--)
        {
            if (data[i] != 0)
            {
                return i + 1;
            }
        }
        return 0;
    }

    private void Normalize()
    {
        int actualLength = GetActualLength(dataWords);
        if (actualLength == 0)
        {
            dataWords = [0];
            Sign = 0;
        }
        else if (actualLength < dataWords.Length)
        {
            Array.Resize(ref dataWords, actualLength);
        }
    }

    /// <summary>
    /// Determines whether the specified object is equal to this instance.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns>true if the specified object is equal to this instance; otherwise, false.</returns>
    public override bool Equals(object? obj)
    {
        return obj is BigInteger other && this == other;
    }

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>A hash code for this instance.</returns>
    public override int GetHashCode()
    {
        unchecked
        {
            int hash = Sign.GetHashCode();
            foreach (uint item in dataWords)
            {
                hash = (hash * 397) ^ item.GetHashCode();
            }
            return hash;
        }
    }

    /// <summary>
    /// Converts this <see cref="BigInteger"/> to its hexadecimal string representation.
    /// </summary>
    /// <returns>A hexadecimal string representation of the value.</returns>
    public override string ToString()
    {
        return Sign switch
        {
            0 => "0",
            -1 => "-" + DataToString(),
            _ => DataToString()
        };
    }

    private string DataToString()
    {
        var hex = new StringBuilder();
        for (int i = dataWords.Length - 1; i >= 0; i--)
        {
            _ = hex.Append(dataWords[i].ToString("X8", CultureInfo.InvariantCulture));
        }
        return hex.ToString().TrimStart('0');
    }
}
