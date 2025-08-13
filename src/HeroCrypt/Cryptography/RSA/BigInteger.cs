using System.Globalization;
using System.Text;

namespace HeroCrypt.Cryptography.RSA;

internal sealed class BigInteger : IComparable<BigInteger>
{
    private uint[] _data;
    private int _sign;
    
    public static readonly BigInteger Zero = new(0);
    public static readonly BigInteger One = new(1);
    
    public BigInteger(long value)
    {
        if (value == 0)
        {
            _data = [0];
            _sign = 0;
        }
        else if (value > 0)
        {
            _data = [(uint)value, (uint)(value >> 32)];
            _sign = 1;
        }
        else
        {
            value = -value;
            _data = [(uint)value, (uint)(value >> 32)];
            _sign = -1;
        }
        
        Normalize();
    }
    
    public BigInteger(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0)
        {
            _data = [0];
            _sign = 0;
            return;
        }
        
        var wordCount = (bytes.Length + 3) / 4;
        _data = new uint[wordCount];
        
        for (var i = 0; i < bytes.Length; i++)
        {
            _data[i / 4] |= (uint)(bytes[bytes.Length - 1 - i] << ((i % 4) * 8));
        }
        
        _sign = 1;
        Normalize();
    }
    
    private BigInteger(uint[] data, int sign)
    {
        _data = data;
        _sign = sign;
        Normalize();
    }
    
    public bool IsZero => _sign == 0;
    public bool IsOne => _sign == 1 && _data.Length == 1 && _data[0] == 1;
    public int Sign => _sign;
    
    public byte[] ToByteArray()
    {
        if (IsZero) return [0];
        
        var bytes = new List<byte>();
        var data = (uint[])_data.Clone();
        
        for (var i = 0; i < data.Length; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                bytes.Add((byte)(data[i] & 0xFF));
                data[i] >>= 8;
            }
        }
        
        while (bytes.Count > 1 && bytes[bytes.Count - 1] == 0)
            bytes.RemoveAt(bytes.Count - 1);
        
        bytes.Reverse();
        return bytes.ToArray();
    }
    
    public static BigInteger operator +(BigInteger left, BigInteger right)
    {
        if (left.IsZero) return right;
        if (right.IsZero) return left;
        
        if (left._sign == right._sign)
            return new BigInteger(Add(left._data, right._data), left._sign);
        
        var cmp = CompareAbs(left._data, right._data);
        if (cmp == 0) return Zero;
        if (cmp > 0)
            return new BigInteger(Subtract(left._data, right._data), left._sign);
        
        return new BigInteger(Subtract(right._data, left._data), right._sign);
    }
    
    public static BigInteger operator -(BigInteger left, BigInteger right)
    {
        return left + new BigInteger(right._data, -right._sign);
    }
    
    public static BigInteger operator *(BigInteger left, BigInteger right)
    {
        if (left.IsZero || right.IsZero) return Zero;
        
        var result = Multiply(left._data, right._data);
        return new BigInteger(result, left._sign * right._sign);
    }
    
    public static BigInteger operator /(BigInteger dividend, BigInteger divisor)
    {
        if (divisor.IsZero) throw new DivideByZeroException();
        if (dividend.IsZero) return Zero;
        
        var (quotient, _) = DivideWithRemainder(dividend._data, divisor._data);
        return new BigInteger(quotient, dividend._sign * divisor._sign);
    }
    
    public static BigInteger operator %(BigInteger dividend, BigInteger divisor)
    {
        if (divisor.IsZero) throw new DivideByZeroException();
        if (dividend.IsZero) return Zero;
        
        var (_, remainder) = DivideWithRemainder(dividend._data, divisor._data);
        return new BigInteger(remainder, dividend._sign);
    }
    
    public static bool operator ==(BigInteger left, BigInteger right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;
        
        return left._sign == right._sign && CompareAbs(left._data, right._data) == 0;
    }
    
    public static bool operator !=(BigInteger left, BigInteger right) => !(left == right);
    
    public static bool operator <(BigInteger left, BigInteger right) => left.CompareTo(right) < 0;
    public static bool operator >(BigInteger left, BigInteger right) => left.CompareTo(right) > 0;
    public static bool operator <=(BigInteger left, BigInteger right) => left.CompareTo(right) <= 0;
    public static bool operator >=(BigInteger left, BigInteger right) => left.CompareTo(right) >= 0;
    
    public int CompareTo(BigInteger? other)
    {
        if (other is null) return 1;
        if (_sign != other._sign) return _sign.CompareTo(other._sign);
        if (_sign == 0) return 0;
        
        var cmp = CompareAbs(_data, other._data);
        return _sign > 0 ? cmp : -cmp;
    }
    
    public BigInteger ModPow(BigInteger exponent, BigInteger modulus)
    {
        if (modulus.IsZero) throw new DivideByZeroException();
        if (exponent.Sign < 0) throw new ArgumentException("Negative exponent not supported");
        
        var result = One;
        var baseValue = this % modulus;
        var exp = exponent;
        
        while (!exp.IsZero)
        {
            if ((exp._data[0] & 1) == 1)
                result = (result * baseValue) % modulus;
            
            baseValue = (baseValue * baseValue) % modulus;
            exp = exp >> 1;
        }
        
        return result;
    }
    
    public BigInteger ModInverse(BigInteger modulus)
    {
        if (modulus.IsZero) throw new DivideByZeroException();
        
        var a = this % modulus;
        var m = modulus;
        var x0 = Zero;
        var x1 = One;
        
        if (a < Zero) a = a + modulus;
        
        while (a > One)
        {
            var q = a / m;
            var t = m;
            
            m = a % m;
            a = t;
            t = x0;
            
            x0 = x1 - q * x0;
            x1 = t;
        }
        
        if (x1 < Zero) x1 = x1 + modulus;
        
        return x1;
    }
    
    public static BigInteger operator <<(BigInteger value, int shift)
    {
        if (shift < 0) throw new ArgumentException("Negative shift");
        if (shift == 0 || value.IsZero) return value;
        
        var wordShift = shift / 32;
        var bitShift = shift % 32;
        
        var newLength = value._data.Length + wordShift + (bitShift > 0 ? 1 : 0);
        var result = new uint[newLength];
        
        if (bitShift == 0)
        {
            Array.Copy(value._data, 0, result, wordShift, value._data.Length);
        }
        else
        {
            ulong carry = 0;
            for (var i = 0; i < value._data.Length; i++)
            {
                carry |= (ulong)value._data[i] << bitShift;
                result[i + wordShift] = (uint)carry;
                carry >>= 32;
            }
            if (carry != 0)
                result[value._data.Length + wordShift] = (uint)carry;
        }
        
        return new BigInteger(result, value._sign);
    }
    
    public static BigInteger operator >>(BigInteger value, int shift)
    {
        if (shift < 0) throw new ArgumentException("Negative shift");
        if (shift == 0 || value.IsZero) return value;
        
        var wordShift = shift / 32;
        var bitShift = shift % 32;
        
        if (wordShift >= value._data.Length) return Zero;
        
        var newLength = value._data.Length - wordShift;
        var result = new uint[newLength];
        
        if (bitShift == 0)
        {
            Array.Copy(value._data, wordShift, result, 0, newLength);
        }
        else
        {
            ulong carry = 0;
            for (var i = value._data.Length - 1; i >= wordShift; i--)
            {
                carry = ((ulong)value._data[i] << (32 - bitShift)) | (carry >> 32);
                if (i - wordShift < result.Length)
                    result[i - wordShift] = (uint)(value._data[i] >> bitShift) | (uint)(carry >> (32 - bitShift));
            }
        }
        
        return new BigInteger(result, value._sign);
    }
    
    private static uint[] Add(uint[] left, uint[] right)
    {
        var maxLength = Math.Max(left.Length, right.Length);
        var result = new uint[maxLength + 1];
        ulong carry = 0;
        
        for (var i = 0; i < maxLength; i++)
        {
            var a = i < left.Length ? left[i] : 0u;
            var b = i < right.Length ? right[i] : 0u;
            
            carry += a + (ulong)b;
            result[i] = (uint)carry;
            carry >>= 32;
        }
        
        if (carry != 0)
            result[maxLength] = (uint)carry;
        
        return result;
    }
    
    private static uint[] Subtract(uint[] left, uint[] right)
    {
        var result = new uint[left.Length];
        long borrow = 0;
        
        for (var i = 0; i < left.Length; i++)
        {
            var a = left[i];
            var b = i < right.Length ? right[i] : 0u;
            
            var diff = a - b - borrow;
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
        
        return result;
    }
    
    private static uint[] Multiply(uint[] left, uint[] right)
    {
        var result = new uint[left.Length + right.Length];
        
        for (var i = 0; i < left.Length; i++)
        {
            ulong carry = 0;
            for (var j = 0; j < right.Length; j++)
            {
                carry += (ulong)left[i] * right[j] + result[i + j];
                result[i + j] = (uint)carry;
                carry >>= 32;
            }
            result[i + right.Length] = (uint)carry;
        }
        
        return result;
    }
    
    private static (uint[] quotient, uint[] remainder) DivideWithRemainder(uint[] dividend, uint[] divisor)
    {
        if (CompareAbs(dividend, divisor) < 0)
            return ([0], dividend);
        
        var quotient = new List<uint>();
        var remainder = (uint[])dividend.Clone();
        
        var divisorBits = GetBitLength(divisor);
        
        while (CompareAbs(remainder, divisor) >= 0)
        {
            var remainderBits = GetBitLength(remainder);
            var shift = remainderBits - divisorBits;
            
            var shiftedDivisor = ShiftLeft(divisor, shift);
            
            if (CompareAbs(remainder, shiftedDivisor) < 0)
            {
                shift--;
                shiftedDivisor = ShiftLeft(divisor, shift);
            }
            
            remainder = Subtract(remainder, shiftedDivisor);
            
            if (shift / 32 >= quotient.Count)
            {
                while (quotient.Count <= shift / 32)
                    quotient.Add(0);
            }
            
            quotient[shift / 32] |= 1u << (shift % 32);
        }
        
        if (quotient.Count == 0) quotient.Add(0);
        
        return (quotient.ToArray(), remainder);
    }
    
    private static uint[] ShiftLeft(uint[] value, int shift)
    {
        if (shift < 0) return value;
        
        var wordShift = shift / 32;
        var bitShift = shift % 32;
        
        var result = new uint[value.Length + wordShift + 1];
        
        if (bitShift == 0)
        {
            Array.Copy(value, 0, result, wordShift, value.Length);
        }
        else
        {
            ulong carry = 0;
            for (var i = 0; i < value.Length; i++)
            {
                carry |= (ulong)value[i] << bitShift;
                result[i + wordShift] = (uint)carry;
                carry >>= 32;
            }
            if (carry != 0)
                result[value.Length + wordShift] = (uint)carry;
        }
        
        return result;
    }
    
    private static int GetBitLength(uint[] value)
    {
        for (var i = value.Length - 1; i >= 0; i--)
        {
            if (value[i] != 0)
            {
                var bits = 0;
                var n = value[i];
                while (n != 0)
                {
                    bits++;
                    n >>= 1;
                }
                return i * 32 + bits;
            }
        }
        return 0;
    }
    
    private static int CompareAbs(uint[] left, uint[] right)
    {
        var leftLen = GetActualLength(left);
        var rightLen = GetActualLength(right);
        
        if (leftLen != rightLen)
            return leftLen.CompareTo(rightLen);
        
        for (var i = leftLen - 1; i >= 0; i--)
        {
            var leftVal = i < left.Length ? left[i] : 0u;
            var rightVal = i < right.Length ? right[i] : 0u;
            
            if (leftVal != rightVal)
                return leftVal.CompareTo(rightVal);
        }
        
        return 0;
    }
    
    private static int GetActualLength(uint[] data)
    {
        for (var i = data.Length - 1; i >= 0; i--)
        {
            if (data[i] != 0) return i + 1;
        }
        return 0;
    }
    
    private void Normalize()
    {
        var actualLength = GetActualLength(_data);
        if (actualLength == 0)
        {
            _data = [0];
            _sign = 0;
        }
        else if (actualLength < _data.Length)
        {
            Array.Resize(ref _data, actualLength);
        }
    }
    
    public override bool Equals(object? obj) => obj is BigInteger other && this == other;
    public override int GetHashCode()
    {
        unchecked
        {
            var hash = _sign.GetHashCode();
            foreach (var item in _data)
            {
                hash = (hash * 397) ^ item.GetHashCode();
            }
            return hash;
        }
    }
    public override string ToString() => _sign switch
    {
        0 => "0",
        -1 => "-" + DataToString(),
        _ => DataToString()
    };
    
    private string DataToString()
    {
        var hex = new StringBuilder();
        for (var i = _data.Length - 1; i >= 0; i--)
        {
            hex.Append(_data[i].ToString("X8"));
        }
        return hex.ToString().TrimStart('0');
    }
}