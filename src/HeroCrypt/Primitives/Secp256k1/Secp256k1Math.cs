using System.Globalization;
using System.Numerics;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>SEC 2 secp256k1 field and Jacobian point operations.</summary>
/// <remarks>BigInteger arithmetic is variable-time and cannot be reliably zeroized.</remarks>
internal static class Secp256k1Math
{
    internal static readonly BigInteger FieldPrime = Parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    internal static readonly BigInteger Order = Parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    internal static readonly Point Generator = new(
        Parse("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        Parse("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"), BigInteger.One);

    internal readonly struct Point(BigInteger x, BigInteger y, BigInteger z)
    {
        internal BigInteger X { get; } = x;
        internal BigInteger Y { get; } = y;
        internal BigInteger Z { get; } = z;
        internal bool IsInfinity => Z.IsZero;
    }

    internal static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        var result = value % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }

    internal static BigInteger ReadScalar(ReadOnlySpan<byte> bytes)
    {
        // The extra zero byte makes the little-endian BigInteger positive on .NET Standard 2.0.
        var littleEndian = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
            littleEndian[i] = bytes[bytes.Length - 1 - i];
        try
        {
            return new BigInteger(littleEndian);
        }
        finally
        {
            Security.SecureMemoryOperations.SecureClear(littleEndian);
        }
    }

    internal static byte[] EncodeScalar(BigInteger value)
    {
        var bytes = value.ToByteArray();
        try
        {
            var output = new byte[32];
            for (var i = 0; i < output.Length && i < bytes.Length; i++)
                output[31 - i] = bytes[i];
            return output;
        }
        finally
        {
            Security.SecureMemoryOperations.SecureClear(bytes);
        }
    }

    internal static Point Multiply(Point point, BigInteger scalar)
    {
        var result = default(Point);
        // Fixed loop length does not make BigInteger or these point formulas constant-time.
        for (var bit = 255; bit >= 0; bit--)
        {
            result = Double(result);
            if (!((scalar >> bit) & BigInteger.One).IsZero)
                result = Add(result, point);
        }
        return result;
    }

    internal static Point Add(Point left, Point right)
    {
        if (left.IsInfinity) return right;
        if (right.IsInfinity) return left;
        var z1Squared = Field(left.Z * left.Z);
        var z2Squared = Field(right.Z * right.Z);
        var u1 = Field(left.X * z2Squared);
        var u2 = Field(right.X * z1Squared);
        var s1 = Field(left.Y * right.Z * z2Squared);
        var s2 = Field(right.Y * left.Z * z1Squared);
        var h = Field(u2 - u1);
        var r = Field(s2 - s1);
        if (h.IsZero) return r.IsZero ? Double(left) : default;
        var hSquared = Field(h * h);
        var hCubed = Field(h * hSquared);
        var u1HSquared = Field(u1 * hSquared);
        var x = Field(r * r - hCubed - 2 * u1HSquared);
        var y = Field(r * (u1HSquared - x) - s1 * hCubed);
        var z = Field(h * left.Z * right.Z);
        return new Point(x, y, z);
    }

    internal static Point ToAffine(Point point)
    {
        if (point.IsInfinity) return point;
        var inverse = BigInteger.ModPow(point.Z, FieldPrime - 2, FieldPrime);
        var squared = Field(inverse * inverse);
        return new Point(Field(point.X * squared), Field(point.Y * squared * inverse), BigInteger.One);
    }

    internal static Point Decode(ReadOnlySpan<byte> encoded)
    {
        BigInteger x;
        BigInteger y;
        if (encoded.Length == 33 && encoded[0] is 2 or 3)
        {
            x = ReadScalar(encoded.Slice(1, 32));
            if (x >= FieldPrime) throw new ArgumentException("Public key coordinate is outside the secp256k1 field.", nameof(encoded));
            var squaredY = Field(x * x * x + 7);
            y = BigInteger.ModPow(squaredY, (FieldPrime + 1) / 4, FieldPrime);
            if (Field(y * y) != squaredY) throw new ArgumentException("Public key is not on secp256k1.", nameof(encoded));
            if (y.IsEven != (encoded[0] == 2)) y = FieldPrime - y;
        }
        else if (encoded.Length == 65 && encoded[0] == 4)
        {
            x = ReadScalar(encoded.Slice(1, 32));
            y = ReadScalar(encoded.Slice(33, 32));
            if (x >= FieldPrime || y >= FieldPrime || Field(y * y) != Field(x * x * x + 7))
                throw new ArgumentException("Public key is not a canonical secp256k1 point.", nameof(encoded));
        }
        else
        {
            throw new ArgumentException("Public key must use compressed or uncompressed SEC encoding.", nameof(encoded));
        }
        // secp256k1 has cofactor one; every finite point on the curve is in its prime-order subgroup.
        return new Point(x, y, BigInteger.One);
    }

    internal static byte[] Encode(Point point, bool compressed)
    {
        var affine = ToAffine(point);
        if (affine.IsInfinity) throw new ArgumentException("The point at infinity cannot be encoded.", nameof(point));
        var encoded = new byte[compressed ? 33 : 65];
        encoded[0] = compressed ? (byte)(affine.Y.IsEven ? 2 : 3) : (byte)4;
        EncodeScalar(affine.X).CopyTo(encoded, 1);
        if (!compressed) EncodeScalar(affine.Y).CopyTo(encoded, 33);
        return encoded;
    }

    private static Point Double(Point point)
    {
        if (point.IsInfinity || point.Y.IsZero) return default;
        var xx = Field(point.X * point.X);
        var yy = Field(point.Y * point.Y);
        var yyyy = Field(yy * yy);
        var s = Field(4 * point.X * yy);
        var m = Field(3 * xx);
        var x = Field(m * m - 2 * s);
        var y = Field(m * (s - x) - 8 * yyyy);
        return new Point(x, y, Field(2 * point.Y * point.Z));
    }

    private static BigInteger Field(BigInteger value) => Mod(value, FieldPrime);
    private static BigInteger Parse(string hex) => BigInteger.Parse("0" + hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
}
