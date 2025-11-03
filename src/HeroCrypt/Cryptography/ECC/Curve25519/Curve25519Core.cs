using HeroCrypt.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.ECC.Curve25519;

/// <summary>
/// Core Curve25519 implementation for X25519 key agreement
/// Based on RFC 7748 specification using radix-2^25.5 representation
/// Ported from curve25519-donna and other reference implementations
/// </summary>
public static class Curve25519Core
{
    private const int KeySize = 32;

    // Radix-2^25.5 constants
    private const long P25 = 33554431;  // 2^25 - 1
    private const long P26 = 67108863;  // 2^26 - 1

    /// <summary>
    /// Field element using radix-2^25.5 representation (10 limbs, alternating 26 and 25 bits)
    /// </summary>
    private sealed class Long10
    {
        public long N0, N1, N2, N3, N4, N5, N6, N7, N8, N9;

        public Long10() { }

        public Long10(Long10 source)
        {
            N0 = source.N0;
            N1 = source.N1;
            N2 = source.N2;
            N3 = source.N3;
            N4 = source.N4;
            N5 = source.N5;
            N6 = source.N6;
            N7 = source.N7;
            N8 = source.N8;
            N9 = source.N9;
        }
    }

    /// <summary>
    /// Generates a random private key for Curve25519
    /// </summary>
    /// <returns>32-byte private key</returns>
    public static byte[] GeneratePrivateKey()
    {
        var privateKey = new byte[KeySize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(privateKey);

        // Clamp the private key according to RFC 7748
        ClampPrivateKey(privateKey);

        return privateKey;
    }

    /// <summary>
    /// Derives the public key from a private key
    /// </summary>
    /// <param name="privateKey">32-byte private key</param>
    /// <returns>32-byte public key</returns>
    public static byte[] DerivePublicKey(byte[] privateKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.Length != KeySize)
            throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));

        var basePoint = new byte[KeySize];
        basePoint[0] = 9;

        return ScalarMult(privateKey, basePoint);
    }

    /// <summary>
    /// Performs X25519 key agreement
    /// </summary>
    /// <param name="privateKey">Local private key (32 bytes)</param>
    /// <param name="publicKey">Remote public key (32 bytes)</param>
    /// <returns>32-byte shared secret</returns>
    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        if (privateKey.Length != KeySize)
            throw new ArgumentException($"Private key must be {KeySize} bytes", nameof(privateKey));
        if (publicKey.Length != KeySize)
            throw new ArgumentException($"Public key must be {KeySize} bytes", nameof(publicKey));

        return ScalarMult(privateKey, publicKey);
    }

    /// <summary>
    /// Clamps a private key according to RFC 7748
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ClampPrivateKey(byte[] privateKey)
    {
        privateKey[0] &= 248;   // Clear bits 0, 1, 2
        privateKey[31] &= 127;  // Clear bit 255
        privateKey[31] |= 64;   // Set bit 254
    }

    /// <summary>
    /// Scalar multiplication: result = scalar * point
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static byte[] ScalarMult(byte[] scalar, byte[] point)
    {
        var clampedScalar = new byte[KeySize];
        Array.Copy(scalar, clampedScalar, KeySize);
        ClampPrivateKey(clampedScalar);

        try
        {
            var dx = new Long10();
            var t1 = new Long10();
            var t2 = new Long10();
            var t3 = new Long10();
            var t4 = new Long10();
            var x = new Long10[2];
            var z = new Long10[2];
            x[0] = new Long10();
            x[1] = new Long10();
            z[0] = new Long10();
            z[1] = new Long10();

            // Unpack the base point
            Unpack(dx, point);

            // 0G = point-at-infinity
            x[0].N0 = 1;
            // z[0] is already zero

            // 1G = G
            Copy(x[1], dx);
            z[1].N0 = 1;

            // Montgomery ladder - process all 256 bits
            for (var i = 32; i-- != 0;)
            {
                for (var j = 8; j-- != 0;)
                {
                    // Swap arguments depending on bit
                    var bit1 = (clampedScalar[i] & 0xFF) >> j & 1;
                    var bit0 = ~(clampedScalar[i] & 0xFF) >> j & 1;
                    var ax = x[bit0];
                    var az = z[bit0];
                    var bx = x[bit1];
                    var bz = z[bit1];

                    // a' = a + b
                    // b' = 2 * b
                    MontPrep(t1, t2, ax, az);
                    MontPrep(t3, t4, bx, bz);
                    MontAdd(t1, t2, t3, t4, ax, az, dx);
                    MontDbl(t1, t2, t3, t4, bx, bz);
                }
            }

            Recip(t1, z[0]);
            Multiply(dx, x[0], t1);

            var result = new byte[KeySize];
            Pack(dx, result);
            return result;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(clampedScalar);
        }
    }

    /// <summary>
    /// Prepare for Montgomery operations: t1 = a+b, t2 = a-b
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void MontPrep(Long10 t1, Long10 t2, Long10 ax, Long10 az)
    {
        Add(t1, ax, az);
        Sub(t2, ax, az);
    }

    /// <summary>
    /// Montgomery point addition: A = P + Q
    /// where X(A) = ax/az, X(P) = (t1+t2)/(t1-t2), X(Q) = (t3+t4)/(t3-t4), X(P-Q) = dx
    /// Clobbers t1 and t2, preserves t3 and t4
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void MontAdd(Long10 t1, Long10 t2, Long10 t3, Long10 t4, Long10 ax, Long10 az, Long10 dx)
    {
        Multiply(ax, t2, t3);
        Multiply(az, t1, t4);
        Add(t1, ax, az);
        Sub(t2, ax, az);
        Square(ax, t1);
        Square(t1, t2);
        Multiply(az, t1, dx);
    }

    /// <summary>
    /// Montgomery point doubling: B = 2 * Q
    /// where X(B) = bx/bz, X(Q) = (t3+t4)/(t3-t4)
    /// Clobbers t1 and t2, preserves t3 and t4
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void MontDbl(Long10 t1, Long10 t2, Long10 t3, Long10 t4, Long10 bx, Long10 bz)
    {
        Square(t1, t3);
        Square(t2, t4);
        Multiply(bx, t1, t2);
        Sub(t2, t1, t2);
        MultiplySmall(bz, t2, 121665);
        Add(t1, t1, bz);
        Multiply(bz, t1, t2);
    }

    /// <summary>
    /// Copy a Long10
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Copy(Long10 output, Long10 input)
    {
        output.N0 = input.N0;
        output.N1 = input.N1;
        output.N2 = input.N2;
        output.N3 = input.N3;
        output.N4 = input.N4;
        output.N5 = input.N5;
        output.N6 = input.N6;
        output.N7 = input.N7;
        output.N8 = input.N8;
        output.N9 = input.N9;
    }

    /// <summary>
    /// Conditional swap in constant time
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ConditionalSwap(Long10 a, Long10 b, int iswap)
    {
        var swap = -iswap;
        var t = swap & (a.N0 ^ b.N0); a.N0 ^= t; b.N0 ^= t;
        t = swap & (a.N1 ^ b.N1); a.N1 ^= t; b.N1 ^= t;
        t = swap & (a.N2 ^ b.N2); a.N2 ^= t; b.N2 ^= t;
        t = swap & (a.N3 ^ b.N3); a.N3 ^= t; b.N3 ^= t;
        t = swap & (a.N4 ^ b.N4); a.N4 ^= t; b.N4 ^= t;
        t = swap & (a.N5 ^ b.N5); a.N5 ^= t; b.N5 ^= t;
        t = swap & (a.N6 ^ b.N6); a.N6 ^= t; b.N6 ^= t;
        t = swap & (a.N7 ^ b.N7); a.N7 ^= t; b.N7 ^= t;
        t = swap & (a.N8 ^ b.N8); a.N8 ^= t; b.N8 ^= t;
        t = swap & (a.N9 ^ b.N9); a.N9 ^= t; b.N9 ^= t;
    }

    /// <summary>
    /// Unpacks 32 bytes (little-endian) into Long10 radix-2^25.5 representation
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Unpack(Long10 x, byte[] m)
    {
        x.N0 = ((m[0] & 0xFF)) | ((m[1] & 0xFF)) << 8 | (m[2] & 0xFF) << 16 | ((m[3] & 0xFF) & 3) << 24;
        x.N1 = (((m[3] & 0xFF) & ~3) >> 2) | (m[4] & 0xFF) << 6 | (m[5] & 0xFF) << 14 | ((m[6] & 0xFF) & 7) << 22;
        x.N2 = (((m[6] & 0xFF) & ~7) >> 3) | (m[7] & 0xFF) << 5 | (m[8] & 0xFF) << 13 | ((m[9] & 0xFF) & 31) << 21;
        x.N3 = (((m[9] & 0xFF) & ~31) >> 5) | (m[10] & 0xFF) << 3 | (m[11] & 0xFF) << 11 | ((m[12] & 0xFF) & 63) << 19;
        x.N4 = (((m[12] & 0xFF) & ~63) >> 6) | (m[13] & 0xFF) << 2 | (m[14] & 0xFF) << 10 | (m[15] & 0xFF) << 18;
        x.N5 = (m[16] & 0xFF) | (m[17] & 0xFF) << 8 | (m[18] & 0xFF) << 16 | ((m[19] & 0xFF) & 1) << 24;
        x.N6 = (((m[19] & 0xFF) & ~1) >> 1) | (m[20] & 0xFF) << 7 | (m[21] & 0xFF) << 15 | ((m[22] & 0xFF) & 7) << 23;
        x.N7 = (((m[22] & 0xFF) & ~7) >> 3) | (m[23] & 0xFF) << 5 | (m[24] & 0xFF) << 13 | ((m[25] & 0xFF) & 15) << 21;
        x.N8 = (((m[25] & 0xFF) & ~15) >> 4) | (m[26] & 0xFF) << 4 | (m[27] & 0xFF) << 12 | ((m[28] & 0xFF) & 63) << 20;
        x.N9 = (((m[28] & 0xFF) & ~63) >> 6) | (m[29] & 0xFF) << 2 | (m[30] & 0xFF) << 10 | (m[31] & 0xFF) << 18;
    }

    /// <summary>
    /// Packs Long10 radix-2^25.5 representation into 32 bytes (little-endian)
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Pack(Long10 x, byte[] m)
    {
        var ld = (IsOverflow(x) ? 1 : 0) - (x.N9 < 0 ? 1 : 0);
        var ud = ld * -(P25 + 1);
        ld *= 19;
        var t = ld + x.N0 + (x.N1 << 26);
        m[0] = (byte)t; m[1] = (byte)(t >> 8); m[2] = (byte)(t >> 16); m[3] = (byte)(t >> 24);
        t = (t >> 32) + (x.N2 << 19);
        m[4] = (byte)t; m[5] = (byte)(t >> 8); m[6] = (byte)(t >> 16); m[7] = (byte)(t >> 24);
        t = (t >> 32) + (x.N3 << 13);
        m[8] = (byte)t; m[9] = (byte)(t >> 8); m[10] = (byte)(t >> 16); m[11] = (byte)(t >> 24);
        t = (t >> 32) + (x.N4 << 6);
        m[12] = (byte)t; m[13] = (byte)(t >> 8); m[14] = (byte)(t >> 16); m[15] = (byte)(t >> 24);
        t = (t >> 32) + x.N5 + (x.N6 << 25);
        m[16] = (byte)t; m[17] = (byte)(t >> 8); m[18] = (byte)(t >> 16); m[19] = (byte)(t >> 24);
        t = (t >> 32) + (x.N7 << 19);
        m[20] = (byte)t; m[21] = (byte)(t >> 8); m[22] = (byte)(t >> 16); m[23] = (byte)(t >> 24);
        t = (t >> 32) + (x.N8 << 12);
        m[24] = (byte)t; m[25] = (byte)(t >> 8); m[26] = (byte)(t >> 16); m[27] = (byte)(t >> 24);
        t = (t >> 32) + ((x.N9 + ud) << 6);
        m[28] = (byte)t; m[29] = (byte)(t >> 8); m[30] = (byte)(t >> 16); m[31] = (byte)(t >> 24);
    }

    /// <summary>
    /// Checks if reduced form >= 2^255-19
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsOverflow(Long10 x)
    {
        return (
            ((x.N0 > P26 - 19)) &&
            ((x.N1 & x.N3 & x.N5 & x.N7 & x.N9) == P25) &&
            ((x.N2 & x.N4 & x.N6 & x.N8) == P26)
        ) || (x.N9 > P25);
    }

    /// <summary>
    /// Carry/reduce values
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Carry(Long10 x)
    {
        long c;
        c = x.N0 >> 26; x.N0 &= P26; x.N1 += c;
        c = x.N1 >> 25; x.N1 &= P25; x.N2 += c;
        c = x.N2 >> 26; x.N2 &= P26; x.N3 += c;
        c = x.N3 >> 25; x.N3 &= P25; x.N4 += c;
        c = x.N4 >> 26; x.N4 &= P26; x.N5 += c;
        c = x.N5 >> 25; x.N5 &= P25; x.N6 += c;
        c = x.N6 >> 26; x.N6 &= P26; x.N7 += c;
        c = x.N7 >> 25; x.N7 &= P25; x.N8 += c;
        c = x.N8 >> 26; x.N8 &= P26; x.N9 += c;
        c = x.N9 >> 25; x.N9 &= P25; x.N0 += 19 * c;
        c = x.N0 >> 26; x.N0 &= P26; x.N1 += c;
    }

    /// <summary>
    /// Field addition
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Add(Long10 xy, Long10 x, Long10 y)
    {
        xy.N0 = x.N0 + y.N0;
        xy.N1 = x.N1 + y.N1;
        xy.N2 = x.N2 + y.N2;
        xy.N3 = x.N3 + y.N3;
        xy.N4 = x.N4 + y.N4;
        xy.N5 = x.N5 + y.N5;
        xy.N6 = x.N6 + y.N6;
        xy.N7 = x.N7 + y.N7;
        xy.N8 = x.N8 + y.N8;
        xy.N9 = x.N9 + y.N9;
    }

    /// <summary>
    /// Field subtraction
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Sub(Long10 xy, Long10 x, Long10 y)
    {
        xy.N0 = x.N0 - y.N0;
        xy.N1 = x.N1 - y.N1;
        xy.N2 = x.N2 - y.N2;
        xy.N3 = x.N3 - y.N3;
        xy.N4 = x.N4 - y.N4;
        xy.N5 = x.N5 - y.N5;
        xy.N6 = x.N6 - y.N6;
        xy.N7 = x.N7 - y.N7;
        xy.N8 = x.N8 - y.N8;
        xy.N9 = x.N9 - y.N9;
    }

    /// <summary>
    /// Field multiplication
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Multiply(Long10 xy, Long10 x, Long10 y)
    {
        var x0 = x.N0; var x1 = x.N1; var x2 = x.N2; var x3 = x.N3; var x4 = x.N4;
        var x5 = x.N5; var x6 = x.N6; var x7 = x.N7; var x8 = x.N8; var x9 = x.N9;
        var y0 = y.N0; var y1 = y.N1; var y2 = y.N2; var y3 = y.N3; var y4 = y.N4;
        var y5 = y.N5; var y6 = y.N6; var y7 = y.N7; var y8 = y.N8; var y9 = y.N9;
        long t;

        t = (x0 * y8) + (x2 * y6) + (x4 * y4) + (x6 * y2) + (x8 * y0) + 2 * ((x1 * y7) + (x3 * y5) + (x5 * y3) + (x7 * y1)) + 38 * (x9 * y9);
        xy.N8 = t & P26;
        t = (t >> 26) + (x0 * y9) + (x1 * y8) + (x2 * y7) + (x3 * y6) + (x4 * y5) + (x5 * y4) + (x6 * y3) + (x7 * y2) + (x8 * y1) + (x9 * y0);
        xy.N9 = t & P25;
        t = (x0 * y0) + 19 * ((t >> 25) + (x2 * y8) + (x4 * y6) + (x6 * y4) + (x8 * y2)) + 38 * ((x1 * y9) + (x3 * y7) + (x5 * y5) + (x7 * y3) + (x9 * y1));
        xy.N0 = t & P26;
        t = (t >> 26) + (x0 * y1) + (x1 * y0) + 19 * ((x2 * y9) + (x3 * y8) + (x4 * y7) + (x5 * y6) + (x6 * y5) + (x7 * y4) + (x8 * y3) + (x9 * y2));
        xy.N1 = t & P25;
        t = (t >> 25) + (x0 * y2) + (x2 * y0) + 19 * ((x4 * y8) + (x6 * y6) + (x8 * y4)) + 2 * (x1 * y1) + 38 * ((x3 * y9) + (x5 * y7) + (x7 * y5) + (x9 * y3));
        xy.N2 = t & P26;
        t = (t >> 26) + (x0 * y3) + (x1 * y2) + (x2 * y1) + (x3 * y0) + 19 * ((x4 * y9) + (x5 * y8) + (x6 * y7) + (x7 * y6) + (x8 * y5) + (x9 * y4));
        xy.N3 = t & P25;
        t = (t >> 25) + (x0 * y4) + (x2 * y2) + (x4 * y0) + 19 * ((x6 * y8) + (x8 * y6)) + 2 * ((x1 * y3) + (x3 * y1)) + 38 * ((x5 * y9) + (x7 * y7) + (x9 * y5));
        xy.N4 = t & P26;
        t = (t >> 26) + (x0 * y5) + (x1 * y4) + (x2 * y3) + (x3 * y2) + (x4 * y1) + (x5 * y0) + 19 * ((x6 * y9) + (x7 * y8) + (x8 * y7) + (x9 * y6));
        xy.N5 = t & P25;
        t = (t >> 25) + (x0 * y6) + (x2 * y4) + (x4 * y2) + (x6 * y0) + 19 * (x8 * y8) + 2 * ((x1 * y5) + (x3 * y3) + (x5 * y1)) + 38 * ((x7 * y9) + (x9 * y7));
        xy.N6 = t & P26;
        t = (t >> 26) + (x0 * y7) + (x1 * y6) + (x2 * y5) + (x3 * y4) + (x4 * y3) + (x5 * y2) + (x6 * y1) + (x7 * y0) + 19 * ((x8 * y9) + (x9 * y8));
        xy.N7 = t & P25;
        t = (t >> 25) + xy.N8;
        xy.N8 = t & P26;
        xy.N9 += (t >> 26);
    }

    /// <summary>
    /// Field squaring
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Square(Long10 xsq, Long10 x)
    {
        var x0 = x.N0; var x1 = x.N1; var x2 = x.N2; var x3 = x.N3; var x4 = x.N4;
        var x5 = x.N5; var x6 = x.N6; var x7 = x.N7; var x8 = x.N8; var x9 = x.N9;
        long t;

        t = (x4 * x4) + 2 * ((x0 * x8) + (x2 * x6)) + 38 * (x9 * x9) + 4 * ((x1 * x7) + (x3 * x5));
        xsq.N8 = t & P26;
        t = (t >> 26) + 2 * ((x0 * x9) + (x1 * x8) + (x2 * x7) + (x3 * x6) + (x4 * x5));
        xsq.N9 = t & P25;
        t = 19 * (t >> 25) + (x0 * x0) + 38 * ((x2 * x8) + (x4 * x6) + (x5 * x5)) + 76 * ((x1 * x9) + (x3 * x7));
        xsq.N0 = t & P26;
        t = (t >> 26) + 2 * (x0 * x1) + 38 * ((x2 * x9) + (x3 * x8) + (x4 * x7) + (x5 * x6));
        xsq.N1 = t & P25;
        t = (t >> 25) + 19 * (x6 * x6) + 2 * ((x0 * x2) + (x1 * x1)) + 38 * (x4 * x8) + 76 * ((x3 * x9) + (x5 * x7));
        xsq.N2 = t & P26;
        t = (t >> 26) + 2 * ((x0 * x3) + (x1 * x2)) + 38 * ((x4 * x9) + (x5 * x8) + (x6 * x7));
        xsq.N3 = t & P25;
        t = (t >> 25) + (x2 * x2) + 2 * (x0 * x4) + 38 * ((x6 * x8) + (x7 * x7)) + 4 * (x1 * x3) + 76 * (x5 * x9);
        xsq.N4 = t & P26;
        t = (t >> 26) + 2 * ((x0 * x5) + (x1 * x4) + (x2 * x3)) + 38 * ((x6 * x9) + (x7 * x8));
        xsq.N5 = t & P25;
        t = (t >> 25) + 19 * (x8 * x8) + 2 * ((x0 * x6) + (x2 * x4) + (x3 * x3)) + 4 * (x1 * x5) + 76 * (x7 * x9);
        xsq.N6 = t & P26;
        t = (t >> 26) + 2 * ((x0 * x7) + (x1 * x6) + (x2 * x5) + (x3 * x4)) + 38 * (x8 * x9);
        xsq.N7 = t & P25;
        t = (t >> 25) + xsq.N8;
        xsq.N8 = t & P26;
        xsq.N9 += (t >> 26);
    }

    /// <summary>
    /// Multiply by small constant
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void MultiplySmall(Long10 xy, Long10 x, long y)
    {
        long t;
        t = x.N8 * y;
        xy.N8 = t & P26; var c = t >> 26;
        t = x.N9 * y + c;
        xy.N9 = t & P25; c = t >> 25;
        t = x.N0 * y + 19 * c;
        xy.N0 = t & P26; c = t >> 26;
        t = x.N1 * y + c;
        xy.N1 = t & P25; c = t >> 25;
        t = x.N2 * y + c;
        xy.N2 = t & P26; c = t >> 26;
        t = x.N3 * y + c;
        xy.N3 = t & P25; c = t >> 25;
        t = x.N4 * y + c;
        xy.N4 = t & P26; c = t >> 26;
        t = x.N5 * y + c;
        xy.N5 = t & P25; c = t >> 25;
        t = x.N6 * y + c;
        xy.N6 = t & P26; c = t >> 26;
        t = x.N7 * y + c;
        xy.N7 = t & P25; c = t >> 25;
        t = x.N8 * y + c;
        xy.N8 = t & P26; c = t >> 26;
        xy.N9 += c;
    }

    /// <summary>
    /// Modular inverse using Fermat's little theorem
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Recip(Long10 y, Long10 x)
    {
        var z0 = new Long10();
        var z1 = new Long10();
        var z2 = new Long10();
        var z9 = new Long10();
        var z11 = new Long10();
        var z2_5_0 = new Long10();
        var z2_10_0 = new Long10();
        var z2_20_0 = new Long10();
        var z2_50_0 = new Long10();
        var z2_100_0 = new Long10();
        var t0 = new Long10();
        var t1 = new Long10();

        /* 2 */ Square(z2, x);
        /* 4 */ Square(t1, z2);
        /* 8 */ Square(t0, t1);
        /* 9 */ Multiply(z9, t0, x);
        /* 11 */ Multiply(z11, z9, z2);
        /* 22 */ Square(t0, z11);
        /* 2^5 - 2^0 = 31 */ Multiply(z2_5_0, t0, z9);

        /* 2^6 - 2^1 */ Square(t0, z2_5_0);
        /* 2^7 - 2^2 */ Square(t1, t0);
        /* 2^8 - 2^3 */ Square(t0, t1);
        /* 2^9 - 2^4 */ Square(t1, t0);
        /* 2^10 - 2^5 */ Square(t0, t1);
        /* 2^10 - 2^0 */ Multiply(z2_10_0, t0, z2_5_0);

        /* 2^11 - 2^1 */ Square(t0, z2_10_0);
        /* 2^12 - 2^2 */ Square(t1, t0);
        /* 2^20 - 2^10 */ for (var i = 2; i < 10; i += 2) { Square(t0, t1); Square(t1, t0); }
        /* 2^20 - 2^0 */ Multiply(z2_20_0, t1, z2_10_0);

        /* 2^21 - 2^1 */ Square(t0, z2_20_0);
        /* 2^22 - 2^2 */ Square(t1, t0);
        /* 2^40 - 2^20 */ for (var i = 2; i < 20; i += 2) { Square(t0, t1); Square(t1, t0); }
        /* 2^40 - 2^0 */ Multiply(t0, t1, z2_20_0);

        /* 2^41 - 2^1 */ Square(t1, t0);
        /* 2^42 - 2^2 */ Square(t0, t1);
        /* 2^50 - 2^10 */ for (var i = 2; i < 10; i += 2) { Square(t1, t0); Square(t0, t1); }
        /* 2^50 - 2^0 */ Multiply(z2_50_0, t0, z2_10_0);

        /* 2^51 - 2^1 */ Square(t0, z2_50_0);
        /* 2^52 - 2^2 */ Square(t1, t0);
        /* 2^100 - 2^50 */ for (var i = 2; i < 50; i += 2) { Square(t0, t1); Square(t1, t0); }
        /* 2^100 - 2^0 */ Multiply(z2_100_0, t1, z2_50_0);

        /* 2^101 - 2^1 */ Square(t1, z2_100_0);
        /* 2^102 - 2^2 */ Square(t0, t1);
        /* 2^200 - 2^100 */ for (var i = 2; i < 100; i += 2) { Square(t1, t0); Square(t0, t1); }
        /* 2^200 - 2^0 */ Multiply(t1, t0, z2_100_0);

        /* 2^201 - 2^1 */ Square(t0, t1);
        /* 2^202 - 2^2 */ Square(t1, t0);
        /* 2^250 - 2^50 */ for (var i = 2; i < 50; i += 2) { Square(t0, t1); Square(t1, t0); }
        /* 2^250 - 2^0 */ Multiply(t0, t1, z2_50_0);

        /* 2^251 - 2^1 */ Square(t1, t0);
        /* 2^252 - 2^2 */ Square(t0, t1);
        /* 2^253 - 2^3 */ Square(t1, t0);
        /* 2^254 - 2^4 */ Square(t0, t1);
        /* 2^255 - 2^5 */ Square(t1, t0);
        /* 2^255 - 21 */ Multiply(y, t1, z11);
    }
}
