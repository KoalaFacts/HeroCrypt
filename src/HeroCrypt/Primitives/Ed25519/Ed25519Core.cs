using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Ed25519;

/// <summary>
/// RFC 8032 Ed25519 digital signature implementation.
/// </summary>
/// <remarks>
/// <para>
/// Ed25519 is an elliptic curve digital signature algorithm using Curve25519.
/// It provides high security (128-bit security level), fast signing and verification,
/// and small key/signature sizes.
/// </para>
/// <para>
/// This is a pure managed implementation based on the TweetNaCl reference.
/// </para>
/// </remarks>
internal static class Ed25519Core
{
    /// <summary>
    /// Size of Ed25519 signatures in bytes (64 bytes as per RFC 8032)
    /// </summary>
    public const int SIGNATURE_SIZE = 64;

    /// <summary>
    /// Size of Ed25519 public keys in bytes (32 bytes as per RFC 8032)
    /// </summary>
    public const int PUBLIC_KEY_SIZE = 32;

    /// <summary>
    /// Size of Ed25519 private keys (seeds) in bytes (32 bytes as per RFC 8032)
    /// </summary>
    public const int PRIVATE_KEY_SIZE = 32;

    /// <summary>
    /// Generates a new Ed25519 key pair
    /// </summary>
    /// <returns>A tuple containing the private key (seed) and public key</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = new byte[PRIVATE_KEY_SIZE];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(privateKey);

        var publicKey = DerivePublicKey(privateKey);
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Derives the public key from a private key (seed)
    /// </summary>
    /// <param name="privateKey">The private key seed (32 bytes)</param>
    /// <returns>The corresponding public key (32 bytes)</returns>
    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        ValidatePrivateKey(privateKey);
        return Ed25519Impl.DerivePublicKey(privateKey.ToArray());
    }

    /// <summary>
    /// Signs a message using the private key
    /// </summary>
    /// <param name="message">The message to sign</param>
    /// <param name="privateKey">The private key seed (32 bytes)</param>
    /// <returns>The signature (64 bytes)</returns>
    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        ValidatePrivateKey(privateKey);
        return Ed25519Impl.Sign(message.ToArray(), privateKey.ToArray());
    }

    /// <summary>
    /// Verifies a signature against a message using the public key
    /// </summary>
    /// <param name="message">The message that was signed</param>
    /// <param name="signature">The signature to verify (64 bytes)</param>
    /// <param name="publicKey">The public key (32 bytes)</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != PUBLIC_KEY_SIZE)
        {
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));
        }
        if (signature.Length != SIGNATURE_SIZE)
        {
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));
        }

        return Ed25519Impl.Verify(message.ToArray(), signature.ToArray(), publicKey.ToArray());
    }

    private static void ValidatePrivateKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != PRIVATE_KEY_SIZE)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        }
    }
}

/// <summary>
/// Ed25519 implementation based on TweetNaCl reference implementation.
/// Uses 64-bit limb representation for field elements.
/// </summary>
internal static class Ed25519Impl
{
    // Static readonly constants for Ed25519 curve (avoid allocation on every call)
    private static readonly long[] GfDConst =
    [
        0x78a3, 0x1359, 0x4dca, 0x75eb,
        0xd8ab, 0x4141, 0x0a4d, 0x0070,
        0xe898, 0x7779, 0x4079, 0x8cc7,
        0xfe73, 0x2b6f, 0x6cee, 0x5203
    ];

    private static readonly long[] GfD2Const =
    [
        0xf159, 0x26b2, 0x9b94, 0xebd6,
        0xb156, 0x8283, 0x149a, 0x00e0,
        0xd130, 0xeef3, 0x80f2, 0x198e,
        0xfce7, 0x56df, 0xd9dc, 0x2406
    ];

    private static readonly long[] GfXConst =
    [
        0xd51a, 0x8f25, 0x2d60, 0xc956,
        0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
        0x53fe, 0xcd6e, 0x36d3, 0x2169
    ];

    private static readonly long[] GfYConst =
    [
        0x6658, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666
    ];

    private static readonly long[] GfIConst =
    [
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
        0xe478, 0xad2f, 0x1806, 0x2f43,
        0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
        0xdf0b, 0x4fc1, 0x2480, 0x2b83
    ];

    // The group order L (as bytes)
    private static readonly byte[] L =
    [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
        0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    ];

    /// <summary>
    /// Derives a public key from the given seed using Ed25519 curve operations.
    /// </summary>
    /// <param name="seed">The 32-byte seed to derive the public key from.</param>
    /// <returns>The 32-byte public key.</returns>
    public static byte[] DerivePublicKey(byte[] seed)
    {
        var h = Sha512(seed);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;

        var p = new long[4][];
        for (var i = 0; i < 4; i++)
        {
            p[i] = new long[16];
        }

        Scalarbase(p, h);
        var pk = new byte[32];
        Pack(pk, p);

        ClearArray(h);
        return pk;
    }

    /// <summary>
    /// Signs a message using the Ed25519 signature algorithm.
    /// </summary>
    /// <param name="m">The message to sign.</param>
    /// <param name="sk">The 32-byte secret key (seed).</param>
    /// <returns>The 64-byte signature.</returns>
    public static byte[] Sign(byte[] m, byte[] sk)
    {
        var h = Sha512(sk);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;

        // Derive public key
        var p = new long[4][];
        for (var i = 0; i < 4; i++)
        {
            p[i] = new long[16];
        }
        Scalarbase(p, h);
        var pk = new byte[32];
        Pack(pk, p);

        // r = H(h[32..64] || m)
        var mlen = m.Length;
        var sm = new byte[64 + mlen];

        Array.Copy(m, 0, sm, 64, mlen);
        Array.Copy(h, 32, sm, 32, 32);

        var r = Sha512(sm.AsSpan(32, 32 + mlen).ToArray());
        Reduce(r);

        // R = rB
        Scalarbase(p, r);
        Pack(sm, p);

        // k = H(R || A || m)
        Array.Copy(pk, 0, sm, 32, 32);
        var hram = Sha512(sm);
        Reduce(hram);

        // S = r + k*a
        var x = new long[64];
        for (var i = 0; i < 32; i++)
        {
            x[i] = r[i];
        }

        for (var i = 0; i < 32; i++)
        {
            for (var j = 0; j < 32; j++)
            {
                x[i + j] += (long)hram[i] * h[j];
            }
        }

        ModL(sm, 32, x);

        var sig = new byte[64];
        Array.Copy(sm, 0, sig, 0, 64);

        ClearArray(h);
        ClearLongArray(x);
        ClearArray(r);

        return sig;
    }

    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="m">The original message.</param>
    /// <param name="sm">The 64-byte signature to verify.</param>
    /// <param name="pk">The 32-byte public key.</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public static bool Verify(byte[] m, byte[] sm, byte[] pk)
    {
        var t = new byte[32];
        var p = new long[4][];
        var q = new long[4][];

        for (var i = 0; i < 4; i++)
        {
            p[i] = new long[16];
            q[i] = new long[16];
        }

        if (!Unpackneg(q, pk))
        {
            return false;
        }

        // Reconstruct message for hashing
        var mlen = m.Length;
        var fullm = new byte[64 + mlen];
        Array.Copy(sm, 0, fullm, 0, 32);  // R
        Array.Copy(pk, 0, fullm, 32, 32); // A
        Array.Copy(m, 0, fullm, 64, mlen);

        var h = Sha512(fullm);
        Reduce(h);

        Scalarmult(p, q, h);
        Scalarbase(q, sm.AsSpan(32, 32).ToArray());
        Add(p, q);
        Pack(t, p);

        if (!SecureMemoryOperations.ConstantTimeEquals(sm.AsSpan(0, 32), t))
        {
            return false;
        }

        return true;
    }

    #region Core Operations

    private static void Set25519(long[] r, long[] a)
    {
        for (var i = 0; i < 16; i++)
        {
            r[i] = a[i];
        }
    }

    private static void Car25519(long[] o)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            var c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + (i == 15 ? 37 * (c - 1) : 0);
            o[i] -= c << 16;
        }
    }

    private static void Sel25519(long[] p, long[] q, int b)
    {
        long c = ~(b - 1);
        for (var i = 0; i < 16; i++)
        {
            var t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack25519(byte[] o, long[] n)
    {
        var m = new long[16];
        var t = new long[16];

        for (var i = 0; i < 16; i++)
        {
            t[i] = n[i];
        }

        Car25519(t);
        Car25519(t);
        Car25519(t);

        for (var j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xFFED;
            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xFFFF;
            }
            m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
            var b = (int)((m[15] >> 16) & 1);
            m[14] &= 0xFFFF;
            Sel25519(t, m, 1 - b);
        }

        for (var i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xFF);
            o[2 * i + 1] = (byte)(t[i] >> 8);
        }
    }

    private static void Unpack25519(long[] o, byte[] n)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] = (n[2 * i] & 0xFF) + ((long)(n[2 * i + 1] & 0xFF) << 8);
        }
        o[15] &= 0x7FFF;
    }

    private static void A(long[] o, long[] a, long[] b)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] = a[i] + b[i];
        }
    }

    private static void Z(long[] o, long[] a, long[] b)
    {
        for (var i = 0; i < 16; i++)
        {
            o[i] = a[i] - b[i];
        }
    }

    private static void M(long[] o, long[] a, long[] b)
    {
        var t = new long[31];

        for (var i = 0; i < 31; i++)
        {
            t[i] = 0;
        }

        for (var i = 0; i < 16; i++)
        {
            for (var j = 0; j < 16; j++)
            {
                t[i + j] += a[i] * b[j];
            }
        }

        for (var i = 0; i < 15; i++)
        {
            t[i] += 38 * t[i + 16];
        }

        for (var i = 0; i < 16; i++)
        {
            o[i] = t[i];
        }

        Car25519(o);
        Car25519(o);
    }

    private static void S(long[] o, long[] a)
    {
        M(o, a, a);
    }

    private static void Inv25519(long[] o, long[] i)
    {
        var c = new long[16];
        for (var a = 0; a < 16; a++)
        {
            c[a] = i[a];
        }

        for (var a = 253; a >= 0; a--)
        {
            S(c, c);
            if (a is not 2 and not 4)
            {
                M(c, c, i);
            }
        }

        for (var a = 0; a < 16; a++)
        {
            o[a] = c[a];
        }
    }

    private static void Pow2523(long[] o, long[] i)
    {
        var c = new long[16];
        for (var a = 0; a < 16; a++)
        {
            c[a] = i[a];
        }

        for (var a = 250; a >= 0; a--)
        {
            S(c, c);
            if (a != 1)
            {
                M(c, c, i);
            }
        }

        for (var a = 0; a < 16; a++)
        {
            o[a] = c[a];
        }
    }

    #endregion

    #region Point Operations

    private static void Pack(byte[] r, long[][] p)
    {
        var tx = new long[16];
        var ty = new long[16];
        var zi = new long[16];

        Inv25519(zi, p[2]);
        M(tx, p[0], zi);
        M(ty, p[1], zi);

        Pack25519(r, ty);
        r[31] ^= (byte)(Par25519(tx) << 7);
    }

    private static int Par25519(long[] a)
    {
        var d = new byte[32];
        Pack25519(d, a);
        return d[0] & 1;
    }

    private static bool Unpackneg(long[][] r, byte[] p)
    {
        var t = new long[16];
        var chk = new long[16];
        var num = new long[16];
        var den = new long[16];
        var den2 = new long[16];
        var den4 = new long[16];
        var den6 = new long[16];

        Set25519(r[2], Gf1());
        Unpack25519(r[1], p);
        S(num, r[1]);
        M(den, num, GfD());
        Z(num, num, r[2]);
        A(den, r[2], den);

        S(den2, den);
        S(den4, den2);
        M(den6, den4, den2);
        M(t, den6, num);
        M(t, t, den);

        Pow2523(t, t);
        M(t, t, num);
        M(t, t, den);
        M(t, t, den);
        M(r[0], t, den);

        S(chk, r[0]);
        M(chk, chk, den);
        if (!Neq25519(chk, num))
        {
            M(r[0], r[0], GfI());
        }

        S(chk, r[0]);
        M(chk, chk, den);
        if (!Neq25519(chk, num))
        {
            return false;
        }

        if (Par25519(r[0]) == (p[31] >> 7))
        {
            Z(r[0], Gf0(), r[0]);
        }

        M(r[3], r[0], r[1]);
        return true;
    }

    private static bool Neq25519(long[] a, long[] b)
    {
        var c = new byte[32];
        var d = new byte[32];
        Pack25519(c, a);
        Pack25519(d, b);
        return CryptoVerify32(c, d);
    }

    private static void Add(long[][] p, long[][] q)
    {
        var a = new long[16];
        var b = new long[16];
        var c = new long[16];
        var d = new long[16];
        var e = new long[16];
        var f = new long[16];
        var g = new long[16];
        var h = new long[16];
        var t = new long[16];

        Z(a, p[1], p[0]);
        Z(t, q[1], q[0]);
        M(a, a, t);
        A(b, p[0], p[1]);
        A(t, q[0], q[1]);
        M(b, b, t);
        M(c, p[3], q[3]);
        M(c, c, GfD2());
        M(d, p[2], q[2]);
        A(d, d, d);
        Z(e, b, a);
        Z(f, d, c);
        A(g, d, c);
        A(h, b, a);

        M(p[0], e, f);
        M(p[1], h, g);
        M(p[2], g, f);
        M(p[3], e, h);
    }

    private static void Cswap(long[][] p, long[][] q, int b)
    {
        for (var i = 0; i < 4; i++)
        {
            Sel25519(p[i], q[i], b);
        }
    }

    private static void Scalarbase(long[][] p, byte[] s)
    {
        var q = new long[4][];
        for (var i = 0; i < 4; i++)
        {
            q[i] = new long[16];
        }

        Set25519(q[0], GfX());
        Set25519(q[1], GfY());
        Set25519(q[2], Gf1());
        M(q[3], GfX(), GfY());

        Scalarmult(p, q, s);
    }

    private static void Scalarmult(long[][] p, long[][] q, byte[] s)
    {
        Set25519(p[0], Gf0());
        Set25519(p[1], Gf1());
        Set25519(p[2], Gf1());
        Set25519(p[3], Gf0());

        for (var i = 255; i >= 0; i--)
        {
            var b = (s[i / 8] >> (i & 7)) & 1;
            Cswap(p, q, b);
            Add(q, p);
            Add(p, p);
            Cswap(p, q, b);
        }
    }

    #endregion

    #region Reduction

    private static void ModL(byte[] r, int roff, long[] x)
    {
        for (var i = 63; i >= 32; i--)
        {
            long carry = 0;
            for (var j = i - 32; j < i - 12; j++)
            {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                carry = (x[j] + 128) >> 8;
                x[j] -= carry << 8;
            }
            x[i - 12] += carry;
            x[i] = 0;
        }

        long carry2 = 0;
        for (var j = 0; j < 32; j++)
        {
            x[j] += carry2 - (x[31] >> 4) * L[j];
            carry2 = x[j] >> 8;
            x[j] &= 255;
        }

        for (var j = 0; j < 32; j++)
        {
            x[j] -= carry2 * L[j];
        }

        for (var i = 0; i < 32; i++)
        {
            x[i + 1] += x[i] >> 8;
            r[roff + i] = (byte)(x[i] & 255);
        }
    }

    private static void Reduce(byte[] r)
    {
        var x = new long[64];
        for (var i = 0; i < 64; i++)
        {
            x[i] = r[i];
        }
        for (var i = 0; i < 64; i++)
        {
            r[i] = 0;
        }
        ModL(r, 0, x);
    }

    #endregion

    #region Constants

    private static long[] Gf0()
    {
        return new long[16];
    }

    private static long[] Gf1()
    {
        var gf = new long[16];
        gf[0] = 1;
        return gf;
    }

    private static long[] GfD()
    {
        return (long[])GfDConst.Clone();
    }

    private static long[] GfD2()
    {
        return (long[])GfD2Const.Clone();
    }

    private static long[] GfX()
    {
        return (long[])GfXConst.Clone();
    }

    private static long[] GfY()
    {
        return (long[])GfYConst.Clone();
    }

    private static long[] GfI()
    {
        return (long[])GfIConst.Clone();
    }

    #endregion

    #region Utilities

    /// <summary>
    /// Performs constant-time comparison of two 32-byte arrays.
    /// Uses SecureMemoryOperations.ConstantTimeEquals for timing attack resistance.
    /// </summary>
    private static bool CryptoVerify32(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        return SecureMemoryOperations.ConstantTimeEquals(x[..32], y[..32]);
    }

    private static byte[] Sha512(byte[] m)
    {
#if NETSTANDARD2_0
        using var sha = SHA512.Create();
        return sha.ComputeHash(m);
#else
        return SHA512.HashData(m);
#endif
    }

    private static void ClearArray(byte[] a)
    {
        SecureMemoryOperations.SecureClear(a);
    }

    private static void ClearLongArray(long[] a)
    {
        SecureMemoryOperations.SecureClear(a.AsSpan());
    }

    #endregion
}
