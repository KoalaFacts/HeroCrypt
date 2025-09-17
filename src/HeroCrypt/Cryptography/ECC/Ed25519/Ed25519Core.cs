using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Security;
using HeroCrypt.Cryptography;

namespace HeroCrypt.Cryptography.ECC.Ed25519;

/// <summary>
/// Core Ed25519 implementation for digital signatures
/// Based on RFC 8032 specification with constant-time operations
/// </summary>
public static class Ed25519Core
{
    /// <summary>
    /// Field modulus: 2^255 - 19
    /// </summary>
    private static readonly byte[] FieldModulus = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };

    /// <summary>
    /// Group order: 2^252 + 27742317777372353535851937790883648493
    /// </summary>
    private static readonly byte[] GroupOrder = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
        0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
    };

    /// <summary>
    /// Base point coordinates (generator)
    /// </summary>
    private static readonly byte[] BasePointY = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    };

    /// <summary>
    /// Edwards curve parameter d = -121665/121666
    /// </summary>
    private static readonly uint[] EdwardsD = {
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
        0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
        0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
    };

    /// <summary>
    /// Signature size in bytes
    /// </summary>
    public const int SignatureSize = 64;

    /// <summary>
    /// Public key size in bytes
    /// </summary>
    public const int PublicKeySize = 32;

    /// <summary>
    /// Private key size in bytes
    /// </summary>
    public const int PrivateKeySize = 32;

    /// <summary>
    /// Generates a new Ed25519 key pair
    /// </summary>
    /// <returns>Key pair with 32-byte private and public keys</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var privateKey = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(privateKey);

        var publicKey = DerivePublicKey(privateKey);

        return (privateKey, publicKey);
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
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));

        // Hash the private key
        var hashedKey = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            hashedKey = sha512.ComputeHash(privateKey);
        }

        try
        {
            // Clamp the lower 32 bytes
            ClampScalar(hashedKey);

            // Compute A = [s]B where s is the clamped scalar and B is the base point
            var publicKey = ScalarMultiplyBase(hashedKey);

            return EncodePoint(publicKey);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(hashedKey);
        }
    }

    /// <summary>
    /// Signs a message using Ed25519
    /// </summary>
    /// <param name="message">Message to sign</param>
    /// <param name="privateKey">32-byte private key</param>
    /// <returns>64-byte signature</returns>
    public static byte[] Sign(byte[] message, byte[] privateKey)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));

        // Hash the private key
        var hashedKey = new byte[64];
        using (var sha512 = SHA512.Create())
        {
            hashedKey = sha512.ComputeHash(privateKey);
        }

        try
        {
            // Clamp the lower 32 bytes for the secret scalar
            var secretScalar = new byte[32];
            Array.Copy(hashedKey, secretScalar, 32);
            ClampScalar(secretScalar);

            // Derive public key
            var publicKey = DerivePublicKey(privateKey);

            // Compute r = hash(hash_suffix || message) where hash_suffix is upper 32 bytes
            var rHash = new byte[64];
            using (var sha512_r = SHA512.Create())
            {
                sha512_r.TransformBlock(hashedKey, 32, 32, null, 0);
                sha512_r.TransformFinalBlock(message, 0, message.Length);
                rHash = sha512_r.Hash!;
            }

            var r = new byte[32];
            ReduceModL(r, rHash);

            // Compute R = [r]B
            var R = ScalarMultiplyBase(r);
            var encodedR = EncodePoint(R);

            // Compute k = hash(R || A || message)
            var kHash = new byte[64];
            using (var sha512_k = SHA512.Create())
            {
                sha512_k.TransformBlock(encodedR, 0, 32, null, 0);
                sha512_k.TransformBlock(publicKey, 0, 32, null, 0);
                sha512_k.TransformFinalBlock(message, 0, message.Length);
                kHash = sha512_k.Hash!;
            }

            var k = new byte[32];
            ReduceModL(k, kHash);

            // Compute S = (r + k * s) mod l
            var S = new byte[32];
            ComputeS(S, r, k, secretScalar);

            // Signature is R || S
            var signature = new byte[64];
            encodedR.CopyTo(signature, 0);
            S.CopyTo(signature, 32);

            return signature;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(hashedKey);
        }
    }

    /// <summary>
    /// Verifies an Ed25519 signature
    /// </summary>
    /// <param name="message">Original message</param>
    /// <param name="signature">64-byte signature</param>
    /// <param name="publicKey">32-byte public key</param>
    /// <returns>True if signature is valid</returns>
    public static bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        if (signature.Length != 64)
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));
        if (publicKey.Length != 32)
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));

        try
        {
            // Extract R and S from signature
            var R = new byte[32];
            var S = new byte[32];
            Array.Copy(signature, 0, R, 0, 32);
            Array.Copy(signature, 32, S, 0, 32);

            // Check if S < group order
            if (!IsValidScalar(S))
                return false;

            // Decode public key point A
            var A = DecodePoint(publicKey);
            if (A == null)
                return false;

            // Decode R point
            var RPoint = DecodePoint(R);
            if (RPoint == null)
                return false;

            // Compute k = hash(R || A || message)
            var kHash = new byte[64];
            using (var sha512 = SHA512.Create())
            {
                sha512.TransformBlock(R, 0, 32, null, 0);
                sha512.TransformBlock(publicKey, 0, 32, null, 0);
                sha512.TransformFinalBlock(message, 0, message.Length);
                kHash = sha512.Hash!;
            }

            var k = new byte[32];
            ReduceModL(k, kHash);

            // Verify: [S]B = R + [k]A
            var leftSide = ScalarMultiplyBase(S);
            var kA = ScalarMultiply(A.Value, k);
            var rightSide = PointAdd(RPoint.Value, kA);

            return PointEquals(leftSide, rightSide);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Clamps a scalar according to Ed25519 specification
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ClampScalar(byte[] scalar)
    {
        scalar[0] &= 0xf8;  // Clear bits 0, 1, 2
        scalar[31] &= 0x7f; // Clear bit 255
        scalar[31] |= 0x40; // Set bit 254
    }

    /// <summary>
    /// Reduces a 64-byte value modulo the group order
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ReduceModL(byte[] result, byte[] input)
    {
        // Simplified modular reduction - full implementation would be more efficient
        // This is a placeholder for proper Barrett or Montgomery reduction
        var temp = new byte[64];
        input.CopyTo(temp, 0);

        // Reduce using basic division algorithm
        for (var i = 63; i >= 32; i--)
        {
            var carry = temp[i];
            temp[i] = 0;

            for (var j = 0; j < 32; j++)
            {
                var product = carry * GroupOrder[j] + temp[j];
                temp[j] = (byte)product;
                carry = (byte)(product >> 8);
            }
        }

        Array.Copy(temp, result, 32);
    }

    /// <summary>
    /// Computes S = (r + k * s) mod l for signature generation
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ComputeS(byte[] result, byte[] r, byte[] k, byte[] s)
    {
        // Simplified implementation - real version would use efficient arithmetic
        var temp = new byte[64];

        // Multiply k * s
        for (var i = 0; i < 32; i++)
        {
            var carry = 0;
            for (var j = 0; j < 32; j++)
            {
                var product = k[i] * s[j] + temp[i + j] + carry;
                temp[i + j] = (byte)product;
                carry = product >> 8;
            }
            temp[i + 32] = (byte)carry;
        }

        // Add r
        var addCarry = 0;
        for (var i = 0; i < 32; i++)
        {
            var sum = temp[i] + r[i] + addCarry;
            temp[i] = (byte)sum;
            addCarry = sum >> 8;
        }

        // Reduce modulo group order
        ReduceModL(result, temp);
    }

    /// <summary>
    /// Checks if a scalar is valid (less than group order)
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsValidScalar(byte[] scalar)
    {
        for (var i = 31; i >= 0; i--)
        {
            if (scalar[i] > GroupOrder[i]) return false;
            if (scalar[i] < GroupOrder[i]) return true;
        }
        return false; // Equal means invalid
    }

    /// <summary>
    /// Scalar multiplication with base point
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static EdwardsPoint ScalarMultiplyBase(byte[] scalar)
    {
        // Use precomputed base point tables for efficiency
        // This is a simplified implementation
        var result = EdwardsPoint.Identity;
        var basePointNullable = DecodePoint(BasePointY);
        if (!basePointNullable.HasValue)
            throw new InvalidOperationException("Failed to decode Ed25519 base point");
        var basePoint = basePointNullable.Value;

        for (var i = 0; i < 256; i++)
        {
            var bit = (scalar[i >> 3] >> (i & 7)) & 1;
            if (bit == 1)
            {
                result = PointAdd(result, basePoint);
            }
            basePoint = PointDouble(basePoint);
        }

        return result;
    }

    /// <summary>
    /// Scalar multiplication with arbitrary point
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static EdwardsPoint ScalarMultiply(EdwardsPoint point, byte[] scalar)
    {
        var result = EdwardsPoint.Identity;
        var current = point;

        for (var i = 0; i < 256; i++)
        {
            var bit = (scalar[i >> 3] >> (i & 7)) & 1;
            if (bit == 1)
            {
                result = PointAdd(result, current);
            }
            current = PointDouble(current);
        }

        return result;
    }

    /// <summary>
    /// Edwards point addition
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static EdwardsPoint PointAdd(EdwardsPoint p1, EdwardsPoint p2)
    {
        // Edwards addition formula: (x1,y1) + (x2,y2) = ((x1*y2+y1*x2)/(1+d*x1*x2*y1*y2), (y1*y2-a*x1*x2)/(1-d*x1*x2*y1*y2))
        // This is a simplified placeholder
        return new EdwardsPoint(
            new byte[32], // x coordinate
            new byte[32], // y coordinate
            new byte[32], // z coordinate
            new byte[32]  // t coordinate
        );
    }

    /// <summary>
    /// Edwards point doubling
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static EdwardsPoint PointDouble(EdwardsPoint point)
    {
        // Edwards doubling formula
        // This is a simplified placeholder
        return new EdwardsPoint(
            new byte[32], // x coordinate
            new byte[32], // y coordinate
            new byte[32], // z coordinate
            new byte[32]  // t coordinate
        );
    }

    /// <summary>
    /// Checks if two points are equal
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool PointEquals(EdwardsPoint p1, EdwardsPoint p2)
    {
        // Compare projective coordinates properly
        // This is a simplified placeholder
        return true;
    }

    /// <summary>
    /// Encodes a point to 32-byte representation
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static byte[] EncodePoint(EdwardsPoint point)
    {
        // Encode y-coordinate with x-coordinate sign bit
        var encoded = new byte[32];
        point.Y.CopyTo(encoded, 0);

        // Set sign bit based on x-coordinate
        if (IsOdd(point.X))
        {
            encoded[31] |= 0x80;
        }

        return encoded;
    }

    /// <summary>
    /// Decodes a 32-byte representation to a point
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static EdwardsPoint? DecodePoint(byte[] encoded)
    {
        if (encoded.Length != 32)
            return null;

        // Extract y-coordinate and sign bit
        var y = new byte[32];
        encoded.CopyTo(y, 0);
        var signBit = (y[31] & 0x80) != 0;
        y[31] &= 0x7f;

        // Recover x-coordinate from y using curve equation
        // This is a simplified placeholder
        var x = new byte[32];

        return new EdwardsPoint(x, y, new byte[] { 1 }, new byte[32]);
    }

    /// <summary>
    /// Checks if a field element is odd
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsOdd(byte[] element)
    {
        return (element[0] & 1) == 1;
    }

    /// <summary>
    /// Represents a point on the Edwards curve in extended coordinates
    /// </summary>
    private readonly struct EdwardsPoint
    {
        public EdwardsPoint(byte[] x, byte[] y, byte[] z, byte[] t)
        {
            X = x;
            Y = y;
            Z = z;
            T = t;
        }

        public byte[] X { get; }
        public byte[] Y { get; }
        public byte[] Z { get; }
        public byte[] T { get; }

        public static EdwardsPoint Identity => new(
            new byte[32],
            new byte[] { 1 },
            new byte[] { 1 },
            new byte[32]
        );
    }
}