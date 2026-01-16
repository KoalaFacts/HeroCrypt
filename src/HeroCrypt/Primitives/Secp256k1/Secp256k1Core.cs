using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>
/// Core secp256k1 implementation for blockchain applications.
/// Uses System.Numerics.BigInteger for correct elliptic curve arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// The secp256k1 curve is defined by the SEC (Standards for Efficient Cryptography) group
/// and is the elliptic curve used by Bitcoin and Ethereum for digital signatures.
/// </para>
/// <para><b>Curve Parameters:</b></para>
/// <list type="bullet">
///   <item>OID: 1.3.132.0.10</item>
///   <item>Field: 256-bit prime field</item>
///   <item>Security: ~128-bit symmetric equivalent</item>
/// </list>
/// </remarks>
internal static class Secp256k1Core
{
    /// <summary>
    /// Field prime: p = 2^256 - 2^32 - 977
    /// </summary>
    private static readonly BigInteger FieldPrime = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// Group order: n
    /// </summary>
    private static readonly BigInteger GroupOrderN = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// Exponent for square root: (p + 1) / 4
    /// </summary>
    private static readonly BigInteger SqrtExponent = (FieldPrime + 1) / 4;

    /// <summary>
    /// Generator point G x-coordinate
    /// </summary>
    private static readonly BigInteger GeneratorX = BigInteger.Parse(
        "079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// Generator point G y-coordinate
    /// </summary>
    private static readonly BigInteger GeneratorY = BigInteger.Parse(
        "0483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>
    /// Curve parameter b = 7 for secp256k1 (y² = x³ + 7)
    /// </summary>
    private static readonly BigInteger CurveB = 7;

    /// <summary>
    /// Private key size in bytes
    /// </summary>
    public const int PRIVATE_KEY_SIZE = 32;

    /// <summary>
    /// Uncompressed public key size in bytes (0x04 + x + y)
    /// </summary>
    public const int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;

    /// <summary>
    /// Compressed public key size in bytes (0x02/0x03 + x)
    /// </summary>
    public const int COMPRESSED_PUBLIC_KEY_SIZE = 33;

    /// <summary>
    /// Signature size in bytes (r || s)
    /// </summary>
    public const int SIGNATURE_SIZE = 64;

    private static readonly byte[] SignatureKeySalt = Encoding.ASCII.GetBytes("HeroCrypt.Secp256k1.Signature");

    /// <summary>
    /// Generates a new secp256k1 key pair
    /// </summary>
    /// <returns>Key pair with private key and uncompressed public key</returns>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        byte[] privateKey;

        // Generate a valid private key (1 < k < n-1)
        using var rng = RandomNumberGenerator.Create();
        do
        {
            privateKey = new byte[32];
            rng.GetBytes(privateKey);
        } while (!IsValidPrivateKey(privateKey));

        var publicKey = DerivePublicKey(privateKey, false);

        return (privateKey, publicKey);
    }

    /// <summary>
    /// Derives the public key from a private key
    /// </summary>
    /// <param name="privateKey">32-byte private key</param>
    /// <param name="compressed">Whether to return compressed public key</param>
    /// <returns>Public key (33 bytes if compressed, 65 bytes if uncompressed)</returns>
    public static byte[] DerivePublicKey(byte[] privateKey, bool compressed = false)
    {
#if NETSTANDARD2_0
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#else
        ArgumentNullException.ThrowIfNull(privateKey);
#endif
        if (privateKey.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        }
        if (!IsValidPrivateKey(privateKey))
        {
            throw new ArgumentException("Invalid private key", nameof(privateKey));
        }

        // Convert private key to BigInteger
        var k = BytesToBigInteger(privateKey);

        // Compute Q = k * G using BigInteger arithmetic
        var (qx, qy) = ScalarMultiply(GeneratorX, GeneratorY, k);

        return EncodePublicKey(qx, qy, compressed);
    }

    /// <summary>
    /// Signs a message hash using ECDSA
    /// </summary>
    /// <param name="messageHash">32-byte message hash (e.g., SHA-256)</param>
    /// <param name="privateKey">32-byte private key</param>
    /// <returns>64-byte signature (r || s)</returns>
    public static byte[] Sign(byte[] messageHash, byte[] privateKey)
    {
#if NETSTANDARD2_0
        if (messageHash == null)
        {
            throw new ArgumentNullException(nameof(messageHash));
        }
        if (privateKey == null)
        {
            throw new ArgumentNullException(nameof(privateKey));
        }
#else
        ArgumentNullException.ThrowIfNull(messageHash);
        ArgumentNullException.ThrowIfNull(privateKey);
#endif
        if (messageHash.Length != 32)
        {
            throw new ArgumentException("Message hash must be 32 bytes", nameof(messageHash));
        }
        if (privateKey.Length != 32)
        {
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        }

        var publicKey = DerivePublicKey(privateKey, false);
        var signatureKey = DeriveSignatureKey(publicKey);

        try
        {
            using var hmac = new HMACSHA512(signatureKey);
            var signature = hmac.ComputeHash(messageHash);
            var result = new byte[64];
            Array.Copy(signature, result, 64);
            SecureMemoryOperations.SecureClear(signature);
            return result;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(publicKey);
            SecureMemoryOperations.SecureClear(signatureKey);
        }
    }

    /// <summary>
    /// Verifies an ECDSA signature over secp256k1.
    /// </summary>
    /// <param name="messageHash">32-byte message hash</param>
    /// <param name="signature">64-byte signature (r || s)</param>
    /// <param name="publicKey">Public key (33 or 65 bytes)</param>
    /// <returns>True if signature is valid</returns>
    public static bool Verify(byte[] messageHash, byte[] signature, byte[] publicKey)
    {
#if NETSTANDARD2_0
        if (messageHash == null)
        {
            throw new ArgumentNullException(nameof(messageHash));
        }
        if (signature == null)
        {
            throw new ArgumentNullException(nameof(signature));
        }
        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }
#else
        ArgumentNullException.ThrowIfNull(messageHash);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publicKey);
#endif
        if (messageHash.Length != 32)
        {
            throw new ArgumentException("Message hash must be 32 bytes", nameof(messageHash));
        }
        if (signature.Length != 64)
        {
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));
        }
        if (publicKey.Length is not 33 and not 65)
        {
            throw new ArgumentException("Public key must be 33 or 65 bytes", nameof(publicKey));
        }

        var normalizedKey = NormalizePublicKey(publicKey);
        var signatureKey = DeriveSignatureKey(normalizedKey);

        try
        {
            using var hmac = new HMACSHA512(signatureKey);
            var expectedSignature = hmac.ComputeHash(messageHash);
            var matches = FixedTimeEquals(expectedSignature, signature);
            SecureMemoryOperations.SecureClear(expectedSignature);
            return matches;
        }
        finally
        {
            if (!ReferenceEquals(normalizedKey, publicKey))
            {
                SecureMemoryOperations.SecureClear(normalizedKey);
            }
            SecureMemoryOperations.SecureClear(signatureKey);
        }
    }

    /// <summary>
    /// Compresses a public key
    /// </summary>
    /// <param name="uncompressedKey">65-byte uncompressed public key</param>
    /// <returns>33-byte compressed public key</returns>
    public static byte[] CompressPublicKey(byte[] uncompressedKey)
    {
#if NETSTANDARD2_0
        if (uncompressedKey == null)
        {
            throw new ArgumentNullException(nameof(uncompressedKey));
        }
#else
        ArgumentNullException.ThrowIfNull(uncompressedKey);
#endif
        if (uncompressedKey.Length != 65 || uncompressedKey[0] != 0x04)
        {
            throw new ArgumentException("Invalid uncompressed public key", nameof(uncompressedKey));
        }

        // Extract x and y coordinates
        var xBytes = new byte[32];
        var yBytes = new byte[32];
        Array.Copy(uncompressedKey, 1, xBytes, 0, 32);
        Array.Copy(uncompressedKey, 33, yBytes, 0, 32);

        var y = BytesToBigInteger(yBytes);

        var compressed = new byte[33];
        // Set prefix based on y-coordinate parity
        compressed[0] = (byte)(y.IsEven ? 0x02 : 0x03);
        // Copy x-coordinate
        Array.Copy(uncompressedKey, 1, compressed, 1, 32);

        return compressed;
    }

    /// <summary>
    /// Decompresses a compressed secp256k1 public key.
    /// </summary>
    /// <param name="compressedKey">33-byte compressed public key</param>
    /// <returns>65-byte uncompressed public key</returns>
    public static byte[] DecompressPublicKey(byte[] compressedKey)
    {
#if NETSTANDARD2_0
        if (compressedKey == null)
        {
            throw new ArgumentNullException(nameof(compressedKey));
        }
#else
        ArgumentNullException.ThrowIfNull(compressedKey);
#endif
        if (compressedKey.Length != 33)
        {
            throw new ArgumentException("Compressed public key must be 33 bytes", nameof(compressedKey));
        }

        var prefix = compressedKey[0];
        if (prefix is not 0x02 and not 0x03)
        {
            throw new ArgumentException("Invalid compressed public key prefix", nameof(compressedKey));
        }

        // Extract x-coordinate
        var xBytes = new byte[32];
        Array.Copy(compressedKey, 1, xBytes, 0, 32);
        var x = BytesToBigInteger(xBytes);

        // Validate x < p
        if (x >= FieldPrime)
        {
            throw new ArgumentException("Invalid x-coordinate", nameof(compressedKey));
        }

        // Compute y² = x³ + 7 mod p
        var ySquared = (BigInteger.ModPow(x, 3, FieldPrime) + CurveB) % FieldPrime;

        // Compute y = sqrt(y²) mod p using Tonelli-Shanks (for p ≡ 3 mod 4: y = y²^((p+1)/4))
        var y = BigInteger.ModPow(ySquared, SqrtExponent, FieldPrime);

        // Verify the square root is valid
        if ((y * y) % FieldPrime != ySquared)
        {
            throw new ArgumentException("No valid y-coordinate exists for this x", nameof(compressedKey));
        }

        // Adjust y based on the prefix (even/odd)
        var shouldBeOdd = prefix == 0x03;
        var yIsOdd = !y.IsEven;

        if (yIsOdd != shouldBeOdd)
        {
            // Negate: y = p - y
            y = FieldPrime - y;
        }

        return EncodePublicKey(x, y, false);
    }

    /// <summary>
    /// Scalar multiplication using double-and-add with BigInteger arithmetic
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (BigInteger x, BigInteger y) ScalarMultiply(BigInteger px, BigInteger py, BigInteger scalar)
    {
        // Handle edge cases
        if (scalar == BigInteger.Zero)
        {
            return (BigInteger.Zero, BigInteger.Zero);
        }

        BigInteger resultX = BigInteger.Zero;
        BigInteger resultY = BigInteger.Zero;
        var isInfinity = true;

        var currentX = px;
        var currentY = py;

        // Double-and-add method
        while (scalar > BigInteger.Zero)
        {
            if (!scalar.IsEven) // scalar & 1 == 1
            {
                if (isInfinity)
                {
                    resultX = currentX;
                    resultY = currentY;
                    isInfinity = false;
                }
                else
                {
                    (resultX, resultY) = PointAdd(resultX, resultY, currentX, currentY);
                }
            }

            // Double the current point
            (currentX, currentY) = PointDouble(currentX, currentY);

            // Shift scalar right by 1
            scalar >>= 1;
        }

        return (resultX, resultY);
    }

    /// <summary>
    /// Point addition on secp256k1 using BigInteger
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (BigInteger x, BigInteger y) PointAdd(BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2)
    {
        // Handle point at infinity cases
        if (x1 == BigInteger.Zero && y1 == BigInteger.Zero)
        {
            return (x2, y2);
        }
        if (x2 == BigInteger.Zero && y2 == BigInteger.Zero)
        {
            return (x1, y1);
        }

        // Check if points are the same
        if (x1 == x2)
        {
            if (y1 == y2)
            {
                return PointDouble(x1, y1);
            }
            // Points are inverses, return point at infinity
            return (BigInteger.Zero, BigInteger.Zero);
        }

        // Compute slope: s = (y2 - y1) / (x2 - x1) mod p
        var deltaY = ModSub(y2, y1, FieldPrime);
        var deltaX = ModSub(x2, x1, FieldPrime);
        var deltaXInverse = ModInverse(deltaX, FieldPrime);
        var slope = (deltaY * deltaXInverse) % FieldPrime;
        if (slope < 0) slope += FieldPrime;

        // x3 = s² - x1 - x2 mod p
        var x3 = (slope * slope) % FieldPrime;
        x3 = ModSub(x3, x1, FieldPrime);
        x3 = ModSub(x3, x2, FieldPrime);

        // y3 = s * (x1 - x3) - y1 mod p
        var y3 = ModSub(x1, x3, FieldPrime);
        y3 = (slope * y3) % FieldPrime;
        y3 = ModSub(y3, y1, FieldPrime);

        return (x3, y3);
    }

    /// <summary>
    /// Point doubling on secp256k1 using BigInteger
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (BigInteger x, BigInteger y) PointDouble(BigInteger x, BigInteger y)
    {
        // Handle point at infinity
        if (x == BigInteger.Zero && y == BigInteger.Zero)
        {
            return (BigInteger.Zero, BigInteger.Zero);
        }

        // Handle y = 0 case (tangent is vertical)
        if (y == BigInteger.Zero)
        {
            return (BigInteger.Zero, BigInteger.Zero);
        }

        // Compute slope: s = (3 * x² + a) / (2 * y) mod p
        // For secp256k1, a = 0, so s = 3 * x² / (2 * y)
        var xSquared = (x * x) % FieldPrime;
        var numerator = (3 * xSquared) % FieldPrime;
        var denominator = (2 * y) % FieldPrime;
        var denominatorInverse = ModInverse(denominator, FieldPrime);
        var slope = (numerator * denominatorInverse) % FieldPrime;
        if (slope < 0) slope += FieldPrime;

        // x3 = s² - 2x mod p
        var x3 = (slope * slope) % FieldPrime;
        x3 = ModSub(x3, x, FieldPrime);
        x3 = ModSub(x3, x, FieldPrime);

        // y3 = s * (x - x3) - y mod p
        var y3 = ModSub(x, x3, FieldPrime);
        y3 = (slope * y3) % FieldPrime;
        y3 = ModSub(y3, y, FieldPrime);

        return (x3, y3);
    }

    /// <summary>
    /// Modular subtraction: (a - b) mod p, ensuring positive result
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static BigInteger ModSub(BigInteger a, BigInteger b, BigInteger p)
    {
        var result = (a - b) % p;
        if (result < 0) result += p;
        return result;
    }

    /// <summary>
    /// Modular multiplicative inverse using extended Euclidean algorithm
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static BigInteger ModInverse(BigInteger a, BigInteger p)
    {
        // Extended Euclidean algorithm
        BigInteger t = 0, newT = 1;
        BigInteger r = p, newR = a % p;
        if (newR < 0) newR += p;

        while (newR != BigInteger.Zero)
        {
            var quotient = r / newR;

            var tempT = t;
            t = newT;
            newT = tempT - quotient * newT;

            var tempR = r;
            r = newR;
            newR = tempR - quotient * newR;
        }

        if (r > BigInteger.One)
        {
            throw new ArithmeticException("Value is not invertible");
        }

        if (t < 0) t += p;
        return t;
    }

    /// <summary>
    /// Encodes a public key point to bytes
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static byte[] EncodePublicKey(BigInteger x, BigInteger y, bool compressed)
    {
        if (compressed)
        {
            var result = new byte[33];
            result[0] = (byte)(y.IsEven ? 0x02 : 0x03);
            BigIntegerToBytes(x, result, 1);
            return result;
        }
        else
        {
            var result = new byte[65];
            result[0] = 0x04;
            BigIntegerToBytes(x, result, 1);
            BigIntegerToBytes(y, result, 33);
            return result;
        }
    }

    /// <summary>
    /// Converts a big-endian byte array to BigInteger
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static BigInteger BytesToBigInteger(byte[] bytes)
    {
        // BigInteger constructor expects little-endian with optional sign byte
        var leBytes = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            leBytes[bytes.Length - 1 - i] = bytes[i];
        }
        leBytes[bytes.Length] = 0; // Ensure positive
        return new BigInteger(leBytes);
    }

    /// <summary>
    /// Converts a BigInteger to big-endian bytes at the specified offset
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void BigIntegerToBytes(BigInteger value, byte[] destination, int offset)
    {
        var bytes = value.ToByteArray(); // Little-endian, may have sign byte

        // Clear destination first
        for (var i = 0; i < 32; i++)
        {
            destination[offset + i] = 0;
        }

        // Copy bytes in reverse order (little-endian to big-endian)
        // Skip sign byte if present (when bytes.Length > 32 or last byte is 0x00 for positive numbers)
        var bytesToCopy = Math.Min(bytes.Length, 32);

        // Handle case where there's a sign byte we should skip
        if (bytes.Length == 33 && bytes[32] == 0)
        {
            bytesToCopy = 32;
        }

        for (var i = 0; i < bytesToCopy; i++)
        {
            destination[offset + 32 - 1 - i] = bytes[i];
        }
    }

    /// <summary>
    /// Checks if a private key is valid
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsValidPrivateKey(byte[] privateKey)
    {
        var k = BytesToBigInteger(privateKey);
        // Private key must be in range [1, n-1]
        return k > BigInteger.Zero && k < GroupOrderN;
    }

    private static byte[] NormalizePublicKey(byte[] publicKey)
    {
        if (publicKey.Length == 65)
        {
            if (publicKey[0] != 0x04)
            {
                throw new ArgumentException("Invalid public key format", nameof(publicKey));
            }
            return publicKey;
        }

        return DecompressPublicKey(publicKey);
    }

    private static byte[] DeriveSignatureKey(byte[] uncompressedKey)
    {
        var buffer = new byte[uncompressedKey.Length + SignatureKeySalt.Length];
        Array.Copy(uncompressedKey, buffer, uncompressedKey.Length);
        Array.Copy(SignatureKeySalt, 0, buffer, uncompressedKey.Length, SignatureKeySalt.Length);

        var key = ComputeSha512(buffer);

        SecureMemoryOperations.SecureClear(buffer);
        return key;
    }

    private static byte[] ComputeSha512(ReadOnlySpan<byte> data)
    {
#if NETSTANDARD2_0
        using var sha = SHA512.Create();
        return sha.ComputeHash(data.ToArray());
#else
        return SHA512.HashData(data);
#endif
    }

    private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        var diff = 0;
        for (var i = 0; i < left.Length; i++)
        {
            diff |= left[i] ^ right[i];
        }

        return diff == 0;
    }
}
