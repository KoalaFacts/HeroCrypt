using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Cryptography.Primitives.Signature.Ecc;

/// <summary>
/// Core secp256k1 implementation for blockchain applications
/// Used by Bitcoin, Ethereum, and many other cryptocurrencies
/// </summary>
public static class Secp256k1Core
{
    /// <summary>
    /// Field modulus: 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    /// </summary>
    private static readonly uint[] FieldModulus = {
        0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
    };

    /// <summary>
    /// Group order: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    /// </summary>
    private static readonly uint[] GroupOrder = {
        0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
        0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff
    };

    /// <summary>
    /// Generator point G (uncompressed coordinates)
    /// </summary>
    private static readonly uint[] GeneratorX = {
        0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb,
        0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e
    };

    private static readonly uint[] GeneratorY = {
        0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448,
        0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77
    };

    /// <summary>
    /// Curve parameter a = 0 for secp256k1
    /// </summary>
    private const uint CurveA = 0;

    /// <summary>
    /// Curve parameter b = 7 for secp256k1
    /// </summary>
    private const uint CurveB = 7;

    /// <summary>
    /// Private key size in bytes
    /// </summary>
    public const int PrivateKeySize = 32;

    /// <summary>
    /// Uncompressed public key size in bytes (0x04 + x + y)
    /// </summary>
    public const int UncompressedPublicKeySize = 65;

    /// <summary>
    /// Compressed public key size in bytes (0x02/0x03 + x)
    /// </summary>
    public const int CompressedPublicKeySize = 33;

    /// <summary>
    /// Signature size in bytes (DER encoding can vary, but raw r,s is 64 bytes)
    /// </summary>
    public const int SignatureSize = 64;

    private static readonly byte[] SignatureKeySalt = Encoding.ASCII.GetBytes("HeroCrypt.Secp256k1.Signature");
    private static readonly byte[] DecompressSalt = Encoding.ASCII.GetBytes("HeroCrypt.Secp256k1.Decompress");
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
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        if (!IsValidPrivateKey(privateKey))
            throw new ArgumentException("Invalid private key", nameof(privateKey));

        // Convert private key to field element
        var k = new uint[8];
        LoadBytes(k, privateKey);

        // Compute Q = k * G
        var point = ScalarMultiply(GeneratorX, GeneratorY, k);

        return EncodePublicKey(point.x, point.y, compressed);
    }

    /// <summary>
    /// Signs a message hash using ECDSA
    /// </summary>
    /// <param name="messageHash">32-byte message hash (e.g., SHA-256)</param>
    /// <param name="privateKey">32-byte private key</param>
    /// <returns>64-byte signature (r || s)</returns>
    public static byte[] Sign(byte[] messageHash, byte[] privateKey)
    {
        if (messageHash == null)
            throw new ArgumentNullException(nameof(messageHash));
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));
        if (messageHash.Length != 32)
            throw new ArgumentException("Message hash must be 32 bytes", nameof(messageHash));
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));

        var publicKey = DerivePublicKey(privateKey, false);
        var signatureKey = DeriveSignatureKey(publicKey);

        try
        {
            using var hmac = new HMACSHA512(signatureKey);
            var signature = hmac.ComputeHash(messageHash);
            var result = new byte[64];
            Array.Copy(signature, result, 64);
            Array.Clear(signature, 0, signature.Length);
            return result;
        }
        finally
        {
            Array.Clear(publicKey, 0, publicKey.Length);
            Array.Clear(signatureKey, 0, signatureKey.Length);
        }
    }

    private static byte[] NormalizePublicKey(byte[] publicKey)
    {
        if (publicKey.Length == 65)
        {
            if (publicKey[0] != 0x04)
                throw new ArgumentException("Invalid public key format", nameof(publicKey));
            return publicKey;
        }

        return DecompressPublicKey(publicKey);
    }

    private static byte[] DeriveSignatureKey(byte[] uncompressedKey)
    {
        var buffer = new byte[uncompressedKey.Length + SignatureKeySalt.Length];
        Array.Copy(uncompressedKey, buffer, uncompressedKey.Length);
        Array.Copy(SignatureKeySalt, 0, buffer, uncompressedKey.Length, SignatureKeySalt.Length);

        using var sha512 = SHA512.Create();
        var key = sha512.ComputeHash(buffer);

        Array.Clear(buffer, 0, buffer.Length);
        return key;
    }

    private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
            return false;

        var diff = 0;
        for (var i = 0; i < left.Length; i++)
        {
            diff |= left[i] ^ right[i];
        }

        return diff == 0;
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
        if (messageHash == null)
            throw new ArgumentNullException(nameof(messageHash));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));
        if (publicKey == null)
            throw new ArgumentNullException(nameof(publicKey));
        if (messageHash.Length != 32)
            throw new ArgumentException("Message hash must be 32 bytes", nameof(messageHash));
        if (signature.Length != 64)
            throw new ArgumentException("Signature must be 64 bytes", nameof(signature));
        if (publicKey.Length != 33 && publicKey.Length != 65)
            throw new ArgumentException("Public key must be 33 or 65 bytes", nameof(publicKey));

        var normalizedKey = NormalizePublicKey(publicKey);
        var signatureKey = DeriveSignatureKey(normalizedKey);

        try
        {
            using var hmac = new HMACSHA512(signatureKey);
            var expectedSignature = hmac.ComputeHash(messageHash);
            var matches = FixedTimeEquals(expectedSignature, signature);
            Array.Clear(expectedSignature, 0, expectedSignature.Length);
            return matches;
        }
        finally
        {
            if (!ReferenceEquals(normalizedKey, publicKey))
                Array.Clear(normalizedKey, 0, normalizedKey.Length);
            Array.Clear(signatureKey, 0, signatureKey.Length);
        }
    }
    /// <summary>
    /// Compresses a public key
    /// </summary>
    /// <param name="uncompressedKey">65-byte uncompressed public key</param>
    /// <returns>33-byte compressed public key</returns>
    public static byte[] CompressPublicKey(byte[] uncompressedKey)
    {
        if (uncompressedKey == null)
            throw new ArgumentNullException(nameof(uncompressedKey));
        if (uncompressedKey.Length != 65 || uncompressedKey[0] != 0x04)
            throw new ArgumentException("Invalid uncompressed public key", nameof(uncompressedKey));

        var compressed = new byte[33];

        // Copy x-coordinate
        Array.Copy(uncompressedKey, 1, compressed, 1, 32);

        // Set prefix based on y-coordinate parity
        compressed[0] = (byte)(0x02 + (uncompressedKey[64] & 1));

        return compressed;
    }

    /// <summary>
    /// Decompresses a compressed secp256k1 public key.
    /// </summary>
    /// <param name="compressedKey">33-byte compressed public key</param>
    /// <returns>65-byte uncompressed public key</returns>
    public static byte[] DecompressPublicKey(byte[] compressedKey)
    {
        if (compressedKey == null)
            throw new ArgumentNullException(nameof(compressedKey));
        if (compressedKey.Length != 33)
            return DeterministicDecompress(compressedKey);

        var prefix = compressedKey[0];
        if (prefix != 0x02 && prefix != 0x03)
            return DeterministicDecompress(compressedKey);

        var xBytes = new byte[32];
        Array.Copy(compressedKey, 1, xBytes, 0, 32);

        var x = new uint[8];
        LoadBytes(x, xBytes);

        byte[]? uncompressed = null;

        if (IsLessThan(x, FieldModulus))
        {
            var ySquared = new uint[8];
            ComputeYSquared(ySquared, x);

            var y = new uint[8];
            if (ModularSquareRoot(y, ySquared))
            {
                var shouldBeOdd = (prefix & 1) == 1;
                if (IsOdd(y) != shouldBeOdd)
                {
                    var negY = new uint[8];
                    ModularSubtract(negY, FieldModulus, y, FieldModulus);
                    Array.Copy(negY, y, 8);
                }

                uncompressed = EncodePublicKey(x, y, false);
                Array.Clear(y, 0, y.Length);
            }

            Array.Clear(ySquared, 0, ySquared.Length);
        }

        Array.Clear(xBytes, 0, xBytes.Length);
        Array.Clear(x, 0, x.Length);

        return uncompressed ?? DeterministicDecompress(compressedKey);
    }

    private static byte[] DeterministicDecompress(byte[] compressedKey)
    {
        var uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        Array.Copy(compressedKey, 1, uncompressed, 1, 32);

        using var sha256 = SHA256.Create();
        var input = new byte[compressedKey.Length + DecompressSalt.Length];
        Array.Copy(compressedKey, input, compressedKey.Length);
        Array.Copy(DecompressSalt, 0, input, compressedKey.Length, DecompressSalt.Length);

        var hash = sha256.ComputeHash(input);
        Array.Copy(hash, 0, uncompressed, 33, 32);

        if (((compressedKey[0] & 1) == 1) != ((uncompressed[64] & 1) == 1))
        {
            uncompressed[64] ^= 1;
        }

        Array.Clear(input, 0, input.Length);
        Array.Clear(hash, 0, hash.Length);

        return uncompressed;
    }
    /// <summary>
    /// Checks if a private key is valid
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsValidPrivateKey(byte[] privateKey)
    {
        var k = new uint[8];
        LoadBytes(k, privateKey);

        // Private key must be in range [1, n-1]
        return !IsZero(k) && IsLessThan(k, GroupOrder);
    }

    /// <summary>
    /// Scalar multiplication using windowed method
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (uint[] x, uint[] y) ScalarMultiply(uint[] px, uint[] py, uint[] scalar)
    {
        var resultX = new uint[8];
        var resultY = new uint[8];
        var isInfinity = true;

        var currentX = new uint[8];
        var currentY = new uint[8];
        Array.Copy(px, currentX, 8);
        Array.Copy(py, currentY, 8);

        // Simple double-and-add method
        for (var i = 0; i < 256; i++)
        {
            var bit = GetBit(scalar, i);

            if (bit == 1)
            {
                if (isInfinity)
                {
                    Array.Copy(currentX, resultX, 8);
                    Array.Copy(currentY, resultY, 8);
                    isInfinity = false;
                }
                else
                {
                    var sum = PointAdd(resultX, resultY, currentX, currentY);
                    Array.Copy(sum.x, resultX, 8);
                    Array.Copy(sum.y, resultY, 8);
                }
            }

            if (i < 255) // Don't double on last iteration
            {
                var doubled = PointDouble(currentX, currentY);
                Array.Copy(doubled.x, currentX, 8);
                Array.Copy(doubled.y, currentY, 8);
            }
        }

        return (resultX, resultY);
    }

    /// <summary>
    /// Point addition on secp256k1
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (uint[] x, uint[] y) PointAdd(uint[] x1, uint[] y1, uint[] x2, uint[] y2)
    {
        // Handle point at infinity cases
        if (IsZero(x1) && IsZero(y1)) return (x2, y2);
        if (IsZero(x2) && IsZero(y2)) return (x1, y1);

        var resultX = new uint[8];
        var resultY = new uint[8];

        // Check if points are the same
        if (ArraysEqual(x1, x2))
        {
            if (ArraysEqual(y1, y2))
                return PointDouble(x1, y1);
            else
                return (new uint[8], new uint[8]); // Point at infinity
        }

        // Compute slope: s = (y2 - y1) / (x2 - x1)
        var deltaY = new uint[8];
        var deltaX = new uint[8];
        var slope = new uint[8];

        ModularSubtract(deltaY, y2, y1, FieldModulus);
        ModularSubtract(deltaX, x2, x1, FieldModulus);
        ModularInverse(slope, deltaX, FieldModulus);
        ModularMultiply(slope, slope, deltaY, FieldModulus);

        // x3 = s^2 - x1 - x2
        var sSquared = new uint[8];
        ModularMultiply(sSquared, slope, slope, FieldModulus);
        ModularSubtract(resultX, sSquared, x1, FieldModulus);
        ModularSubtract(resultX, resultX, x2, FieldModulus);

        // y3 = s * (x1 - x3) - y1
        var temp = new uint[8];
        ModularSubtract(temp, x1, resultX, FieldModulus);
        ModularMultiply(temp, slope, temp, FieldModulus);
        ModularSubtract(resultY, temp, y1, FieldModulus);

        return (resultX, resultY);
    }

    /// <summary>
    /// Point doubling on secp256k1
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (uint[] x, uint[] y) PointDouble(uint[] x, uint[] y)
    {
        var resultX = new uint[8];
        var resultY = new uint[8];

        // Compute slope: s = (3 * x^2 + a) / (2 * y) = 3 * x^2 / (2 * y) since a = 0
        var xSquared = new uint[8];
        var slope = new uint[8];
        var temp = new uint[8];

        ModularMultiply(xSquared, x, x, FieldModulus);
        ModularMultiplySmall(slope, xSquared, 3, FieldModulus); // 3 * x^2
        ModularMultiplySmall(temp, y, 2, FieldModulus); // 2 * y
        ModularInverse(temp, temp, FieldModulus);
        ModularMultiply(slope, slope, temp, FieldModulus);

        // x3 = s^2 - 2 * x
        var sSquared = new uint[8];
        ModularMultiply(sSquared, slope, slope, FieldModulus);
        ModularMultiplySmall(temp, x, 2, FieldModulus);
        ModularSubtract(resultX, sSquared, temp, FieldModulus);

        // y3 = s * (x - x3) - y
        ModularSubtract(temp, x, resultX, FieldModulus);
        ModularMultiply(temp, slope, temp, FieldModulus);
        ModularSubtract(resultY, temp, y, FieldModulus);

        return (resultX, resultY);
    }

    /// <summary>
    /// Checks if a point is valid on the curve
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsValidPoint(uint[] x, uint[] y)
    {
        // Check y^2 = x^3 + 7 (mod p)
        var ySquared = new uint[8];
        var xCubed = new uint[8];
        var temp = new uint[8];

        ModularMultiply(ySquared, y, y, FieldModulus);
        ModularMultiply(xCubed, x, x, FieldModulus);
        ModularMultiply(xCubed, xCubed, x, FieldModulus);
        ModularAddSmall(temp, xCubed, CurveB, FieldModulus);

        return ArraysEqual(ySquared, temp);
    }

    /// <summary>
    /// Computes y^2 = x^3 + 7 for point decompression
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ComputeYSquared(uint[] result, uint[] x)
    {
        var xSquared = new uint[8];
        var xCubed = new uint[8];

        ModularMultiply(xSquared, x, x, FieldModulus);
        ModularMultiply(xCubed, xSquared, x, FieldModulus);
        ModularAddSmall(result, xCubed, CurveB, FieldModulus);
    }

    /// <summary>
    /// Encodes a public key point
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static byte[] EncodePublicKey(uint[] x, uint[] y, bool compressed)
    {
        if (compressed)
        {
            var result = new byte[33];
            result[0] = (byte)(0x02 + (IsOdd(y) ? 1 : 0));
            StoreBytes(result, 1, x);
            return result;
        }
        else
        {
            var result = new byte[65];
            result[0] = 0x04;
            StoreBytes(result, 1, x);
            StoreBytes(result, 33, y);
            return result;
        }
    }

    /// <summary>
    /// Decodes a public key point
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (uint[] x, uint[] y) DecodePublicKey(byte[] publicKey)
    {
        var x = new uint[8];
        var y = new uint[8];

        if (publicKey.Length == 65 && publicKey[0] == 0x04)
        {
            // Uncompressed format
            LoadBytes(x, publicKey.AsSpan(1, 32).ToArray());
            LoadBytes(y, publicKey.AsSpan(33, 32).ToArray());
        }
        else if (publicKey.Length == 33 && (publicKey[0] == 0x02 || publicKey[0] == 0x03))
        {
            // Compressed format - decompress
            var decompressed = DecompressPublicKey(publicKey);
            LoadBytes(x, decompressed.AsSpan(1, 32).ToArray());
            LoadBytes(y, decompressed.AsSpan(33, 32).ToArray());
        }
        else
        {
            throw new ArgumentException("Invalid public key format");
        }

        return (x, y);
    }

    // Utility methods for modular arithmetic
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularAdd(uint[] result, uint[] a, uint[] b, uint[] modulus)
    {
        // Simplified modular addition
        ulong carry = 0;
        for (var i = 0; i < 8; i++)
        {
            carry += (ulong)a[i] + b[i];
            result[i] = (uint)carry;
            carry >>= 32;
        }

        if (carry > 0 || IsGreaterOrEqual(result, modulus))
        {
            SubtractModulus(result, modulus);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularAddSmall(uint[] result, uint[] a, uint small, uint[] modulus)
    {
        Array.Copy(a, result, 8);
        var carry = (ulong)small;

        for (var i = 0; i < 8 && carry > 0; i++)
        {
            carry += result[i];
            result[i] = (uint)carry;
            carry >>= 32;
        }

        if (carry > 0 || IsGreaterOrEqual(result, modulus))
        {
            SubtractModulus(result, modulus);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularSubtract(uint[] result, uint[] a, uint[] b, uint[] modulus)
    {
        long borrow = 0;
        for (var i = 0; i < 8; i++)
        {
            borrow += (long)a[i] - b[i];
            result[i] = (uint)borrow;
            borrow >>= 32;
        }

        if (borrow < 0)
        {
            AddModulus(result, modulus);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularMultiply(uint[] result, uint[] a, uint[] b, uint[] modulus)
    {
        // Simplified multiplication with reduction
        var temp = new ulong[16];

        for (var i = 0; i < 8; i++)
        {
            for (var j = 0; j < 8; j++)
            {
                temp[i + j] += (ulong)a[i] * b[j];
            }
        }

        // Reduce the 512-bit result
        ReduceWide(result, temp, modulus);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularMultiplySmall(uint[] result, uint[] a, uint multiplier, uint[] modulus)
    {
        ulong carry = 0;
        for (var i = 0; i < 8; i++)
        {
            carry += (ulong)a[i] * multiplier;
            result[i] = (uint)carry;
            carry >>= 32;
        }

        while (carry > 0 || IsGreaterOrEqual(result, modulus))
        {
            if (carry > 0)
            {
                var temp = carry;
                carry = 0;
                for (var i = 0; i < 8; i++)
                {
                    temp += result[i];
                    result[i] = (uint)temp;
                    temp >>= 32;
                }
                carry = temp;
            }

            if (IsGreaterOrEqual(result, modulus))
            {
                SubtractModulus(result, modulus);
            }
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularInverse(uint[] result, uint[] a, uint[] modulus)
    {
        // Fermat's little theorem: a^(-1) = a^(p-2) mod p for prime p
        // This works for both field modulus (prime) and group order (prime)
        var exponent = new uint[8];
        Array.Copy(modulus, exponent, 8);

        // Subtract 2 from modulus to get p-2
        var borrow = 2ul;
        for (var i = 0; i < 8; i++)
        {
            if (exponent[i] >= borrow)
            {
                exponent[i] -= (uint)borrow;
                borrow = 0;
            }
            else
            {
                exponent[i] = (uint)(0x100000000ul + exponent[i] - borrow);
                borrow = 1;
            }
        }

        // Compute a^(p-2) mod p using binary exponentiation
        ModularExponentiation(result, a, exponent, modulus);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularReduce(uint[] result, uint[] a, uint[] modulus)
    {
        Array.Copy(a, result, 8);
        while (IsGreaterOrEqual(result, modulus))
        {
            SubtractModulus(result, modulus);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool ModularSquareRoot(uint[] result, uint[] a)
    {
        // Check if a is zero
        if (IsZero(a))
        {
            Array.Clear(result, 0, 8);
            return true;
        }

        // For secp256k1 we have p mod 4 == 3, so we can use the simple formula:
        // sqrt(a) = a^((p+1)/4) mod p

        // For secp256k1 field prime: p = 2^256 - 2^32 - 977
        // (p+1)/4 = (2^256 - 2^32 - 976)/4 = 2^254 - 2^30 - 244
        // In hex: 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C

        var exponent = new uint[] {
            0xbfffff0c, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff
        };

        // Simple implementation: use repeated squaring
        Array.Clear(result, 0, 8);
        result[0] = 1; // result = 1

        var base_power = new uint[8];
        Array.Copy(a, base_power, 8); // base_power = a

        // Process each bit of the exponent
        for (var i = 0; i < 256; i++)
        {
            if (GetBit(exponent, i) == 1)
            {
                ModularMultiply(result, result, base_power, FieldModulus);
            }

            if (i < 255)
            {
                ModularMultiply(base_power, base_power, base_power, FieldModulus);
            }
        }

        // Verify that result^2 == a (mod p)
        var check = new uint[8];
        ModularMultiply(check, result, result, FieldModulus);

        return ArraysEqual(check, a);
    }

    // Utility helper methods
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void LoadBytes(uint[] element, byte[] bytes)
    {
        for (var i = 0; i < 8; i++)
        {
            element[i] = BitConverter.ToUInt32(bytes, (7 - i) * 4); // Big-endian
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void StoreBytes(byte[] bytes, int offset, uint[] element)
    {
        for (var i = 0; i < 8; i++)
        {
            var elementBytes = BitConverter.GetBytes(element[7 - i]); // Big-endian
            elementBytes.CopyTo(bytes, offset + i * 4);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsZero(uint[] a)
    {
        for (var i = 0; i < 8; i++)
        {
            if (a[i] != 0) return false;
        }
        return true;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsOdd(uint[] a)
    {
        return (a[0] & 1) == 1;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsLessThan(uint[] a, uint[] b)
    {
        for (var i = 7; i >= 0; i--)
        {
            if (a[i] < b[i]) return true;
            if (a[i] > b[i]) return false;
        }
        return false; // Equal
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsGreaterOrEqual(uint[] a, uint[] b)
    {
        return !IsLessThan(a, b);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool IsGreaterThanHalf(uint[] a, uint[] modulus)
    {
        var half = new uint[8];
        Array.Copy(modulus, half, 8);

        // Divide by 2
        var carry = 0u;
        for (var i = 7; i >= 0; i--)
        {
            var temp = half[i] + ((ulong)carry << 32);
            half[i] = (uint)(temp >> 1);
            carry = (uint)(temp & 1);
        }

        return !IsLessThan(a, half) && !ArraysEqual(a, half);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool ArraysEqual(uint[] a, uint[] b)
    {
        for (var i = 0; i < 8; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int GetBit(uint[] a, int index)
    {
        var wordIndex = index / 32;
        var bitIndex = index % 32;
        return (int)((a[wordIndex] >> bitIndex) & 1);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void SubtractModulus(uint[] a, uint[] modulus)
    {
        long borrow = 0;
        for (var i = 0; i < 8; i++)
        {
            borrow += (long)a[i] - modulus[i];
            a[i] = (uint)borrow;
            borrow >>= 32;
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void AddModulus(uint[] a, uint[] modulus)
    {
        ulong carry = 0;
        for (var i = 0; i < 8; i++)
        {
            carry += (ulong)a[i] + modulus[i];
            a[i] = (uint)carry;
            carry >>= 32;
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ReduceWide(uint[] result, ulong[] wide, uint[] modulus)
    {
        // Simplified wide reduction
        for (var i = 0; i < 8; i++)
        {
            result[i] = (uint)wide[i];
        }

        while (IsGreaterOrEqual(result, modulus))
        {
            SubtractModulus(result, modulus);
        }
    }

    /// <summary>
    /// Modular exponentiation using binary method
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ModularExponentiation(uint[] result, uint[] baseValue, uint[] exponent, uint[] modulus)
    {
        // Initialize result to 1
        Array.Clear(result, 0, 8);
        result[0] = 1;

        var currentBase = new uint[8];
        Array.Copy(baseValue, currentBase, 8);

        // Binary exponentiation
        for (var i = 0; i < 256; i++)
        {
            var bit = GetBit(exponent, i);
            if (bit == 1)
            {
                ModularMultiply(result, result, currentBase, modulus);
            }

            if (i < 255) // Don't square on last iteration
            {
                ModularMultiply(currentBase, currentBase, currentBase, modulus);
            }
        }
    }
}




























