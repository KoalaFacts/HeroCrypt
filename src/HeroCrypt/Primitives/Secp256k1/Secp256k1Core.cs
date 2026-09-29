using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Secp256k1;

/// <summary>
/// Core secp256k1 implementation for blockchain applications.
/// Uses the platform ECDSA provider for private-key operations.
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
internal sealed class Secp256k1Core
{
    private readonly SecurityPolicyOptions policy;
    private static readonly ECCurve Curve = ECCurve.CreateFromFriendlyName("secP256k1");

    /// <summary>
    /// Initializes a Secp256k1Core with the effective security policy.
    /// </summary>
    /// <param name="policy">Optional policy; uses the current policy when omitted.</param>
    public Secp256k1Core(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
    }
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

    /// <summary>
    /// Generates a new secp256k1 key pair
    /// </summary>
    /// <returns>Key pair with private key and uncompressed public key</returns>
    public (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        policy.ValidateSignature("SECP256K1");
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
    public byte[] DerivePublicKey(byte[] privateKey, bool compressed = false)
    {
        policy.ValidateSignature("SECP256K1");
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

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(new ECParameters { Curve = Curve, D = privateKey });
        var point = ecdsa.ExportParameters(false).Q;
        var x = point.X ?? throw new CryptographicException("ECDSA provider did not return a public X coordinate.");
        var y = point.Y ?? throw new CryptographicException("ECDSA provider did not return a public Y coordinate.");
        if (x.Length != 32 || y.Length != 32)
        {
            throw new CryptographicException("ECDSA provider returned an invalid secp256k1 public point.");
        }

        if (compressed)
        {
            var result = new byte[COMPRESSED_PUBLIC_KEY_SIZE];
            result[0] = (byte)((y[y.Length - 1] & 1) == 0 ? 0x02 : 0x03);
            Array.Copy(x, 0, result, 1, x.Length);
            return result;
        }

        var uncompressed = new byte[UNCOMPRESSED_PUBLIC_KEY_SIZE];
        uncompressed[0] = 0x04;
        Array.Copy(x, 0, uncompressed, 1, x.Length);
        Array.Copy(y, 0, uncompressed, 33, y.Length);
        return uncompressed;
    }

    /// <summary>
    /// Signs a message hash using ECDSA
    /// </summary>
    /// <param name="messageHash">32-byte message hash (e.g., SHA-256)</param>
    /// <param name="privateKey">32-byte private key</param>
    /// <returns>64-byte signature (r || s)</returns>
    public byte[] Sign(byte[] messageHash, byte[] privateKey)
    {
        policy.ValidateSignature("SECP256K1");
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

        if (!IsValidPrivateKey(privateKey))
        {
            throw new ArgumentException("Invalid private key", nameof(privateKey));
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(new ECParameters { Curve = Curve, D = privateKey });
        return ecdsa.SignHash(messageHash);
    }

    /// <summary>
    /// Verifies an ECDSA signature over secp256k1.
    /// </summary>
    /// <param name="messageHash">32-byte message hash</param>
    /// <param name="signature">64-byte signature (r || s)</param>
    /// <param name="publicKey">Public key (33 or 65 bytes)</param>
    /// <returns>True if signature is valid</returns>
    public bool Verify(byte[] messageHash, byte[] signature, byte[] publicKey)
    {
        policy.ValidateSignature("SECP256K1");
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

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = Curve,
                Q = new ECPoint
                {
                    X = normalizedKey.AsSpan(1, 32).ToArray(),
                    Y = normalizedKey.AsSpan(33, 32).ToArray()
                }
            });
            return ecdsa.VerifyHash(messageHash, signature);
        }
        finally
        {
            if (!ReferenceEquals(normalizedKey, publicKey))
            {
                SecureMemoryOperations.SecureClear(normalizedKey);
            }
        }
    }

    /// <summary>
    /// Compresses a public key
    /// </summary>
    /// <param name="uncompressedKey">65-byte uncompressed public key</param>
    /// <returns>33-byte compressed public key</returns>
    public byte[] CompressPublicKey(byte[] uncompressedKey)
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
    public byte[] DecompressPublicKey(byte[] compressedKey)
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
    /// Encodes a public key point to bytes
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private byte[] EncodePublicKey(BigInteger x, BigInteger y, bool compressed)
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
    private BigInteger BytesToBigInteger(byte[] bytes)
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
    private void BigIntegerToBytes(BigInteger value, byte[] destination, int offset)
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
    private bool IsValidPrivateKey(byte[] privateKey)
    {
        var k = BytesToBigInteger(privateKey);
        // Private key must be in range [1, n-1]
        return k > BigInteger.Zero && k < GroupOrderN;
    }

    private byte[] NormalizePublicKey(byte[] publicKey)
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

}
