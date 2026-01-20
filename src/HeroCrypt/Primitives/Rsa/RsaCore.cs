using System.Numerics;
using System.Security.Cryptography;

namespace HeroCrypt.Primitives.Rsa;

internal static class RsaCore
{
    /// <summary>
    /// Generates an RSA key pair with the specified key size.
    /// </summary>
    /// <param name="keySize">The size of the key in bits (typically 2048 or 4096).</param>
    /// <returns>An <see cref="RsaKeyPair"/> containing the generated public and private keys.</returns>
    public static RsaKeyPair GenerateKeyPair(int keySize)
    {
        using var rsa = RSA.Create();
        rsa.KeySize = keySize;
        var parameters = rsa.ExportParameters(includePrivateParameters: true);

        ValidateGeneratedParameters(parameters);

        return new RsaKeyPair(
            new RsaPublicKey(
                BytesToBigInteger(parameters.Modulus!),
                BytesToBigInteger(parameters.Exponent!)
            ),
            new RsaPrivateKey(
                BytesToBigInteger(parameters.Modulus!),
                BytesToBigInteger(parameters.D!),
                BytesToBigInteger(parameters.P!),
                BytesToBigInteger(parameters.Q!),
                BytesToBigInteger(parameters.Exponent!)
            )
        );
    }

    /// <summary>
    /// Encrypts data using RSA public key encryption.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="publicKey">The RSA public key.</param>
    /// <param name="padding">The padding mode to use (default: PKCS1).</param>
    /// <param name="hashAlgorithm">The hash algorithm for OAEP padding (default: SHA256).</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] Encrypt(
        byte[] data,
        RsaPublicKey publicKey,
        RsaPaddingMode padding = RsaPaddingMode.Pkcs1,
        HashAlgorithmName? hashAlgorithm = null)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(ToRsaParameters(publicKey));
        return rsa.Encrypt(data, ResolveEncryptionPadding(padding, hashAlgorithm));
    }

    /// <summary>
    /// Decrypts data using RSA private key decryption.
    /// </summary>
    /// <param name="encryptedData">The encrypted data to decrypt.</param>
    /// <param name="privateKey">The RSA private key.</param>
    /// <param name="padding">The padding mode to use (default: PKCS1).</param>
    /// <param name="hashAlgorithm">The hash algorithm for OAEP padding (default: SHA256).</param>
    /// <returns>The decrypted data.</returns>
    public static byte[] Decrypt(
        byte[] encryptedData,
        RsaPrivateKey privateKey,
        RsaPaddingMode padding = RsaPaddingMode.Pkcs1,
        HashAlgorithmName? hashAlgorithm = null)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(ToRsaParameters(privateKey));
        return rsa.Decrypt(encryptedData, ResolveEncryptionPadding(padding, hashAlgorithm));
    }

    /// <summary>
    /// Creates a digital signature for the specified data using RSA-SHA256.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="privateKey">The RSA private key.</param>
    /// <returns>The digital signature.</returns>
    public static byte[] Sign(byte[] data, RsaPrivateKey privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(ToRsaParameters(privateKey));
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Verifies an RSA-SHA256 digital signature.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="publicKey">The RSA public key.</param>
    /// <returns>true if the signature is valid; otherwise, false.</returns>
    public static bool Verify(byte[] data, byte[] signature, RsaPublicKey publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(ToRsaParameters(publicKey));
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    internal static RSAParameters ToRsaParameters(RsaPublicKey publicKey)
    {
        return new RSAParameters
        {
            Modulus = BigIntegerToBytes(publicKey.Modulus),
            Exponent = BigIntegerToBytes(publicKey.Exponent)
        };
    }

    internal static RSAParameters ToRsaParameters(RsaPrivateKey privateKey)
    {
        var modulusBytes = BigIntegerToBytes(privateKey.Modulus);
        var exponentBytes = BigIntegerToBytes(privateKey.E);
        var dBytes = PadLeft(BigIntegerToBytes(privateKey.D), modulusBytes.Length);

        // .NET RSA CRT requires P > Q. If P < Q, swap them.
        // This is necessary because OpenPGP doesn't enforce P > Q order.
        var p = privateKey.P;
        var q = privateKey.Q;
        if (p < q)
        {
            (p, q) = (q, p);
        }

        // .NET RSA expects P and Q to be exactly half the modulus length
        var halfModulusLen = (modulusBytes.Length + 1) / 2;

        var pBytes = PadLeft(BigIntegerToBytes(p), halfModulusLen);
        var qBytes = PadLeft(BigIntegerToBytes(q), halfModulusLen);

        var pMinusOne = p - BigInteger.One;
        var qMinusOne = q - BigInteger.One;

        var dpBytes = PadLeft(BigIntegerToBytes(PositiveModulo(privateKey.D, pMinusOne)), halfModulusLen);
        var dqBytes = PadLeft(BigIntegerToBytes(PositiveModulo(privateKey.D, qMinusOne)), halfModulusLen);

        // InverseQ = q^-1 mod p (using Fermat's little theorem: q^(p-2) mod p)
        var inverseQValue = BigInteger.ModPow(q, p - 2, p);
        var inverseQBytes = PadLeft(BigIntegerToBytes(inverseQValue), halfModulusLen);

        return new RSAParameters
        {
            Modulus = modulusBytes,
            Exponent = exponentBytes,
            D = dBytes,
            P = pBytes,
            Q = qBytes,
            DP = dpBytes,
            DQ = dqBytes,
            InverseQ = inverseQBytes
        };
    }

    /// <summary>
    /// Converts a big-endian byte array to BigInteger
    /// </summary>
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
    /// Converts a BigInteger to big-endian bytes (unsigned)
    /// </summary>
    private static byte[] BigIntegerToBytes(BigInteger value)
    {
        if (value.IsZero)
        {
            return [0];
        }

        var littleEndian = value.ToByteArray();
        var length = littleEndian.Length;

        // Skip sign byte if present
        while (length > 1 && littleEndian[length - 1] == 0)
        {
            length--;
        }

        var result = new byte[length];
        for (var i = 0; i < length; i++)
        {
            result[i] = littleEndian[length - 1 - i];
        }

        return result;
    }

    private static byte[] PadLeft(byte[] value, int length)
    {
        if (value.Length == length)
        {
            return value;
        }

        if (value.Length > length)
        {
            var result = new byte[length];
            Array.Copy(value, value.Length - length, result, 0, length);
            return result;
        }

        var padded = new byte[length];
        Array.Copy(value, 0, padded, length - value.Length, value.Length);
        return padded;
    }

    private static BigInteger PositiveModulo(BigInteger value, BigInteger modulus)
    {
        if (modulus.IsZero)
        {
            throw new DivideByZeroException();
        }

        var result = BigInteger.Remainder(value, modulus);
        return result.Sign < 0 ? result + modulus : result;
    }

    private static RSAEncryptionPadding ResolveEncryptionPadding(RsaPaddingMode padding, HashAlgorithmName? hashAlgorithm)
    {
        return padding switch
        {
            RsaPaddingMode.Pkcs1 => RSAEncryptionPadding.Pkcs1,
            RsaPaddingMode.Oaep => RSAEncryptionPadding.CreateOaep(hashAlgorithm ?? HashAlgorithmName.SHA256),
            _ => throw new ArgumentOutOfRangeException(nameof(padding), padding, "Unsupported RSA padding mode.")
        };
    }

    private static void ValidateGeneratedParameters(RSAParameters parameters)
    {
        if (parameters.Modulus is null ||
            parameters.Exponent is null ||
            parameters.D is null ||
            parameters.P is null ||
            parameters.Q is null)
        {
            throw new InvalidOperationException("RSA provider did not return the expected private key components.");
        }
    }
}

/// <summary>
/// Represents an RSA key pair containing both public and private keys.
/// </summary>
/// <param name="publicKey">The RSA public key.</param>
/// <param name="privateKey">The RSA private key.</param>
public sealed class RsaKeyPair(RsaPublicKey publicKey, RsaPrivateKey privateKey)
{
    /// <summary>
    /// Gets the RSA public key.
    /// </summary>
    public RsaPublicKey PublicKey { get; } = publicKey;

    /// <summary>
    /// Gets the RSA private key.
    /// </summary>
    public RsaPrivateKey PrivateKey { get; } = privateKey;
}

/// <summary>
/// Represents an RSA public key.
/// </summary>
/// <param name="modulus">The RSA modulus (n).</param>
/// <param name="exponent">The public exponent (e).</param>
public sealed class RsaPublicKey(BigInteger modulus, BigInteger exponent)
{
    /// <summary>
    /// Gets the RSA modulus (n).
    /// </summary>
    public BigInteger Modulus { get; } = modulus;

    /// <summary>
    /// Gets the public exponent (e).
    /// </summary>
    public BigInteger Exponent { get; } = exponent;
}

/// <summary>
/// Represents an RSA private key.
/// </summary>
/// <param name="modulus">The RSA modulus (n).</param>
/// <param name="d">The private exponent (d).</param>
/// <param name="p">The first prime factor of n.</param>
/// <param name="q">The second prime factor of n.</param>
/// <param name="e">The public exponent (e).</param>
public sealed class RsaPrivateKey(BigInteger modulus, BigInteger d, BigInteger p, BigInteger q, BigInteger e)
{
    /// <summary>
    /// Gets the RSA modulus (n).
    /// </summary>
    public BigInteger Modulus { get; } = modulus;

    /// <summary>
    /// Gets the private exponent (d).
    /// </summary>
    public BigInteger D { get; } = d;

    /// <summary>
    /// Gets the first prime factor of n.
    /// </summary>
    public BigInteger P { get; } = p;

    /// <summary>
    /// Gets the second prime factor of n.
    /// </summary>
    public BigInteger Q { get; } = q;

    /// <summary>
    /// Gets the public exponent (e).
    /// </summary>
    public BigInteger E { get; } = e;
}
