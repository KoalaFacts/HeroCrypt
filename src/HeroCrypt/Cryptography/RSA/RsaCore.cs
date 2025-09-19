using System.Security.Cryptography;
using SystemNumericsBigInteger = System.Numerics.BigInteger;
using SystemSecurityRSA = System.Security.Cryptography.RSA;
namespace HeroCrypt.Cryptography.RSA;

internal static class RsaCore
{
    public static RsaKeyPair GenerateKeyPair(int keySize)
    {
        using var rsa = SystemSecurityRSA.Create();
        rsa.KeySize = keySize;
        var parameters = rsa.ExportParameters(includePrivateParameters: true);

        ValidateGeneratedParameters(parameters);

        return new RsaKeyPair(
            new RsaPublicKey(
                new BigInteger(parameters.Modulus!),
                new BigInteger(parameters.Exponent!)
            ),
            new RsaPrivateKey(
                new BigInteger(parameters.Modulus!),
                new BigInteger(parameters.D!),
                new BigInteger(parameters.P!),
                new BigInteger(parameters.Q!),
                new BigInteger(parameters.Exponent!)
            )
        );
    }

    public static byte[] Encrypt(byte[] data, RsaPublicKey publicKey, RsaPaddingMode padding = RsaPaddingMode.Pkcs1, HashAlgorithmName? hashAlgorithm = null)
    {
        using var rsa = SystemSecurityRSA.Create();
        rsa.ImportParameters(ToRsaParameters(publicKey));
        return rsa.Encrypt(data, ResolveEncryptionPadding(padding, hashAlgorithm));
    }

    public static byte[] Decrypt(byte[] encryptedData, RsaPrivateKey privateKey, RsaPaddingMode padding = RsaPaddingMode.Pkcs1, HashAlgorithmName? hashAlgorithm = null)
    {
        using var rsa = SystemSecurityRSA.Create();
        rsa.ImportParameters(ToRsaParameters(privateKey));
        return rsa.Decrypt(encryptedData, ResolveEncryptionPadding(padding, hashAlgorithm));
    }

    public static byte[] Sign(byte[] data, RsaPrivateKey privateKey)
    {
        using var rsa = SystemSecurityRSA.Create();
        rsa.ImportParameters(ToRsaParameters(privateKey));
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static bool Verify(byte[] data, byte[] signature, RsaPublicKey publicKey)
    {
        using var rsa = SystemSecurityRSA.Create();
        rsa.ImportParameters(ToRsaParameters(publicKey));
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static RSAParameters ToRsaParameters(RsaPublicKey publicKey)
    {
        return new RSAParameters
        {
            Modulus = ToUnsignedBigEndian(publicKey.Modulus),
            Exponent = ToUnsignedBigEndian(publicKey.Exponent)
        };
    }

    private static RSAParameters ToRsaParameters(RsaPrivateKey privateKey)
    {
        var modulusBytes = ToUnsignedBigEndian(privateKey.Modulus);
        var exponentBytes = ToUnsignedBigEndian(privateKey.E);
        var dBytes = PadLeft(ToUnsignedBigEndian(privateKey.D), modulusBytes.Length);

        var pBytes = ToUnsignedBigEndian(privateKey.P);
        var qBytes = ToUnsignedBigEndian(privateKey.Q);

        var sysP = ToSystemBigInteger(privateKey.P);
        var sysQ = ToSystemBigInteger(privateKey.Q);
        var sysD = ToSystemBigInteger(privateKey.D);

        var sysPMinusOne = sysP - SystemNumericsBigInteger.One;
        var sysQMinusOne = sysQ - SystemNumericsBigInteger.One;

        var dpBytes = PadLeft(ToBigEndianBytes(PositiveModulo(sysD, sysPMinusOne)), pBytes.Length);
        var dqBytes = PadLeft(ToBigEndianBytes(PositiveModulo(sysD, sysQMinusOne)), qBytes.Length);

        var sysTwo = new SystemNumericsBigInteger(2);
        var inverseQValue = SystemNumericsBigInteger.ModPow(sysQ, sysP - sysTwo, sysP);
        var inverseQBytes = PadLeft(ToBigEndianBytes(inverseQValue), pBytes.Length);

        return new RSAParameters
        {
            Modulus = modulusBytes,
            Exponent = exponentBytes,
            D = dBytes,
            P = PadLeft(pBytes, pBytes.Length),
            Q = PadLeft(qBytes, qBytes.Length),
            DP = dpBytes,
            DQ = dqBytes,
            InverseQ = inverseQBytes
        };
    }

    private static byte[] ToUnsignedBigEndian(BigInteger value)
    {
        var bytes = value.ToByteArray();
        var index = 0;

        while (index < bytes.Length - 1 && bytes[index] == 0)
        {
            index++;
        }

        if (index == 0)
            return bytes;

        var result = new byte[bytes.Length - index];
        Array.Copy(bytes, index, result, 0, result.Length);
        return result;
    }

    private static byte[] PadLeft(byte[] value, int length)
    {
        if (value.Length == length)
            return value;

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

    private static SystemNumericsBigInteger PositiveModulo(SystemNumericsBigInteger value, SystemNumericsBigInteger modulus)
    {
        if (modulus.IsZero)
            throw new DivideByZeroException();

        var result = SystemNumericsBigInteger.Remainder(value, modulus);
        return result.Sign < 0 ? result + modulus : result;
    }

    private static SystemNumericsBigInteger ToSystemBigInteger(BigInteger value)
    {
        var bytes = ToUnsignedBigEndian(value);
        if (bytes.Length == 0)
            return SystemNumericsBigInteger.Zero;

        var buffer = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            buffer[i] = bytes[bytes.Length - 1 - i];
        }

        return new SystemNumericsBigInteger(buffer);
    }

    private static byte[] ToBigEndianBytes(SystemNumericsBigInteger value)
    {
        if (value.IsZero)
            return new[] { (byte)0 };

        var littleEndian = value.ToByteArray();
        var length = littleEndian.Length;

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

internal sealed class RsaKeyPair
{
    public RsaPublicKey PublicKey { get; }
    public RsaPrivateKey PrivateKey { get; }

    public RsaKeyPair(RsaPublicKey publicKey, RsaPrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }
}

internal sealed class RsaPublicKey
{
    public BigInteger Modulus { get; }
    public BigInteger Exponent { get; }

    public RsaPublicKey(BigInteger modulus, BigInteger exponent)
    {
        Modulus = modulus;
        Exponent = exponent;
    }
}

internal sealed class RsaPrivateKey
{
    public BigInteger Modulus { get; }
    public BigInteger D { get; }
    public BigInteger P { get; }
    public BigInteger Q { get; }
    public BigInteger E { get; }

    public RsaPrivateKey(BigInteger modulus, BigInteger d, BigInteger p, BigInteger q, BigInteger e)
    {
        Modulus = modulus;
        D = d;
        P = p;
        Q = q;
        E = e;
    }
}



