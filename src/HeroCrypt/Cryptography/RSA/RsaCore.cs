using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.RSA;

internal static class RsaCore
{
    public static RsaKeyPair GenerateKeyPair(int keySize)
    {
        if (keySize < 512) throw new ArgumentException("Key size must be at least 512 bits");
        if (keySize % 8 != 0) throw new ArgumentException("Key size must be a multiple of 8");
        
        var halfSize = keySize / 2;
        
        var p = GeneratePrime(halfSize);
        var q = GeneratePrime(halfSize);
        
        var n = p * q;
        
        var phi = (p - BigInteger.One) * (q - BigInteger.One);
        
        var e = new BigInteger(65537);
        
        while (Gcd(e, phi) != BigInteger.One)
        {
            e = e + new BigInteger(2);
        }
        
        var d = e.ModInverse(phi);
        
        return new RsaKeyPair(
            new RsaPublicKey(n, e),
            new RsaPrivateKey(n, d, p, q, e));
    }
    
    public static byte[] Encrypt(byte[] data, RsaPublicKey publicKey, RsaPaddingMode padding = RsaPaddingMode.Pkcs1, HashAlgorithmName? hashAlgorithm = null)
    {
        var modulusBytes = GetByteLength(publicKey.Modulus);
        byte[] paddedData;
        
        switch (padding)
        {
            case RsaPaddingMode.Pkcs1:
                paddedData = PadPkcs1(data, modulusBytes, false);
                break;
            case RsaPaddingMode.Oaep:
                var hash = hashAlgorithm ?? HashAlgorithmName.SHA256;
                paddedData = RsaOaep.Pad(data, modulusBytes, hash);
                break;
            default:
                throw new ArgumentException($"Unsupported padding mode: {padding}");
        }
        
        var m = new BigInteger(paddedData);
        
        if (m >= publicKey.Modulus)
            throw new ArgumentException("Message too large for key size");
        
        var c = m.ModPow(publicKey.Exponent, publicKey.Modulus);
        
        return c.ToByteArray();
    }
    
    public static byte[] Decrypt(byte[] encryptedData, RsaPrivateKey privateKey, RsaPaddingMode padding = RsaPaddingMode.Pkcs1, HashAlgorithmName? hashAlgorithm = null)
    {
        var c = new BigInteger(encryptedData);
        var m = c.ModPow(privateKey.D, privateKey.Modulus);
        var decryptedPadded = m.ToByteArray();
        
        var modulusBytes = GetByteLength(privateKey.Modulus);
        
        // Ensure decrypted data is the right length
        if (decryptedPadded.Length < modulusBytes)
        {
            var temp = new byte[modulusBytes];
            Array.Copy(decryptedPadded, 0, temp, modulusBytes - decryptedPadded.Length, decryptedPadded.Length);
            decryptedPadded = temp;
        }
        
        switch (padding)
        {
            case RsaPaddingMode.Pkcs1:
                return UnpadPkcs1(decryptedPadded, false);
            case RsaPaddingMode.Oaep:
                var hash = hashAlgorithm ?? HashAlgorithmName.SHA256;
                return RsaOaep.Unpad(decryptedPadded, modulusBytes, hash);
            default:
                throw new ArgumentException($"Unsupported padding mode: {padding}");
        }
    }
    
    public static byte[] Sign(byte[] data, RsaPrivateKey privateKey)
    {
#if NET5_0_OR_GREATER
        var hash = SHA256.HashData(data);
#else
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
#endif
        
        var paddedHash = PadForSignature(hash, GetByteLength(privateKey.Modulus));
        
        var m = new BigInteger(paddedHash);
        var s = m.ModPow(privateKey.D, privateKey.Modulus);
        
        return s.ToByteArray();
    }
    
    public static bool Verify(byte[] data, byte[] signature, RsaPublicKey publicKey)
    {
#if NET5_0_OR_GREATER
        var hash = SHA256.HashData(data);
#else
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
#endif
        
        var s = new BigInteger(signature);
        var m = s.ModPow(publicKey.Exponent, publicKey.Modulus);
        
        var decryptedPadded = m.ToByteArray();
        var expectedPadded = PadForSignature(hash, GetByteLength(publicKey.Modulus));
        
#if NETSTANDARD2_0
        return FixedTimeEquals(decryptedPadded, expectedPadded);
#else
        return CryptographicOperations.FixedTimeEquals(decryptedPadded, expectedPadded);
#endif
    }
    
    private static byte[] PadForSignature(byte[] hash, int targetLength)
    {
        var padded = new byte[targetLength];
        padded[0] = 0x00;
        padded[1] = 0x01;
        
        for (var i = 2; i < targetLength - hash.Length - 1; i++)
        {
            padded[i] = 0xFF;
        }
        
        padded[targetLength - hash.Length - 1] = 0x00;
        Array.Copy(hash, 0, padded, targetLength - hash.Length, hash.Length);
        
        return padded;
    }
    
    private static byte[] PadPkcs1(byte[] data, int targetLength, bool forSignature)
    {
        if (data.Length > targetLength - 11)
            throw new ArgumentException("Data too long for PKCS#1 padding");
        
        var padded = new byte[targetLength];
        padded[0] = 0x00;
        padded[1] = forSignature ? (byte)0x01 : (byte)0x02;
        
        var paddingLength = targetLength - data.Length - 3;
        
        if (forSignature)
        {
            // For signatures, use 0xFF padding
            for (var i = 2; i < 2 + paddingLength; i++)
            {
                padded[i] = 0xFF;
            }
        }
        else
        {
            // For encryption, use random non-zero padding
            using var rng = RandomNumberGenerator.Create();
            var randomPadding = new byte[paddingLength];
            rng.GetBytes(randomPadding);
            
            // Ensure no zero bytes in padding
            for (var i = 0; i < randomPadding.Length; i++)
            {
                while (randomPadding[i] == 0)
                {
#if NETSTANDARD2_0
                    var singleByte = new byte[1];
                    rng.GetBytes(singleByte);
                    randomPadding[i] = singleByte[0];
#else
                    rng.GetBytes(randomPadding.AsSpan(i, 1));
#endif
                }
            }
            
            Array.Copy(randomPadding, 0, padded, 2, paddingLength);
        }
        
        padded[2 + paddingLength] = 0x00;
        Array.Copy(data, 0, padded, 3 + paddingLength, data.Length);
        
        return padded;
    }
    
    private static byte[] UnpadPkcs1(byte[] paddedData, bool forSignature)
    {
        if (paddedData.Length < 11)
            throw new CryptographicException("Invalid PKCS#1 padding");
        
        if (paddedData[0] != 0x00)
            throw new CryptographicException("Invalid PKCS#1 padding");
        
        var expectedSecondByte = forSignature ? (byte)0x01 : (byte)0x02;
        if (paddedData[1] != expectedSecondByte)
            throw new CryptographicException("Invalid PKCS#1 padding");
        
        // Find the 0x00 separator
        var separatorIndex = -1;
        for (var i = 2; i < paddedData.Length; i++)
        {
            if (paddedData[i] == 0x00)
            {
                separatorIndex = i;
                break;
            }
            
            if (forSignature && paddedData[i] != 0xFF)
            {
                throw new CryptographicException("Invalid PKCS#1 padding");
            }
        }
        
        if (separatorIndex == -1 || separatorIndex < 10)
            throw new CryptographicException("Invalid PKCS#1 padding");
        
        var dataLength = paddedData.Length - separatorIndex - 1;
        var data = new byte[dataLength];
        Array.Copy(paddedData, separatorIndex + 1, data, 0, dataLength);
        
        return data;
    }
    
    private static int GetByteLength(BigInteger value)
    {
        var bytes = value.ToByteArray();
        return bytes.Length;
    }
    
    private static BigInteger GeneratePrime(int bits)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[bits / 8];
        
        while (true)
        {
            rng.GetBytes(bytes);
            
            bytes[0] |= 0x80;
            bytes[bytes.Length - 1] |= 0x01;
            
            var candidate = new BigInteger(bytes);
            
            if (IsProbablePrime(candidate, 20))
                return candidate;
        }
    }
    
    private static bool IsProbablePrime(BigInteger n, int k)
    {
        if (n == new BigInteger(2)) return true;
        if (n < new BigInteger(2) || (n.ToByteArray()[0] & 1) == 0) return false;
        
        var smallPrimes = new[] { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47 };
        foreach (var prime in smallPrimes)
        {
            if (n == new BigInteger(prime)) return true;
            if (n % new BigInteger(prime) == BigInteger.Zero) return false;
        }
        
        var d = n - BigInteger.One;
        var r = 0;
        
        while ((d.ToByteArray()[0] & 1) == 0)
        {
            d = d >> 1;
            r++;
        }
        
        using var rng = RandomNumberGenerator.Create();
        
        for (var i = 0; i < k; i++)
        {
            var bytes = new byte[n.ToByteArray().Length];
            rng.GetBytes(bytes);
            var a = new BigInteger(bytes);
            
            if (a < new BigInteger(2)) a = new BigInteger(2);
            if (a >= n - BigInteger.One) a = n - new BigInteger(2);
            
            var x = a.ModPow(d, n);
            
            if (x == BigInteger.One || x == n - BigInteger.One)
                continue;
            
            var continueWitnessing = false;
            for (var j = 0; j < r - 1; j++)
            {
                x = x.ModPow(new BigInteger(2), n);
                if (x == n - BigInteger.One)
                {
                    continueWitnessing = true;
                    break;
                }
            }
            
            if (!continueWitnessing)
                return false;
        }
        
        return true;
    }
    
    private static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        while (!b.IsZero)
        {
            var temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

#if NETSTANDARD2_0
    /// <summary>
    /// Constant-time comparison to prevent timing attacks
    /// </summary>
    private static bool FixedTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;

        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
#endif
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