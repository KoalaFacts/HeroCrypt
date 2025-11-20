using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Primitives.Signature.Rsa;

/// <summary>
/// RSA-OAEP (Optimal Asymmetric Encryption Padding) implementation according to PKCS#1 v2.2 (RFC 8017)
/// </summary>
internal static class RsaOaep
{
    /// <summary>
    /// Apply OAEP padding to a message
    /// </summary>
    public static byte[] Pad(byte[] message, int modulusLength, HashAlgorithmName hashAlgorithm, byte[]? label = null)
    {
        using var hash = CreateHashAlgorithm(hashAlgorithm);
        var hLen = hash.HashSize / 8;
        var maxMessageLength = modulusLength - 2 * hLen - 2;

        if (message.Length > maxMessageLength)
        {
            throw new ArgumentException($"Message too long. Maximum length is {maxMessageLength} bytes.");
        }

        // Hash the label (default is empty string)
        var lHash = hash.ComputeHash(label ?? Array.Empty<byte>());

        // Create PS (padding string) of zeros
        var psLength = modulusLength - message.Length - 2 * hLen - 2;
        var ps = new byte[psLength];

        // Construct DB = lHash || PS || 0x01 || M
        var db = new byte[modulusLength - hLen - 1];
        Array.Copy(lHash, 0, db, 0, hLen);
        // PS is already zeros
        db[hLen + psLength] = 0x01;
        Array.Copy(message, 0, db, hLen + psLength + 1, message.Length);

        // Generate random seed
        var seed = new byte[hLen];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(seed);
        }

        // dbMask = MGF(seed, k - hLen - 1)
        var dbMask = Mgf1(seed, modulusLength - hLen - 1, hash);

        // maskedDB = DB xor dbMask
        var maskedDb = new byte[db.Length];
        for (var i = 0; i < db.Length; i++)
        {
            maskedDb[i] = (byte)(db[i] ^ dbMask[i]);
        }

        // seedMask = MGF(maskedDB, hLen)
        var seedMask = Mgf1(maskedDb, hLen, hash);

        // maskedSeed = seed xor seedMask
        var maskedSeed = new byte[hLen];
        for (var i = 0; i < hLen; i++)
        {
            maskedSeed[i] = (byte)(seed[i] ^ seedMask[i]);
        }

        // EM = 0x00 || maskedSeed || maskedDB
        var em = new byte[modulusLength];
        em[0] = 0x00;
        Array.Copy(maskedSeed, 0, em, 1, hLen);
        Array.Copy(maskedDb, 0, em, hLen + 1, maskedDb.Length);

        return em;
    }

    /// <summary>
    /// Remove OAEP padding from a message
    /// </summary>
    public static byte[] Unpad(byte[] paddedMessage, int modulusLength, HashAlgorithmName hashAlgorithm, byte[]? label = null)
    {
        using var hash = CreateHashAlgorithm(hashAlgorithm);
        var hLen = hash.HashSize / 8;

        if (paddedMessage.Length != modulusLength)
        {
            throw new ArgumentException("Invalid padded message length");
        }

        if (paddedMessage[0] != 0x00)
        {
            throw new CryptographicException("Decryption error");
        }

        // Extract maskedSeed and maskedDB
        var maskedSeed = new byte[hLen];
        Array.Copy(paddedMessage, 1, maskedSeed, 0, hLen);

        var maskedDb = new byte[modulusLength - hLen - 1];
        Array.Copy(paddedMessage, hLen + 1, maskedDb, 0, maskedDb.Length);

        // seedMask = MGF(maskedDB, hLen)
        var seedMask = Mgf1(maskedDb, hLen, hash);

        // seed = maskedSeed xor seedMask
        var seed = new byte[hLen];
        for (var i = 0; i < hLen; i++)
        {
            seed[i] = (byte)(maskedSeed[i] ^ seedMask[i]);
        }

        // dbMask = MGF(seed, k - hLen - 1)
        var dbMask = Mgf1(seed, modulusLength - hLen - 1, hash);

        // DB = maskedDB xor dbMask
        var db = new byte[maskedDb.Length];
        for (var i = 0; i < maskedDb.Length; i++)
        {
            db[i] = (byte)(maskedDb[i] ^ dbMask[i]);
        }

        // Verify lHash
        var lHash = hash.ComputeHash(label ?? Array.Empty<byte>());
        for (var i = 0; i < hLen; i++)
        {
            if (db[i] != lHash[i])
            {
                throw new CryptographicException("Decryption error");
            }
        }

        // Find the 0x01 separator
        var separatorIndex = -1;
        for (var i = hLen; i < db.Length; i++)
        {
            if (db[i] == 0x01)
            {
                separatorIndex = i;
                break;
            }
            else if (db[i] != 0x00)
            {
                throw new CryptographicException("Decryption error");
            }
        }

        if (separatorIndex == -1)
        {
            throw new CryptographicException("Decryption error");
        }

        // Extract message
        var messageLength = db.Length - separatorIndex - 1;
        var message = new byte[messageLength];
        Array.Copy(db, separatorIndex + 1, message, 0, messageLength);

        return message;
    }

    /// <summary>
    /// MGF1 (Mask Generation Function) as specified in PKCS#1
    /// </summary>
    private static byte[] Mgf1(byte[] seed, int length, HashAlgorithm hash)
    {
        var hLen = hash.HashSize / 8;
        var iterations = (length + hLen - 1) / hLen;
        var result = new byte[iterations * hLen];

        var counter = new byte[4];
        for (var i = 0; i < iterations; i++)
        {
            counter[3] = (byte)i;

            hash.Initialize();
            hash.TransformBlock(seed, 0, seed.Length, seed, 0);
            hash.TransformFinalBlock(counter, 0, 4);

            Array.Copy(hash.Hash!, 0, result, i * hLen, hLen);
        }

        // Truncate to requested length
        var output = new byte[length];
        Array.Copy(result, output, length);
        return output;
    }

    private static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName name)
    {
        if (name == HashAlgorithmName.SHA256)
        {
            return SHA256.Create();
        }
        if (name == HashAlgorithmName.SHA384)
        {
            return SHA384.Create();
        }
        if (name == HashAlgorithmName.SHA512)
        {
            return SHA512.Create();
        }
        if (name == HashAlgorithmName.SHA1)
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - SHA1 is required for OAEP compatibility
            return SHA1.Create();
#pragma warning restore CA5350

        throw new ArgumentException($"Unsupported hash algorithm: {name}");
    }
}
