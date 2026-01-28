using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Rsa;

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
        using HashAlgorithm hash = CreateHashAlgorithm(hashAlgorithm);
        int hLen = hash.HashSize / 8;
        int maxMessageLength = modulusLength - (2 * hLen) - 2;

        if (message.Length > maxMessageLength)
        {
            throw new ArgumentException($"Message too long. Maximum length is {maxMessageLength} bytes.");
        }

        byte[]? db = null;
        byte[]? seed = null;
        byte[]? dbMask = null;
        byte[]? seedMask = null;

        try
        {
            // Hash the label (default is empty string)
            byte[] lHash = hash.ComputeHash(label ?? []);

            // Create PS (padding string) of zeros
            int psLength = modulusLength - message.Length - (2 * hLen) - 2;

            // Construct DB = lHash || PS || 0x01 || M
            db = new byte[modulusLength - hLen - 1];
            Array.Copy(lHash, 0, db, 0, hLen);
            // PS is already zeros
            db[hLen + psLength] = 0x01;
            Array.Copy(message, 0, db, hLen + psLength + 1, message.Length);

            // Generate random seed
            seed = new byte[hLen];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(seed);
            }

            // dbMask = MGF(seed, k - hLen - 1)
            dbMask = Mgf1(seed, modulusLength - hLen - 1, hash);

            // maskedDB = DB xor dbMask
            byte[] maskedDb = new byte[db.Length];
            for (int i = 0; i < db.Length; i++)
            {
                maskedDb[i] = (byte)(db[i] ^ dbMask[i]);
            }

            // seedMask = MGF(maskedDB, hLen)
            seedMask = Mgf1(maskedDb, hLen, hash);

            // maskedSeed = seed xor seedMask
            byte[] maskedSeed = new byte[hLen];
            for (int i = 0; i < hLen; i++)
            {
                maskedSeed[i] = (byte)(seed[i] ^ seedMask[i]);
            }

            // EM = 0x00 || maskedSeed || maskedDB
            byte[] em = new byte[modulusLength];
            em[0] = 0x00;
            Array.Copy(maskedSeed, 0, em, 1, hLen);
            Array.Copy(maskedDb, 0, em, hLen + 1, maskedDb.Length);

            return em;
        }
        finally
        {
            // Clear sensitive intermediate buffers
            if (db != null) SecureMemoryOperations.SecureClear(db);
            if (seed != null) SecureMemoryOperations.SecureClear(seed);
            if (dbMask != null) SecureMemoryOperations.SecureClear(dbMask);
            if (seedMask != null) SecureMemoryOperations.SecureClear(seedMask);
        }
    }

    /// <summary>
    /// Remove OAEP padding from a message
    /// </summary>
    public static byte[] Unpad(byte[] paddedMessage, int modulusLength, HashAlgorithmName hashAlgorithm, byte[]? label = null)
    {
        using HashAlgorithm hash = CreateHashAlgorithm(hashAlgorithm);
        int hLen = hash.HashSize / 8;

        if (paddedMessage.Length != modulusLength)
        {
            throw new ArgumentException("Invalid padded message length");
        }

        byte[]? maskedSeed = null;
        byte[]? maskedDb = null;
        byte[]? seedMask = null;
        byte[]? seed = null;
        byte[]? dbMask = null;
        byte[]? db = null;

        try
        {
            // Accumulate errors in constant-time to prevent timing attacks
            int errorFlags = 0;

            // Check first byte (should be 0x00)
            errorFlags |= paddedMessage[0];

            // Extract maskedSeed and maskedDB
            maskedSeed = new byte[hLen];
            Array.Copy(paddedMessage, 1, maskedSeed, 0, hLen);

            maskedDb = new byte[modulusLength - hLen - 1];
            Array.Copy(paddedMessage, hLen + 1, maskedDb, 0, maskedDb.Length);

            // seedMask = MGF(maskedDB, hLen)
            seedMask = Mgf1(maskedDb, hLen, hash);

            // seed = maskedSeed xor seedMask
            seed = new byte[hLen];
            for (int i = 0; i < hLen; i++)
            {
                seed[i] = (byte)(maskedSeed[i] ^ seedMask[i]);
            }

            // dbMask = MGF(seed, k - hLen - 1)
            dbMask = Mgf1(seed, modulusLength - hLen - 1, hash);

            // DB = maskedDB xor dbMask
            db = new byte[maskedDb.Length];
            for (int i = 0; i < maskedDb.Length; i++)
            {
                db[i] = (byte)(maskedDb[i] ^ dbMask[i]);
            }

            // Constant-time lHash verification
            byte[] lHash = hash.ComputeHash(label ?? []);
            if (!SecureMemoryOperations.ConstantTimeEquals(db.AsSpan(0, hLen), lHash))
            {
                errorFlags |= 1;
            }

            // Constant-time separator search
            // We need to find 0x01 while ensuring PS is all zeros
            int separatorIndex = -1;
            int foundSeparator = 0;
            int invalidPadding = 0;

            for (int i = hLen; i < db.Length; i++)
            {
                // Check if this is the first 0x01 we've seen (and we haven't found one yet)
                int isSeparator = ConstantTimeOperations.ConstantTimeEquals(db[i], 0x01) & (1 - foundSeparator);

                // Update separator index only when we find the first 0x01
                // Using constant-time conditional: separatorIndex = isSeparator ? i : separatorIndex
                separatorIndex = (isSeparator * i) | ((1 - isSeparator) * separatorIndex);
                foundSeparator |= isSeparator;

                // Before finding separator, all bytes must be 0x00
                // After finding separator, any byte is valid (it's the message)
                int beforeSeparator = 1 - foundSeparator;
                int isInvalidPs = beforeSeparator & (1 - ConstantTimeOperations.ConstantTimeEquals(db[i], 0x00)) & (1 - isSeparator);
                invalidPadding |= isInvalidPs;
            }

            // Check for errors: no separator found, or invalid PS bytes
            errorFlags |= (1 - foundSeparator);
            errorFlags |= invalidPadding;

            // Throw if any errors occurred (constant-time check accumulation, but single branch at the end)
            if (errorFlags != 0)
            {
                throw new CryptographicException("Decryption error");
            }

            // Extract message
            int messageLength = db.Length - separatorIndex - 1;
            byte[] message = new byte[messageLength];
            Array.Copy(db, separatorIndex + 1, message, 0, messageLength);

            return message;
        }
        finally
        {
            // Clear sensitive intermediate buffers
            if (maskedSeed != null) SecureMemoryOperations.SecureClear(maskedSeed);
            if (maskedDb != null) SecureMemoryOperations.SecureClear(maskedDb);
            if (seedMask != null) SecureMemoryOperations.SecureClear(seedMask);
            if (seed != null) SecureMemoryOperations.SecureClear(seed);
            if (dbMask != null) SecureMemoryOperations.SecureClear(dbMask);
            if (db != null) SecureMemoryOperations.SecureClear(db);
        }
    }

    /// <summary>
    /// MGF1 (Mask Generation Function) as specified in PKCS#1
    /// </summary>
    private static byte[] Mgf1(byte[] seed, int length, HashAlgorithm hash)
    {
        int hLen = hash.HashSize / 8;
        int iterations = (length + hLen - 1) / hLen;
        byte[] result = new byte[iterations * hLen];

        byte[] counter = new byte[4];
        for (int i = 0; i < iterations; i++)
        {
            counter[3] = (byte)i;

            hash.Initialize();
            _ = hash.TransformBlock(seed, 0, seed.Length, seed, 0);
            _ = hash.TransformFinalBlock(counter, 0, 4);

            Array.Copy(hash.Hash!, 0, result, i * hLen, hLen);
        }

        // Truncate to requested length
        byte[] output = new byte[length];
        Array.Copy(result, output, length);
        return output;
    }

    private static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName name)
    {
        // Validate hash algorithm against security policy (blocks SHA-1 at Standard+ level)
        SecurityPolicy.ValidateHash(name.Name ?? "Unknown");

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
        {
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - SHA1 is required for OAEP compatibility
            return SHA1.Create();
#pragma warning restore CA5350
        }

        throw new ArgumentException($"Unsupported hash algorithm: {name}");
    }
}
