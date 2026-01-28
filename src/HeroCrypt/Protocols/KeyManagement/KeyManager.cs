using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.KeyManagement;

/// <summary>
/// Key management utilities for key rotation, derivation trees, and policies
/// </summary>
public static class KeyManager
{
    internal static readonly char[] PathSeparator = ['/'];
    private static readonly byte[] CombinedKeyDomain = "HeroCrypt.CombineKeys.v2"u8.ToArray();

    /// <summary>
    /// Creates a new key rotation schedule
    /// </summary>
    /// <param name="masterKey">Master key for derivation</param>
    /// <param name="salt">Salt for derivation</param>
    /// <param name="rotationInterval">How often keys should rotate</param>
    /// <param name="keySize">Size of derived keys</param>
    /// <param name="maxKeys">Maximum number of keys to maintain</param>
    /// <returns>Key rotation manager</returns>
    public static KeyRotationManager CreateKeyRotation(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt,
        TimeSpan rotationInterval, int keySize = 32, int maxKeys = 10)
    {
        if (masterKey.IsEmpty)
        {
            throw new ArgumentException("Master key cannot be empty", nameof(masterKey));
        }
        if (salt.IsEmpty)
        {
            throw new ArgumentException("Salt cannot be empty", nameof(salt));
        }
        if (rotationInterval <= TimeSpan.Zero)
        {
            throw new ArgumentException("Rotation interval must be positive", nameof(rotationInterval));
        }
        if (keySize <= 0)
        {
            throw new ArgumentException("Key size must be positive", nameof(keySize));
        }
        if (maxKeys <= 0)
        {
            throw new ArgumentException("Max keys must be positive", nameof(maxKeys));
        }

        return new KeyRotationManager(masterKey.ToArray(), salt.ToArray(), rotationInterval, keySize, maxKeys);
    }

    /// <summary>
    /// Creates a key derivation tree for hierarchical keys
    /// </summary>
    /// <param name="rootKey">Root key material</param>
    /// <param name="salt">Salt for derivation</param>
    /// <param name="treeDepth">Maximum depth of the tree</param>
    /// <param name="keySize">Size of each key</param>
    /// <returns>Key derivation tree</returns>
    public static KeyDerivationTree CreateDerivationTree(ReadOnlySpan<byte> rootKey, ReadOnlySpan<byte> salt,
        int treeDepth = 5, int keySize = 32)
    {
        if (rootKey.IsEmpty)
        {
            throw new ArgumentException("Root key cannot be empty", nameof(rootKey));
        }
        if (salt.IsEmpty)
        {
            throw new ArgumentException("Salt cannot be empty", nameof(salt));
        }
        if (treeDepth <= 0)
        {
            throw new ArgumentException("Tree depth must be positive", nameof(treeDepth));
        }
        if (keySize <= 0)
        {
            throw new ArgumentException("Key size must be positive", nameof(keySize));
        }

        return new KeyDerivationTree(rootKey.ToArray(), salt.ToArray(), treeDepth, keySize);
    }

    /// <summary>
    /// Creates a key policy for automatic key lifecycle management
    /// </summary>
    /// <param name="policy">Key policy configuration</param>
    /// <returns>Key policy manager</returns>
    public static KeyPolicyManager CreateKeyPolicy(KeyPolicy policy)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(policy);
#else
        if (policy == null)
        {
            throw new ArgumentNullException(nameof(policy));
        }
#endif

        return new KeyPolicyManager(policy);
    }

    /// <summary>
    /// Validates key material entropy and strength
    /// </summary>
    /// <param name="keyMaterial">Key material to validate</param>
    /// <returns>Key validation result</returns>
    public static KeyValidationResult ValidateKey(ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.IsEmpty)
        {
            return new KeyValidationResult { IsValid = false, Issues = ["Key is empty"] };
        }

        var issues = new List<string>();
        var score = 0;

        // Check minimum length
        if (keyMaterial.Length < 16)
        {
            issues.Add("Key is too short (minimum 16 bytes)");
        }
        else
        {
            score += 20;
        }

        // Check for all zeros
        var allZeros = true;
        for (var i = 0; i < keyMaterial.Length; i++)
        {
            if (keyMaterial[i] != 0)
            {
                allZeros = false;
                break;
            }
        }

        if (allZeros)
        {
            issues.Add("Key contains all zeros");
        }
        else
        {
            score += 20;
        }

        // Empirical entropy of a short sample cannot establish its generator's
        // quality. Report it as a diagnostic without rejecting the key for it.
        var entropy = CalculateShannonEntropy(keyMaterial);
        var maximumSampleEntropy = Math.Log(Math.Min(keyMaterial.Length, 256), 2);
        score += maximumSampleEntropy > 0
            ? (int)Math.Min(40, (entropy / maximumSampleEntropy) * 40)
            : 0;

        // Check for repeating patterns
        if (HasRepeatingPatterns(keyMaterial))
        {
            issues.Add("Repeating patterns detected");
        }
        else
        {
            score += 20;
        }

        return new KeyValidationResult
        {
            IsValid = issues.Count == 0,
            Issues = [.. issues],
            Score = Math.Min(score, 100),
            Entropy = entropy
        };
    }

    /// <summary>
    /// Generates secure random key material
    /// </summary>
    /// <param name="length">Length of key in bytes</param>
    /// <returns>Secure random key</returns>
    public static byte[] GenerateSecureKey(int length = 32)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Length must be positive", nameof(length));
        }

        var key = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);

        return key;
    }

    /// <summary>
    /// Combines multiple keys using HKDF
    /// </summary>
    /// <param name="keys">Keys to combine</param>
    /// <param name="salt">Salt for combination</param>
    /// <param name="info">Context information</param>
    /// <param name="outputLength">Desired output length</param>
    /// <returns>Combined key</returns>
    public static byte[] CombineKeys(IEnumerable<byte[]> keys, ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info, int outputLength = 32)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(keys);
#else
        if (keys == null)
        {
            throw new ArgumentNullException(nameof(keys));
        }
#endif
        if (outputLength <= 0)
        {
            throw new ArgumentException("Output length must be positive", nameof(outputLength));
        }

        var keyParts = new List<byte[]>();
        int encodedLength = CombinedKeyDomain.Length + sizeof(int);
        foreach (var key in keys)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentException("Keys cannot contain null or empty elements", nameof(keys));
            }

            keyParts.Add(key);
            encodedLength = checked(encodedLength + sizeof(int) + key.Length);
        }

        if (keyParts.Count == 0)
        {
            throw new ArgumentException("No valid keys provided", nameof(keys));
        }

        var combinedInput = new byte[encodedLength];
        try
        {
            var destination = combinedInput.AsSpan();
            CombinedKeyDomain.AsSpan().CopyTo(destination);
            int offset = CombinedKeyDomain.Length;
            BinaryPrimitives.WriteInt32BigEndian(destination.Slice(offset), keyParts.Count);
            offset += sizeof(int);
            foreach (var key in keyParts)
            {
                BinaryPrimitives.WriteInt32BigEndian(destination.Slice(offset), key.Length);
                offset += sizeof(int);
                key.AsSpan().CopyTo(destination.Slice(offset));
                offset += key.Length;
            }

            var hkdf = new HkdfCore(SecurityPolicy.CurrentPolicy);
            return hkdf.DeriveKey(combinedInput, salt, info, outputLength, HashAlgorithmName.SHA256);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(combinedInput);
        }
    }

    /// <summary>
    /// Calculates Shannon entropy of byte array
    /// </summary>
    private static double CalculateShannonEntropy(ReadOnlySpan<byte> data)
    {
        var frequency = new int[256];
        foreach (var b in data)
        {
            frequency[b]++;
        }

        var entropy = 0.0;
        var length = data.Length;

        for (var i = 0; i < 256; i++)
        {
            if (frequency[i] == 0)
            {
                continue;
            }

            var p = (double)frequency[i] / length;
            entropy -= p * (Math.Log(p) / Math.Log(2));
        }

        return entropy;
    }

    /// <summary>
    /// Checks for simple repeating patterns
    /// </summary>
    private static bool HasRepeatingPatterns(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
        {
            return false;
        }

        // Check for 2-byte patterns
        for (var i = 0; i <= data.Length - 4; i += 2)
        {
            if (data[i] == data[i + 2] && data[i + 1] == data[i + 3])
            {
                return true;
            }
        }

        return false;
    }
}
