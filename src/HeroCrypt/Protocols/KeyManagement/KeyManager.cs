using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Security;

#if NET9_0_OR_GREATER
using LockType = System.Threading.Lock;
using LockScope = System.Threading.Lock.Scope;
#else
using LockType = System.Object;
#endif

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

            return HkdfCore.DeriveKey(combinedInput, salt, info, outputLength, HashAlgorithmName.SHA256);
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

/// <summary>
/// Manages key rotation with configurable schedules
/// </summary>
public class KeyRotationManager : IDisposable
{
    private readonly byte[] masterKey;
    private readonly byte[] salt;
    private readonly TimeSpan rotationInterval;
    private readonly int keySize;
    private readonly int maxKeys;
    private readonly Func<DateTimeOffset> utcNow;
    private readonly Dictionary<DateTimeOffset, byte[]> activeKeys;
#if NET9_0_OR_GREATER
    private readonly LockType syncLock = new();
    private LockScope EnterLock() => syncLock.EnterScope();
#else
    private readonly LockType syncLock = new();
    private LockReleaser EnterLock() => new(syncLock);
#endif

    internal KeyRotationManager(byte[] masterKey, byte[] salt, TimeSpan rotationInterval, int keySize, int maxKeys,
        Func<DateTimeOffset>? utcNow = null)
    {
        this.masterKey = masterKey;
        this.salt = salt;
        this.rotationInterval = rotationInterval;
        this.keySize = keySize;
        this.maxKeys = maxKeys;
        this.utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        activeKeys = [];

        // Generate initial key
        RotateKey(this.utcNow());
    }

    /// <summary>
    /// Gets the current active key
    /// </summary>
    /// <returns>Current key and its creation time</returns>
    public (byte[] Key, DateTimeOffset CreatedAt) GetCurrentKey()
    {
        using var guard = EnterLock();
        var now = utcNow();

        // Check if we need to rotate
        var shouldRotate = true;
        DateTimeOffset latestTime = DateTimeOffset.MinValue;

        foreach (var kvp in activeKeys)
        {
            if (kvp.Key > latestTime)
            {
                latestTime = kvp.Key;
                if (now - kvp.Key < rotationInterval)
                {
                    shouldRotate = false;
                }
            }
        }

        if (shouldRotate)
        {
            RotateKey(now);
            latestTime = now;
        }

        // Return the latest key
        return ((byte[])activeKeys[latestTime].Clone(), latestTime);
    }

    /// <summary>
    /// Forces key rotation
    /// </summary>
    /// <returns>New key and its creation time</returns>
    public (byte[] Key, DateTimeOffset CreatedAt) ForceRotation()
    {
        using var guard = EnterLock();
        var now = utcNow();
        RotateKey(now);
        return ((byte[])activeKeys[now].Clone(), now);
    }

    /// <summary>
    /// Gets a specific key by timestamp
    /// </summary>
    /// <param name="timestamp">Timestamp of key</param>
    /// <returns>Key if found, null otherwise</returns>
    public byte[]? GetKeyByTimestamp(DateTimeOffset timestamp)
    {
        using var guard = EnterLock();
        return activeKeys.TryGetValue(timestamp, out var key) ? (byte[])key.Clone() : null;
    }

    /// <summary>
    /// Gets all active keys
    /// </summary>
    /// <returns>Dictionary of timestamps and keys</returns>
    public Dictionary<DateTimeOffset, byte[]> GetAllActiveKeys()
    {
        using var guard = EnterLock();
        var result = new Dictionary<DateTimeOffset, byte[]>(activeKeys.Count);
        foreach (var (timestamp, key) in activeKeys)
        {
            result.Add(timestamp, (byte[])key.Clone());
        }
        return result;
    }

    private void RotateKey(DateTimeOffset timestamp)
    {
        // Derive new key using timestamp as context
        var context = System.Text.Encoding.UTF8.GetBytes($"rotation:{timestamp.Ticks}");
        var newKey = HkdfCore.DeriveKey(masterKey, salt, context, keySize, HashAlgorithmName.SHA256);

        activeKeys[timestamp] = newKey;

        // Clean up old keys if we have too many
        if (activeKeys.Count > maxKeys)
        {
            var oldestKeys = new List<DateTimeOffset>();
            foreach (var kvp in activeKeys)
            {
                oldestKeys.Add(kvp.Key);
            }
            oldestKeys.Sort();

            var keysToRemove = oldestKeys.Count - maxKeys;
            for (var i = 0; i < keysToRemove; i++)
            {
                var keyToRemove = oldestKeys[i];
                SecureMemoryOperations.SecureClear(activeKeys[keyToRemove]);
                activeKeys.Remove(keyToRemove);
            }
        }
    }

    /// <summary>
    /// Disposes the key rotation manager and securely clears all keys
    /// </summary>
    public void Dispose()
    {
        using var guard = EnterLock();
        foreach (var key in activeKeys.Values)
        {
            SecureMemoryOperations.SecureClear(key);
        }
        activeKeys.Clear();

        SecureMemoryOperations.SecureClear(masterKey);
        SecureMemoryOperations.SecureClear(salt);

        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Hierarchical key derivation tree
/// </summary>
public class KeyDerivationTree : IDisposable
{
    private readonly byte[] rootKey;
    private readonly byte[] salt;
    private readonly int maxDepth;
    private readonly int keySize;
    private readonly Dictionary<string, byte[]> derivedKeys;
    private readonly LockType syncLock = new();

#if !NET9_0_OR_GREATER
    private LockReleaser EnterLock() => new(syncLock);
#else
    private LockScope EnterLock() => syncLock.EnterScope();
#endif

    internal KeyDerivationTree(byte[] rootKey, byte[] salt, int maxDepth, int keySize)
    {
        this.rootKey = rootKey;
        this.salt = salt;
        this.maxDepth = maxDepth;
        this.keySize = keySize;
        derivedKeys = [];
    }

    /// <summary>
    /// Derives a key at a specific path
    /// </summary>
    /// <param name="path">Hierarchical path (e.g., "app/user/session")</param>
    /// <returns>Derived key</returns>
    public byte[] DeriveKey(string path)
    {
        var normalizedPath = NormalizePath(path);

        using var guard = EnterLock();
        if (derivedKeys.TryGetValue(normalizedPath, out var existingKey))
        {
            return (byte[])existingKey.Clone();
        }

        // Derive key using normalized path as context
        var context = System.Text.Encoding.UTF8.GetBytes(normalizedPath);
        var derivedKey = HkdfCore.DeriveKey(rootKey, salt, context, keySize, HashAlgorithmName.SHA256);

        derivedKeys[normalizedPath] = derivedKey;
        return (byte[])derivedKey.Clone();
    }

    /// <summary>
    /// Derives multiple keys at once
    /// </summary>
    /// <param name="paths">Array of paths</param>
    /// <returns>Dictionary of paths to keys</returns>
    public Dictionary<string, byte[]> DeriveKeys(string[] paths)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(paths);
#else
        if (paths == null)
        {
            throw new ArgumentNullException(nameof(paths));
        }
#endif

        var result = new Dictionary<string, byte[]>();
        foreach (var path in paths)
        {
            result[path] = DeriveKey(path);
        }
        return result;
    }

    /// <summary>
    /// Gets all derived keys
    /// </summary>
    /// <returns>Dictionary of paths to keys</returns>
    public Dictionary<string, byte[]> GetAllKeys()
    {
        using var guard = EnterLock();
        var result = new Dictionary<string, byte[]>(derivedKeys.Count);
        foreach (var (path, key) in derivedKeys)
        {
            result.Add(path, (byte[])key.Clone());
        }
        return result;
    }

    /// <summary>
    /// Clears a specific key from the tree
    /// </summary>
    /// <param name="path">Path of key to clear</param>
    public void ClearKey(string path)
    {
        var normalizedPath = NormalizePath(path);
        using var guard = EnterLock();
        if (derivedKeys.TryGetValue(normalizedPath, out var key))
        {
            SecureMemoryOperations.SecureClear(key);
            derivedKeys.Remove(normalizedPath);
        }
    }

    private string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentException("Path cannot be null or empty", nameof(path));
        }

        var parts = path.Split(KeyManager.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Length > maxDepth)
        {
            throw new ArgumentException($"Path must have between 1 and {maxDepth} segments", nameof(path));
        }

        return string.Join("/", parts);
    }

    /// <summary>
    /// Disposes the key derivation tree and securely clears all keys
    /// </summary>
    public void Dispose()
    {
        using var guard = EnterLock();
        foreach (var key in derivedKeys.Values)
        {
            SecureMemoryOperations.SecureClear(key);
        }
        derivedKeys.Clear();

        SecureMemoryOperations.SecureClear(rootKey);
        SecureMemoryOperations.SecureClear(salt);

        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Key policy configuration
/// </summary>
public class KeyPolicy
{
    /// <summary>Maximum key age before mandatory rotation</summary>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Recommended key rotation interval</summary>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Minimum key size in bytes</summary>
    public int MinKeySize { get; set; } = 32;

    /// <summary>Maximum number of old keys to retain</summary>
    public int MaxRetainedKeys { get; set; } = 5;

    /// <summary>Whether to enforce secure key generation</summary>
    public bool EnforceSecureGeneration { get; set; } = true;

    /// <summary>Optional minimum empirical byte entropy; zero disables this short-sample check.</summary>
    public double MinEntropy { get; set; }

    /// <summary>Hash algorithm for key derivation</summary>
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>Custom validation rules</summary>
    public Func<byte[], bool>? CustomValidator { get; set; }
}

/// <summary>
/// Key policy manager for enforcing key lifecycle rules
/// </summary>
public class KeyPolicyManager
{
    private readonly KeyPolicy policy;

    internal KeyPolicyManager(KeyPolicy policy)
    {
        this.policy = policy;
    }

    /// <summary>
    /// Validates a key against the policy
    /// </summary>
    /// <param name="keyMaterial">Key to validate</param>
    /// <param name="createdAt">When key was created</param>
    /// <returns>Validation result</returns>
    public PolicyValidationResult ValidateKey(ReadOnlySpan<byte> keyMaterial, DateTimeOffset createdAt)
    {
        var issues = new List<string>();
        var now = DateTimeOffset.UtcNow;

        // Check age
        var age = now - createdAt;
        if (age > policy.MaxAge)
        {
            issues.Add($"Key is too old ({age.TotalDays:F1} days, max: {policy.MaxAge.TotalDays} days)");
        }

        var shouldRotate = age > policy.RotationInterval;

        // Check size
        if (keyMaterial.Length < policy.MinKeySize)
        {
            issues.Add($"Key is too small ({keyMaterial.Length} bytes, min: {policy.MinKeySize} bytes)");
        }

        // Validate entropy if enforcing secure generation
        if (policy.EnforceSecureGeneration)
        {
            var validation = KeyManager.ValidateKey(keyMaterial);
            if (policy.MinEntropy > 0 && validation.Entropy < policy.MinEntropy)
            {
                issues.Add($"Key entropy too low ({validation.Entropy:F2}, min: {policy.MinEntropy})");
            }

            issues.AddRange(validation.Issues);
        }

        // Custom validation
        if (policy.CustomValidator != null && !policy.CustomValidator(keyMaterial.ToArray()))
        {
            issues.Add("Custom validation failed");
        }

        return new PolicyValidationResult
        {
            IsValid = issues.Count == 0,
            Issues = [.. issues],
            ShouldRotate = shouldRotate,
            KeyAge = age
        };
    }

    /// <summary>
    /// Generates a key that complies with the policy
    /// </summary>
    /// <returns>Policy-compliant key</returns>
    public byte[] GenerateCompliantKey()
    {
        var keySize = Math.Max(policy.MinKeySize, 32);
        var maximumSampleEntropy = Math.Log(Math.Min(keySize, 256), 2);
        if (policy.EnforceSecureGeneration && policy.MinEntropy > maximumSampleEntropy)
        {
            throw new InvalidOperationException("The requested minimum sample entropy is impossible for this key size.");
        }

        const int maxAttempts = 32;
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            var key = KeyManager.GenerateSecureKey(keySize);
            var validation = ValidateKey(key, DateTimeOffset.UtcNow);
            if (validation.IsValid)
            {
                return key;
            }

            SecureMemoryOperations.SecureClear(key);
        }

        throw new InvalidOperationException("Unable to generate a key that satisfies the policy after 32 attempts.");
    }
}

/// <summary>
/// Result of key validation
/// </summary>
public class KeyValidationResult
{
    /// <summary>Whether the key is valid</summary>
    public bool IsValid { get; set; }

    /// <summary>List of validation issues</summary>
    public string[] Issues { get; set; } = [];

    /// <summary>Key strength score (0-100)</summary>
    public int Score { get; set; }

    /// <summary>Empirical sample entropy in bits per byte, not a measure of generator quality.</summary>
    public double Entropy { get; set; }
}

/// <summary>
/// Result of policy validation
/// </summary>
public class PolicyValidationResult
{
    /// <summary>Whether the key meets policy requirements</summary>
    public bool IsValid { get; set; }

    /// <summary>List of policy violations</summary>
    public string[] Issues { get; set; } = [];

    /// <summary>Whether the key should be rotated</summary>
    public bool ShouldRotate { get; set; }

    /// <summary>Age of the key</summary>
    public TimeSpan KeyAge { get; set; }
}
