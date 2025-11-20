using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Kdf;

/// <summary>
/// Key management utilities for key rotation, derivation trees, and policies
/// </summary>
public static class KeyManagement
{
    internal static readonly char[] PathSeparator = { '/' };

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
            return new KeyValidationResult { IsValid = false, Issues = new[] { "Key is empty" } };
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

        // Simple entropy estimation
        var entropy = CalculateShannonnEntropy(keyMaterial);
        if (entropy < 6.0)
        {
            issues.Add($"Low entropy detected ({entropy:F2} bits per byte, should be > 6.0)");
        }
        else
        {
            score += (int)((entropy / 8.0) * 40); // Max 40 points for perfect entropy
        }

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
            Issues = issues.ToArray(),
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

        var combinedInput = new List<byte>();
        foreach (var key in keys)
        {
            if (key != null)
            {
                combinedInput.AddRange(key);
            }
        }

        if (combinedInput.Count == 0)
        {
            throw new ArgumentException("No valid keys provided", nameof(keys));
        }

        return HkdfCore.DeriveKey(combinedInput.ToArray(), salt, info, outputLength, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Calculates Shannon entropy of byte array
    /// </summary>
    private static double CalculateShannonnEntropy(ReadOnlySpan<byte> data)
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
    private readonly byte[] _masterKey;
    private readonly byte[] _salt;
    private readonly TimeSpan _rotationInterval;
    private readonly int _keySize;
    private readonly int _maxKeys;
    private readonly Dictionary<DateTimeOffset, byte[]> _activeKeys;
    private readonly object _lock = new();

    internal KeyRotationManager(byte[] masterKey, byte[] salt, TimeSpan rotationInterval, int keySize, int maxKeys)
    {
        _masterKey = masterKey;
        _salt = salt;
        _rotationInterval = rotationInterval;
        _keySize = keySize;
        _maxKeys = maxKeys;
        _activeKeys = new Dictionary<DateTimeOffset, byte[]>();

        // Generate initial key
        RotateKey(DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Gets the current active key
    /// </summary>
    /// <returns>Current key and its creation time</returns>
    public (byte[] Key, DateTimeOffset CreatedAt) GetCurrentKey()
    {
        lock (_lock)
        {
            var now = DateTimeOffset.UtcNow;

            // Check if we need to rotate
            var shouldRotate = true;
            DateTimeOffset latestTime = DateTimeOffset.MinValue;

            foreach (var kvp in _activeKeys)
            {
                if (kvp.Key > latestTime)
                {
                    latestTime = kvp.Key;
                    if (now - kvp.Key < _rotationInterval)
                    {
                        shouldRotate = false;
                    }
                }
            }

            if (shouldRotate)
            {
                RotateKey(now);
            }

            // Return the latest key
            return (_activeKeys[latestTime], latestTime);
        }
    }

    /// <summary>
    /// Forces key rotation
    /// </summary>
    /// <returns>New key and its creation time</returns>
    public (byte[] Key, DateTimeOffset CreatedAt) ForceRotation()
    {
        lock (_lock)
        {
            var now = DateTimeOffset.UtcNow;
            RotateKey(now);
            return (_activeKeys[now], now);
        }
    }

    /// <summary>
    /// Gets a specific key by timestamp
    /// </summary>
    /// <param name="timestamp">Timestamp of key</param>
    /// <returns>Key if found, null otherwise</returns>
    public byte[]? GetKeyByTimestamp(DateTimeOffset timestamp)
    {
        lock (_lock)
        {
            return _activeKeys.TryGetValue(timestamp, out var key) ? key : null;
        }
    }

    /// <summary>
    /// Gets all active keys
    /// </summary>
    /// <returns>Dictionary of timestamps and keys</returns>
    public Dictionary<DateTimeOffset, byte[]> GetAllActiveKeys()
    {
        lock (_lock)
        {
            return new Dictionary<DateTimeOffset, byte[]>(_activeKeys);
        }
    }

    private void RotateKey(DateTimeOffset timestamp)
    {
        // Derive new key using timestamp as context
        var context = System.Text.Encoding.UTF8.GetBytes($"rotation:{timestamp.Ticks}");
        var newKey = HkdfCore.DeriveKey(_masterKey, _salt, context, _keySize, HashAlgorithmName.SHA256);

        _activeKeys[timestamp] = newKey;

        // Clean up old keys if we have too many
        if (_activeKeys.Count > _maxKeys)
        {
            var oldestKeys = new List<DateTimeOffset>();
            foreach (var kvp in _activeKeys)
            {
                oldestKeys.Add(kvp.Key);
            }
            oldestKeys.Sort();

            var keysToRemove = oldestKeys.Count - _maxKeys;
            for (var i = 0; i < keysToRemove; i++)
            {
                var keyToRemove = oldestKeys[i];
                SecureMemoryOperations.SecureClear(_activeKeys[keyToRemove]);
                _activeKeys.Remove(keyToRemove);
            }
        }
    }

    /// <summary>
    /// Disposes the key rotation manager and securely clears all keys
    /// </summary>
    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var key in _activeKeys.Values)
            {
                SecureMemoryOperations.SecureClear(key);
            }
            _activeKeys.Clear();

            SecureMemoryOperations.SecureClear(_masterKey);
            SecureMemoryOperations.SecureClear(_salt);
        }

        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Hierarchical key derivation tree
/// </summary>
public class KeyDerivationTree : IDisposable
{
    private readonly byte[] _rootKey;
    private readonly byte[] _salt;
    private readonly int _maxDepth;
    private readonly int _keySize;
    private readonly Dictionary<string, byte[]> _derivedKeys;
    private readonly object _lock = new();

    internal KeyDerivationTree(byte[] rootKey, byte[] salt, int maxDepth, int keySize)
    {
        _rootKey = rootKey;
        _salt = salt;
        _maxDepth = maxDepth;
        _keySize = keySize;
        _derivedKeys = new Dictionary<string, byte[]>();
    }

    /// <summary>
    /// Derives a key at a specific path
    /// </summary>
    /// <param name="path">Hierarchical path (e.g., "app/user/session")</param>
    /// <returns>Derived key</returns>
    public byte[] DeriveKey(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentException("Path cannot be null or empty", nameof(path));
        }

        var pathParts = path.Split(KeyManagement.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        if (pathParts.Length > _maxDepth)
        {
            throw new ArgumentException($"Path depth exceeds maximum ({_maxDepth})", nameof(path));
        }

        lock (_lock)
        {
            if (_derivedKeys.TryGetValue(path, out var existingKey))
            {
                return existingKey;
            }

            // Derive key using full path as context
            var context = System.Text.Encoding.UTF8.GetBytes(path);
            var derivedKey = HkdfCore.DeriveKey(_rootKey, _salt, context, _keySize, HashAlgorithmName.SHA256);

            _derivedKeys[path] = derivedKey;
            return derivedKey;
        }
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
        lock (_lock)
        {
            return new Dictionary<string, byte[]>(_derivedKeys);
        }
    }

    /// <summary>
    /// Clears a specific key from the tree
    /// </summary>
    /// <param name="path">Path of key to clear</param>
    public void ClearKey(string path)
    {
        lock (_lock)
        {
            if (_derivedKeys.TryGetValue(path, out var key))
            {
                SecureMemoryOperations.SecureClear(key);
                _derivedKeys.Remove(path);
            }
        }
    }

    /// <summary>
    /// Disposes the key derivation tree and securely clears all keys
    /// </summary>
    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var key in _derivedKeys.Values)
            {
                SecureMemoryOperations.SecureClear(key);
            }
            _derivedKeys.Clear();

            SecureMemoryOperations.SecureClear(_rootKey);
            SecureMemoryOperations.SecureClear(_salt);
        }

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

    /// <summary>Required minimum entropy for keys</summary>
    public double MinEntropy { get; set; } = 6.0;

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
    private readonly KeyPolicy _policy;

    internal KeyPolicyManager(KeyPolicy policy)
    {
        _policy = policy;
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
        if (age > _policy.MaxAge)
        {
            issues.Add($"Key is too old ({age.TotalDays:F1} days, max: {_policy.MaxAge.TotalDays} days)");
        }

        var shouldRotate = age > _policy.RotationInterval;

        // Check size
        if (keyMaterial.Length < _policy.MinKeySize)
        {
            issues.Add($"Key is too small ({keyMaterial.Length} bytes, min: {_policy.MinKeySize} bytes)");
        }

        // Validate entropy if enforcing secure generation
        if (_policy.EnforceSecureGeneration)
        {
            var validation = KeyManagement.ValidateKey(keyMaterial);
            if (validation.Entropy < _policy.MinEntropy)
            {
                issues.Add($"Key entropy too low ({validation.Entropy:F2}, min: {_policy.MinEntropy})");
            }

            issues.AddRange(validation.Issues);
        }

        // Custom validation
        if (_policy.CustomValidator != null && !_policy.CustomValidator(keyMaterial.ToArray()))
        {
            issues.Add("Custom validation failed");
        }

        return new PolicyValidationResult
        {
            IsValid = issues.Count == 0,
            Issues = issues.ToArray(),
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
        var keySize = Math.Max(_policy.MinKeySize, 32);
        byte[] key;

        do
        {
            key = KeyManagement.GenerateSecureKey(keySize);
            var validation = ValidateKey(key, DateTimeOffset.UtcNow);

            if (validation.IsValid)
            {
                break;
            }

            SecureMemoryOperations.SecureClear(key);
        }
        while (true);

        return key;
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
    public string[] Issues { get; set; } = Array.Empty<string>();

    /// <summary>Key strength score (0-100)</summary>
    public int Score { get; set; }

    /// <summary>Calculated entropy in bits per byte</summary>
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
    public string[] Issues { get; set; } = Array.Empty<string>();

    /// <summary>Whether the key should be rotated</summary>
    public bool ShouldRotate { get; set; }

    /// <summary>Age of the key</summary>
    public TimeSpan KeyAge { get; set; }
}
