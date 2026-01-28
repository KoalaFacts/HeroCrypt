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
        var newKey = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(masterKey, salt, context, keySize, HashAlgorithmName.SHA256);

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
