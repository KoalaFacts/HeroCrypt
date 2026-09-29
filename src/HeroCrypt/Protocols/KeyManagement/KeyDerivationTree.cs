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
        var derivedKey = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(rootKey, salt, context, keySize, HashAlgorithmName.SHA256);

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
