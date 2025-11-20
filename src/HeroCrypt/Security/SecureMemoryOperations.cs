using System.Security.Cryptography;

namespace HeroCrypt.Security;

/// <summary>
/// Provides secure memory operations for cryptographic material
/// </summary>
public static class SecureMemoryOperations
{
    /// <summary>
    /// Securely clears sensitive data from memory using cryptographically secure methods
    /// </summary>
    /// <param name="sensitiveData">The sensitive data to clear</param>
    public static void SecureClear(byte[] sensitiveData)
    {
        if (sensitiveData == null || sensitiveData.Length == 0)
        {
            return;
        }

#if NET5_0_OR_GREATER
        // Use the built-in cryptographically secure clear method
        CryptographicOperations.ZeroMemory(sensitiveData);
#else
        // For older frameworks, use multiple clearing methods to prevent compiler optimization
        Array.Clear(sensitiveData, 0, sensitiveData.Length);

        // Fill with random data first to prevent memory recovery
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(sensitiveData);

        // Clear again
        Array.Clear(sensitiveData, 0, sensitiveData.Length);

        // Force garbage collection to ensure memory is reclaimed
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
#endif
    }

    /// <summary>
    /// Securely clears multiple sensitive byte arrays
    /// </summary>
    /// <param name="sensitiveArrays">The sensitive arrays to clear</param>
    public static void SecureClear(params byte[][] sensitiveArrays)
    {
        if (sensitiveArrays == null)
        {
            return;
        }

        foreach (var array in sensitiveArrays)
        {
            SecureClear(array);
        }
    }

    /// <summary>
    /// Securely clears a span of sensitive data
    /// </summary>
    /// <param name="sensitiveData">The sensitive data span to clear</param>
    public static void SecureClear(Span<byte> sensitiveData)
    {
        if (sensitiveData.Length == 0)
        {
            return;
        }

#if NET5_0_OR_GREATER
        CryptographicOperations.ZeroMemory(sensitiveData);
#else
        sensitiveData.Clear();

        // Additional clearing for older frameworks
        for (var i = 0; i < sensitiveData.Length; i++)
        {
            sensitiveData[i] = 0;
        }
#endif
    }

    /// <summary>
    /// Securely clears a span of ulong values
    /// </summary>
    /// <param name="sensitiveData">The sensitive data span to clear</param>
    public static void SecureClear(Span<ulong> sensitiveData)
    {
        if (sensitiveData.Length == 0)
        {
            return;
        }

        for (var i = 0; i < sensitiveData.Length; i++)
        {
            sensitiveData[i] = 0;
        }
    }

    /// <summary>
    /// Securely clears a span of uint values
    /// </summary>
    /// <param name="sensitiveData">The sensitive data span to clear</param>
    public static void SecureClear(Span<uint> sensitiveData)
    {
        if (sensitiveData.Length == 0)
        {
            return;
        }

        for (var i = 0; i < sensitiveData.Length; i++)
        {
            sensitiveData[i] = 0;
        }
    }

    /// <summary>
    /// Performs constant-time comparison of two byte arrays to prevent timing attacks
    /// </summary>
    /// <param name="a">First array to compare</param>
    /// <param name="b">Second array to compare</param>
    /// <returns>True if arrays are equal, false otherwise</returns>
    public static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null)
        {
            return a == b;
        }

        if (a.Length != b.Length)
        {
            return false;
        }

#if NET5_0_OR_GREATER
        return CryptographicOperations.FixedTimeEquals(a, b);
#else
        return ConstantTimeEqualsLegacy(a, b);
#endif
    }

    /// <summary>
    /// Performs constant-time comparison of two spans to prevent timing attacks
    /// </summary>
    /// <param name="a">First span to compare</param>
    /// <param name="b">Second span to compare</param>
    /// <returns>True if spans are equal, false otherwise</returns>
    public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

#if NET5_0_OR_GREATER
        return CryptographicOperations.FixedTimeEquals(a, b);
#else
        // Convert spans to arrays for legacy framework compatibility
        return ConstantTimeEqualsLegacy(a.ToArray(), b.ToArray());
#endif
    }

#if !NET5_0_OR_GREATER
    /// <summary>
    /// Legacy implementation of constant-time comparison for older .NET frameworks
    /// </summary>
    private static bool ConstantTimeEqualsLegacy(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }
#endif

    /// <summary>
    /// Creates a secure copy of sensitive data with automatic cleanup
    /// </summary>
    /// <param name="source">Source data to copy</param>
    /// <returns>Secure wrapper around the copied data</returns>
    public static SecureByteArray CreateSecureCopy(byte[] source)
    {
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return new SecureByteArray(source);
    }

    /// <summary>
    /// Allocates secure memory that is automatically cleared on disposal
    /// </summary>
    /// <param name="length">Length of memory to allocate</param>
    /// <returns>Secure memory allocation</returns>
    public static SecureByteArray AllocateSecure(int length)
    {
        if (length < 0)
        {
            throw new ArgumentException("Length must be non-negative", nameof(length));
        }

        return new SecureByteArray(length);
    }

    /// <summary>
    /// Validates that sensitive data has been properly cleared
    /// </summary>
    /// <param name="data">Data to validate</param>
    /// <returns>True if data appears to be cleared</returns>
    public static bool IsCleared(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return true;
        }

        foreach (var b in data)
        {
            if (b != 0)
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// Secure wrapper for byte arrays that automatically clears memory on disposal
/// </summary>
public sealed class SecureByteArray : IDisposable
{
    private byte[] _data;
    private bool _disposed;
    private readonly object _lock = new();

    /// <summary>
    /// Initializes a new secure byte array with the specified length
    /// </summary>
    /// <param name="length">Length of the array</param>
    public SecureByteArray(int length)
    {
        if (length < 0)
        {
            throw new ArgumentException("Length must be non-negative", nameof(length));
        }

        _data = new byte[length];
    }

    /// <summary>
    /// Initializes a new secure byte array with a copy of the provided data
    /// </summary>
    /// <param name="source">Source data to copy</param>
    public SecureByteArray(byte[] source)
    {
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        _data = new byte[source.Length];
        Array.Copy(source, _data, source.Length);
    }

    /// <summary>
    /// Gets the length of the secure array
    /// </summary>
    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _data?.Length ?? 0;
        }
    }

    /// <summary>
    /// Gets or sets a byte at the specified index
    /// </summary>
    /// <param name="index">Index to access</param>
    public byte this[int index]
    {
        get
        {
            ThrowIfDisposed();
            return _data[index];
        }
        set
        {
            ThrowIfDisposed();
            _data[index] = value;
        }
    }

    /// <summary>
    /// Executes an action with access to the underlying byte array
    /// </summary>
    /// <param name="action">Action to execute with the byte array</param>
    public void WithBytes(Action<byte[]> action)
    {
        if (action == null)
        {
            throw new ArgumentNullException(nameof(action));
        }

        lock (_lock)
        {
            ThrowIfDisposed();
            action(_data);
        }
    }

    /// <summary>
    /// Executes a function with access to the underlying byte array and returns a result
    /// </summary>
    /// <typeparam name="T">Return type</typeparam>
    /// <param name="func">Function to execute with the byte array</param>
    /// <returns>Result of the function</returns>
    public T WithBytes<T>(Func<byte[], T> func)
    {
        if (func == null)
        {
            throw new ArgumentNullException(nameof(func));
        }

        lock (_lock)
        {
            ThrowIfDisposed();
            return func(_data);
        }
    }

    /// <summary>
    /// Creates a copy of the secure array data
    /// </summary>
    /// <returns>Copy of the array data</returns>
    public byte[] ToArray()
    {
        lock (_lock)
        {
            ThrowIfDisposed();
            var copy = new byte[_data.Length];
            Array.Copy(_data, copy, _data.Length);
            return copy;
        }
    }

    /// <summary>
    /// Copies data to the secure array
    /// </summary>
    /// <param name="source">Source data to copy</param>
    /// <param name="sourceIndex">Starting index in source</param>
    /// <param name="destinationIndex">Starting index in destination</param>
    /// <param name="length">Number of bytes to copy</param>
    public void CopyFrom(byte[] source, int sourceIndex = 0, int destinationIndex = 0, int? length = null)
    {
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        var copyLength = length ?? source.Length;

        lock (_lock)
        {
            ThrowIfDisposed();
            Array.Copy(source, sourceIndex, _data, destinationIndex, copyLength);
        }
    }

    /// <summary>
    /// Disposes the secure array and clears all sensitive data
    /// </summary>
    public void Dispose()
    {
        lock (_lock)
        {
            if (!_disposed && _data != null)
            {
                SecureMemoryOperations.SecureClear(_data);
                _data = null!;
                _disposed = true;
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(SecureByteArray));
        }
    }

    /// <summary>
    /// Finalizer to ensure secure cleanup
    /// </summary>
    ~SecureByteArray()
    {
        Dispose();
    }
}
