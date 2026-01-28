using System.Security.Cryptography;

#if NET9_0_OR_GREATER
using Lock = System.Threading.Lock;
using LockScope = System.Threading.Lock.Scope;
#endif

namespace HeroCrypt.Security;

/// <summary>
/// Provides secure memory operations for cryptographic material.
/// </summary>
/// <remarks>
/// <para>
/// This class provides methods for securely clearing sensitive data from memory,
/// preventing key material from persisting after use.
/// </para>
/// <para>
/// <b>Platform-Specific Behavior:</b>
/// <list type="bullet">
///   <item><b>.NET 5.0+:</b> Uses CryptographicOperations.ZeroMemory which is
///   guaranteed not to be optimized away by the JIT compiler.</item>
///   <item><b>.NET Standard 2.0:</b> Uses a fallback implementation with Array.Clear,
///   random data overwrite, and GC.Collect to reduce the risk of optimization, but this
///   is <b>not guaranteed</b> to prevent all optimizations.</item>
/// </list>
/// </para>
/// <para>
/// <b>⚠️ .NET Standard 2.0 Limitation:</b>
/// On .NET Standard 2.0 and older frameworks, the JIT compiler may theoretically optimize
/// away the memory clearing operations if it determines the array is not used after clearing.
/// The fallback implementation includes multiple mitigations:
/// <list type="number">
///   <item>Multiple clear operations with random data in between</item>
///   <item>GC.Collect calls to encourage immediate memory reclamation</item>
///   <item>Volatile.Write for span-based clearing</item>
/// </list>
/// However, for maximum security on sensitive applications, consider:
/// <list type="bullet">
///   <item>Targeting .NET 5.0 or later where CryptographicOperations.ZeroMemory is available</item>
///   <item>Using secure memory allocators provided by the operating system</item>
/// </list>
/// </para>
/// </remarks>
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

        // Use volatile writes to prevent JIT optimization from removing the clearing
        for (var i = 0; i < sensitiveData.Length; i++)
        {
            Volatile.Write(ref sensitiveData[i], 0);
        }

        // Memory barrier to ensure writes are not reordered
        Thread.MemoryBarrier();
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

        // Use volatile writes to prevent JIT optimization from removing the clearing
        for (var i = 0; i < sensitiveData.Length; i++)
        {
            Volatile.Write(ref sensitiveData[i], 0);
        }

        // Memory barrier to ensure writes are not reordered
        Thread.MemoryBarrier();
    }

    /// <summary>
    /// Securely clears a span of long values
    /// </summary>
    /// <param name="sensitiveData">The sensitive data span to clear</param>
    public static void SecureClear(Span<long> sensitiveData)
    {
        if (sensitiveData.Length == 0)
        {
            return;
        }

        // Use volatile writes to prevent JIT optimization from removing the clearing
        for (var i = 0; i < sensitiveData.Length; i++)
        {
            Volatile.Write(ref sensitiveData[i], 0);
        }

        // Memory barrier to ensure writes are not reordered
        Thread.MemoryBarrier();
    }

    /// <summary>
    /// Performs constant-time comparison of two byte arrays to prevent timing attacks.
    /// Uses CryptographicOperations.FixedTimeEquals (built-in on .NET 5+, polyfill on older frameworks).
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

        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Performs constant-time comparison of two spans to prevent timing attacks.
    /// Uses CryptographicOperations.FixedTimeEquals (built-in on .NET 5+, polyfill on older frameworks).
    /// </summary>
    /// <param name="a">First span to compare</param>
    /// <param name="b">Second span to compare</param>
    /// <returns>True if spans are equal, false otherwise</returns>
    public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Compares two unsigned 16-bit integers in constant time.
    /// </summary>
    /// <param name="a">The first value.</param>
    /// <param name="b">The second value.</param>
    /// <returns>True if the values are equal; otherwise, false.</returns>
    /// <remarks>
    /// This method prevents timing attacks by ensuring the comparison takes
    /// the same amount of time regardless of the values being compared.
    /// </remarks>
    public static bool ConstantTimeEquals(ushort a, ushort b)
    {
        // XOR the values - result is 0 only if equal
        // Then use bitwise operations to check for zero in constant time
        uint diff = (uint)(a ^ b);

        // Propagate any set bit to all lower bits, then check lowest bit
        // This avoids branching on the comparison result
        diff |= diff >> 8;
        diff |= diff >> 4;
        diff |= diff >> 2;
        diff |= diff >> 1;

        return (diff & 1) == 0;
    }

    /// <summary>
    /// Creates a secure copy of sensitive data with automatic cleanup
    /// </summary>
    /// <param name="source">Source data to copy</param>
    /// <returns>Secure wrapper around the copied data</returns>
    public static SecureByteArray CreateSecureCopy(byte[] source)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(source);
#else
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }
#endif

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
/// Secure wrapper for byte arrays that automatically clears memory on disposal.
/// </summary>
/// <remarks>
/// <para>
/// <b>Thread-Safety Guarantees:</b>
/// </para>
/// <para>
/// This class uses internal synchronization to ensure thread-safe access to the underlying data.
/// All public properties and methods acquire a lock before accessing or modifying the data.
/// However, there are important edge cases to consider:
/// </para>
/// <list type="number">
///   <item>
///     <term>Reference Leaking via WithBytes</term>
///     <description>
///       The <see cref="WithBytes(Action{byte[]})"/> and <see cref="WithBytes{T}(Func{byte[], T})"/>
///       methods expose the underlying byte array to the callback. If the callback stores this
///       reference (e.g., in a field or closure), that reference can be accessed outside the lock
///       scope or even after disposal, leading to race conditions or use-after-clear scenarios.
///       <b>Never store the byte array reference passed to callbacks.</b>
///     </description>
///   </item>
///   <item>
///     <term>ToArray Returns Unsecured Copy</term>
///     <description>
///       The <see cref="ToArray"/> method returns a regular byte array that is NOT automatically
///       cleared on disposal. Callers are responsible for securely clearing this copy using
///       <see cref="SecureMemoryOperations.SecureClear(byte[])"/> when finished.
///     </description>
///   </item>
///   <item>
///     <term>Indexer Access Granularity</term>
///     <description>
///       Each indexer access (<c>this[index]</c>) acquires and releases the lock independently.
///       When iterating over the array, prefer using <see cref="WithBytes(Action{byte[]})"/> to
///       hold the lock for the entire operation rather than accessing elements individually.
///     </description>
///   </item>
///   <item>
///     <term>Finalizer Behavior</term>
///     <description>
///       The finalizer acquires the internal lock before clearing data. While this is generally
///       safe (finalizers run on a dedicated GC thread), it means disposal during finalization
///       may briefly block if another thread holds the lock. Always explicitly dispose instances
///       using <c>using</c> statements or <see cref="Dispose"/> rather than relying on finalization.
///     </description>
///   </item>
/// </list>
/// <para>
/// <b>Cross-Framework Compatibility:</b>
/// </para>
/// <para>
/// On .NET 9 and later, this class uses the new <c>System.Threading.Lock</c> type for improved
/// performance. On earlier frameworks (.NET Standard 2.0, .NET 6/7/8), it uses <c>Monitor</c>-based
/// locking via the internal <c>LockReleaser</c> helper class. Both mechanisms provide equivalent
/// thread-safety guarantees.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Correct usage - lock held for entire operation
/// using var secure = SecureMemoryOperations.CreateSecureCopy(sensitiveData);
/// secure.WithBytes(bytes =>
/// {
///     // Work with bytes here - lock is held
///     ProcessSensitiveData(bytes);
/// });
/// // Data is automatically cleared when secure is disposed
///
/// // INCORRECT - storing reference leads to race conditions
/// byte[]? leakedReference = null;
/// secure.WithBytes(bytes =>
/// {
///     leakedReference = bytes; // DON'T DO THIS!
/// });
/// // leakedReference can now be accessed without synchronization
/// </code>
/// </example>
public sealed class SecureByteArray : IDisposable
{
    private byte[] data;
    private bool disposed;
#if NET9_0_OR_GREATER
    private readonly Lock syncLock = new();
#else
    private readonly object @lock = new();
#endif

#if NET9_0_OR_GREATER
    private LockScope EnterLock() => syncLock.EnterScope();
#else
    private LockReleaser EnterLock() => new(@lock);
#endif

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

        data = new byte[length];
    }

    /// <summary>
    /// Initializes a new secure byte array with a copy of the provided data
    /// </summary>
    /// <param name="source">Source data to copy</param>
    public SecureByteArray(byte[] source)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(source);
#else
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }
#endif

        data = new byte[source.Length];
        Array.Copy(source, data, source.Length);
    }

    /// <summary>
    /// Gets the length of the secure array
    /// </summary>
    public int Length
    {
        get
        {
            using var guard = EnterLock();
            ThrowIfDisposed();
            return data.Length;
        }
    }

    /// <summary>
    /// Gets or sets a byte at the specified index.
    /// </summary>
    /// <param name="index">Index to access.</param>
    /// <remarks>
    /// <para>
    /// <b>PERFORMANCE NOTE:</b> Each indexer access acquires and releases the lock independently.
    /// For bulk operations or iterations, use <see cref="WithBytes(Action{byte[]})"/> to hold
    /// the lock for the entire operation, which is both more efficient and provides consistent
    /// snapshot semantics.
    /// </para>
    /// </remarks>
    public byte this[int index]
    {
        get
        {
            using var guard = EnterLock();
            ThrowIfDisposed();
            return data[index];
        }
        set
        {
            using var guard = EnterLock();
            ThrowIfDisposed();
            data[index] = value;
        }
    }

    /// <summary>
    /// Executes an action with access to the underlying byte array.
    /// </summary>
    /// <param name="action">Action to execute with the byte array.</param>
    /// <remarks>
    /// <para>
    /// <b>SECURITY WARNING:</b> The lock is only held during the callback execution.
    /// <b>Never store the byte array reference</b> passed to the callback, as this would
    /// allow unsynchronized access and potential use-after-clear vulnerabilities.
    /// </para>
    /// </remarks>
    public void WithBytes(Action<byte[]> action)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(action);
#else
        if (action == null)
        {
            throw new ArgumentNullException(nameof(action));
        }
#endif

        using var guard = EnterLock();
        ThrowIfDisposed();
        action(data);
    }

    /// <summary>
    /// Executes a function with access to the underlying byte array and returns a result.
    /// </summary>
    /// <typeparam name="T">Return type.</typeparam>
    /// <param name="func">Function to execute with the byte array.</param>
    /// <returns>Result of the function.</returns>
    /// <remarks>
    /// <para>
    /// <b>SECURITY WARNING:</b> The lock is only held during the callback execution.
    /// <b>Never store the byte array reference</b> passed to the callback, as this would
    /// allow unsynchronized access and potential use-after-clear vulnerabilities.
    /// </para>
    /// <para>
    /// If the return type <typeparamref name="T"/> is <c>byte[]</c>, ensure you securely clear
    /// the returned data when finished, as it will not be automatically cleared.
    /// </para>
    /// </remarks>
    public T WithBytes<T>(Func<byte[], T> func)
    {
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(func);
#else
        if (func == null)
        {
            throw new ArgumentNullException(nameof(func));
        }
#endif

        using var guard = EnterLock();
        ThrowIfDisposed();
        return func(data);
    }

    /// <summary>
    /// Creates a copy of the secure array data.
    /// </summary>
    /// <returns>Copy of the array data.</returns>
    /// <remarks>
    /// <para>
    /// <b>SECURITY WARNING:</b> The returned array is a regular <c>byte[]</c> that is
    /// <b>NOT automatically cleared</b> when this <see cref="SecureByteArray"/> is disposed.
    /// </para>
    /// <para>
    /// Callers are responsible for securely clearing the returned copy when finished:
    /// </para>
    /// <code>
    /// byte[] copy = secureArray.ToArray();
    /// try
    /// {
    ///     // Use the copy
    /// }
    /// finally
    /// {
    ///     SecureMemoryOperations.SecureClear(copy);
    /// }
    /// </code>
    /// </remarks>
    public byte[] ToArray()
    {
        using var guard = EnterLock();
        ThrowIfDisposed();
        var copy = new byte[data.Length];
        Array.Copy(data, copy, data.Length);
        return copy;
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
#if !NETSTANDARD2_0
        ArgumentNullException.ThrowIfNull(source);
#else
        if (source == null)
        {
            throw new ArgumentNullException(nameof(source));
        }
#endif

        var copyLength = length ?? source.Length;

        using var guard = EnterLock();
        ThrowIfDisposed();
        Array.Copy(source, sourceIndex, data, destinationIndex, copyLength);
    }

    /// <summary>
    /// Disposes the secure array and clears all sensitive data
    /// </summary>
    public void Dispose()
    {
        using var guard = EnterLock();
        if (!disposed && data != null)
        {
            SecureMemoryOperations.SecureClear(data);
            data = null!;
            disposed = true;
        }

        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed()
    {
#if !NETSTANDARD2_0
        ObjectDisposedException.ThrowIf(disposed, nameof(SecureByteArray));
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(SecureByteArray));
        }
#endif
    }

    /// <summary>
    /// Finalizer to ensure secure cleanup
    /// </summary>
    ~SecureByteArray()
    {
        Dispose();
    }
}
