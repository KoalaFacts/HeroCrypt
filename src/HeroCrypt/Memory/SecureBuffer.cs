using System.Runtime.InteropServices;

namespace HeroCrypt.Memory;

/// <summary>
/// Secure buffer that ensures cryptographic material is properly handled in memory
/// </summary>
public sealed class SecureBuffer : IDisposable
{
    private IntPtr _handle;
    private readonly int _size;
    private bool _disposed;
    private readonly object _lock = new();

    /// <summary>
    /// Size of the secure buffer in bytes
    /// </summary>
    public int Size => _size;

    /// <summary>
    /// Whether the buffer has been disposed
    /// </summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Creates a new secure buffer with the specified size
    /// </summary>
    /// <param name="size">Size in bytes</param>
    public SecureBuffer(int size)
    {
        if (size <= 0)
            throw new ArgumentException("Size must be positive", nameof(size));

        _size = size;
        _handle = AllocateSecureMemory(size);
    }

    /// <summary>
    /// Creates a secure buffer from existing data
    /// </summary>
    /// <param name="data">Data to copy into secure buffer</param>
    public SecureBuffer(byte[] data) : this(data?.Length ?? throw new ArgumentNullException(nameof(data)))
    {
        CopyFromArray(data);
    }

    /// <summary>
    /// Creates a secure buffer from a span
    /// </summary>
    /// <param name="data">Data to copy into secure buffer</param>
    public SecureBuffer(ReadOnlySpan<byte> data) : this(data.Length)
    {
        CopyFromSpan(data);
    }

    /// <summary>
    /// Gets a span view of the secure buffer
    /// </summary>
    /// <returns>Span of the buffer contents</returns>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public unsafe Span<byte> AsSpan()
    {
        ThrowIfDisposed();
        lock (_lock)
        {
            return new Span<byte>(_handle.ToPointer(), _size);
        }
    }

    /// <summary>
    /// Gets a read-only span view of the secure buffer
    /// </summary>
    /// <returns>Read-only span of the buffer contents</returns>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public unsafe ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ThrowIfDisposed();
        lock (_lock)
        {
            return new ReadOnlySpan<byte>(_handle.ToPointer(), _size);
        }
    }

    /// <summary>
    /// Copies data from this secure buffer to a byte array
    /// </summary>
    /// <returns>Copy of buffer contents</returns>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public byte[] ToArray()
    {
        ThrowIfDisposed();
        var result = new byte[_size];
        AsReadOnlySpan().CopyTo(result);
        return result;
    }

    /// <summary>
    /// Copies data from a byte array into this secure buffer
    /// </summary>
    /// <param name="source">Source array</param>
    /// <exception cref="ArgumentException">Array size doesn't match buffer size</exception>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public void CopyFromArray(byte[] source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        if (source.Length != _size)
            throw new ArgumentException($"Source array size ({source.Length}) doesn't match buffer size ({_size})", nameof(source));

        ThrowIfDisposed();
        source.AsSpan().CopyTo(AsSpan());
    }

    /// <summary>
    /// Copies data from a span into this secure buffer
    /// </summary>
    /// <param name="source">Source span</param>
    /// <exception cref="ArgumentException">Span size doesn't match buffer size</exception>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public void CopyFromSpan(ReadOnlySpan<byte> source)
    {
        if (source.Length != _size)
            throw new ArgumentException($"Source span size ({source.Length}) doesn't match buffer size ({_size})", nameof(source));

        ThrowIfDisposed();
        source.CopyTo(AsSpan());
    }

    /// <summary>
    /// Fills the entire buffer with a specific byte value
    /// </summary>
    /// <param name="value">Byte value to fill with</param>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public void Fill(byte value)
    {
        ThrowIfDisposed();
        AsSpan().Fill(value);
    }

    /// <summary>
    /// Clears the buffer (fills with zeros)
    /// </summary>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public void Clear()
    {
        if (!_disposed)
        {
            Fill(0);
        }
    }

    /// <summary>
    /// Performs a constant-time comparison with another secure buffer
    /// </summary>
    /// <param name="other">Buffer to compare with</param>
    /// <returns>True if buffers are equal</returns>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public bool ConstantTimeEquals(SecureBuffer other)
    {
        if (other == null)
            return false;

        ThrowIfDisposed();
        other.ThrowIfDisposed();

        if (_size != other._size)
            return false;

        return ConstantTimeEquals(AsReadOnlySpan(), other.AsReadOnlySpan());
    }

    /// <summary>
    /// Performs a constant-time comparison with a byte array
    /// </summary>
    /// <param name="other">Array to compare with</param>
    /// <returns>True if contents are equal</returns>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public bool ConstantTimeEquals(byte[] other)
    {
        if (other == null)
            return false;

        ThrowIfDisposed();

        if (_size != other.Length)
            return false;

        return ConstantTimeEquals(AsReadOnlySpan(), other.AsSpan());
    }

    /// <summary>
    /// Creates a copy of this secure buffer
    /// </summary>
    /// <returns>New secure buffer with copied contents</returns>
    /// <exception cref="ObjectDisposedException">Buffer has been disposed</exception>
    public SecureBuffer Clone()
    {
        ThrowIfDisposed();
        return new SecureBuffer(AsReadOnlySpan());
    }

    /// <summary>
    /// Disposes the secure buffer and clears memory
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            lock (_lock)
            {
                if (!_disposed)
                {
                    // Multiple-pass secure cleanup
                    SecureZeroMemory(_handle, _size);

                    if (_handle != IntPtr.Zero)
                    {
                        FreeSecureMemory(_handle);
                        _handle = IntPtr.Zero;
                    }

                    _disposed = true;
                }
            }
        }
    }

    /// <summary>
    /// Finalizer to ensure cleanup
    /// </summary>
    ~SecureBuffer()
    {
        Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(SecureBuffer));
    }

    private static unsafe IntPtr AllocateSecureMemory(int size)
    {
        // Allocate memory that won't be paged to disk
        IntPtr ptr;

#if NET5_0_OR_GREATER
        unsafe
        {
            ptr = (IntPtr)NativeMemory.AlignedAlloc((nuint)size, (nuint)IntPtr.Size);
        }
#else
        ptr = Marshal.AllocHGlobal(size);
#endif

        if (ptr == IntPtr.Zero)
            throw new OutOfMemoryException("Failed to allocate secure memory");

        try
        {
            // Lock memory to prevent paging (best effort)
            VirtualLock(ptr, (nuint)size);
        }
        catch
        {
            // Ignore if VirtualLock fails - not critical
        }

        // Initialize with random data first, then clear
        var randomBytes = new byte[size];
#if NETSTANDARD2_0
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
#else
        System.Security.Cryptography.RandomNumberGenerator.Fill(randomBytes);
#endif
        Marshal.Copy(randomBytes, 0, ptr, size);

        // Clear the random data
        ZeroMemory(ptr, size);

        // Clear the temporary array
        Array.Clear(randomBytes, 0, randomBytes.Length);

        return ptr;
    }

    private static void FreeSecureMemory(IntPtr ptr)
    {
        if (ptr != IntPtr.Zero)
        {
            try
            {
                // Unlock memory
                VirtualUnlock(ptr, 0);
            }
            catch
            {
                // Ignore unlock failures
            }

#if NET5_0_OR_GREATER
            unsafe
            {
                NativeMemory.AlignedFree(ptr.ToPointer());
            }
#else
            Marshal.FreeHGlobal(ptr);
#endif
        }
    }

    private static void SecureZeroMemory(IntPtr ptr, int size)
    {
        if (ptr == IntPtr.Zero || size <= 0)
            return;

        // Multiple-pass secure cleanup to defeat forensic recovery
        var patterns = new byte[] { 0x00, 0xFF, 0xAA, 0x55, 0x00 };

        foreach (var pattern in patterns)
        {
            FillMemory(ptr, size, pattern);
        }
    }

    private static void ZeroMemory(IntPtr ptr, int size)
    {
        if (ptr == IntPtr.Zero || size <= 0)
            return;

        FillMemory(ptr, size, 0);
    }

    private static unsafe void FillMemory(IntPtr ptr, int size, byte value)
    {
        var span = new Span<byte>(ptr.ToPointer(), size);
        span.Fill(value);
    }

    private static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
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

    // P/Invoke declarations for memory locking (Windows)
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualLock(IntPtr lpAddress, nuint dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, nuint dwSize);
}