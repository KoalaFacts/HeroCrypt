using HeroCrypt.Cryptography.Primitives.Hash;
using System.Runtime.CompilerServices;

namespace HeroCrypt.Hashing;

/// <summary>
/// Service implementation for Blake2b hashing operations.
/// </summary>
public class Blake2bHashingService : IBlake2bService
{
    /// <summary>
    /// Initializes a new instance of the Blake2bHashingService.
    /// </summary>
    public Blake2bHashingService()
    {
    }

    /// <inheritdoc/>
    public byte[] ComputeHash(
        byte[] data,
        int outputLength = 64,
        byte[]? key = null,
        byte[]? salt = null,
        byte[]? personalization = null)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        try
        {
            var result = Blake2bCore.ComputeHash(data, outputLength, key, salt, personalization);
            return result;
        }
        catch
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> ComputeHashAsync(
        byte[] data,
        int outputLength = 64,
        byte[]? key = null,
        byte[]? salt = null,
        byte[]? personalization = null,
        CancellationToken cancellationToken = default)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        return Task.Run(() => ComputeHash(data, outputLength, key, salt, personalization), cancellationToken);
    }

    /// <inheritdoc/>
    public byte[] ComputeLongHash(byte[] data, int outputLength)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        try
        {
            var result = Blake2bCore.ComputeLongHash(data, outputLength);
            return result;
        }
        catch
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public bool VerifyHash(byte[] data, byte[] expectedHash, byte[]? key = null)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (expectedHash == null)
            throw new ArgumentNullException(nameof(expectedHash));

        var actualHash = ComputeHash(data, expectedHash.Length, key);
        var result = ConstantTimeEquals(actualHash, expectedHash);

        return result;
    }

    /// <summary>
    /// Performs a constant-time comparison of two byte arrays.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static bool ConstantTimeEquals(byte[] a, byte[] b)
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
}
