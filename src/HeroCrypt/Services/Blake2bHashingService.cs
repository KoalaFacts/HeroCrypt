using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Blake2b;
using Microsoft.Extensions.Logging;
using System.Runtime.CompilerServices;

namespace HeroCrypt.Services;

/// <summary>
/// Service implementation for Blake2b hashing operations.
/// </summary>
public class Blake2bHashingService : IBlake2bService
{
    private readonly ILogger<Blake2bHashingService>? _logger;

    /// <summary>
    /// Initializes a new instance of the Blake2bHashingService.
    /// </summary>
    /// <param name="logger">Optional logger for operation tracking.</param>
    public Blake2bHashingService(
        ILogger<Blake2bHashingService>? logger = null)
    {
        _logger = logger;
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

        _logger?.LogDebug("Computing Blake2b hash with output length {OutputLength} bytes", outputLength);

        try
        {
            var result = Blake2bCore.ComputeHash(data, outputLength, key, salt, personalization);
            _logger?.LogDebug("Blake2b hash computed successfully");
            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to compute Blake2b hash");
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

        _logger?.LogDebug("Computing Blake2b long hash with output length {OutputLength} bytes", outputLength);

        try
        {
            var result = Blake2bCore.ComputeLongHash(data, outputLength);
            _logger?.LogDebug("Blake2b long hash computed successfully");
            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to compute Blake2b long hash");
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

        _logger?.LogDebug("Verifying Blake2b hash");

        var actualHash = ComputeHash(data, expectedHash.Length, key);
        var result = ConstantTimeEquals(actualHash, expectedHash);

        if (result)
        {
            _logger?.LogDebug("Blake2b hash verification succeeded");
        }
        else
        {
            _logger?.LogWarning("Blake2b hash verification failed");
        }

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