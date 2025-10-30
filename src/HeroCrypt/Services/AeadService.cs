using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Symmetric.ChaCha20Poly1305;
using HeroCrypt.Cryptography.Symmetric.XChaCha20Poly1305;
using HeroCrypt.Cryptography.Symmetric.AesCcm;
using HeroCrypt.Cryptography.Symmetric.AesSiv;
using HeroCrypt.Security;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Security.Cryptography;

namespace HeroCrypt.Services;

/// <summary>
/// High-performance AEAD (Authenticated Encryption with Associated Data) service
/// Supports ChaCha20-Poly1305, AES-GCM, and XChaCha20-Poly1305
/// </summary>
public class AeadService : IAeadService
{
    private readonly ILogger<AeadService>? _logger;
    private readonly RandomNumberGenerator _rng;

    /// <summary>
    /// Initializes a new instance of the AeadService
    /// </summary>
    /// <param name="logger">Optional logger for operation tracking</param>
    public AeadService(ILogger<AeadService>? logger = null)
    {
        _logger = logger;
        _rng = RandomNumberGenerator.Create();
    }

    /// <inheritdoc/>
    public async Task<byte[]> EncryptAsync(
        byte[] plaintext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        CancellationToken cancellationToken = default)
    {
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (nonce == null)
            throw new ArgumentNullException(nameof(nonce));

        InputValidator.ValidateByteArray(plaintext, nameof(plaintext), allowEmpty: true);
        InputValidator.ValidateByteArray(key, nameof(key));
        InputValidator.ValidateByteArray(nonce, nameof(nonce));

        if (associatedData != null)
            InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);

        ValidateKeyAndNonceSize(key, nonce, algorithm);

        _logger?.LogDebug("Encrypting {PlaintextSize} bytes using {Algorithm}",
            plaintext.Length, algorithm);

        var stopwatch = Stopwatch.StartNew();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result = await Task.Run(() =>
            {
                var ciphertext = new byte[plaintext.Length + GetTagSize(algorithm)];
                var actualLength = EncryptCore(ciphertext, plaintext, key, nonce, associatedData ?? Array.Empty<byte>(), algorithm);

                if (actualLength != ciphertext.Length)
                {
                    Array.Resize(ref ciphertext, actualLength);
                }

                return ciphertext;
            }, cancellationToken);

            stopwatch.Stop();

            _logger?.LogDebug("Successfully encrypted {PlaintextSize} bytes to {CiphertextSize} bytes using {Algorithm} in {Duration}ms",
                plaintext.Length, result.Length, algorithm, stopwatch.Elapsed.TotalMilliseconds);

            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to encrypt using {Algorithm}", algorithm);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]> DecryptAsync(
        byte[] ciphertext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        CancellationToken cancellationToken = default)
    {
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (nonce == null)
            throw new ArgumentNullException(nameof(nonce));

        InputValidator.ValidateByteArray(ciphertext, nameof(ciphertext));
        InputValidator.ValidateByteArray(key, nameof(key));
        InputValidator.ValidateByteArray(nonce, nameof(nonce));

        if (associatedData != null)
            InputValidator.ValidateByteArray(associatedData, nameof(associatedData), allowEmpty: true);

        ValidateKeyAndNonceSize(key, nonce, algorithm);

        if (ciphertext.Length < GetTagSize(algorithm))
            throw new ArgumentException("Ciphertext too short", nameof(ciphertext));

        _logger?.LogDebug("Decrypting {CiphertextSize} bytes using {Algorithm}",
            ciphertext.Length, algorithm);

        var stopwatch = Stopwatch.StartNew();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result = await Task.Run(() =>
            {
                var maxPlaintextLength = ciphertext.Length - GetTagSize(algorithm);
                var plaintext = new byte[maxPlaintextLength];

                var actualLength = DecryptCore(plaintext, ciphertext, key, nonce, associatedData ?? Array.Empty<byte>(), algorithm);

                if (actualLength == -1)
                {
                    throw new UnauthorizedAccessException("Authentication failed - ciphertext has been tampered with");
                }

                if (actualLength != plaintext.Length)
                {
                    Array.Resize(ref plaintext, actualLength);
                }

                return plaintext;
            }, cancellationToken);

            stopwatch.Stop();

            _logger?.LogDebug("Successfully decrypted {CiphertextSize} bytes to {PlaintextSize} bytes using {Algorithm} in {Duration}ms",
                ciphertext.Length, result.Length, algorithm, stopwatch.Elapsed.TotalMilliseconds);

            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to decrypt using {Algorithm}", algorithm);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task EncryptStreamAsync(
        Stream plaintext,
        Stream ciphertext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        int chunkSize = 64 * 1024,
        CancellationToken cancellationToken = default)
    {
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (nonce == null)
            throw new ArgumentNullException(nameof(nonce));

        ValidateKeyAndNonceSize(key, nonce, algorithm);

        if (chunkSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be positive");

        _logger?.LogDebug("Starting stream encryption using {Algorithm} with {ChunkSize} byte chunks",
            algorithm, chunkSize);

        var stopwatch = Stopwatch.StartNew();
        var totalBytesProcessed = 0L;
        var chunkCounter = 0;

        try
        {
            var buffer = new byte[chunkSize];
            var outputBuffer = new byte[chunkSize + GetTagSize(algorithm)];

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesRead = await plaintext.ReadAsync(buffer, 0, chunkSize, cancellationToken);
                if (bytesRead == 0)
                    break;

                // Create chunk-specific nonce by combining original nonce with chunk counter
                var chunkNonce = CreateChunkNonce(nonce, chunkCounter, algorithm);

                // Create chunk-specific associated data
                var chunkAssociatedData = CreateChunkAssociatedData(associatedData, chunkCounter, bytesRead == chunkSize);

                // Encrypt chunk
                var chunkInput = buffer.AsSpan(0, bytesRead);
                var chunkOutput = outputBuffer.AsSpan();

                var encryptedLength = EncryptCore(chunkOutput, chunkInput, key, chunkNonce, chunkAssociatedData, algorithm);

                // Write encrypted chunk
                await ciphertext.WriteAsync(outputBuffer, 0, encryptedLength, cancellationToken);

                totalBytesProcessed += bytesRead;
                chunkCounter++;

                // Clear sensitive data
                SecureMemoryOperations.SecureClear(chunkNonce);
            }

            stopwatch.Stop();

            _logger?.LogDebug("Successfully encrypted {TotalBytes} bytes in {ChunkCount} chunks using {Algorithm} in {Duration}ms",
                totalBytesProcessed, chunkCounter, algorithm, stopwatch.Elapsed.TotalMilliseconds);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to encrypt stream using {Algorithm}", algorithm);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task DecryptStreamAsync(
        Stream ciphertext,
        Stream plaintext,
        byte[] key,
        byte[] nonce,
        byte[]? associatedData = null,
        AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305,
        int chunkSize = 64 * 1024,
        CancellationToken cancellationToken = default)
    {
        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));
        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));
        if (key == null)
            throw new ArgumentNullException(nameof(key));
        if (nonce == null)
            throw new ArgumentNullException(nameof(nonce));

        ValidateKeyAndNonceSize(key, nonce, algorithm);

        if (chunkSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be positive");

        _logger?.LogDebug("Starting stream decryption using {Algorithm} with {ChunkSize} byte chunks",
            algorithm, chunkSize);

        var stopwatch = Stopwatch.StartNew();
        var totalBytesProcessed = 0L;
        var chunkCounter = 0;

        try
        {
            var encryptedChunkSize = chunkSize + GetTagSize(algorithm);
            var buffer = new byte[encryptedChunkSize];
            var outputBuffer = new byte[chunkSize];

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesRead = await ciphertext.ReadAsync(buffer, 0, encryptedChunkSize, cancellationToken);
                if (bytesRead == 0)
                    break;

                if (bytesRead < GetTagSize(algorithm))
                    throw new InvalidDataException("Incomplete encrypted chunk");

                // Create chunk-specific nonce
                var chunkNonce = CreateChunkNonce(nonce, chunkCounter, algorithm);

                // Determine if this is the last chunk
                var isLastChunk = bytesRead < encryptedChunkSize;
                var expectedPlaintextSize = bytesRead - GetTagSize(algorithm);

                // Create chunk-specific associated data
                var chunkAssociatedData = CreateChunkAssociatedData(associatedData, chunkCounter, !isLastChunk);

                // Decrypt chunk
                var chunkInput = buffer.AsSpan(0, bytesRead);
                var chunkOutput = outputBuffer.AsSpan(0, expectedPlaintextSize);

                var decryptedLength = DecryptCore(chunkOutput, chunkInput, key, chunkNonce, chunkAssociatedData, algorithm);

                if (decryptedLength == -1)
                {
                    throw new UnauthorizedAccessException($"Authentication failed for chunk {chunkCounter}");
                }

                // Write decrypted chunk
                await plaintext.WriteAsync(outputBuffer, 0, decryptedLength, cancellationToken);

                totalBytesProcessed += decryptedLength;
                chunkCounter++;

                // Clear sensitive data
                SecureMemoryOperations.SecureClear(chunkNonce);

                if (isLastChunk)
                    break;
            }

            stopwatch.Stop();

            _logger?.LogDebug("Successfully decrypted {TotalBytes} bytes in {ChunkCount} chunks using {Algorithm} in {Duration}ms",
                totalBytesProcessed, chunkCounter, algorithm, stopwatch.Elapsed.TotalMilliseconds);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to decrypt stream using {Algorithm}", algorithm);
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] GenerateKey(AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305)
    {
        var keySize = GetKeySize(algorithm);
        var key = new byte[keySize];
        _rng.GetBytes(key);

        _logger?.LogDebug("Generated {KeySize}-byte key for {Algorithm}", keySize, algorithm);

        return key;
    }

    /// <inheritdoc/>
    public byte[] GenerateNonce(AeadAlgorithm algorithm = AeadAlgorithm.ChaCha20Poly1305)
    {
        var nonceSize = GetNonceSize(algorithm);
        var nonce = new byte[nonceSize];
        _rng.GetBytes(nonce);

        _logger?.LogDebug("Generated {NonceSize}-byte nonce for {Algorithm}", nonceSize, algorithm);

        return nonce;
    }

    /// <inheritdoc/>
    public int GetKeySize(AeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            AeadAlgorithm.ChaCha20Poly1305 => ChaCha20Poly1305Core.KeySize,
            AeadAlgorithm.XChaCha20Poly1305 => XChaCha20Poly1305Core.KeySize,
            AeadAlgorithm.Aes128Gcm => 16, // AES-128 key size
            AeadAlgorithm.Aes256Gcm => 32, // AES-256 key size
            AeadAlgorithm.Aes128Ccm => 16, // AES-128 key size
            AeadAlgorithm.Aes256Ccm => 32, // AES-256 key size
            AeadAlgorithm.Aes256Siv => 64, // AES-SIV-256 (32+32 for MAC+CTR)
            AeadAlgorithm.Aes512Siv => 128, // AES-SIV-512 (64+64 for MAC+CTR)
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <inheritdoc/>
    public int GetNonceSize(AeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            AeadAlgorithm.ChaCha20Poly1305 => ChaCha20Poly1305Core.NonceSize,
            AeadAlgorithm.XChaCha20Poly1305 => XChaCha20Poly1305Core.NonceSize,
            AeadAlgorithm.Aes128Gcm => 12, // AES-GCM nonce size
            AeadAlgorithm.Aes256Gcm => 12, // AES-GCM nonce size
            AeadAlgorithm.Aes128Ccm => AesCcmCore.DefaultNonceSize, // AES-CCM default nonce size
            AeadAlgorithm.Aes256Ccm => AesCcmCore.DefaultNonceSize, // AES-CCM default nonce size
            AeadAlgorithm.Aes256Siv => 12, // AES-SIV default (can be any length)
            AeadAlgorithm.Aes512Siv => 12, // AES-SIV default (can be any length)
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <inheritdoc/>
    public int GetTagSize(AeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            AeadAlgorithm.ChaCha20Poly1305 => ChaCha20Poly1305Core.TagSize,
            AeadAlgorithm.XChaCha20Poly1305 => XChaCha20Poly1305Core.TagSize,
            AeadAlgorithm.Aes128Gcm => 16, // AES-GCM tag size
            AeadAlgorithm.Aes256Gcm => 16, // AES-GCM tag size
            AeadAlgorithm.Aes128Ccm => AesCcmCore.DefaultTagSize, // AES-CCM default tag size
            AeadAlgorithm.Aes256Ccm => AesCcmCore.DefaultTagSize, // AES-CCM default tag size
            AeadAlgorithm.Aes256Siv => AesSivCore.SivSize, // AES-SIV tag (SIV) size
            AeadAlgorithm.Aes512Siv => AesSivCore.SivSize, // AES-SIV tag (SIV) size
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Core encryption method
    /// </summary>
    private static int EncryptCore(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, AeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            AeadAlgorithm.ChaCha20Poly1305 => ChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.XChaCha20Poly1305 => XChaCha20Poly1305Core.Encrypt(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.Aes128Gcm => EncryptAesGcm(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.Aes256Gcm => EncryptAesGcm(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.Aes128Ccm => AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.Aes256Ccm => AesCcmCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.Aes256Siv => AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData),
            AeadAlgorithm.Aes512Siv => AesSivCore.Encrypt(ciphertext, plaintext, key, nonce, associatedData),
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Core decryption method
    /// </summary>
    private static int DecryptCore(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, AeadAlgorithm algorithm)
    {
        return algorithm switch
        {
            AeadAlgorithm.ChaCha20Poly1305 => ChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.XChaCha20Poly1305 => XChaCha20Poly1305Core.Decrypt(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.Aes128Gcm => DecryptAesGcm(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.Aes256Gcm => DecryptAesGcm(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.Aes128Ccm => AesCcmCore.Decrypt(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.Aes256Ccm => AesCcmCore.Decrypt(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.Aes256Siv => AesSivCore.Decrypt(plaintext, ciphertext, key, nonce, associatedData),
            AeadAlgorithm.Aes512Siv => AesSivCore.Decrypt(plaintext, ciphertext, key, nonce, associatedData),
            _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported")
        };
    }

    /// <summary>
    /// Creates a chunk-specific nonce for streaming
    /// </summary>
    private static byte[] CreateChunkNonce(ReadOnlySpan<byte> baseNonce, int chunkCounter, AeadAlgorithm algorithm)
    {
        var nonce = new byte[baseNonce.Length];
        baseNonce.CopyTo(nonce);

        // XOR the last 4 bytes with the chunk counter for uniqueness
        var counterBytes = BitConverter.GetBytes(chunkCounter);
        for (var i = 0; i < 4 && i < nonce.Length; i++)
        {
            nonce[nonce.Length - 4 + i] ^= counterBytes[i];
        }

        return nonce;
    }

    /// <summary>
    /// Creates chunk-specific associated data for streaming
    /// </summary>
    private static byte[] CreateChunkAssociatedData(byte[]? baseAssociatedData, int chunkCounter, bool isFullChunk)
    {
        var counterBytes = BitConverter.GetBytes(chunkCounter);
        var flagByte = isFullChunk ? (byte)0x01 : (byte)0x00;

        if (baseAssociatedData == null || baseAssociatedData.Length == 0)
        {
            var result = new byte[5];
            counterBytes.CopyTo(result, 0);
            result[4] = flagByte;
            return result;
        }
        else
        {
            var result = new byte[baseAssociatedData.Length + 5];
            baseAssociatedData.CopyTo(result, 0);
            counterBytes.CopyTo(result, baseAssociatedData.Length);
            result[result.Length - 1] = flagByte;
            return result;
        }
    }

    /// <summary>
    /// Validates key and nonce sizes for the specified algorithm
    /// </summary>
    private void ValidateKeyAndNonceSize(byte[] key, byte[] nonce, AeadAlgorithm algorithm)
    {
        var expectedKeySize = GetKeySize(algorithm);
        var expectedNonceSize = GetNonceSize(algorithm);

        if (key.Length != expectedKeySize)
            throw new ArgumentException($"Key must be {expectedKeySize} bytes for {algorithm}", nameof(key));
        if (nonce.Length != expectedNonceSize)
            throw new ArgumentException($"Nonce must be {expectedNonceSize} bytes for {algorithm}", nameof(nonce));
    }

    private static int EncryptAesGcm(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
#if NET7_0_OR_GREATER
        const int TagSizeInBytes = 16;
        using var aes = new AesGcm(key, TagSizeInBytes);
        var tag = ciphertext.Slice(plaintext.Length, TagSizeInBytes);
        var actualCiphertext = ciphertext.Slice(0, plaintext.Length);

        aes.Encrypt(nonce, plaintext, actualCiphertext, tag, associatedData);

        return plaintext.Length + 16; // Include tag length
#elif NET6_0_OR_GREATER
        const int TagSizeInBytes = 16;
#pragma warning disable SYSLIB0053 // AesGcm single-argument constructor is obsolete in .NET 7+
        using var aes = new AesGcm(key);
#pragma warning restore SYSLIB0053
        var tag = ciphertext.Slice(plaintext.Length, TagSizeInBytes);
        var actualCiphertext = ciphertext.Slice(0, plaintext.Length);

        aes.Encrypt(nonce, plaintext, actualCiphertext, tag, associatedData);

        return plaintext.Length + 16; // Include tag length
#else
        throw new NotSupportedException("AES-GCM requires .NET 6 or higher");
#endif
    }

    private static int DecryptAesGcm(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
#if NET7_0_OR_GREATER
        const int TagSizeInBytes = 16;
        using var aes = new AesGcm(key, TagSizeInBytes);
        var tag = ciphertext.Slice(ciphertext.Length - TagSizeInBytes, TagSizeInBytes);
        var actualCiphertext = ciphertext.Slice(0, ciphertext.Length - 16);

        try
        {
            aes.Decrypt(nonce, actualCiphertext, tag, plaintext, associatedData);
        }
#elif NET6_0_OR_GREATER
        const int TagSizeInBytes = 16;
#pragma warning disable SYSLIB0053 // AesGcm single-argument constructor is obsolete in .NET 7+
        using var aes = new AesGcm(key);
#pragma warning restore SYSLIB0053
        var tag = ciphertext.Slice(ciphertext.Length - TagSizeInBytes, TagSizeInBytes);
        var actualCiphertext = ciphertext.Slice(0, ciphertext.Length - 16);

        try
        {
            aes.Decrypt(nonce, actualCiphertext, tag, plaintext, associatedData);
        }
        catch (CryptographicException ex)
        {
            throw new UnauthorizedAccessException("Authentication failed: invalid ciphertext, key, nonce, or associated data", ex);
        }

        return actualCiphertext.Length;
#else
        throw new NotSupportedException("AES-GCM requires .NET 6 or higher");
#endif
    }

    /// <summary>
    /// Disposes the service and clears sensitive data
    /// </summary>
    public void Dispose()
    {
        _rng?.Dispose();
    }
}