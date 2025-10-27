using HeroCrypt.Abstractions;
using HeroCrypt.Cryptography.Scrypt;
using HeroCrypt.Security;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using CryptoHashAlgorithmName = System.Security.Cryptography.HashAlgorithmName;
using HeroCryptHashAlgorithmName = HeroCrypt.Abstractions.HashAlgorithmName;

namespace HeroCrypt.Services;

/// <summary>
/// Service implementation for cryptographic key derivation operations.
/// </summary>
public class KeyDerivationService : IKeyDerivationService
{
    private readonly ILogger<KeyDerivationService>? _logger;
    private readonly IBlake2bService? _blake2bService;

    /// <summary>
    /// Initializes a new instance of the KeyDerivationService.
    /// </summary>
    /// <param name="logger">Optional logger for operation tracking.</param>
    /// <param name="blake2bService">Optional Blake2b service for Blake2b-based derivations.</param>
    public KeyDerivationService(
        ILogger<KeyDerivationService>? logger = null,
        IBlake2bService? blake2bService = null)
    {
        _logger = logger;
        _blake2bService = blake2bService;
    }

    /// <inheritdoc/>
    public byte[] DerivePbkdf2(
        byte[] password,
        byte[] salt,
        int iterations,
        int keyLength,
        HeroCryptHashAlgorithmName hashAlgorithm = default)
    {
        InputValidator.ValidatePbkdf2Parameters(password, salt, iterations, keyLength);

        var algorithm = hashAlgorithm == default ? HeroCryptHashAlgorithmName.SHA256 : hashAlgorithm;
        _logger?.LogDebug("Deriving PBKDF2 key with {Algorithm}, {Iterations} iterations, {KeyLength} bytes",
            algorithm.Name, iterations, keyLength);

        try
        {
#if NETSTANDARD2_0
#if NETSTANDARD2_0
#pragma warning disable CA5379 // Rfc2898DeriveBytes constructor with HashAlgorithmName not available in .NET Standard 2.0
#endif
            // For .NET Standard 2.0, use Rfc2898DeriveBytes
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            var result = pbkdf2.GetBytes(keyLength);
#else
            // For newer frameworks, use the static method with hash algorithm selection
            var hashName = algorithm.Name switch
            {
                "SHA256" => CryptoHashAlgorithmName.SHA256,
                "SHA384" => CryptoHashAlgorithmName.SHA384,
                "SHA512" => CryptoHashAlgorithmName.SHA512,
                _ => CryptoHashAlgorithmName.SHA256
            };

            var result = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashName, keyLength);
#endif
            _logger?.LogDebug("PBKDF2 key derivation completed successfully");
            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to derive PBKDF2 key");
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> DerivePbkdf2Async(
        byte[] password,
        byte[] salt,
        int iterations,
        int keyLength,
        HeroCryptHashAlgorithmName hashAlgorithm = default,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => DerivePbkdf2(password, salt, iterations, keyLength, hashAlgorithm), cancellationToken);
    }

    /// <inheritdoc/>
    public byte[] DeriveHkdf(
        byte[] ikm,
        int keyLength,
        byte[]? salt = null,
        byte[]? info = null,
        HeroCryptHashAlgorithmName hashAlgorithm = default)
    {
        InputValidator.ValidateHkdfParameters(ikm, salt ?? Array.Empty<byte>(), info ?? Array.Empty<byte>(), keyLength);

        var algorithm = hashAlgorithm == default ? HeroCryptHashAlgorithmName.SHA256 : hashAlgorithm;
        _logger?.LogDebug("Deriving HKDF key with {Algorithm}, {KeyLength} bytes", algorithm.Name, keyLength);

        try
        {
#if NET5_0_OR_GREATER
            // Use built-in HKDF for .NET 5+
            var hashName = algorithm.Name switch
            {
                "SHA256" => CryptoHashAlgorithmName.SHA256,
                "SHA384" => CryptoHashAlgorithmName.SHA384,
                "SHA512" => CryptoHashAlgorithmName.SHA512,
                _ => CryptoHashAlgorithmName.SHA256
            };

            var result = HKDF.DeriveKey(hashName, ikm, keyLength, salt, info);
#else
            // Manual HKDF implementation for older frameworks
            var result = HkdfManual(ikm, keyLength, salt, info, algorithm);
#endif
            _logger?.LogDebug("HKDF key derivation completed successfully");
            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to derive HKDF key");
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> DeriveHkdfAsync(
        byte[] ikm,
        int keyLength,
        byte[]? salt = null,
        byte[]? info = null,
        HeroCryptHashAlgorithmName hashAlgorithm = default,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => DeriveHkdf(ikm, keyLength, salt, info, hashAlgorithm), cancellationToken);
    }

    /// <inheritdoc/>
    public byte[] DeriveScrypt(
        byte[] password,
        byte[] salt,
        int n,
        int r,
        int p,
        int keyLength)
    {
        InputValidator.ValidateScryptParameters(password, salt, n, r, p, keyLength);

        _logger?.LogDebug("Deriving scrypt key with N={N}, r={R}, p={P}, {KeyLength} bytes", n, r, p, keyLength);

        try
        {
            var result = ScryptCore.DeriveKey(password, salt, n, r, p, keyLength);

            _logger?.LogDebug("Successfully derived scrypt key: {KeyLength} bytes", result.Length);

            return result;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to derive scrypt key");
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] DeriveKey(byte[] masterKey, string context, int keyLength)
    {
        InputValidator.ValidateByteArray(masterKey, nameof(masterKey));
        if (string.IsNullOrEmpty(context))
            throw new ArgumentException("Context cannot be null or empty", nameof(context));
        InputValidator.ValidateArraySize(keyLength, "key derivation");

        _logger?.LogDebug("Deriving key for context '{Context}', {KeyLength} bytes", context, keyLength);

        // Use HKDF with the context as info
        var contextBytes = System.Text.Encoding.UTF8.GetBytes(context);
        return DeriveHkdf(masterKey, keyLength, info: contextBytes);
    }

#if !NET5_0_OR_GREATER
    /// <summary>
    /// Manual HKDF implementation for frameworks that don't have built-in support.
    /// Implements RFC 5869.
    /// </summary>
    private byte[] HkdfManual(byte[] ikm, int length, byte[]? salt, byte[]? info, HeroCryptHashAlgorithmName hashAlgorithm)
    {
        // Select the hash algorithm
        using var hashAlgo = hashAlgorithm.Name switch
        {
            "SHA256" => (HashAlgorithm)SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            "Blake2b" when _blake2bService != null => new Blake2bHashAlgorithm(_blake2bService),
            _ => SHA256.Create()
        };

        var hashLen = hashAlgo.HashSize / 8;

        // Step 1: Extract
        var actualSalt = salt ?? new byte[hashLen];
        using var hmacExtract = new HMACSHA256(actualSalt);

        if (hashAlgorithm.Name == "SHA384")
        {
            hmacExtract.Dispose();
            using var hmac384 = new HMACSHA384(actualSalt);
            var prk = hmac384.ComputeHash(ikm);
            return HkdfExpand(prk, info ?? Array.Empty<byte>(), length, hashAlgorithm);
        }
        else if (hashAlgorithm.Name == "SHA512")
        {
            hmacExtract.Dispose();
            using var hmac512 = new HMACSHA512(actualSalt);
            var prk = hmac512.ComputeHash(ikm);
            return HkdfExpand(prk, info ?? Array.Empty<byte>(), length, hashAlgorithm);
        }
        else
        {
            var prk = hmacExtract.ComputeHash(ikm);
            return HkdfExpand(prk, info ?? Array.Empty<byte>(), length, hashAlgorithm);
        }
    }

    /// <summary>
    /// HKDF-Expand function (RFC 5869).
    /// </summary>
    private byte[] HkdfExpand(byte[] prk, byte[] info, int length, HeroCryptHashAlgorithmName hashAlgorithm)
    {
        HMAC hmac = hashAlgorithm.Name switch
        {
            "SHA384" => new HMACSHA384(prk),
            "SHA512" => new HMACSHA512(prk),
            _ => new HMACSHA256(prk)
        };

        using (hmac)
        {
            var hashLen = hmac.HashSize / 8;
            var n = (length + hashLen - 1) / hashLen;

            if (n > 255)
                throw new ArgumentException("Output length too large");

            var okm = new byte[length];
            var okmOffset = 0;
            var t = Array.Empty<byte>();

            for (byte i = 1; i <= n; i++)
            {
                var input = new byte[t.Length + info.Length + 1];
                Array.Copy(t, 0, input, 0, t.Length);
                Array.Copy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = i;

                t = hmac.ComputeHash(input);

                var copyLen = Math.Min(hashLen, length - okmOffset);
                Array.Copy(t, 0, okm, okmOffset, copyLen);
                okmOffset += copyLen;
            }

            return okm;
        }
    }

    /// <summary>
    /// Blake2b wrapper for HashAlgorithm compatibility.
    /// </summary>
    private sealed class Blake2bHashAlgorithm : HashAlgorithm
    {
        private readonly IBlake2bService _blake2bService;
        private readonly MemoryStream _buffer = new();

        public Blake2bHashAlgorithm(IBlake2bService blake2bService)
        {
            _blake2bService = blake2bService;
            HashSizeValue = 512; // Blake2b default
        }

        public override void Initialize()
        {
            _buffer.SetLength(0);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _buffer.Write(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            return _blake2bService.ComputeHash(_buffer.ToArray(), HashSizeValue / 8);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _buffer.Dispose();
            }
            base.Dispose(disposing);
        }
    }
#endif
}
