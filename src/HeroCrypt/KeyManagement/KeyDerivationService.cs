using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Hashing;
using HeroCrypt.Security;
using System.Security.Cryptography;
using CryptoHashAlgorithmName = System.Security.Cryptography.HashAlgorithmName;
using HeroCryptHashAlgorithmName = HeroCrypt.KeyManagement.HashAlgorithmName;
using CryptoHashAlgorithm = System.Security.Cryptography.HashAlgorithm;

namespace HeroCrypt.KeyManagement;

/// <summary>
/// Service implementation for cryptographic key derivation operations.
/// </summary>
public class KeyDerivationService : IKeyDerivationService
{
    private readonly IBlake2bService? _blake2bService;

    /// <summary>
    /// Initializes a new instance of the KeyDerivationService.
    /// </summary>
    /// <param name="blake2bService">Optional Blake2b service for Blake2b-based derivations.</param>
    public KeyDerivationService(
        IBlake2bService? blake2bService = null)
    {
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

        try
        {
#if NETSTANDARD2_0
#pragma warning disable CA5379 // Rfc2898DeriveBytes with HashAlgorithmName not available in .NET Standard 2.0
            // For .NET Standard 2.0, use Rfc2898DeriveBytes
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            var result = pbkdf2.GetBytes(keyLength);
#pragma warning restore CA5379
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

            return result;
        }
        catch (Exception ex)
        {

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

            return result;
        }
        catch (Exception ex)
        {

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



        try
        {
            // Use the full-featured ScryptCore from KeyDerivation namespace
            var result = ScryptCore.DeriveKey(password.AsSpan(), salt.AsSpan(), n, r, p, keyLength);



            return result;
        }
        catch (Exception ex)
        {

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
            "SHA256" => (CryptoHashAlgorithm)SHA256.Create(),
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
    /// Enables Blake2b to be used with HKDF and other algorithms expecting HashAlgorithm.
    /// </summary>
    private sealed class Blake2bHashAlgorithm : CryptoHashAlgorithm
    {
        private readonly IBlake2bService _blake2bService;
        private readonly MemoryStream _buffer = new();

        /// <summary>
        /// Initializes a new instance of the Blake2bHashAlgorithm wrapper.
        /// </summary>
        /// <param name="blake2bService">The Blake2b service to use for hashing.</param>
        public Blake2bHashAlgorithm(IBlake2bService blake2bService)
        {
            _blake2bService = blake2bService;
            HashSizeValue = 512; // Blake2b default
        }

        /// <summary>
        /// Initializes or resets the hash algorithm state.
        /// </summary>
        /// <remarks>
        /// Clears the internal buffer to prepare for a new hash computation.
        /// </remarks>
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
