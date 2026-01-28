namespace HeroCrypt.Security;

/// <summary>
/// Provides comprehensive input validation for cryptographic operations.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security Note on Error Messages:</b>
/// </para>
/// <para>
/// This validator intentionally provides detailed error messages that include specific parameter
/// values (e.g., "Data size 150MB exceeds maximum 100MB"). This is a deliberate design decision
/// that prioritizes developer experience and debugging capability over minimal information disclosure.
/// </para>
/// <para>
/// <b>Rationale:</b>
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       The disclosed values are validation parameters (sizes, iteration counts), not cryptographic
///       secrets. An attacker typically already knows these values because they provided them.
///     </description>
///   </item>
///   <item>
///     <description>
///       Maximum limits (e.g., <see cref="MAX_ARRAY_SIZE"/>, <see cref="MAX_ITERATION_COUNT"/>)
///       are public constants, so hiding them in error messages provides no security benefit.
///     </description>
///   </item>
///   <item>
///     <description>
///       Generic error messages like "Invalid parameter" significantly hinder development and
///       debugging, causing developers to waste time identifying simple configuration issues.
///     </description>
///   </item>
///   <item>
///     <description>
///       Cryptographic oracles (e.g., padding oracles) require error differentiation during
///       the cryptographic operation itself, not during pre-operation parameter validation.
///     </description>
///   </item>
/// </list>
/// <para>
/// <b>For High-Security Deployments:</b>
/// </para>
/// <para>
/// If your threat model requires hiding validation details from end users, catch
/// <see cref="ArgumentException"/> at your API boundary and re-throw with generic messages:
/// </para>
/// <code>
/// try
/// {
///     InputValidator.ValidateByteArray(data, nameof(data));
/// }
/// catch (ArgumentException)
/// {
///     throw new ArgumentException("Invalid input parameters");
/// }
/// </code>
/// </remarks>
public static class InputValidator
{
    /// <summary>
    /// Maximum allowed array size to prevent DoS attacks
    /// </summary>
    public const int MAX_ARRAY_SIZE = 100 * 1024 * 1024; // 100MB

    /// <summary>
    /// Maximum allowed key size in bits
    /// </summary>
    public const int MAX_KEY_SIZE_BITS = 16384; // 16KB keys

    /// <summary>
    /// Minimum secure key size in bits (2048 bits per NIST recommendations)
    /// </summary>
    public const int MIN_SECURE_KEY_SIZE_BITS = 2048;

    /// <summary>
    /// Maximum allowed iteration count for key derivation
    /// </summary>
    public const int MAX_ITERATION_COUNT = 10_000_000;

    /// <summary>
    /// Maximum allowed memory usage for Scrypt (in bytes)
    /// </summary>
    public const long MAX_SCRYPT_MEMORY = 1L * 1024 * 1024 * 1024; // 1GB

    /// <summary>
    /// Common RSA key sizes for validation
    /// </summary>
    private static readonly int[] CommonRsaKeySizes = [2048, 3072, 4096, 8192, 16384];

    /// <summary>
    /// Validates a byte span for cryptographic use
    /// </summary>
    /// <param name="data">Data to validate</param>
    /// <param name="parameterName">Parameter name for exception messages</param>
    /// <param name="allowEmpty">Whether to allow empty spans</param>
    /// <param name="maxSize">Maximum allowed size</param>
    /// <exception cref="ArgumentException">When data fails validation</exception>
    public static void ValidateByteArray(ReadOnlySpan<byte> data, string parameterName, bool allowEmpty = false, int maxSize = MAX_ARRAY_SIZE)
    {
        if (!allowEmpty && data.Length == 0)
        {
            throw new ArgumentException("Data cannot be empty", parameterName);
        }

        if (data.Length > maxSize)
        {
            throw new ArgumentException($"Data size {data.Length} exceeds maximum allowed size {maxSize}", parameterName);
        }
    }

    /// <summary>
    /// Validates RSA key size
    /// </summary>
    /// <param name="keySizeBits">Key size in bits</param>
    /// <param name="parameterName">Parameter name for exception messages</param>
    /// <exception cref="ArgumentException">When key size is invalid</exception>
    public static void ValidateRsaKeySize(int keySizeBits, string parameterName)
    {
        if (keySizeBits < MIN_SECURE_KEY_SIZE_BITS)
        {
            throw new ArgumentException($"RSA key size must be at least {MIN_SECURE_KEY_SIZE_BITS} bits", parameterName);
        }

        if (keySizeBits > MAX_KEY_SIZE_BITS)
        {
            throw new ArgumentException($"RSA key size {keySizeBits} exceeds maximum allowed size {MAX_KEY_SIZE_BITS}", parameterName);
        }

        if (keySizeBits % 8 != 0)
        {
            throw new ArgumentException($"RSA key size {keySizeBits} must be a multiple of 8", parameterName);
        }

        // Ensure key size is reasonable (power of 2 or common sizes)
        if (Array.IndexOf(CommonRsaKeySizes, keySizeBits) < 0)
        {
            // Allow other sizes but warn if they're not common
            if (!BitOperations.IsPowerOfTwo(keySizeBits) && keySizeBits % 1024 != 0)
            {
                throw new ArgumentException($"RSA key size {keySizeBits} is not a standard size. Use 2048, 3072, 4096, 8192, or 16384", parameterName);
            }
        }
    }

    /// <summary>
    /// Validates PBKDF2 parameters
    /// </summary>
    /// <param name="password">Password data</param>
    /// <param name="salt">Salt data</param>
    /// <param name="iterations">Iteration count</param>
    /// <param name="keyLength">Desired key length</param>
    public static void ValidatePbkdf2Parameters(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int keyLength)
    {
        ValidateByteArray(password, nameof(password), allowEmpty: true);
        ValidateByteArray(salt, nameof(salt), allowEmpty: false, maxSize: 1024);

        if (iterations < 1)
        {
            throw new ArgumentException("Iterations must be positive", nameof(iterations));
        }

        // Allow 4+ byte salts for testing, but reject very short salts
        if (salt.Length < 4)
        {
            throw new ArgumentException("Salt must be at least 4 bytes", nameof(salt));
        }

        if (iterations < 1000)
        {
            throw new ArgumentException("Iteration count must be at least 1000 for security", nameof(iterations));
        }

        if (iterations > MAX_ITERATION_COUNT)
        {
            throw new ArgumentException($"Iteration count {iterations} exceeds maximum {MAX_ITERATION_COUNT}", nameof(iterations));
        }

        if (keyLength < 1)
        {
            throw new ArgumentException("Key length must be positive", nameof(keyLength));
        }

        if (keyLength > MAX_ARRAY_SIZE)
        {
            throw new ArgumentException($"Key length {keyLength} exceeds maximum {MAX_ARRAY_SIZE}", nameof(keyLength));
        }
    }

    /// <summary>
    /// Validates HKDF parameters
    /// </summary>
    /// <param name="ikm">Input key material</param>
    /// <param name="salt">Salt (optional, can be empty)</param>
    /// <param name="info">Info parameter (optional, can be empty)</param>
    /// <param name="keyLength">Desired output length</param>
    public static void ValidateHkdfParameters(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int keyLength)
    {
        ValidateByteArray(ikm, nameof(ikm), allowEmpty: false);

        // Salt and info are optional (can be empty), just validate size limits
        ValidateByteArray(salt, nameof(salt), allowEmpty: true, maxSize: 1024);
        ValidateByteArray(info, nameof(info), allowEmpty: true, maxSize: 1024);

        if (keyLength < 1)
        {
            throw new ArgumentException("Key length must be positive", nameof(keyLength));
        }

        if (keyLength > 255 * 32) // RFC 5869 limit for SHA-256
        {
            throw new ArgumentException($"Key length {keyLength} exceeds HKDF maximum for SHA-256", nameof(keyLength));
        }
    }

    /// <summary>
    /// Validates Scrypt parameters for security and DoS prevention
    /// </summary>
    /// <param name="password">Password data</param>
    /// <param name="salt">Salt data</param>
    /// <param name="n">CPU/memory cost parameter</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="keyLength">Desired key length</param>
    public static void ValidateScryptParameters(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int n, int r, int p, int keyLength)
    {
        ValidateByteArray(password, nameof(password), allowEmpty: true);
        ValidateByteArray(salt, nameof(salt), allowEmpty: true, maxSize: 1024);

        if (n < 2)
        {
            throw new ArgumentException("N must be at least 2", nameof(n));
        }

        if ((n & (n - 1)) != 0)
        {
            throw new ArgumentException("N must be a power of 2", nameof(n));
        }

        if (r < 1)
        {
            throw new ArgumentException("R must be at least 1", nameof(r));
        }

        if (p < 1)
        {
            throw new ArgumentException("P must be at least 1", nameof(p));
        }

        if (keyLength < 1)
        {
            throw new ArgumentException("Key length must be positive", nameof(keyLength));
        }

        if (keyLength > MAX_ARRAY_SIZE)
        {
            throw new ArgumentException($"Key length {keyLength} exceeds maximum {MAX_ARRAY_SIZE}", nameof(keyLength));
        }

        // Check for potential overflow and DoS conditions
        var memoryRequired = (long)128 * r * n;
        if (memoryRequired > MAX_SCRYPT_MEMORY)
        {
            throw new ArgumentException($"Scrypt memory requirement {memoryRequired} bytes exceeds maximum {MAX_SCRYPT_MEMORY}", nameof(n));
        }

        var operationsRequired = (long)2 * n * r * p;
        if (operationsRequired > MAX_ITERATION_COUNT)
        {
            throw new ArgumentException($"Scrypt operations {operationsRequired} exceed maximum {MAX_ITERATION_COUNT}", nameof(n));
        }

        // Additional security checks
        if (n > 1048576) // 2^20, reasonable upper limit
        {
            throw new ArgumentException($"N parameter {n} is too large for practical use", nameof(n));
        }

        if (r > 64)
        {
            throw new ArgumentException($"R parameter {r} is too large for practical use", nameof(r));
        }

        if (p > 64)
        {
            throw new ArgumentException($"P parameter {p} is too large for practical use", nameof(p));
        }
    }

    /// <summary>
    /// Validates symmetric key parameters
    /// </summary>
    /// <param name="keyLength">Key length in bytes</param>
    /// <param name="algorithm">Algorithm name</param>
    public static void ValidateSymmetricKeyLength(int keyLength, string algorithm)
    {
        if (keyLength < 1)
        {
            throw new ArgumentException("Key length must be positive", nameof(keyLength));
        }

        if (keyLength > 256) // 2048-bit keys
        {
            throw new ArgumentException($"Key length {keyLength} is unreasonably large", nameof(keyLength));
        }

        // Algorithm-specific validation
        switch (algorithm?.ToUpperInvariant())
        {
            case "AES":
            case "AES128":
                if (keyLength != 16)
                {
                    throw new ArgumentException("AES-128 requires 16-byte keys", nameof(keyLength));
                }
                break;
            case "AES192":
                if (keyLength != 24)
                {
                    throw new ArgumentException("AES-192 requires 24-byte keys", nameof(keyLength));
                }
                break;
            case "AES256":
                if (keyLength != 32)
                {
                    throw new ArgumentException("AES-256 requires 32-byte keys", nameof(keyLength));
                }
                break;
            case "CHACHA20":
                if (keyLength != 32)
                {
                    throw new ArgumentException("ChaCha20 requires 32-byte keys", nameof(keyLength));
                }
                break;
            case "CHACHA20POLY1305":
                if (keyLength != 32)
                {
                    throw new ArgumentException("ChaCha20-Poly1305 requires 32-byte keys", nameof(keyLength));
                }
                break;
            default:
                throw new ArgumentException($"Unsupported algorithm '{algorithm}'", nameof(algorithm));
        }
    }

    /// <summary>
    /// Validates that a key contains sufficient entropy
    /// </summary>
    /// <param name="key">Key to validate</param>
    /// <param name="parameterName">Parameter name for exceptions</param>
    /// <returns>True if key appears to have sufficient entropy</returns>
    public static bool ValidateKeyEntropy(ReadOnlySpan<byte> key, string parameterName)
    {
        if (key.Length == 0)
        {
            return false;
        }

        // Check for all-zero key
        var allZero = true;
        for (var i = 0; i < key.Length; i++)
        {
            if (key[i] != 0)
            {
                allZero = false;
                break;
            }
        }
        if (allZero)
        {
            throw new ArgumentException("Key cannot be all zeros", parameterName);
        }

        // Check for all-same bytes
        var firstByte = key[0];
        var allSame = true;
        for (var i = 1; i < key.Length; i++)
        {
            if (key[i] != firstByte)
            {
                allSame = false;
                break;
            }
        }
        if (allSame)
        {
            throw new ArgumentException("Key cannot contain all identical bytes", parameterName);
        }

        // Simple entropy check - count unique bytes using a bitset
        Span<bool> seen = stackalloc bool[256];
        var uniqueBytes = 0;
        for (var i = 0; i < key.Length; i++)
        {
            if (!seen[key[i]])
            {
                seen[key[i]] = true;
                uniqueBytes++;
            }
        }

        // Require at least 25% unique bytes, minimum 2 (to catch weak patterns), max 16
        var expectedMinimumUnique = Math.Max(2, Math.Min(16, key.Length / 4));

        if (uniqueBytes < expectedMinimumUnique)
        {
            throw new ArgumentException($"Key appears to have low entropy (only {uniqueBytes} unique bytes, expected at least {expectedMinimumUnique})", parameterName);
        }

        return true;
    }

    /// <summary>
    /// Validates password strength for key derivation
    /// </summary>
    /// <param name="password">Password to validate</param>
    /// <param name="parameterName">Parameter name for exceptions</param>
    /// <param name="minLength">Minimum password length</param>
    /// <returns>True if password meets minimum requirements</returns>
    public static bool ValidatePasswordStrength(ReadOnlySpan<byte> password, string parameterName, int minLength = 8)
    {
        if (password.Length < minLength)
        {
            throw new ArgumentException($"Password must be at least {minLength} bytes", parameterName);
        }

        // Additional entropy checks for passwords
        if (password.Length > 4)
        {
            ValidateKeyEntropy(password, parameterName);
        }

        return true;
    }

    /// <summary>
    /// Validates that an array size is reasonable for the given operation
    /// </summary>
    /// <param name="size">Size to validate</param>
    /// <param name="operation">Operation name for error messages</param>
    /// <param name="maxSize">Maximum allowed size</param>
    public static void ValidateArraySize(int size, string operation, int maxSize = MAX_ARRAY_SIZE)
    {
        if (size <= 0)
        {
            throw new ArgumentException($"Length must be positive for {operation}", nameof(size));
        }

        if (size > maxSize)
        {
            throw new ArgumentException($"Size {size} exceeds maximum {maxSize} for {operation}", nameof(size));
        }
    }

}
