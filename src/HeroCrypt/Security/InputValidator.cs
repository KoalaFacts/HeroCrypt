namespace HeroCrypt.Security;

/// <summary>
/// Provides comprehensive input validation for cryptographic operations
/// </summary>
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
    /// Validates a byte array for cryptographic use
    /// </summary>
    /// <param name="data">Data to validate</param>
    /// <param name="parameterName">Parameter name for exception messages</param>
    /// <param name="allowEmpty">Whether to allow empty arrays</param>
    /// <param name="maxSize">Maximum allowed size</param>
    /// <exception cref="ArgumentNullException">When data is null</exception>
    /// <exception cref="ArgumentException">When data fails validation</exception>
    public static void ValidateByteArray(byte[] data, string parameterName, bool allowEmpty = false, int maxSize = MAX_ARRAY_SIZE)
    {
        if (data == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (!allowEmpty && data.Length == 0)
        {
            throw new ArgumentException("Array cannot be empty", parameterName);
        }

        if (data.Length > maxSize)
        {
            throw new ArgumentException($"Array size {data.Length} exceeds maximum allowed size {maxSize}", parameterName);
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
        var commonSizes = new[] { 2048, 3072, 4096, 8192, 16384 };
        if (!commonSizes.Contains(keySizeBits))
        {
            // Allow other sizes but warn if they're not common
            if (!IsPowerOfTwo(keySizeBits) && keySizeBits % 1024 != 0)
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
    public static void ValidatePbkdf2Parameters(byte[] password, byte[] salt, int iterations, int keyLength)
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
    /// <param name="salt">Salt (optional)</param>
    /// <param name="info">Info parameter (optional)</param>
    /// <param name="keyLength">Desired output length</param>
    public static void ValidateHkdfParameters(byte[] ikm, byte[] salt, byte[] info, int keyLength)
    {
        ValidateByteArray(ikm, nameof(ikm), allowEmpty: false);

        if (salt != null)
        {
            ValidateByteArray(salt, nameof(salt), allowEmpty: true, maxSize: 1024);
        }

        if (info != null)
        {
            ValidateByteArray(info, nameof(info), allowEmpty: true, maxSize: 1024);
        }

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
    public static void ValidateScryptParameters(byte[] password, byte[] salt, int n, int r, int p, int keyLength)
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
    public static bool ValidateKeyEntropy(byte[] key, string parameterName)
    {
        if (key == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (key.Length == 0)
        {
            return false;
        }

        // Check for all-zero key
        if (key.All(b => b == 0))
        {
            throw new ArgumentException("Key cannot be all zeros", parameterName);
        }

        // Check for all-same bytes
        if (key.All(b => b == key[0]))
        {
            throw new ArgumentException("Key cannot contain all identical bytes", parameterName);
        }

        // Simple entropy check - count unique bytes
        var uniqueBytes = key.Distinct().Count();
        var expectedMinimumUnique = Math.Min(16, key.Length / 4); // At least 25% unique bytes, max 16

        if (uniqueBytes < expectedMinimumUnique)
        {
            throw new ArgumentException($"Key appears to have low entropy (only {uniqueBytes} unique bytes)", parameterName);
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
    public static bool ValidatePasswordStrength(byte[] password, string parameterName, int minLength = 8)
    {
        if (password == null)
        {
            throw new ArgumentNullException(parameterName);
        }

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

    /// <summary>
    /// Checks if a number is a power of two
    /// </summary>
    /// <param name="value">Value to check</param>
    /// <returns>True if value is a power of two</returns>
    private static bool IsPowerOfTwo(int value)
    {
        return value > 0 && (value & (value - 1)) == 0;
    }
}
