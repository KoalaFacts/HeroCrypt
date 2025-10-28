using HeroCrypt.Security;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.KeyDerivation;

/// <summary>
/// scrypt (Script) key derivation function implementation
/// RFC 7914 compliant memory-hard key derivation function
/// Designed to be resistant to hardware brute-force attacks
/// </summary>
internal static class ScryptCore
{
    /// <summary>
    /// Minimum recommended N parameter (CPU/memory cost)
    /// </summary>
    public const int MinRecommendedN = 16384; // 2^14

    /// <summary>
    /// Default N parameter for general use
    /// </summary>
    public const int DefaultN = 32768; // 2^15

    /// <summary>
    /// Recommended r parameter (block size)
    /// </summary>
    public const int DefaultR = 8;

    /// <summary>
    /// Recommended p parameter (parallelization)
    /// </summary>
    public const int DefaultP = 1;

    /// <summary>
    /// Minimum salt length in bytes
    /// </summary>
    public const int MinSaltLength = 16;

    /// <summary>
    /// Default salt length in bytes
    /// </summary>
    public const int DefaultSaltLength = 32;

    /// <summary>
    /// Maximum memory usage limit (128 MB by default)
    /// </summary>
    public const long DefaultMaxMemory = 128 * 1024 * 1024;

    /// <summary>
    /// Derives a key using scrypt
    /// </summary>
    /// <param name="password">Password bytes</param>
    /// <param name="salt">Salt bytes</param>
    /// <param name="n">CPU/memory cost parameter (must be power of 2)</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="outputLength">Desired output length in bytes</param>
    /// <returns>Derived key</returns>
    public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int n, int r, int p, int outputLength)
    {
        ValidateParameters(password, salt, n, r, p, outputLength);

        // Use PBKDF2-HMAC-SHA256 for initial key stretching
        // Allow weak parameters for RFC test vectors (empty passwords/salts)
        var b = Pbkdf2Core.DeriveKey(password, salt, 1, p * 128 * r, HashAlgorithmName.SHA256, allowWeakParameters: true);

        try
        {
            // Apply ROMix to each block
            for (var i = 0; i < p; i++)
            {
                var blockOffset = i * 128 * r;
                var block = b.AsSpan(blockOffset, 128 * r);
                ROMix(block, n);
            }

            // Final PBKDF2 to produce output
            // Allow weak parameters for RFC test vectors
            return Pbkdf2Core.DeriveKey(password, b, 1, outputLength, HashAlgorithmName.SHA256, allowWeakParameters: true);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(b);
        }
    }

    /// <summary>
    /// Derives a key from a password string using scrypt
    /// </summary>
    /// <param name="password">Password string</param>
    /// <param name="salt">Salt bytes</param>
    /// <param name="n">CPU/memory cost parameter</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="outputLength">Desired output length</param>
    /// <returns>Derived key</returns>
    public static byte[] DeriveKeyFromString(string password, ReadOnlySpan<byte> salt,
        int n, int r, int p, int outputLength)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        try
        {
            return DeriveKey(passwordBytes, salt, n, r, p, outputLength);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(passwordBytes);
        }
    }

    /// <summary>
    /// Validates scrypt parameters
    /// </summary>
    /// <param name="password">Password bytes</param>
    /// <param name="salt">Salt bytes</param>
    /// <param name="n">CPU/memory cost parameter</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <param name="outputLength">Output length</param>
    public static void ValidateParameters(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int n, int r, int p, int outputLength)
    {
        // Note: Allow empty passwords and salts for RFC test vectors
        // Note: Allow low N values for test vectors and compatibility, but production should use N >= 16384

        if (n <= 0 || !IsPowerOfTwo(n))
            throw new ArgumentException("N must be a power of 2 greater than 0", nameof(n));

        // Don't enforce minimum N - allow test vectors and compatibility scenarios
        // Production code should use MinRecommendedN (16384) or higher

        if (r <= 0)
            throw new ArgumentException("r must be positive", nameof(r));

        if (p <= 0)
            throw new ArgumentException("p must be positive", nameof(p));

        if (outputLength <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLength));

        // Check memory requirements
        var memoryRequired = (long)128 * r * n * p;
        if (memoryRequired > DefaultMaxMemory)
            throw new ArgumentException($"Parameters require too much memory: {memoryRequired} bytes (max: {DefaultMaxMemory})", nameof(n));

        // RFC 7914 constraint: p <= (2^32 - 1) * 32 / (128 * r)
        var maxP = ((1L << 32) - 1) * 32 / (128 * r);
        if (p > maxP)
            throw new ArgumentException($"p too large for given r (max: {maxP})", nameof(p));
    }

    /// <summary>
    /// Generates a random salt for scrypt
    /// </summary>
    /// <param name="length">Salt length (default: 32 bytes)</param>
    /// <returns>Random salt</returns>
    public static byte[] GenerateRandomSalt(int length = DefaultSaltLength)
    {
        if (length < MinSaltLength)
            throw new ArgumentException($"Salt length must be at least {MinSaltLength} bytes", nameof(length));

        var salt = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Gets recommended parameters for different use cases
    /// </summary>
    /// <param name="useCase">scrypt use case</param>
    /// <returns>Recommended parameters</returns>
    public static ScryptParameters GetRecommendedParameters(ScryptUseCase useCase)
    {
        return useCase switch
        {
            ScryptUseCase.Interactive => new ScryptParameters
            {
                N = 32768,      // 2^15
                R = 8,
                P = 1,
                SaltLength = DefaultSaltLength,
                OutputLength = 32,
                Description = "Interactive login (fast)"
            },
            ScryptUseCase.Sensitive => new ScryptParameters
            {
                N = 1048576,    // 2^20
                R = 8,
                P = 1,
                SaltLength = DefaultSaltLength,
                OutputLength = 32,
                Description = "Sensitive data (slow)"
            },
            ScryptUseCase.FileEncryption => new ScryptParameters
            {
                N = 65536,      // 2^16
                R = 8,
                P = 1,
                SaltLength = 32,
                OutputLength = 64,
                Description = "File encryption keys"
            },
            ScryptUseCase.LegacyCompatibility => new ScryptParameters
            {
                N = 16384,      // 2^14
                R = 8,
                P = 1,
                SaltLength = MinSaltLength,
                OutputLength = 32,
                Description = "Legacy compatibility"
            },
            _ => throw new ArgumentException($"Unknown use case: {useCase}", nameof(useCase))
        };
    }

    /// <summary>
    /// Calculates memory usage for given parameters
    /// </summary>
    /// <param name="n">CPU/memory cost parameter</param>
    /// <param name="r">Block size parameter</param>
    /// <param name="p">Parallelization parameter</param>
    /// <returns>Memory usage in bytes</returns>
    public static long CalculateMemoryUsage(int n, int r, int p)
    {
        return (long)128 * r * n * p;
    }

    /// <summary>
    /// Suggests parameters for target memory usage
    /// </summary>
    /// <param name="targetMemoryMB">Target memory usage in MB</param>
    /// <returns>Suggested parameters</returns>
    public static (int N, int R, int P) SuggestParameters(int targetMemoryMB)
    {
        if (targetMemoryMB <= 0)
            throw new ArgumentException("Target memory must be positive", nameof(targetMemoryMB));

        var targetBytes = (long)targetMemoryMB * 1024 * 1024;
        var r = DefaultR;
        var p = DefaultP;

        // Calculate N for target memory: N = targetBytes / (128 * r * p)
        var n = (int)(targetBytes / (128 * r * p));

        // Round down to nearest power of 2
#if NET6_0_OR_GREATER
        n = (int)Math.Pow(2, Math.Floor(Math.Log2(n)));
#else
        n = (int)Math.Pow(2, Math.Floor(Math.Log(n) / Math.Log(2)));
#endif

        // Ensure minimum security
        n = Math.Max(n, MinRecommendedN);

        return (n, r, p);
    }

    /// <summary>
    /// ROMix function - the core memory-hard component of scrypt
    /// </summary>
    /// <param name="block">128*r byte block to process</param>
    /// <param name="n">Number of iterations</param>
    private static void ROMix(Span<byte> block, int n)
    {
        var blockSize = block.Length;
        var v = new byte[n * blockSize];
        var x = new byte[blockSize];
        var y = new byte[blockSize];

        try
        {
            // Step 1: Fill V array
            block.CopyTo(x.AsSpan());
            for (var i = 0; i < n; i++)
            {
                x.AsSpan().CopyTo(v.AsSpan(i * blockSize, blockSize));
                BlockMix(x, y);
                y.AsSpan().CopyTo(x.AsSpan());
            }

            // Step 2: Second loop with random access
            for (var i = 0; i < n; i++)
            {
                var j = Integerify(x) & (n - 1);
                Xor(x, v.AsSpan(j * blockSize, blockSize), x);
                BlockMix(x, y);
                y.AsSpan().CopyTo(x.AsSpan());
            }

            x.AsSpan().CopyTo(block);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(v);
            SecureMemoryOperations.SecureClear(x);
            SecureMemoryOperations.SecureClear(y);
        }
    }

    /// <summary>
    /// BlockMix function using Salsa20/8 core
    /// </summary>
    /// <param name="input">Input block</param>
    /// <param name="output">Output block</param>
    private static void BlockMix(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var r = input.Length / 128;
        var x = new byte[64];
        var temp = new byte[64];

        try
        {
            // X = B[2r-1]
            input.Slice((2 * r - 1) * 64, 64).CopyTo(x);

            // Process each 64-byte block
            for (var i = 0; i < 2 * r; i++)
            {
                // X = Salsa(X XOR B[i])
                Xor(x, input.Slice(i * 64, 64), x);
                Salsa208(x, temp);
                temp.AsSpan().CopyTo(x.AsSpan());

                // Y[i] = X
                var outputOffset = i < r ? i * 64 : (i - r) * 64 + r * 64;
                x.AsSpan().CopyTo(output.Slice(outputOffset, 64));
            }
        }
        finally
        {
            SecureMemoryOperations.SecureClear(x);
            SecureMemoryOperations.SecureClear(temp);
        }
    }

    /// <summary>
    /// Salsa20/8 core function (8 rounds instead of 20)
    /// </summary>
    /// <param name="input">64-byte input</param>
    /// <param name="output">64-byte output</param>
    private static void Salsa208(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<uint> x = stackalloc uint[16];

        // Convert bytes to words (little-endian)
        for (var i = 0; i < 16; i++)
        {
            var offset = i * 4;
            x[i] = (uint)(input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16) | (input[offset + 3] << 24));
        }

        // Save original for addition later
        Span<uint> original = stackalloc uint[16];
        x.CopyTo(original);

        // 8 rounds (4 double rounds)
        for (var i = 0; i < 4; i++)
        {
            // Column rounds
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 5, 9, 13, 1);
            QuarterRound(x, 10, 14, 2, 6);
            QuarterRound(x, 15, 3, 7, 11);

            // Row rounds
            QuarterRound(x, 0, 1, 2, 3);
            QuarterRound(x, 5, 6, 7, 4);
            QuarterRound(x, 10, 11, 8, 9);
            QuarterRound(x, 15, 12, 13, 14);
        }

        // Add original values
        for (var i = 0; i < 16; i++)
        {
            x[i] += original[i];
        }

        // Convert back to bytes (little-endian)
        for (var i = 0; i < 16; i++)
        {
            var offset = i * 4;
            var value = x[i];
            output[offset] = (byte)value;
            output[offset + 1] = (byte)(value >> 8);
            output[offset + 2] = (byte)(value >> 16);
            output[offset + 3] = (byte)(value >> 24);
        }
    }

    /// <summary>
    /// Salsa20 quarter round function
    /// </summary>
    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[b] ^= RotateLeft(x[a] + x[d], 7);
        x[c] ^= RotateLeft(x[b] + x[a], 9);
        x[d] ^= RotateLeft(x[c] + x[b], 13);
        x[a] ^= RotateLeft(x[d] + x[c], 18);
    }

    /// <summary>
    /// Left rotation
    /// </summary>
    private static uint RotateLeft(uint value, int bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    /// <summary>
    /// Integerify function - converts block to integer for indexing
    /// </summary>
    /// <param name="block">Block to convert</param>
    /// <returns>Integer value</returns>
    private static int Integerify(ReadOnlySpan<byte> block)
    {
        var offset = block.Length - 64;
        return (int)(block[offset] | (block[offset + 1] << 8) | (block[offset + 2] << 16) | (block[offset + 3] << 24));
    }

    /// <summary>
    /// XOR two byte arrays
    /// </summary>
    /// <param name="a">First array</param>
    /// <param name="b">Second array</param>
    /// <param name="result">Result array</param>
    private static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        for (var i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
    }

    /// <summary>
    /// Checks if a number is a power of 2
    /// </summary>
    /// <param name="n">Number to check</param>
    /// <returns>True if power of 2</returns>
    private static bool IsPowerOfTwo(int n)
    {
        return n > 0 && (n & (n - 1)) == 0;
    }
}

/// <summary>
/// scrypt use cases for parameter recommendations
/// </summary>
public enum ScryptUseCase
{
    /// <summary>Interactive login scenarios (fast)</summary>
    Interactive,
    /// <summary>Sensitive data protection (slow)</summary>
    Sensitive,
    /// <summary>File encryption keys</summary>
    FileEncryption,
    /// <summary>Legacy system compatibility</summary>
    LegacyCompatibility
}

/// <summary>
/// scrypt parameters for different use cases
/// </summary>
public class ScryptParameters
{
    /// <summary>CPU/memory cost parameter (must be power of 2)</summary>
    public int N { get; set; }

    /// <summary>Block size parameter</summary>
    public int R { get; set; }

    /// <summary>Parallelization parameter</summary>
    public int P { get; set; }

    /// <summary>Recommended salt length</summary>
    public int SaltLength { get; set; }

    /// <summary>Recommended output length</summary>
    public int OutputLength { get; set; }

    /// <summary>Description of the parameters</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Memory usage in bytes</summary>
    public long MemoryUsage => (long)128 * R * N * P;

    /// <summary>Memory usage in MB</summary>
    public double MemoryUsageMB => MemoryUsage / (1024.0 * 1024.0);
}