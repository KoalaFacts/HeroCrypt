using HeroCrypt.Security;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Primitives.Kdf;

#if !NETSTANDARD2_0

/// <summary>
/// Balloon Hashing implementation
/// A memory-hard password hashing function resistant to cache-timing attacks
///
/// Based on "Balloon Hashing: A Memory-Hard Function Providing Provable
/// Protection Against Sequential Attacks" by Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter
///
/// Key features:
/// - Memory-hard (resistant to time-memory trade-offs)
/// - Cache-timing resistant
/// - Sequential memory-hard variant available
/// - Configurable space and time costs
/// - Built on standard hash functions (SHA256, SHA512)
/// </summary>
public static class BalloonHashing
{
    /// <summary>
    /// Minimum space cost (memory usage)
    /// </summary>
    public const int MinSpaceCost = 1;

    /// <summary>
    /// Minimum time cost (iterations)
    /// </summary>
    public const int MinTimeCost = 1;

    /// <summary>
    /// Default space cost
    /// </summary>
    public const int DefaultSpaceCost = 16; // 16 blocks

    /// <summary>
    /// Default time cost
    /// </summary>
    public const int DefaultTimeCost = 20; // 20 rounds

    /// <summary>
    /// Default output length in bytes
    /// </summary>
    public const int DefaultOutputLength = 32;

    /// <summary>
    /// Computes Balloon hash of a password
    /// </summary>
    /// <param name="password">Password to hash</param>
    /// <param name="salt">Salt (recommended: 16+ bytes)</param>
    /// <param name="spaceCost">Space cost (memory usage in blocks)</param>
    /// <param name="timeCost">Time cost (number of mixing rounds)</param>
    /// <param name="outputLength">Output hash length in bytes</param>
    /// <param name="hashAlgorithm">Hash algorithm to use</param>
    /// <returns>Derived hash</returns>
    public static byte[] Hash(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int spaceCost = DefaultSpaceCost,
        int timeCost = DefaultTimeCost,
        int outputLength = DefaultOutputLength,
        HashAlgorithmName? hashAlgorithm = null)
    {
        ValidateParameters(spaceCost, timeCost, outputLength);

        var algo = hashAlgorithm ?? HashAlgorithmName.SHA256;
        var hashLength = GetHashLength(algo);

        // Allocate buffer (space_cost blocks of hash_length bytes)
        var buffer = new byte[spaceCost][];
        for (var i = 0; i < spaceCost; i++)
        {
            buffer[i] = new byte[hashLength];
        }

        try
        {
            // Step 1: Expand input into buffer
            Expand(buffer, password, salt, algo);

            // Step 2: Mix buffer contents (time_cost rounds)
            for (var t = 0; t < timeCost; t++)
            {
                Mix(buffer, t, algo);
            }

            // Step 3: Extract output
            return Extract(buffer, outputLength, algo);
        }
        finally
        {
            // Clear sensitive data
            foreach (var block in buffer)
            {
                if (block != null)
                {
                    SecureMemoryOperations.SecureClear(block);
                }
            }
        }
    }

    /// <summary>
    /// Computes Balloon hash with string password and generates random salt
    /// </summary>
    /// <param name="password">Password string</param>
    /// <param name="spaceCost">Space cost</param>
    /// <param name="timeCost">Time cost</param>
    /// <param name="outputLength">Output length</param>
    /// <returns>Hash with embedded salt (first 16 bytes are salt)</returns>
    public static byte[] HashWithRandomSalt(
        string password,
        int spaceCost = DefaultSpaceCost,
        int timeCost = DefaultTimeCost,
        int outputLength = DefaultOutputLength)
    {
        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        var salt = new byte[16];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        try
        {
            var hash = Hash(passwordBytes, salt, spaceCost, timeCost, outputLength);

            // Prepend salt to hash
            var result = new byte[salt.Length + hash.Length];
            salt.CopyTo(result, 0);
            hash.CopyTo(result, salt.Length);

            Array.Clear(hash, 0, hash.Length);
            return result;
        }
        finally
        {
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
            Array.Clear(salt, 0, salt.Length);
        }
    }

    /// <summary>
    /// Verifies a password against a hash
    /// </summary>
    /// <param name="password">Password to verify</param>
    /// <param name="hashWithSalt">Hash with embedded salt (from HashWithRandomSalt)</param>
    /// <param name="spaceCost">Space cost used during hashing</param>
    /// <param name="timeCost">Time cost used during hashing</param>
    /// <returns>True if password matches</returns>
    public static bool Verify(
        string password,
        byte[] hashWithSalt,
        int spaceCost = DefaultSpaceCost,
        int timeCost = DefaultTimeCost)
    {
        if (hashWithSalt.Length < 16)
            throw new ArgumentException("Hash too short to contain salt", nameof(hashWithSalt));

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        var salt = hashWithSalt.AsSpan(0, 16);
        var expectedHash = hashWithSalt.AsSpan(16);

        try
        {
            var computedHash = Hash(passwordBytes, salt, spaceCost, timeCost, expectedHash.Length);

            var result = SecureMemoryOperations.ConstantTimeEquals(computedHash, expectedHash);

            Array.Clear(computedHash, 0, computedHash.Length);
            return result;
        }
        finally
        {
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
        }
    }

    /// <summary>
    /// Expand: Initialize buffer from password and salt
    /// </summary>
    private static void Expand(byte[][] buffer, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, HashAlgorithmName algo)
    {
        var spaceCost = buffer.Length;

        // buffer[0] = hash(counter || password || salt)
        for (var i = 0; i < spaceCost; i++)
        {
            Span<byte> input = stackalloc byte[8 + password.Length + salt.Length];

            // Encode counter as 64-bit little-endian
            BitConverter.TryWriteBytes(input, (long)i);
            password.CopyTo(input.Slice(8));
            salt.CopyTo(input.Slice(8 + password.Length));

            buffer[i] = ComputeHash(input, algo);
        }
    }

    /// <summary>
    /// Mix: Perform one mixing round
    /// </summary>
    private static void Mix(byte[][] buffer, int round, HashAlgorithmName algo)
    {
        var spaceCost = buffer.Length;

        for (var m = 0; m < spaceCost; m++)
        {
            // Compute prev = (m - 1) mod space_cost
            var prev = (m == 0) ? spaceCost - 1 : m - 1;

            // buffer[m] = hash(round || buffer[prev] || buffer[m])
            Span<byte> input = stackalloc byte[8 + buffer[prev].Length + buffer[m].Length];

            BitConverter.TryWriteBytes(input, (long)round);
            buffer[prev].CopyTo(input.Slice(8));
            buffer[m].CopyTo(input.Slice(8 + buffer[prev].Length));

            var newValue = ComputeHash(input, algo);
            Array.Clear(buffer[m], 0, buffer[m].Length);
            buffer[m] = newValue;

            // Compute other = to_int(buffer[m]) mod space_cost
            var other = Math.Abs(BitConverter.ToInt32(buffer[m], 0)) % spaceCost;

            // buffer[m] = hash(round || buffer[m] || buffer[other])
            input = stackalloc byte[8 + buffer[m].Length + buffer[other].Length];

            BitConverter.TryWriteBytes(input, (long)round);
            buffer[m].CopyTo(input.Slice(8));
            buffer[other].CopyTo(input.Slice(8 + buffer[m].Length));

            newValue = ComputeHash(input, algo);
            Array.Clear(buffer[m], 0, buffer[m].Length);
            buffer[m] = newValue;
        }
    }

    /// <summary>
    /// Extract: Generate final output from buffer
    /// </summary>
    private static byte[] Extract(byte[][] buffer, int outputLength, HashAlgorithmName algo)
    {
        // Return first outputLength bytes of last buffer block
        var lastBlock = buffer[buffer.Length - 1];

        if (outputLength <= lastBlock.Length)
        {
            var output = new byte[outputLength];
            Array.Copy(lastBlock, output, outputLength);
            return output;
        }

        // If output length exceeds hash length, derive more data
        var result = new byte[outputLength];
        var pos = 0;

        while (pos < outputLength)
        {
            var chunk = ComputeHash(lastBlock, algo);
            var toCopy = Math.Min(chunk.Length, outputLength - pos);
            Array.Copy(chunk, 0, result, pos, toCopy);
            pos += toCopy;

            if (pos < outputLength)
            {
                Array.Clear(lastBlock, 0, lastBlock.Length);
                lastBlock = chunk;
            }
            else
            {
                Array.Clear(chunk, 0, chunk.Length);
            }
        }

        return result;
    }

    /// <summary>
    /// Computes hash of input using specified algorithm
    /// </summary>
    private static byte[] ComputeHash(ReadOnlySpan<byte> input, HashAlgorithmName algo)
    {
        if (algo == HashAlgorithmName.SHA256)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(input.ToArray());
        }
        else if (algo == HashAlgorithmName.SHA512)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(input.ToArray());
        }
        else if (algo == HashAlgorithmName.SHA384)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(input.ToArray());
        }
        else
        {
            throw new NotSupportedException($"Hash algorithm {algo.Name} not supported");
        }
    }

    /// <summary>
    /// Gets hash output length for algorithm
    /// </summary>
    private static int GetHashLength(HashAlgorithmName algo)
    {
        if (algo == HashAlgorithmName.SHA256) return 32;
        if (algo == HashAlgorithmName.SHA384) return 48;
        if (algo == HashAlgorithmName.SHA512) return 64;
        throw new NotSupportedException($"Hash algorithm {algo.Name} not supported");
    }

    /// <summary>
    /// Validates parameters
    /// </summary>
    private static void ValidateParameters(int spaceCost, int timeCost, int outputLength)
    {
        if (spaceCost < MinSpaceCost)
            throw new ArgumentException($"Space cost must be at least {MinSpaceCost}", nameof(spaceCost));
        if (timeCost < MinTimeCost)
            throw new ArgumentException($"Time cost must be at least {MinTimeCost}", nameof(timeCost));
        if (outputLength <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLength));
    }

    /// <summary>
    /// Gets information about Balloon Hashing
    /// </summary>
    public static string GetInfo()
    {
        return $"Balloon Hashing - Memory-hard password hashing function. " +
               $"Default space cost: {DefaultSpaceCost} blocks, time cost: {DefaultTimeCost} rounds. " +
               $"Resistant to cache-timing attacks and parallel attacks.";
    }

    /// <summary>
    /// Gets recommended parameters for security level
    /// </summary>
    /// <param name="level">Security level (1-5, where 5 is highest)</param>
    /// <returns>Tuple of (spaceCost, timeCost)</returns>
    public static (int spaceCost, int timeCost) GetRecommendedParameters(int level)
    {
        return level switch
        {
            1 => (8, 10),      // Fast: 8 blocks, 10 rounds
            2 => (16, 20),     // Balanced: 16 blocks, 20 rounds (default)
            3 => (32, 30),     // Secure: 32 blocks, 30 rounds
            4 => (64, 40),     // High: 64 blocks, 40 rounds
            5 => (128, 50),    // Maximum: 128 blocks, 50 rounds
            _ => throw new ArgumentException("Security level must be between 1 and 5", nameof(level))
        };
    }
}
#endif
