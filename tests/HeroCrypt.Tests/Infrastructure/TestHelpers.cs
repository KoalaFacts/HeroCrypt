using System.Security.Cryptography;

namespace HeroCrypt.Tests.Infrastructure;

/// <summary>
/// Base class providing common test utilities for cryptographic algorithm tests.
/// All algorithm test classes should use these utilities for consistency.
/// </summary>
public static class TestHelpers
{
    /// <summary>
    /// Generates cryptographically secure random bytes.
    /// </summary>
    public static byte[] RandomBytes(int length)
        => RandomNumberGenerator.GetBytes(length);

    /// <summary>
    /// Fills a buffer with cryptographically secure random bytes.
    /// </summary>
    public static void FillRandom(Span<byte> buffer)
        => RandomNumberGenerator.Fill(buffer);

    /// <summary>
    /// Creates a byte array filled with a specific value.
    /// </summary>
    public static byte[] FilledBytes(int length, byte value)
        => Enumerable.Repeat(value, length).ToArray();

    /// <summary>
    /// Creates a byte array with sequential values (0, 1, 2, ...).
    /// </summary>
    public static byte[] SequentialBytes(int length)
        => Enumerable.Range(0, length).Select(i => (byte)(i % 256)).ToArray();

    /// <summary>
    /// Creates a zero-filled byte array.
    /// </summary>
    public static byte[] ZeroBytes(int length)
        => new byte[length];

    /// <summary>
    /// Converts a hex string to byte array.
    /// </summary>
    public static byte[] HexToBytes(string hex)
        => Convert.FromHexString(hex.Replace(" ", "").Replace("-", ""));

    /// <summary>
    /// Converts a byte array to hex string.
    /// </summary>
    public static string BytesToHex(byte[] bytes)
        => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>
    /// XORs two byte arrays and returns the result.
    /// </summary>
    public static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("Arrays must have the same length");

        var result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }

    /// <summary>
    /// Checks if all bytes in an array are the same value.
    /// </summary>
    public static bool AllSameValue(byte[] bytes, byte value)
        => bytes.All(b => b == value);

    /// <summary>
    /// Checks if all bytes in an array are zero.
    /// </summary>
    public static bool AllZeros(byte[] bytes)
        => AllSameValue(bytes, 0);

    /// <summary>
    /// Counts the number of distinct byte values in an array.
    /// Useful for checking randomness/entropy.
    /// </summary>
    public static int CountDistinctBytes(byte[] bytes)
        => bytes.Distinct().Count();

    /// <summary>
    /// Copies an array and modifies a single byte.
    /// Useful for tampering tests.
    /// </summary>
    public static byte[] TamperByte(byte[] original, int index)
    {
        var copy = (byte[])original.Clone();
        copy[index] ^= 0xFF;
        return copy;
    }

    /// <summary>
    /// Creates a copy of an array with the first byte modified.
    /// </summary>
    public static byte[] TamperFirst(byte[] original)
        => TamperByte(original, 0);

    /// <summary>
    /// Creates a copy of an array with the last byte modified.
    /// </summary>
    public static byte[] TamperLast(byte[] original)
        => TamperByte(original, original.Length - 1);
}

/// <summary>
/// Standard test data sizes for consistent testing across algorithms.
/// </summary>
public static class TestDataSizes
{
    /// <summary>Empty data (0 bytes)</summary>
    public const int Empty = 0;

    /// <summary>Single byte</summary>
    public const int SingleByte = 1;

    /// <summary>Small data (16 bytes)</summary>
    public const int Small = 16;

    /// <summary>Medium data (256 bytes)</summary>
    public const int Medium = 256;

    /// <summary>Large data (1 KB)</summary>
    public const int Large = 1024;

    /// <summary>Very large data (1 MB)</summary>
    public const int VeryLarge = 1024 * 1024;

    /// <summary>
    /// Common block sizes for partial block testing.
    /// </summary>
    public static readonly int[] PartialBlockSizes = [1, 7, 15, 17, 31, 33, 63, 65];

    /// <summary>
    /// Standard AES key sizes (16, 24, 32 bytes).
    /// </summary>
    public static readonly int[] AesKeySizes = [16, 24, 32];
}

/// <summary>
/// Assertion extensions for cryptographic testing.
/// </summary>
public static class CryptoAssertions
{
    /// <summary>
    /// Asserts that a buffer appears to contain random data.
    /// Checks that not all bytes are the same and there's reasonable variety.
    /// </summary>
    public static void AssertAppearsRandom(byte[] data, int minDistinctBytes = 10)
    {
        Assert.False(data.All(b => b == data[0]),
            "Data appears non-random: all bytes are identical");
        Assert.True(TestHelpers.CountDistinctBytes(data) >= minDistinctBytes,
            $"Data appears non-random: fewer than {minDistinctBytes} distinct byte values");
    }

    /// <summary>
    /// Asserts that two byte arrays are equal using constant-time comparison.
    /// </summary>
    public static void AssertBytesEqual(byte[] expected, byte[] actual)
    {
        Assert.Equal(expected.Length, actual.Length);
        Assert.True(CryptographicOperations.FixedTimeEquals(expected, actual),
            "Byte arrays are not equal");
    }

    /// <summary>
    /// Asserts that decryption failed and plaintext was cleared.
    /// </summary>
    public static void AssertDecryptionFailed(int result, byte[] plaintext)
    {
        Assert.Equal(-1, result);
        Assert.True(TestHelpers.AllZeros(plaintext),
            "Plaintext should be cleared on authentication failure");
    }

    /// <summary>
    /// Asserts that an exception message contains the expected text.
    /// </summary>
    public static void AssertExceptionContains<TException>(Action action, string expectedText)
        where TException : Exception
    {
        var ex = Assert.Throws<TException>(action);
        Assert.Contains(expectedText, ex.Message);
    }
}
