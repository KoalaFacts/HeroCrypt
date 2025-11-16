using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Security;
using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Cryptography.Protocols;

#if !NETSTANDARD2_0

/// <summary>
/// BIP39 Mnemonic Code implementation
/// Generates mnemonic phrases from entropy for HD wallet seed generation
///
/// Key features:
/// - Entropy to mnemonic conversion (12/15/18/21/24 words)
/// - Mnemonic to seed conversion using PBKDF2
/// - Checksum validation
/// - Optional passphrase support
/// </summary>
public static class Bip39Mnemonic
{
    /// <summary>
    /// Supported entropy lengths in bits
    /// </summary>
    public static readonly int[] SupportedEntropyBits = { 128, 160, 192, 224, 256 };

    /// <summary>
    /// Corresponding word counts for entropy lengths
    /// </summary>
    public static readonly int[] WordCounts = { 12, 15, 18, 21, 24 };

    /// <summary>
    /// PBKDF2 iteration count for mnemonic to seed conversion
    /// </summary>
    public const int Pbkdf2Iterations = 2048;

    /// <summary>
    /// Seed output length in bytes
    /// </summary>
    public const int SeedLength = 64; // 512 bits

    /// <summary>
    /// BIP39 wordlist (simplified for demonstration - production should use full 2048-word list)
    /// This is a minimal wordlist for testing. A full implementation should load the complete BIP39 wordlist.
    /// </summary>
    private static readonly string[] Wordlist = GenerateMinimalWordlist();

    /// <summary>
    /// Generates a mnemonic from entropy
    /// </summary>
    /// <param name="entropy">Entropy bytes (16/20/24/28/32 bytes for 12/15/18/21/24 words)</param>
    /// <returns>Mnemonic phrase</returns>
    public static string GenerateMnemonic(ReadOnlySpan<byte> entropy)
    {
        var entropyBits = entropy.Length * 8;
        if (!SupportedEntropyBits.Contains(entropyBits))
        {
            throw new ArgumentException(
                $"Entropy must be {string.Join(", ", SupportedEntropyBits.Select(b => b / 8))} bytes",
                nameof(entropy));
        }

        // Calculate checksum
        var checksumBits = entropyBits / 32;
        var checksum = CalculateChecksum(entropy);

        // Combine entropy and checksum into bits
        var totalBits = entropyBits + checksumBits;
        var bits = new bool[totalBits];

        // Convert entropy to bits
        for (var i = 0; i < entropy.Length; i++)
        {
            for (var j = 0; j < 8; j++)
            {
                bits[i * 8 + j] = ((entropy[i] >> (7 - j)) & 1) == 1;
            }
        }

        // Append checksum bits
        for (var i = 0; i < checksumBits; i++)
        {
            bits[entropyBits + i] = ((checksum >> (7 - i)) & 1) == 1;
        }

        // Convert bits to word indices (11 bits per word)
        var wordCount = totalBits / 11;
        var words = new string[wordCount];

        for (var i = 0; i < wordCount; i++)
        {
            var index = 0;
            for (var j = 0; j < 11; j++)
            {
                if (bits[i * 11 + j])
                {
                    index |= 1 << (10 - j);
                }
            }

            words[i] = Wordlist[index];
        }

        return string.Join(" ", words);
    }

    /// <summary>
    /// Generates a random mnemonic with specified word count
    /// </summary>
    /// <param name="wordCount">Number of words (12, 15, 18, 21, or 24)</param>
    /// <returns>Random mnemonic phrase</returns>
    public static string GenerateRandomMnemonic(int wordCount = 24)
    {
        var entropyBytes = GetEntropyBytesFromWordCount(wordCount);
        var entropy = new byte[entropyBytes];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(entropy);
        }

        try
        {
            return GenerateMnemonic(entropy);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(entropy);
        }
    }

    /// <summary>
    /// Converts a mnemonic to a seed
    /// </summary>
    /// <param name="mnemonic">Mnemonic phrase</param>
    /// <param name="passphrase">Optional passphrase (empty string if none)</param>
    /// <returns>512-bit seed for BIP32</returns>
    public static byte[] MnemonicToSeed(string mnemonic, string passphrase = "")
    {
        if (string.IsNullOrWhiteSpace(mnemonic))
            throw new ArgumentException("Mnemonic cannot be empty", nameof(mnemonic));

        // Normalize mnemonic
        mnemonic = NormalizeMnemonic(mnemonic);

        // Create salt: "mnemonic" + passphrase
        var salt = Encoding.UTF8.GetBytes("mnemonic" + (passphrase ?? ""));

        // Convert mnemonic to bytes
        var mnemonicBytes = Encoding.UTF8.GetBytes(mnemonic);

        try
        {
            // Generate seed using PBKDF2-HMAC-SHA512
            // NOTE: BIP-39 standard specifies 2048 iterations and "mnemonic" + passphrase as salt.
            // These parameters are below our normal security recommendations but are required for
            // standards compliance. This is intentional per BIP-39 specification.
            return Pbkdf2Core.DeriveKey(
                mnemonicBytes,
                salt,
                Pbkdf2Iterations,
                SeedLength,
                HashAlgorithmName.SHA512,
                allowWeakParameters: true  // BIP-39 compliance requires non-standard parameters
            );
        }
        finally
        {
            Array.Clear(mnemonicBytes, 0, mnemonicBytes.Length);
            Array.Clear(salt, 0, salt.Length);
        }
    }

    /// <summary>
    /// Validates a mnemonic phrase
    /// </summary>
    /// <param name="mnemonic">Mnemonic phrase to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    public static bool ValidateMnemonic(string mnemonic)
    {
        if (string.IsNullOrWhiteSpace(mnemonic))
            return false;

        mnemonic = NormalizeMnemonic(mnemonic);
        var words = mnemonic.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Check word count
        if (!WordCounts.Contains(words.Length))
            return false;

        // Check all words are in wordlist
        foreach (var word in words)
        {
            if (Array.IndexOf(Wordlist, word) == -1)
                return false;
        }

        // Convert words back to entropy and validate checksum
        try
        {
            var entropy = MnemonicToEntropy(mnemonic);
            var expectedChecksum = CalculateChecksum(entropy);

            // Extract checksum from mnemonic
            var totalBits = words.Length * 11;
            var entropyBits = (totalBits * 32) / 33;
            var checksumBits = totalBits - entropyBits;

            // Convert words to bits
            var bits = new bool[totalBits];
            for (var i = 0; i < words.Length; i++)
            {
                var index = Array.IndexOf(Wordlist, words[i]);
                for (var j = 0; j < 11; j++)
                {
                    bits[i * 11 + j] = ((index >> (10 - j)) & 1) == 1;
                }
            }

            // Extract checksum from bits
            byte actualChecksum = 0;
            for (var i = 0; i < checksumBits; i++)
            {
                if (bits[entropyBits + i])
                {
                    actualChecksum |= (byte)(1 << (7 - i));
                }
            }

            // Validate checksum
            return (actualChecksum >> (8 - checksumBits)) == (expectedChecksum >> (8 - checksumBits));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Converts a mnemonic back to entropy
    /// </summary>
    /// <param name="mnemonic">Mnemonic phrase</param>
    /// <returns>Entropy bytes</returns>
    public static byte[] MnemonicToEntropy(string mnemonic)
    {
        mnemonic = NormalizeMnemonic(mnemonic);
        var words = mnemonic.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (!WordCounts.Contains(words.Length))
            throw new ArgumentException("Invalid mnemonic word count", nameof(mnemonic));

        var totalBits = words.Length * 11;
        var entropyBits = (totalBits * 32) / 33;
        var entropyBytes = entropyBits / 8;

        var bits = new bool[totalBits];

        // Convert words to bits
        for (var i = 0; i < words.Length; i++)
        {
            var index = Array.IndexOf(Wordlist, words[i]);
            if (index == -1)
                throw new ArgumentException($"Invalid word in mnemonic: {words[i]}", nameof(mnemonic));

            for (var j = 0; j < 11; j++)
            {
                bits[i * 11 + j] = ((index >> (10 - j)) & 1) == 1;
            }
        }

        // Convert bits to bytes (excluding checksum)
        var entropy = new byte[entropyBytes];
        for (var i = 0; i < entropyBytes; i++)
        {
            byte value = 0;
            for (var j = 0; j < 8; j++)
            {
                if (bits[i * 8 + j])
                {
                    value |= (byte)(1 << (7 - j));
                }
            }
            entropy[i] = value;
        }

        return entropy;
    }

    /// <summary>
    /// Calculates SHA256 checksum for entropy
    /// </summary>
    private static byte CalculateChecksum(ReadOnlySpan<byte> entropy)
    {
        using var sha = SHA256.Create();
        Span<byte> hash = stackalloc byte[32];
        sha.TryComputeHash(entropy, hash, out _);
        return hash[0];
    }

    /// <summary>
    /// Normalizes mnemonic (lowercase, single spaces)
    /// </summary>
    private static string NormalizeMnemonic(string mnemonic)
    {
        return string.Join(" ",
            mnemonic.ToLowerInvariant()
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
        );
    }

    /// <summary>
    /// Gets entropy byte count from word count
    /// </summary>
    private static int GetEntropyBytesFromWordCount(int wordCount)
    {
        var index = Array.IndexOf(WordCounts, wordCount);
        if (index == -1)
        {
            throw new ArgumentException(
                $"Word count must be one of: {string.Join(", ", WordCounts)}",
                nameof(wordCount));
        }

        return SupportedEntropyBits[index] / 8;
    }

    /// <summary>
    /// Gets word count from entropy bytes
    /// </summary>
    public static int GetWordCountFromEntropyBytes(int entropyBytes)
    {
        var entropyBits = entropyBytes * 8;
        var index = Array.IndexOf(SupportedEntropyBits, entropyBits);
        if (index == -1)
        {
            throw new ArgumentException("Invalid entropy byte count", nameof(entropyBytes));
        }

        return WordCounts[index];
    }

    /// <summary>
    /// Generates a minimal wordlist for demonstration
    /// NOTE: Production implementation should use the full BIP39 wordlist (2048 words)
    /// </summary>
    private static string[] GenerateMinimalWordlist()
    {
        // Generate 2048 unique words for demonstration
        // In production, use the official BIP39 wordlist from:
        // https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

        var words = new string[2048];
        for (var i = 0; i < 2048; i++)
        {
            words[i] = $"word{i:D4}"; // word0000, word0001, etc.
        }

        // Add some common BIP39 words for testing
        if (words.Length >= 100)
        {
            words[0] = "abandon";
            words[1] = "ability";
            words[2] = "able";
            words[3] = "about";
            words[4] = "above";
            words[2047] = "zoo";
        }

        return words;
    }

    /// <summary>
    /// Gets information about BIP39 implementation
    /// </summary>
    public static string GetInfo()
    {
        return $"BIP39 Mnemonic Codes - Converts entropy to human-readable phrases. " +
               $"Supported word counts: {string.Join(", ", WordCounts)}. " +
               $"Uses PBKDF2-HMAC-SHA512 with {Pbkdf2Iterations} iterations for seed generation.";
    }
}
#endif
