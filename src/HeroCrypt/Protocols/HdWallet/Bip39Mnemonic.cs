using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Pbkdf2;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.HdWallet;

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
/// <remarks>Generation and checksum validation use the official English wordlist.
/// Raw seed conversion applies NFKD to mnemonic and passphrase without wordlist
/// validation or case/whitespace changes. Validate wallet inputs separately or use
/// HdWalletBuilder. Callers must clear returned seed/entropy buffers; mnemonic and
/// passphrase strings cannot be reliably erased by managed code.</remarks>
public sealed class Bip39Mnemonic
{
    private readonly SecurityPolicyOptions policy;

    /// <summary>
    /// Initializes a new instance of the Bip39Mnemonic class.
    /// </summary>
    /// <param name="policy">Optional security policy. If null, uses SecurityPolicy.CurrentPolicy.</param>
    public Bip39Mnemonic(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
    }
    private static readonly int[] SupportedEntropyBits = [128, 160, 192, 224, 256];
    private static readonly int[] WordCounts = [12, 15, 18, 21, 24];
    private const int Pbkdf2Iterations = 2048;
    private const int SeedLength = 64; // 512 bits

    /// <summary>
    /// Official, ordered 2048-word BIP39 English wordlist, embedded with attribution.
    /// </summary>
    private static readonly string[] Wordlist = LoadEnglishWordlist();

    /// <summary>
    /// Generates a mnemonic from entropy
    /// </summary>
    /// <param name="entropy">Entropy bytes (16/20/24/28/32 bytes for 12/15/18/21/24 words)</param>
    /// <returns>Mnemonic phrase</returns>
    public string GenerateMnemonic(ReadOnlySpan<byte> entropy)
    {
        if (entropy.Length is not (16 or 20 or 24 or 28 or 32))
        {
            throw new ArgumentException(
                $"Entropy must be {string.Join(", ", SupportedEntropyBits.Select(b => b / 8))} bytes",
                nameof(entropy));
        }
        var entropyBits = entropy.Length * 8;

        // Calculate checksum
        var checksumBits = entropyBits / 32;
        var checksum = CalculateChecksum(entropy);

        // Combine entropy and checksum into bits
        var totalBits = entropyBits + checksumBits;
        var bits = new bool[totalBits];
        try
        {
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
        finally
        {
            Array.Clear(bits);
        }
    }

    /// <summary>
    /// Generates a random mnemonic with specified word count
    /// </summary>
    /// <param name="wordCount">Number of words (12, 15, 18, 21, or 24)</param>
    /// <returns>Random mnemonic phrase</returns>
    public string GenerateRandomMnemonic(int wordCount = 24)
    {
        var entropyBytes = GetEntropyBytesFromWordCount(wordCount);
        var entropy = new byte[entropyBytes];

        try
        {
            RandomNumberGenerator.Fill(entropy);
            return GenerateMnemonic(entropy);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(entropy);
        }
    }

    /// <summary>
    /// Converts raw mnemonic text to a seed using BIP39 NFKD and PBKDF2-HMAC-SHA512.
    /// Does not validate an English wordlist/checksum or canonicalize case/spacing.
    /// </summary>
    /// <param name="mnemonic">Mnemonic phrase</param>
    /// <param name="passphrase">Optional passphrase (empty string if none)</param>
    /// <returns>512-bit seed for BIP32</returns>
    public byte[] MnemonicToSeed(string mnemonic, string passphrase = "")
    {
        if (string.IsNullOrWhiteSpace(mnemonic))
        {
            throw new ArgumentException("Mnemonic cannot be empty", nameof(mnemonic));
        }

        byte[]? salt = null;
        byte[]? mnemonicBytes = null;
        try
        {
            // BIP39 applies NFKD only; raw text case and spaces affect the seed.
            mnemonicBytes = Encoding.UTF8.GetBytes(mnemonic.Normalize(NormalizationForm.FormKD));
            salt = Encoding.UTF8.GetBytes(("mnemonic" + (passphrase ?? "")).Normalize(NormalizationForm.FormKD));
            policy.ValidateKdf("PBKDF2-SHA512");
            // Generate seed using PBKDF2-HMAC-SHA512
            // NOTE: BIP-39 standard specifies 2048 iterations and "mnemonic" + passphrase as salt.
            // These parameters are below our normal security recommendations but are required for
            // standards compliance. This is intentional per BIP-39 specification.
            var pbkdf2 = new Pbkdf2Core(policy);
            return pbkdf2.DeriveKey(
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
            if (mnemonicBytes != null) SecureMemoryOperations.SecureClear(mnemonicBytes);
            if (salt != null) SecureMemoryOperations.SecureClear(salt);
        }
    }

    /// <summary>
    /// Validates a mnemonic phrase
    /// </summary>
    /// <param name="mnemonic">Mnemonic phrase to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    public bool ValidateMnemonic(string mnemonic)
    {
        if (string.IsNullOrWhiteSpace(mnemonic))
        {
            return false;
        }

        byte[]? entropy = null;
        try
        {
            entropy = MnemonicToEntropy(mnemonic);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        finally
        {
            if (entropy != null) SecureMemoryOperations.SecureClear(entropy);
        }
    }

    /// <summary>
    /// Converts a valid English mnemonic back to entropy, checking its checksum.
    /// </summary>
    /// <param name="mnemonic">Mnemonic phrase</param>
    /// <returns>Entropy bytes</returns>
    public byte[] MnemonicToEntropy(string mnemonic)
    {
        ArgumentNullException.ThrowIfNull(mnemonic);
        mnemonic = NormalizeMnemonic(mnemonic);
        var words = mnemonic.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (!WordCounts.Contains(words.Length))
        {
            throw new ArgumentException("Invalid mnemonic word count", nameof(mnemonic));
        }

        var totalBits = words.Length * 11;
        var entropyBits = (totalBits * 32) / 33;
        var entropyBytes = entropyBits / 8;

        var bits = new bool[totalBits];
        byte[]? entropy = null;
        var succeeded = false;
        try
        {
            // Convert words to bits
            for (var i = 0; i < words.Length; i++)
            {
                var index = Array.IndexOf(Wordlist, words[i]);
                if (index == -1)
                {
                    throw new ArgumentException("Mnemonic contains a word outside the English BIP39 wordlist.", nameof(mnemonic));
                }

                for (var j = 0; j < 11; j++)
                {
                    bits[i * 11 + j] = ((index >> (10 - j)) & 1) == 1;
                }
            }

            // Convert bits to bytes (excluding checksum)
            entropy = new byte[entropyBytes];
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

            var checksumBits = totalBits - entropyBits;
            var actualChecksum = 0;
            for (var i = 0; i < checksumBits; i++)
            {
                actualChecksum = (actualChecksum << 1) | (bits[entropyBits + i] ? 1 : 0);
            }
            if (actualChecksum != CalculateChecksum(entropy) >> (8 - checksumBits))
            {
                throw new ArgumentException("Invalid mnemonic checksum.", nameof(mnemonic));
            }
            succeeded = true;
            return entropy;
        }
        finally
        {
            Array.Clear(bits);
            if (!succeeded && entropy != null) SecureMemoryOperations.SecureClear(entropy);
        }
    }

    /// <summary>
    /// Calculates SHA256 checksum for entropy
    /// </summary>
    private byte CalculateChecksum(ReadOnlySpan<byte> entropy)
    {
        policy.ValidateHash("SHA256");
        Span<byte> hash = stackalloc byte[32];
        try
        {
            SHA256.HashData(entropy, hash);
            return hash[0];
        }
        finally
        {
            SecureMemoryOperations.SecureClear(hash);
        }
    }

    /// <summary>
    /// Canonicalizes English wordlist input; raw seed conversion does not use this.
    /// </summary>
    private static string NormalizeMnemonic(string mnemonic)
    {
        return string.Join(" ",
            mnemonic.Normalize(NormalizationForm.FormKD).ToLowerInvariant()
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
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
    public int GetWordCountFromEntropyBytes(int entropyBytes)
    {
        if (entropyBytes is not (16 or 20 or 24 or 28 or 32))
        {
            throw new ArgumentException("Invalid entropy byte count", nameof(entropyBytes));
        }
        var index = Array.IndexOf(SupportedEntropyBits, entropyBytes * 8);
        return WordCounts[index];
    }

    /// <summary>
    /// Loads the official BIP39 English wordlist from its assembly resource.
    /// </summary>
    private static string[] LoadEnglishWordlist()
    {
        using var stream = typeof(Bip39Mnemonic).Assembly.GetManifestResourceStream(
            "HeroCrypt.Protocols.HdWallet.Bip39English.txt")
            ?? throw new InvalidOperationException("The BIP39 English wordlist resource is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var words = reader.ReadToEnd().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (words.Length != 2048)
        {
            throw new InvalidOperationException("The BIP39 English wordlist must contain 2048 words.");
        }

        return words;
    }
}
#endif
