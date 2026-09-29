using HeroCrypt.Protocols.HdWallet;

namespace HeroCrypt.Tests.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// Tests for BIP39 Mnemonic Codes - Standard for generating deterministic keys from mnemonic phrases.
/// </summary>
public class Bip39MnemonicTests
{

    /// <summary>
    /// Basic functionality tests for mnemonic generation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class MnemonicGeneration
    {
        private readonly Bip39Mnemonic bip39 = new();
        [Fact]
        public void GenerateMnemonic_12Words_Success()
        {
            // Arrange - 128 bits = 16 bytes = 12 words
            var entropy = new byte[16];
            new Random(42).NextBytes(entropy);

            // Act
            var mnemonic = bip39.GenerateMnemonic(entropy);

            // Assert
            var words = mnemonic.Split(' ');
            Assert.Equal(12, words.Length);
        }

        [Fact]
        public void GenerateMnemonic_24Words_Success()
        {
            // Arrange - 256 bits = 32 bytes = 24 words
            var entropy = new byte[32];
            new Random(42).NextBytes(entropy);

            // Act
            var mnemonic = bip39.GenerateMnemonic(entropy);

            // Assert
            var words = mnemonic.Split(' ');
            Assert.Equal(24, words.Length);
        }

        [Theory]
        [InlineData(16, 12)]  // 128 bits -> 12 words
        [InlineData(20, 15)]  // 160 bits -> 15 words
        [InlineData(24, 18)]  // 192 bits -> 18 words
        [InlineData(28, 21)]  // 224 bits -> 21 words
        [InlineData(32, 24)]  // 256 bits -> 24 words
        public void GenerateMnemonic_AllEntropyLengths_ProducesCorrectWordCount(int entropyBytes, int expectedWords)
        {
            var entropy = new byte[entropyBytes];
            new Random(42).NextBytes(entropy);

            var mnemonic = bip39.GenerateMnemonic(entropy);

            var words = mnemonic.Split(' ');
            Assert.Equal(expectedWords, words.Length);
        }

        [Fact]
        public void GenerateRandomMnemonic_Default24Words_Success()
        {
            var mnemonic = bip39.GenerateRandomMnemonic();

            var words = mnemonic.Split(' ');
            Assert.Equal(24, words.Length);
        }

        [Theory]
        [InlineData(12)]
        [InlineData(15)]
        [InlineData(18)]
        [InlineData(21)]
        [InlineData(24)]
        public void GenerateRandomMnemonic_SpecifiedWordCount_Success(int wordCount)
        {
            var mnemonic = bip39.GenerateRandomMnemonic(wordCount);

            var words = mnemonic.Split(' ');
            Assert.Equal(wordCount, words.Length);
        }

        [Fact]
        public void GenerateMnemonic_DeterministicFromEntropy_Success()
        {
            var entropy = new byte[16];
            for (var i = 0; i < entropy.Length; i++)
            {
                entropy[i] = (byte)(i + 1);
            }

            var mnemonic1 = bip39.GenerateMnemonic(entropy);
            var mnemonic2 = bip39.GenerateMnemonic(entropy);

            Assert.Equal(mnemonic1, mnemonic2);
        }
    }

    /// <summary>
    /// Tests for seed derivation from mnemonics.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SeedDerivation
    {
        private readonly Bip39Mnemonic bip39 = new();

        [Fact]
        public void MnemonicToSeed_WithoutPassphrase_Success()
        {
            var mnemonic = bip39.GenerateRandomMnemonic(12);

            var seed = bip39.MnemonicToSeed(mnemonic);

            Assert.NotNull(seed);
            Assert.Equal(64, seed.Length);
        }

        [Fact]
        public void MnemonicToSeed_WithPassphrase_Success()
        {
            var mnemonic = bip39.GenerateRandomMnemonic(12);
            var passphrase = "my secret passphrase";

            var seed = bip39.MnemonicToSeed(mnemonic, passphrase);

            Assert.NotNull(seed);
            Assert.Equal(64, seed.Length);
        }

        [Fact]
        public void MnemonicToSeed_DifferentPassphrases_ProduceDifferentSeeds()
        {
            var mnemonic = bip39.GenerateRandomMnemonic(12);

            var seed1 = bip39.MnemonicToSeed(mnemonic, "");
            var seed2 = bip39.MnemonicToSeed(mnemonic, "passphrase1");
            var seed3 = bip39.MnemonicToSeed(mnemonic, "passphrase2");

            Assert.NotEqual(seed1, seed2);
            Assert.NotEqual(seed1, seed3);
            Assert.NotEqual(seed2, seed3);
        }

        [Fact]
        public void MnemonicToSeed_SameMnemonicAndPassphrase_ProducesSameSeed()
        {
            var mnemonic = bip39.GenerateRandomMnemonic(12);
            var passphrase = "test";

            var seed1 = bip39.MnemonicToSeed(mnemonic, passphrase);
            var seed2 = bip39.MnemonicToSeed(mnemonic, passphrase);

            Assert.Equal(seed1, seed2);
        }
    }

    /// <summary>
    /// Tests for mnemonic validation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class Validation
    {
        private readonly Bip39Mnemonic bip39 = new();

        [Fact]
        public void ValidateMnemonic_ValidMnemonic_ReturnsTrue()
        {
            var entropy = new byte[16];
            new Random(42).NextBytes(entropy);
            var mnemonic = bip39.GenerateMnemonic(entropy);

            var isValid = bip39.ValidateMnemonic(mnemonic);

            Assert.True(isValid);
        }

        [Fact]
        public void ValidateMnemonic_CaseInsensitive_Success()
        {
            var entropy = new byte[16];
            new Random(42).NextBytes(entropy);
            var mnemonic = bip39.GenerateMnemonic(entropy);

            var lowerValid = bip39.ValidateMnemonic(mnemonic.ToLowerInvariant());
            var upperValid = bip39.ValidateMnemonic(mnemonic.ToUpperInvariant());

            Assert.True(lowerValid);
            Assert.True(upperValid);
        }

        [Fact]
        public void ValidateMnemonic_ExtraSpaces_HandledCorrectly()
        {
            var entropy = new byte[16];
            new Random(42).NextBytes(entropy);
            var mnemonic = bip39.GenerateMnemonic(entropy);
            var mnemonicWithSpaces = "  " + mnemonic.Replace(" ", "  ") + "  ";

            var isValid = bip39.ValidateMnemonic(mnemonicWithSpaces);

            Assert.True(isValid);
        }

        [Fact]
        public void GetWordCountFromEntropyBytes_AllValidSizes_Success()
        {
            Assert.Equal(12, bip39.GetWordCountFromEntropyBytes(16));
            Assert.Equal(15, bip39.GetWordCountFromEntropyBytes(20));
            Assert.Equal(18, bip39.GetWordCountFromEntropyBytes(24));
            Assert.Equal(21, bip39.GetWordCountFromEntropyBytes(28));
            Assert.Equal(24, bip39.GetWordCountFromEntropyBytes(32));
        }
    }

    /// <summary>
    /// Tests for entropy conversion round-trips.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EntropyConversion
    {
        private readonly Bip39Mnemonic bip39 = new();

        [Fact]
        public void MnemonicToEntropy_RoundTrip_Success()
        {
            var originalEntropy = new byte[16];
            new Random(42).NextBytes(originalEntropy);
            var mnemonic = bip39.GenerateMnemonic(originalEntropy);

            var recoveredEntropy = bip39.MnemonicToEntropy(mnemonic);

            Assert.Equal(originalEntropy, recoveredEntropy);
        }
    }

    /// <summary>
    /// Tests for edge cases and invalid inputs.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly Bip39Mnemonic bip39 = new();

        [Fact]
        public void GenerateMnemonic_InvalidEntropyLength_ThrowsException()
        {
            var invalidEntropy = new byte[15];

            Assert.Throws<ArgumentException>(() =>
                bip39.GenerateMnemonic(invalidEntropy));
        }

        [Fact]
        public void GenerateRandomMnemonic_InvalidWordCount_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() =>
                bip39.GenerateRandomMnemonic(13));
        }

        [Fact]
        public void MnemonicToSeed_EmptyMnemonic_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() =>
                bip39.MnemonicToSeed(""));
        }

        [Fact]
        public void ValidateMnemonic_InvalidWordCount_ReturnsFalse()
        {
            var mnemonic = string.Join(" ", Enumerable.Repeat("word0001", 13));

            var isValid = bip39.ValidateMnemonic(mnemonic);

            Assert.False(isValid);
        }

        [Fact]
        public void ValidateMnemonic_EmptyString_ReturnsFalse()
        {
            var isValid = bip39.ValidateMnemonic("");

            Assert.False(isValid);
        }

        [Fact]
        public void MnemonicToEntropy_InvalidMnemonic_ThrowsException()
        {
            var invalidMnemonic = "invalid words that are not in wordlist";

            Assert.Throws<ArgumentException>(() =>
                bip39.MnemonicToEntropy(invalidMnemonic));
        }

        [Fact]
        public void GetWordCountFromEntropyBytes_InvalidSize_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() =>
                bip39.GetWordCountFromEntropyBytes(15));
        }
    }
}
#endif
