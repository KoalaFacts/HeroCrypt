using HeroCrypt.Cryptography.HDWallet;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for BIP39 Mnemonic Codes
/// </summary>
public class Bip39MnemonicTests
{
    [Fact]
    public void GenerateMnemonic_12Words_Success()
    {
        // Arrange - 128 bits = 16 bytes = 12 words
        var entropy = new byte[16];
        new Random(42).NextBytes(entropy);

        // Act
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(entropy);

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
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(entropy);

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
        // Arrange
        var entropy = new byte[entropyBytes];
        new Random(42).NextBytes(entropy);

        // Act
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(entropy);

        // Assert
        var words = mnemonic.Split(' ');
        Assert.Equal(expectedWords, words.Length);
    }

    [Fact]
    public void GenerateMnemonic_InvalidEntropyLength_ThrowsException()
    {
        // Arrange - 15 bytes is not a valid entropy length
        var invalidEntropy = new byte[15];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip39Mnemonic.GenerateMnemonic(invalidEntropy));
    }

    [Fact]
    public void GenerateRandomMnemonic_Default24Words_Success()
    {
        // Act
        var mnemonic = Bip39Mnemonic.GenerateRandomMnemonic();

        // Assert
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
        // Act
        var mnemonic = Bip39Mnemonic.GenerateRandomMnemonic(wordCount);

        // Assert
        var words = mnemonic.Split(' ');
        Assert.Equal(wordCount, words.Length);
    }

    [Fact]
    public void GenerateRandomMnemonic_InvalidWordCount_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip39Mnemonic.GenerateRandomMnemonic(13)); // Invalid word count
    }

    [Fact]
    public void MnemonicToSeed_WithoutPassphrase_Success()
    {
        // Arrange
        var mnemonic = Bip39Mnemonic.GenerateRandomMnemonic(12);

        // Act
        var seed = Bip39Mnemonic.MnemonicToSeed(mnemonic);

        // Assert
        Assert.NotNull(seed);
        Assert.Equal(64, seed.Length); // BIP39 produces 512-bit seed
    }

    [Fact]
    public void MnemonicToSeed_WithPassphrase_Success()
    {
        // Arrange
        var mnemonic = Bip39Mnemonic.GenerateRandomMnemonic(12);
        var passphrase = "my secret passphrase";

        // Act
        var seed = Bip39Mnemonic.MnemonicToSeed(mnemonic, passphrase);

        // Assert
        Assert.NotNull(seed);
        Assert.Equal(64, seed.Length);
    }

    [Fact]
    public void MnemonicToSeed_DifferentPassphrases_ProduceDifferentSeeds()
    {
        // Arrange
        var mnemonic = Bip39Mnemonic.GenerateRandomMnemonic(12);

        // Act
        var seed1 = Bip39Mnemonic.MnemonicToSeed(mnemonic, "");
        var seed2 = Bip39Mnemonic.MnemonicToSeed(mnemonic, "passphrase1");
        var seed3 = Bip39Mnemonic.MnemonicToSeed(mnemonic, "passphrase2");

        // Assert - Different passphrases should produce different seeds
        Assert.NotEqual(seed1, seed2);
        Assert.NotEqual(seed1, seed3);
        Assert.NotEqual(seed2, seed3);
    }

    [Fact]
    public void MnemonicToSeed_SameMnemonicAndPassphrase_ProducesSameSeed()
    {
        // Arrange
        var mnemonic = Bip39Mnemonic.GenerateRandomMnemonic(12);
        var passphrase = "test";

        // Act
        var seed1 = Bip39Mnemonic.MnemonicToSeed(mnemonic, passphrase);
        var seed2 = Bip39Mnemonic.MnemonicToSeed(mnemonic, passphrase);

        // Assert - Same inputs should produce same output
        Assert.Equal(seed1, seed2);
    }

    [Fact]
    public void MnemonicToSeed_EmptyMnemonic_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip39Mnemonic.MnemonicToSeed(""));
    }

    [Fact]
    public void ValidateMnemonic_ValidMnemonic_ReturnsTrue()
    {
        // Arrange
        var entropy = new byte[16];
        new Random(42).NextBytes(entropy);
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(entropy);

        // Act
        var isValid = Bip39Mnemonic.ValidateMnemonic(mnemonic);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateMnemonic_InvalidWordCount_ReturnsFalse()
    {
        // Arrange - 13 words is not valid
        var mnemonic = string.Join(" ", Enumerable.Repeat("word0001", 13));

        // Act
        var isValid = Bip39Mnemonic.ValidateMnemonic(mnemonic);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateMnemonic_EmptyString_ReturnsFalse()
    {
        // Act
        var isValid = Bip39Mnemonic.ValidateMnemonic("");

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void MnemonicToEntropy_RoundTrip_Success()
    {
        // Arrange
        var originalEntropy = new byte[16];
        new Random(42).NextBytes(originalEntropy);
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(originalEntropy);

        // Act
        var recoveredEntropy = Bip39Mnemonic.MnemonicToEntropy(mnemonic);

        // Assert
        Assert.Equal(originalEntropy, recoveredEntropy);
    }

    [Fact]
    public void MnemonicToEntropy_InvalidMnemonic_ThrowsException()
    {
        // Arrange - Mnemonic with words not in wordlist
        var invalidMnemonic = "invalid words that are not in wordlist";

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip39Mnemonic.MnemonicToEntropy(invalidMnemonic));
    }

    [Fact]
    public void GetWordCountFromEntropyBytes_AllValidSizes_Success()
    {
        // Act & Assert
        Assert.Equal(12, Bip39Mnemonic.GetWordCountFromEntropyBytes(16));
        Assert.Equal(15, Bip39Mnemonic.GetWordCountFromEntropyBytes(20));
        Assert.Equal(18, Bip39Mnemonic.GetWordCountFromEntropyBytes(24));
        Assert.Equal(21, Bip39Mnemonic.GetWordCountFromEntropyBytes(28));
        Assert.Equal(24, Bip39Mnemonic.GetWordCountFromEntropyBytes(32));
    }

    [Fact]
    public void GetWordCountFromEntropyBytes_InvalidSize_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip39Mnemonic.GetWordCountFromEntropyBytes(15));
    }

    [Fact]
    public void GetInfo_ReturnsDescription()
    {
        // Act
        var info = Bip39Mnemonic.GetInfo();

        // Assert
        Assert.Contains("BIP39", info);
        Assert.Contains("Mnemonic", info);
        Assert.Contains("2048", info.ToString()); // PBKDF2 iterations
    }

    [Fact]
    public void GenerateMnemonic_DeterministicFromEntropy_Success()
    {
        // Arrange
        var entropy = new byte[16];
        for (var i = 0; i < entropy.Length; i++)
            entropy[i] = (byte)(i + 1);

        // Act - Generate mnemonic twice
        var mnemonic1 = Bip39Mnemonic.GenerateMnemonic(entropy);
        var mnemonic2 = Bip39Mnemonic.GenerateMnemonic(entropy);

        // Assert - Should be identical
        Assert.Equal(mnemonic1, mnemonic2);
    }

    [Fact]
    public void ValidateMnemonic_CaseInsensitive_Success()
    {
        // Arrange
        var entropy = new byte[16];
        new Random(42).NextBytes(entropy);
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(entropy);

        // Act - Test with different cases
        var lowerValid = Bip39Mnemonic.ValidateMnemonic(mnemonic.ToLowerInvariant());
        var upperValid = Bip39Mnemonic.ValidateMnemonic(mnemonic.ToUpperInvariant());

        // Assert - Should accept both cases
        Assert.True(lowerValid);
        Assert.True(upperValid);
    }

    [Fact]
    public void ValidateMnemonic_ExtraSpaces_HandledCorrectly()
    {
        // Arrange
        var entropy = new byte[16];
        new Random(42).NextBytes(entropy);
        var mnemonic = Bip39Mnemonic.GenerateMnemonic(entropy);
        var mnemonicWithSpaces = "  " + mnemonic.Replace(" ", "  ") + "  "; // Extra spaces

        // Act
        var isValid = Bip39Mnemonic.ValidateMnemonic(mnemonicWithSpaces);

        // Assert - Should handle extra spaces
        Assert.True(isValid);
    }
}
