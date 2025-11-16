using HeroCrypt.Cryptography.Protocols;
using System.Text;

namespace HeroCrypt.Tests;

#if !NETSTANDARD2_0

/// <summary>
/// Tests for BIP32 Hierarchical Deterministic Wallets
/// </summary>
public class Bip32HdWalletTests
{
    private readonly byte[] _testSeed = Encoding.UTF8.GetBytes("test seed for BIP32 wallet implementation 1234567890");

    [Fact]
    public void GenerateMasterKey_ValidSeed_Success()
    {
        // Arrange - Use 64-byte seed (recommended)
        var seed = new byte[64];
        new Random(42).NextBytes(seed);

        // Act
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Assert
        Assert.NotNull(masterKey);
        Assert.Equal(32, masterKey.Key.Length); // Private key is 32 bytes
        Assert.Equal(32, masterKey.ChainCode.Length);
        Assert.Equal(0, masterKey.Depth);
        Assert.True(masterKey.IsPrivate);
    }

    [Fact]
    public void GenerateMasterKey_MinimumSeed_Success()
    {
        // Arrange - Minimum 16 bytes
        var seed = new byte[16];
        new Random(42).NextBytes(seed);

        // Act
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Assert
        Assert.NotNull(masterKey);
        Assert.Equal(32, masterKey.Key.Length);
    }

    [Fact]
    public void GenerateMasterKey_SeedTooShort_ThrowsException()
    {
        // Arrange
        var seed = new byte[15]; // Below minimum

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip32HdWallet.GenerateMasterKey(seed));
    }

    [Fact]
    public void GenerateMasterKey_SeedTooLong_ThrowsException()
    {
        // Arrange
        var seed = new byte[65]; // Above maximum

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Bip32HdWallet.GenerateMasterKey(seed));
    }

    [Fact]
    public void DeriveChild_NormalDerivation_Success()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Derive child at index 0 (normal derivation)
        var childKey = Bip32HdWallet.DeriveChild(masterKey, 0);

        // Assert
        Assert.NotNull(childKey);
        Assert.Equal(32, childKey.Key.Length);
        Assert.Equal(1, childKey.Depth); // Depth increased
        Assert.NotEqual(masterKey.Key, childKey.Key); // Keys should be different
        Assert.True(childKey.IsPrivate);
    }

    [Fact]
    public void DeriveChild_HardenedDerivation_Success()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Derive hardened child (index >= 2^31)
        var childKey = Bip32HdWallet.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset);

        // Assert
        Assert.NotNull(childKey);
        Assert.Equal(32, childKey.Key.Length);
        Assert.Equal(1, childKey.Depth);
        Assert.Equal(Bip32HdWallet.HardenedOffset, childKey.ChildIndex);
    }

    [Fact]
    public void DeriveChild_MultipleChildren_ProduceDifferentKeys()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act
        var child0 = Bip32HdWallet.DeriveChild(masterKey, 0);
        var child1 = Bip32HdWallet.DeriveChild(masterKey, 1);
        var child2 = Bip32HdWallet.DeriveChild(masterKey, 2);

        // Assert - All children should have different keys
        Assert.NotEqual(child0.Key, child1.Key);
        Assert.NotEqual(child0.Key, child2.Key);
        Assert.NotEqual(child1.Key, child2.Key);
    }

    [Fact]
    public void ParsePath_ValidPath_ReturnsIndices()
    {
        // Act & Assert - Various valid paths
        var indices1 = Bip32HdWallet.ParsePath("m/44'/0'/0'/0/0");
        Assert.Equal(5, indices1.Length);
        Assert.Equal(Bip32HdWallet.HardenedOffset + 44, indices1[0]);
        Assert.Equal(Bip32HdWallet.HardenedOffset + 0, indices1[1]);
        Assert.Equal(Bip32HdWallet.HardenedOffset + 0, indices1[2]);
        Assert.Equal(0u, indices1[3]);
        Assert.Equal(0u, indices1[4]);

        var indices2 = Bip32HdWallet.ParsePath("m/0/1/2");
        Assert.Equal(3, indices2.Length);
        Assert.Equal(0u, indices2[0]);
        Assert.Equal(1u, indices2[1]);
        Assert.Equal(2u, indices2[2]);
    }

    [Fact]
    public void ParsePath_MasterOnly_ReturnsEmpty()
    {
        // Act
        var indices = Bip32HdWallet.ParsePath("m");

        // Assert
        Assert.Empty(indices);
    }

    [Fact]
    public void ParsePath_WithoutPrefix_Success()
    {
        // Act
        var indices = Bip32HdWallet.ParsePath("0/1/2");

        // Assert
        Assert.Equal(3, indices.Length);
        Assert.Equal(0u, indices[0]);
        Assert.Equal(1u, indices[1]);
        Assert.Equal(2u, indices[2]);
    }

    [Fact]
    public void ParsePath_InvalidPath_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Bip32HdWallet.ParsePath(""));
        Assert.Throws<ArgumentException>(() => Bip32HdWallet.ParsePath("m/abc"));
        Assert.Throws<ArgumentException>(() => Bip32HdWallet.ParsePath("m/0/invalid/2"));
    }

    [Fact]
    public void FormatIndex_NormalAndHardened_Success()
    {
        // Act & Assert
        Assert.Equal("0", Bip32HdWallet.FormatIndex(0));
        Assert.Equal("1", Bip32HdWallet.FormatIndex(1));
        Assert.Equal("44'", Bip32HdWallet.FormatIndex(Bip32HdWallet.HardenedOffset + 44));
        Assert.Equal("0'", Bip32HdWallet.FormatIndex(Bip32HdWallet.HardenedOffset));
    }

    [Fact]
    public void FormatPath_VariousPaths_Success()
    {
        // Arrange
        var indices1 = new uint[] { Bip32HdWallet.HardenedOffset + 44, 0, 1 };
        var indices2 = new uint[] { 0, 1, 2 };
        var indices3 = Array.Empty<uint>();

        // Act
        var path1 = Bip32HdWallet.FormatPath(indices1);
        var path2 = Bip32HdWallet.FormatPath(indices2);
        var path3 = Bip32HdWallet.FormatPath(indices3);

        // Assert
        Assert.Equal("m/44'/0/1", path1);
        Assert.Equal("m/0/1/2", path2);
        Assert.Equal("m", path3);
    }

    [Fact]
    public void DerivePath_SimplePathSync_Success()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act
        var derivedKey = Bip32HdWallet.DerivePath(masterKey, "m/0/1");

        // Assert
        Assert.NotNull(derivedKey);
        Assert.Equal(2, derivedKey.Depth);
    }

    [Fact]
    public void DerivePath_BIP44Path_Success()
    {
        // Arrange - Standard BIP44 path for Bitcoin
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - m/44'/0'/0'/0/0 (BIP44 Bitcoin receiving address)
        var derivedKey = Bip32HdWallet.DerivePath(masterKey, "m/44'/0'/0'/0/0");

        // Assert
        Assert.NotNull(derivedKey);
        Assert.Equal(5, derivedKey.Depth);
    }

    [Fact]
    public void IsValidPath_VariousPaths_ReturnsExpected()
    {
        // Act & Assert
        Assert.True(Bip32HdWallet.IsValidPath("m"));
        Assert.True(Bip32HdWallet.IsValidPath("m/0"));
        Assert.True(Bip32HdWallet.IsValidPath("m/44'/0'/0'"));
        Assert.True(Bip32HdWallet.IsValidPath("0/1/2"));

        Assert.False(Bip32HdWallet.IsValidPath(""));
        Assert.False(Bip32HdWallet.IsValidPath("m/abc"));
        Assert.False(Bip32HdWallet.IsValidPath("invalid"));
    }

    [Fact]
    public void ExtendedKey_IsPrivate_ReturnsCorrectValue()
    {
        // Arrange
        var privateKey = new byte[32];
        var publicKey = new byte[33];
        var chainCode = new byte[32];

        // Act
        var extendedPrivate = new Bip32HdWallet.ExtendedKey(privateKey, chainCode);
        var extendedPublic = new Bip32HdWallet.ExtendedKey(publicKey, chainCode);

        // Assert
        Assert.True(extendedPrivate.IsPrivate);
        Assert.False(extendedPublic.IsPrivate);
    }

    [Fact]
    public void ExtendedKey_InvalidKeyLength_ThrowsException()
    {
        // Arrange
        var invalidKey = new byte[30]; // Not 32 or 33
        var chainCode = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new Bip32HdWallet.ExtendedKey(invalidKey, chainCode));
    }

    [Fact]
    public void ExtendedKey_InvalidChainCodeLength_ThrowsException()
    {
        // Arrange
        var key = new byte[32];
        var invalidChainCode = new byte[30]; // Not 32

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new Bip32HdWallet.ExtendedKey(key, invalidChainCode));
    }

    [Fact]
    public void ExtendedKey_Clear_ClearsData()
    {
        // Arrange
        var key = new byte[32];
        for (var i = 0; i < key.Length; i++) key[i] = (byte)(i + 1);
        var chainCode = new byte[32];
        for (var i = 0; i < chainCode.Length; i++) chainCode[i] = (byte)(i + 100);

        var extendedKey = new Bip32HdWallet.ExtendedKey(key, chainCode);

        // Act
        extendedKey.Clear();

        // Assert - All sensitive data should be zeroed
        Assert.All(extendedKey.Key, b => Assert.Equal(0, b));
        Assert.All(extendedKey.ChainCode, b => Assert.Equal(0, b));
    }

    [Fact]
    public void GetInfo_ReturnsDescription()
    {
        // Act
        var info = Bip32HdWallet.GetInfo();

        // Assert
        Assert.Contains("BIP32", info);
        Assert.Contains("Hierarchical", info);
    }

    [Fact]
    public void DeterministicDerivation_SameSeed_ProducesSameKeys()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);

        // Act - Generate keys twice from same seed
        var master1 = Bip32HdWallet.GenerateMasterKey(seed);
        var master2 = Bip32HdWallet.GenerateMasterKey(seed);

        // Assert - Should produce identical keys
        Assert.Equal(master1.Key, master2.Key);
        Assert.Equal(master1.ChainCode, master2.ChainCode);
    }
}
#endif
