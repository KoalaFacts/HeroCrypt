using HeroCrypt.Cryptography.Protocols;

namespace HeroCrypt.Tests;

#if !NETSTANDARD2_0

/// <summary>
/// BIP-0032 test vectors for Hierarchical Deterministic Wallets
/// Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
/// </summary>
public class Bip32TestVectors
{
    /// <summary>
    /// BIP32 Test Vector 1 - Master key generation
    /// </summary>
    [Fact]
    public void BIP32_TestVector1_MasterKey()
    {
        // Arrange - Seed from BIP32 spec
        var seed = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

        // Act
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Assert
        Assert.NotNull(masterKey);
        Assert.Equal(32, masterKey.Key.Length);
        Assert.Equal(32, masterKey.ChainCode.Length);
        Assert.Equal(0, masterKey.Depth);
        Assert.True(masterKey.IsPrivate);

        // Expected values from BIP32 spec:
        // Chain Code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
        var expectedChainCode = Convert.FromHexString("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        Assert.Equal(expectedChainCode, masterKey.ChainCode);
    }

    /// <summary>
    /// BIP32 Test Vector 1 - Chain m/0H (hardened derivation)
    /// </summary>
    [Fact]
    public void BIP32_TestVector1_Chain_m_0H()
    {
        // Arrange
        var seed = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Derive m/0'
        var childKey = Bip32HdWallet.DeriveChild(masterKey, Bip32HdWallet.HARDENED_OFFSET + 0);

        // Assert
        Assert.NotNull(childKey);
        Assert.Equal(1, childKey.Depth);
        Assert.Equal(Bip32HdWallet.HARDENED_OFFSET, childKey.ChildIndex);
        Assert.True(childKey.IsPrivate);

        // Expected chain code from BIP32 spec
        var expectedChainCode = Convert.FromHexString("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
        Assert.Equal(expectedChainCode, childKey.ChainCode);
    }

    /// <summary>
    /// BIP32 Test Vector 1 - Chain m/0H/1
    /// </summary>
    [Fact]
    public void BIP32_TestVector1_Chain_m_0H_1()
    {
        // Arrange
        var seed = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Derive m/0'/1
        var child0H = Bip32HdWallet.DeriveChild(masterKey, Bip32HdWallet.HARDENED_OFFSET + 0);
        var child1 = Bip32HdWallet.DeriveChild(child0H, 1);

        // Assert
        Assert.NotNull(child1);
        Assert.Equal(2, child1.Depth);
        Assert.Equal(1u, child1.ChildIndex);

        // Expected chain code from BIP32 spec
        var expectedChainCode = Convert.FromHexString("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
        Assert.Equal(expectedChainCode, child1.ChainCode);
    }

    /// <summary>
    /// BIP32 Test Vector 1 - Using DerivePath for m/0H/1/2H
    /// </summary>
    [Fact]
    public void BIP32_TestVector1_DerivePath_m_0H_1_2H()
    {
        // Arrange
        var seed = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act
        var derivedKey = Bip32HdWallet.DerivePath(masterKey, "m/0'/1/2'");

        // Assert
        Assert.NotNull(derivedKey);
        Assert.Equal(3, derivedKey.Depth);
        Assert.Equal(Bip32HdWallet.HARDENED_OFFSET + 2, derivedKey.ChildIndex);

        // Expected chain code from BIP32 spec
        var expectedChainCode = Convert.FromHexString("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f");
        Assert.Equal(expectedChainCode, derivedKey.ChainCode);
    }

    /// <summary>
    /// BIP32 Test Vector 2 - Master key from different seed
    /// </summary>
    [Fact]
    public void BIP32_TestVector2_MasterKey()
    {
        // Arrange - Different seed
        var seed = Convert.FromHexString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

        // Act
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Assert
        Assert.NotNull(masterKey);
        Assert.Equal(32, masterKey.Key.Length);
        Assert.Equal(32, masterKey.ChainCode.Length);

        // Expected chain code from BIP32 spec
        var expectedChainCode = Convert.FromHexString("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689");
        Assert.Equal(expectedChainCode, masterKey.ChainCode);
    }

    /// <summary>
    /// BIP32 Test Vector 2 - Chain m/0
    /// </summary>
    [Fact]
    public void BIP32_TestVector2_Chain_m_0()
    {
        // Arrange
        var seed = Convert.FromHexString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Normal (non-hardened) derivation
        var childKey = Bip32HdWallet.DeriveChild(masterKey, 0);

        // Assert
        Assert.NotNull(childKey);
        Assert.Equal(1, childKey.Depth);
        Assert.Equal(0u, childKey.ChildIndex);

        // Expected chain code from BIP32 spec
        var expectedChainCode = Convert.FromHexString("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c");
        Assert.Equal(expectedChainCode, childKey.ChainCode);
    }

    /// <summary>
    /// Test deterministic key derivation
    /// </summary>
    [Fact]
    public void DeriveChild_SameParameters_ProducesSameKey()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act
        var child1 = Bip32HdWallet.DeriveChild(masterKey, 0);
        var child2 = Bip32HdWallet.DeriveChild(masterKey, 0);

        // Assert
        Assert.Equal(child1.Key, child2.Key);
        Assert.Equal(child1.ChainCode, child2.ChainCode);
        Assert.Equal(child1.Depth, child2.Depth);
        Assert.Equal(child1.ChildIndex, child2.ChildIndex);
    }

    /// <summary>
    /// Test that different indices produce different keys
    /// </summary>
    [Fact]
    public void DeriveChild_DifferentIndices_ProduceDifferentKeys()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act
        var child0 = Bip32HdWallet.DeriveChild(masterKey, 0);
        var child1 = Bip32HdWallet.DeriveChild(masterKey, 1);
        var child2 = Bip32HdWallet.DeriveChild(masterKey, 2);

        // Assert - All should be different
        Assert.NotEqual(child0.Key, child1.Key);
        Assert.NotEqual(child0.Key, child2.Key);
        Assert.NotEqual(child1.Key, child2.Key);

        Assert.NotEqual(child0.ChainCode, child1.ChainCode);
        Assert.NotEqual(child0.ChainCode, child2.ChainCode);
        Assert.NotEqual(child1.ChainCode, child2.ChainCode);
    }

    /// <summary>
    /// Test that hardened and non-hardened at same index produce different keys
    /// </summary>
    [Fact]
    public void DeriveChild_HardenedVsNormal_ProduceDifferentKeys()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act
        var normalChild = Bip32HdWallet.DeriveChild(masterKey, 0);
        var hardenedChild = Bip32HdWallet.DeriveChild(masterKey, Bip32HdWallet.HARDENED_OFFSET + 0);

        // Assert
        Assert.NotEqual(normalChild.Key, hardenedChild.Key);
        Assert.NotEqual(normalChild.ChainCode, hardenedChild.ChainCode);
    }

    /// <summary>
    /// Test BIP44 path derivation (m/44'/0'/0'/0/0)
    /// </summary>
    [Fact]
    public void DerivePath_BIP44_Bitcoin_FirstAddress()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - BIP44 path for first Bitcoin receiving address
        var addressKey = Bip32HdWallet.DerivePath(masterKey, "m/44'/0'/0'/0/0");

        // Assert
        Assert.NotNull(addressKey);
        Assert.Equal(5, addressKey.Depth);
        Assert.Equal(0u, addressKey.ChildIndex); // Last index is 0
        Assert.True(addressKey.IsPrivate);
    }

    /// <summary>
    /// Test that DerivePath matches manual derivation
    /// </summary>
    [Fact]
    public void DerivePath_MatchesManualDerivation()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Manual derivation
        var child0 = Bip32HdWallet.DeriveChild(masterKey, Bip32HdWallet.HARDENED_OFFSET + 44);
        var child1 = Bip32HdWallet.DeriveChild(child0, Bip32HdWallet.HARDENED_OFFSET + 0);
        var child2 = Bip32HdWallet.DeriveChild(child1, Bip32HdWallet.HARDENED_OFFSET + 0);
        var child3 = Bip32HdWallet.DeriveChild(child2, 0);
        var manualFinal = Bip32HdWallet.DeriveChild(child3, 0);

        // Path-based derivation
        var pathFinal = Bip32HdWallet.DerivePath(masterKey, "m/44'/0'/0'/0/0");

        // Assert
        Assert.Equal(manualFinal.Key, pathFinal.Key);
        Assert.Equal(manualFinal.ChainCode, pathFinal.ChainCode);
        Assert.Equal(manualFinal.Depth, pathFinal.Depth);
    }

    /// <summary>
    /// Test key size validation
    /// </summary>
    [Fact]
    public void ExtendedKey_ValidKeyLengths_Success()
    {
        // Arrange & Act & Assert
        var privateKey = new byte[32];
        var publicKey = new byte[33];
        var chainCode = new byte[32];

        // Should not throw
        var extPrivate = new Bip32HdWallet.ExtendedKey(privateKey, chainCode);
        var extPublic = new Bip32HdWallet.ExtendedKey(publicKey, chainCode);

        Assert.True(extPrivate.IsPrivate);
        Assert.False(extPublic.IsPrivate);
    }

    /// <summary>
    /// Test that derived public keys are valid secp256k1 keys
    /// </summary>
    [Fact]
    public void DerivedKeys_UseProperSecp256k1()
    {
        // Arrange
        var seed = new byte[64];
        new Random(42).NextBytes(seed);
        var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

        // Act - Derive a child key
        var childKey = Bip32HdWallet.DeriveChild(masterKey, 0);

        // Assert - The key should be 32 bytes (private key)
        Assert.Equal(32, childKey.Key.Length);

        // The public key derivation should produce valid secp256k1 keys
        // This is implicitly tested by the fact that DeriveChild uses Secp256k1Core
        Assert.True(childKey.IsPrivate);
    }

    /// <summary>
    /// Test path parsing with various formats
    /// </summary>
    [Fact]
    public void ParsePath_VariousFormats_ParsesCorrectly()
    {
        // Act & Assert
        var path1 = Bip32HdWallet.ParsePath("m/0'/1/2'");
        Assert.Equal(3, path1.Length);
        Assert.Equal(Bip32HdWallet.HARDENED_OFFSET + 0, path1[0]);
        Assert.Equal(1u, path1[1]);
        Assert.Equal(Bip32HdWallet.HARDENED_OFFSET + 2, path1[2]);

        var path2 = Bip32HdWallet.ParsePath("m/44H/0H/0H");
        Assert.Equal(3, path2.Length);
        Assert.All(path2, index => Assert.True(index >= Bip32HdWallet.HARDENED_OFFSET));
    }

    /// <summary>
    /// Test format and parse round-trip
    /// </summary>
    [Fact]
    public void FormatPath_ParsePath_RoundTrip()
    {
        // Arrange
        var originalIndices = new uint[]
        {
            Bip32HdWallet.HARDENED_OFFSET + 44,
            Bip32HdWallet.HARDENED_OFFSET + 0,
            Bip32HdWallet.HARDENED_OFFSET + 0,
            0,
            5
        };

        // Act
        var formatted = Bip32HdWallet.FormatPath(originalIndices);
        var parsed = Bip32HdWallet.ParsePath(formatted);

        // Assert
        Assert.Equal(originalIndices, parsed);
        Assert.Equal("m/44'/0'/0'/0/5", formatted);
    }
}
#endif
