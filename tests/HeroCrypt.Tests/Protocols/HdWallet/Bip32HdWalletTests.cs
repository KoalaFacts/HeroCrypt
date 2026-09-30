using HeroCrypt.Protocols.HdWallet;

namespace HeroCrypt.Tests.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// Tests for BIP32 Hierarchical Deterministic Wallets.
/// </summary>
/// <remarks>
/// Private derivation uses the portable secp256k1 core; the same tests run on
/// Windows, Linux and macOS without platform exclusions.
/// </remarks>
[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class Bip32HdWalletTests
{

    /// <summary>
    /// Tests for master key generation from seed.
    /// </summary>
    public class MasterKeyGeneration
    {
        private readonly Bip32HdWallet bip32 = new();
        [Fact]
        public void ValidSeed_Success()
        {
            // Use 64-byte seed (recommended)
            var seed = new byte[64];
            new Random(42).NextBytes(seed);

            var masterKey = bip32.GenerateMasterKey(seed);

            Assert.NotNull(masterKey);
            Assert.Equal(32, masterKey.Key.Length); // Private key is 32 bytes
            Assert.Equal(32, masterKey.ChainCode.Length);
            Assert.Equal(0, masterKey.Depth);
            Assert.True(masterKey.IsPrivate);
        }

        [Fact]
        public void MinimumSeed_Success()
        {
            // Minimum 16 bytes
            var seed = new byte[16];
            new Random(42).NextBytes(seed);

            var masterKey = bip32.GenerateMasterKey(seed);

            Assert.NotNull(masterKey);
            Assert.Equal(32, masterKey.Key.Length);
        }

        [Fact]
        public void SeedTooShort_ThrowsException()
        {
            var seed = new byte[15]; // Below minimum

            Assert.Throws<ArgumentException>(() =>
                bip32.GenerateMasterKey(seed));
        }

        [Fact]
        public void SeedTooLong_ThrowsException()
        {
            var seed = new byte[65]; // Above maximum

            Assert.Throws<ArgumentException>(() =>
                bip32.GenerateMasterKey(seed));
        }

        [Fact]
        public void SameSeed_ProducesSameKeys()
        {
            var seed = new byte[64];
            new Random(42).NextBytes(seed);

            // Generate keys twice from same seed
            var master1 = bip32.GenerateMasterKey(seed);
            var master2 = bip32.GenerateMasterKey(seed);

            // Should produce identical keys
            Assert.Equal(master1.Key, master2.Key);
            Assert.Equal(master1.ChainCode, master2.ChainCode);
        }
    }

    /// <summary>
    /// Tests for child key derivation.
    /// </summary>
    public class ChildKeyDerivation
    {
        private readonly Bip32HdWallet bip32 = new();
        [Fact]
        public void NormalDerivation_Success()
        {

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = bip32.GenerateMasterKey(seed);

            // Derive child at index 0 (normal derivation)
            var childKey = bip32.DeriveChild(masterKey, 0);

            Assert.NotNull(childKey);
            Assert.Equal(32, childKey.Key.Length);
            Assert.Equal(1, childKey.Depth); // Depth increased
            Assert.NotEqual(masterKey.Key, childKey.Key); // Keys should be different
            Assert.True(childKey.IsPrivate);
        }

        [Fact]
        public void HardenedDerivation_Success()
        {

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = bip32.GenerateMasterKey(seed);

            // Derive hardened child (index >= 2^31)
            var childKey = bip32.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset);

            Assert.NotNull(childKey);
            Assert.Equal(32, childKey.Key.Length);
            Assert.Equal(1, childKey.Depth);
            Assert.Equal(Bip32HdWallet.HardenedOffset, childKey.ChildIndex);
        }

        [Fact]
        public void MultipleChildren_ProduceDifferentKeys()
        {

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = bip32.GenerateMasterKey(seed);

            var child0 = bip32.DeriveChild(masterKey, 0);
            var child1 = bip32.DeriveChild(masterKey, 1);
            var child2 = bip32.DeriveChild(masterKey, 2);

            // All children should have different keys
            Assert.NotEqual(child0.Key, child1.Key);
            Assert.NotEqual(child0.Key, child2.Key);
            Assert.NotEqual(child1.Key, child2.Key);
        }

        [Fact]
        public void SimplePathSync_Success()
        {

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = bip32.GenerateMasterKey(seed);

            var derivedKey = bip32.DerivePath(masterKey, "m/0/1");

            Assert.NotNull(derivedKey);
            Assert.Equal(2, derivedKey.Depth);
        }

        [Fact]
        public void BIP44Path_Success()
        {

            // Standard BIP44 path for Bitcoin
            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = bip32.GenerateMasterKey(seed);

            // m/44'/0'/0'/0/0 (BIP44 Bitcoin receiving address)
            var derivedKey = bip32.DerivePath(masterKey, "m/44'/0'/0'/0/0");

            Assert.NotNull(derivedKey);
            Assert.Equal(5, derivedKey.Depth);
        }
    }

    /// <summary>
    /// Tests for path parsing and validation.
    /// </summary>
    public class PathParsing
    {
        private readonly Bip32HdWallet bip32 = new();

        [Fact]
        public void ValidPath_ReturnsIndices()
        {
            // Various valid paths
            var indices1 = bip32.ParsePath("m/44'/0'/0'/0/0");
            Assert.Equal(5, indices1.Length);
            Assert.Equal(Bip32HdWallet.HardenedOffset + 44, indices1[0]);
            Assert.Equal(Bip32HdWallet.HardenedOffset + 0, indices1[1]);
            Assert.Equal(Bip32HdWallet.HardenedOffset + 0, indices1[2]);
            Assert.Equal(0u, indices1[3]);
            Assert.Equal(0u, indices1[4]);

            var indices2 = bip32.ParsePath("m/0/1/2");
            Assert.Equal(3, indices2.Length);
            Assert.Equal(0u, indices2[0]);
            Assert.Equal(1u, indices2[1]);
            Assert.Equal(2u, indices2[2]);
        }

        [Fact]
        public void MasterOnly_ReturnsEmpty()
        {
            var indices = bip32.ParsePath("m");

            Assert.Empty(indices);
        }

        [Fact]
        public void WithoutPrefix_Success()
        {
            var indices = bip32.ParsePath("0/1/2");

            Assert.Equal(3, indices.Length);
            Assert.Equal(0u, indices[0]);
            Assert.Equal(1u, indices[1]);
            Assert.Equal(2u, indices[2]);
        }

        [Fact]
        public void InvalidPath_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() => bip32.ParsePath(""));
            Assert.Throws<ArgumentException>(() => bip32.ParsePath("m/abc"));
            Assert.Throws<ArgumentException>(() => bip32.ParsePath("m/0/invalid/2"));
        }

        [Fact]
        public void IsValidPath_VariousPaths_ReturnsExpected()
        {
            Assert.True(bip32.IsValidPath("m"));
            Assert.True(bip32.IsValidPath("m/0"));
            Assert.True(bip32.IsValidPath("m/44'/0'/0'"));
            Assert.True(bip32.IsValidPath("0/1/2"));

            Assert.False(bip32.IsValidPath(""));
            Assert.False(bip32.IsValidPath("m/abc"));
            Assert.False(bip32.IsValidPath("invalid"));
        }
    }

    /// <summary>
    /// Tests for path formatting utilities.
    /// </summary>
    public class PathFormatting
    {
        private readonly Bip32HdWallet bip32 = new();

        [Fact]
        public void FormatIndex_NormalAndHardened_Success()
        {
            Assert.Equal("0", bip32.FormatIndex(0));
            Assert.Equal("1", bip32.FormatIndex(1));
            Assert.Equal("44'", bip32.FormatIndex(Bip32HdWallet.HardenedOffset + 44));
            Assert.Equal("0'", bip32.FormatIndex(Bip32HdWallet.HardenedOffset));
        }

        [Fact]
        public void FormatPath_VariousPaths_Success()
        {
            var indices1 = new uint[] { Bip32HdWallet.HardenedOffset + 44, 0, 1 };
            var indices2 = new uint[] { 0, 1, 2 };
            var indices3 = Array.Empty<uint>();

            var path1 = bip32.FormatPath(indices1);
            var path2 = bip32.FormatPath(indices2);
            var path3 = bip32.FormatPath(indices3);

            Assert.Equal("m/44'/0/1", path1);
            Assert.Equal("m/0/1/2", path2);
            Assert.Equal("m", path3);
        }
    }

    /// <summary>
    /// Tests for the ExtendedKey class.
    /// </summary>
    public class ExtendedKeyTests
    {

        [Fact]
        public void IsPrivate_ReturnsCorrectValue()
        {
            var privateKey = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000001");
            var publicKey = Convert.FromHexString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
            var chainCode = new byte[32];

            var extendedPrivate = new Bip32HdWallet.ExtendedKey(privateKey, chainCode);
            var extendedPublic = new Bip32HdWallet.ExtendedKey(publicKey, chainCode);

            Assert.True(extendedPrivate.IsPrivate);
            Assert.False(extendedPublic.IsPrivate);
        }

        [Fact]
        public void InvalidKeyLength_ThrowsException()
        {
            var invalidKey = new byte[30]; // Not 32 or 33
            var chainCode = new byte[32];

            Assert.Throws<ArgumentException>(() =>
                new Bip32HdWallet.ExtendedKey(invalidKey, chainCode));
        }

        [Fact]
        public void InvalidChainCodeLength_ThrowsException()
        {
            var key = new byte[32];
            key[31] = 1;
            var invalidChainCode = new byte[30]; // Not 32

            Assert.Throws<ArgumentException>(() =>
                new Bip32HdWallet.ExtendedKey(key, invalidChainCode));
        }

        [Fact]
        public void Clear_ClearsData()
        {
            var key = new byte[32];
            for (var i = 0; i < key.Length; i++)
            {
                key[i] = (byte)(i + 1);
            }
            var chainCode = new byte[32];
            for (var i = 0; i < chainCode.Length; i++)
            {
                chainCode[i] = (byte)(i + 100);
            }

            var extendedKey = new Bip32HdWallet.ExtendedKey(key, chainCode);

            extendedKey.Clear();

            // All sensitive data should be zeroed
            Assert.All(extendedKey.Key, b => Assert.Equal(0, b));
            Assert.All(extendedKey.ChainCode, b => Assert.Equal(0, b));
        }
    }
}
#endif
