using HeroCrypt.Protocols.HdWallet;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// Tests for BIP32 Hierarchical Deterministic Wallets.
/// </summary>
/// <remarks>
/// <para><b>Platform Support Notes:</b></para>
/// <list type="bullet">
///   <item>
///     <term>secp256k1 on macOS</term>
///     <description>
///       The secp256k1 elliptic curve (OID 1.3.132.0.10) used by Bitcoin and BIP32 is not
///       supported by the macOS Security framework. Apple's CommonCrypto only supports
///       NIST curves (P-256, P-384, P-521). Tests that require child key derivation
///       (which uses secp256k1 for public key computation) are automatically skipped on
///       macOS using <c>Assert.Skip()</c>.
///     </description>
///   </item>
///   <item>
///     <term>Master key generation</term>
///     <description>
///       Master key generation uses HMAC-SHA512 which is supported on all platforms.
///       Only child key derivation requires secp256k1.
///     </description>
///   </item>
/// </list>
/// <para>
/// For production use on macOS, consider using a software implementation of secp256k1
/// (e.g., libsecp256k1 via P/Invoke or a managed implementation).
/// </para>
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
        [Fact]
        public void ValidSeed_Success()
        {
            // Use 64-byte seed (recommended)
            var seed = new byte[64];
            new Random(42).NextBytes(seed);

            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

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

            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

            Assert.NotNull(masterKey);
            Assert.Equal(32, masterKey.Key.Length);
        }

        [Fact]
        public void SeedTooShort_ThrowsException()
        {
            var seed = new byte[15]; // Below minimum

            Assert.Throws<ArgumentException>(() =>
                Bip32HdWallet.GenerateMasterKey(seed));
        }

        [Fact]
        public void SeedTooLong_ThrowsException()
        {
            var seed = new byte[65]; // Above maximum

            Assert.Throws<ArgumentException>(() =>
                Bip32HdWallet.GenerateMasterKey(seed));
        }

        [Fact]
        public void SameSeed_ProducesSameKeys()
        {
            var seed = new byte[64];
            new Random(42).NextBytes(seed);

            // Generate keys twice from same seed
            var master1 = Bip32HdWallet.GenerateMasterKey(seed);
            var master2 = Bip32HdWallet.GenerateMasterKey(seed);

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
        [Fact]
        public void NormalDerivation_Success()
        {
            if (OperatingSystem.IsMacOS()) { Assert.Skip("secp256k1 not supported on macOS"); return; }

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

            // Derive child at index 0 (normal derivation)
            var childKey = Bip32HdWallet.DeriveChild(masterKey, 0);

            Assert.NotNull(childKey);
            Assert.Equal(32, childKey.Key.Length);
            Assert.Equal(1, childKey.Depth); // Depth increased
            Assert.NotEqual(masterKey.Key, childKey.Key); // Keys should be different
            Assert.True(childKey.IsPrivate);
        }

        [Fact]
        public void HardenedDerivation_Success()
        {
            if (OperatingSystem.IsMacOS()) { Assert.Skip("secp256k1 not supported on macOS"); return; }

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

            // Derive hardened child (index >= 2^31)
            var childKey = Bip32HdWallet.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset);

            Assert.NotNull(childKey);
            Assert.Equal(32, childKey.Key.Length);
            Assert.Equal(1, childKey.Depth);
            Assert.Equal(Bip32HdWallet.HardenedOffset, childKey.ChildIndex);
        }

        [Fact]
        public void MultipleChildren_ProduceDifferentKeys()
        {
            if (OperatingSystem.IsMacOS()) { Assert.Skip("secp256k1 not supported on macOS"); return; }

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

            var child0 = Bip32HdWallet.DeriveChild(masterKey, 0);
            var child1 = Bip32HdWallet.DeriveChild(masterKey, 1);
            var child2 = Bip32HdWallet.DeriveChild(masterKey, 2);

            // All children should have different keys
            Assert.NotEqual(child0.Key, child1.Key);
            Assert.NotEqual(child0.Key, child2.Key);
            Assert.NotEqual(child1.Key, child2.Key);
        }

        [Fact]
        public void SimplePathSync_Success()
        {
            if (OperatingSystem.IsMacOS()) { Assert.Skip("secp256k1 not supported on macOS"); return; }

            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

            var derivedKey = Bip32HdWallet.DerivePath(masterKey, "m/0/1");

            Assert.NotNull(derivedKey);
            Assert.Equal(2, derivedKey.Depth);
        }

        [Fact]
        public void BIP44Path_Success()
        {
            if (OperatingSystem.IsMacOS()) { Assert.Skip("secp256k1 not supported on macOS"); return; }

            // Standard BIP44 path for Bitcoin
            var seed = new byte[64];
            new Random(42).NextBytes(seed);
            var masterKey = Bip32HdWallet.GenerateMasterKey(seed);

            // m/44'/0'/0'/0/0 (BIP44 Bitcoin receiving address)
            var derivedKey = Bip32HdWallet.DerivePath(masterKey, "m/44'/0'/0'/0/0");

            Assert.NotNull(derivedKey);
            Assert.Equal(5, derivedKey.Depth);
        }
    }

    /// <summary>
    /// Tests for path parsing and validation.
    /// </summary>
    public class PathParsing
    {
        [Fact]
        public void ValidPath_ReturnsIndices()
        {
            // Various valid paths
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
        public void MasterOnly_ReturnsEmpty()
        {
            var indices = Bip32HdWallet.ParsePath("m");

            Assert.Empty(indices);
        }

        [Fact]
        public void WithoutPrefix_Success()
        {
            var indices = Bip32HdWallet.ParsePath("0/1/2");

            Assert.Equal(3, indices.Length);
            Assert.Equal(0u, indices[0]);
            Assert.Equal(1u, indices[1]);
            Assert.Equal(2u, indices[2]);
        }

        [Fact]
        public void InvalidPath_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() => Bip32HdWallet.ParsePath(""));
            Assert.Throws<ArgumentException>(() => Bip32HdWallet.ParsePath("m/abc"));
            Assert.Throws<ArgumentException>(() => Bip32HdWallet.ParsePath("m/0/invalid/2"));
        }

        [Fact]
        public void IsValidPath_VariousPaths_ReturnsExpected()
        {
            Assert.True(Bip32HdWallet.IsValidPath("m"));
            Assert.True(Bip32HdWallet.IsValidPath("m/0"));
            Assert.True(Bip32HdWallet.IsValidPath("m/44'/0'/0'"));
            Assert.True(Bip32HdWallet.IsValidPath("0/1/2"));

            Assert.False(Bip32HdWallet.IsValidPath(""));
            Assert.False(Bip32HdWallet.IsValidPath("m/abc"));
            Assert.False(Bip32HdWallet.IsValidPath("invalid"));
        }
    }

    /// <summary>
    /// Tests for path formatting utilities.
    /// </summary>
    public class PathFormatting
    {
        [Fact]
        public void FormatIndex_NormalAndHardened_Success()
        {
            Assert.Equal("0", Bip32HdWallet.FormatIndex(0));
            Assert.Equal("1", Bip32HdWallet.FormatIndex(1));
            Assert.Equal("44'", Bip32HdWallet.FormatIndex(Bip32HdWallet.HardenedOffset + 44));
            Assert.Equal("0'", Bip32HdWallet.FormatIndex(Bip32HdWallet.HardenedOffset));
        }

        [Fact]
        public void FormatPath_VariousPaths_Success()
        {
            var indices1 = new uint[] { Bip32HdWallet.HardenedOffset + 44, 0, 1 };
            var indices2 = new uint[] { 0, 1, 2 };
            var indices3 = Array.Empty<uint>();

            var path1 = Bip32HdWallet.FormatPath(indices1);
            var path2 = Bip32HdWallet.FormatPath(indices2);
            var path3 = Bip32HdWallet.FormatPath(indices3);

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
            var privateKey = new byte[32];
            var publicKey = new byte[33];
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
