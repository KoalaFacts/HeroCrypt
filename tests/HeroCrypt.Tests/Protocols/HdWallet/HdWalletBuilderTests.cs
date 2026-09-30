using HeroCrypt.Protocols.HdWallet;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// Comprehensive tests for HdWalletBuilder fluent API.
/// </summary>
public class HdWalletBuilderTests
{
    public class AuditRegressions
    {
        private const string Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        [Fact]
        public void FromSeed_Null_CannotFallBackToRandomWallet()
        {
            Assert.Throws<ArgumentNullException>(() => new HdWalletBuilder().FromSeed(null!));
        }

        [Fact]
        public void FromMnemonic_Null_CannotFallBackToRandomWallet()
        {
            Assert.Throws<ArgumentNullException>(() => new HdWalletBuilder().FromMnemonic(null!));
        }

        [Fact]
        public void WithPath_Null_CannotFallBackToMasterKey()
        {
            Assert.Throws<ArgumentNullException>(() => new HdWalletBuilder().WithPath(null!));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        public void WithPath_EmptyOrWhitespace_IsRejected(string path)
        {
            Assert.Throws<ArgumentException>(() => new HdWalletBuilder().WithPath(path));
        }

        [Fact]
        public void FromMnemonic_AfterSeed_UsesTheLastSelectedSource()
        {
            var result = new HdWalletBuilder().FromSeed(new byte[16]).FromMnemonic(Mnemonic).Derive();
            try
            {
                Assert.Equal(Mnemonic, result.Mnemonic);
                Assert.Equal(64, result.Seed.Length);
            }
            finally
            {
                HeroCrypt.Security.SecureMemoryOperations.SecureClear(result.Seed);
                result.Key.Clear();
            }
        }

        [Fact]
        public void GenerateMnemonic_AfterSeed_UsesTheLastSelectedSource()
        {
            var result = new HdWalletBuilder().FromSeed(new byte[16]).GenerateMnemonic(12).Derive();
            try
            {
                Assert.NotNull(result.Mnemonic);
                Assert.Equal(12, result.Mnemonic.Split(' ').Length);
                Assert.Equal(64, result.Seed.Length);
            }
            finally
            {
                HeroCrypt.Security.SecureMemoryOperations.SecureClear(result.Seed);
                result.Key.Clear();
            }
        }

        [Fact]
        public void FromSeed_AfterMnemonic_UsesTheLastSelectedSource()
        {
            var result = new HdWalletBuilder().FromMnemonic(Mnemonic).FromSeed(new byte[16]).Derive();
            try
            {
                Assert.Null(result.Mnemonic);
                Assert.Equal(new byte[16], result.Seed);
            }
            finally
            {
                HeroCrypt.Security.SecureMemoryOperations.SecureClear(result.Seed);
                result.Key.Clear();
            }
        }
    }

    /// <summary>
    /// Tests for mnemonic generation.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class MnemonicGenerationTests
    {
        [Fact]
        public void GenerateMnemonic_Default24Words_Succeeds()
        {
            var result = new HdWalletBuilder()
                .GenerateMnemonic()
                .Derive();

            Assert.NotNull(result.Mnemonic);
            var words = result.Mnemonic.Split(' ');
            Assert.Equal(24, words.Length);
        }

        [Theory]
        [InlineData(12)]
        [InlineData(15)]
        [InlineData(18)]
        [InlineData(21)]
        [InlineData(24)]
        public void GenerateMnemonic_DifferentWordCounts_Succeeds(int wordCount)
        {
            var result = new HdWalletBuilder()
                .GenerateMnemonic(wordCount)
                .Derive();

            Assert.NotNull(result.Mnemonic);
            var words = result.Mnemonic.Split(' ');
            Assert.Equal(wordCount, words.Length);
        }

        [Fact]
        public void GenerateMnemonic_ProducesValidSeed()
        {
            var result = new HdWalletBuilder()
                .GenerateMnemonic()
                .Derive();

            Assert.NotNull(result.Seed);
            Assert.Equal(64, result.Seed.Length);
        }
    }

    /// <summary>
    /// Tests for using existing mnemonic.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FromMnemonicTests
    {
        private const string TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        [Fact]
        public void FromMnemonic_ValidMnemonic_Succeeds()
        {
            var result = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .Derive();

            Assert.Equal(TestMnemonic, result.Mnemonic);
            Assert.NotNull(result.Seed);
        }

        [Fact]
        public void FromMnemonic_SameMnemonic_ProducesSameSeed()
        {
            var result1 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .Derive();

            var result2 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .Derive();

            Assert.Equal(result1.Seed, result2.Seed);
        }

        [Fact]
        public void FromMnemonic_DifferentMnemonics_ProduceDifferentSeeds()
        {
            var mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            var mnemonic2 = "legal winner thank year wave sausage worth useful legal winner thank yellow";

            var result1 = new HdWalletBuilder().FromMnemonic(mnemonic1).Derive();
            var result2 = new HdWalletBuilder().FromMnemonic(mnemonic2).Derive();

            Assert.NotEqual(result1.Seed, result2.Seed);
        }
    }

    /// <summary>
    /// Tests for passphrase handling.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PassphraseTests
    {
        private const string TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        [Fact]
        public void WithPassphrase_ChangesSeeed()
        {
            var resultNoPass = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .Derive();

            var resultWithPass = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPassphrase("mypassword")
                .Derive();

            Assert.NotEqual(resultNoPass.Seed, resultWithPass.Seed);
        }

        [Fact]
        public void WithPassphrase_SamePassphrase_ProducesSameSeed()
        {
            var result1 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPassphrase("password123")
                .Derive();

            var result2 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPassphrase("password123")
                .Derive();

            Assert.Equal(result1.Seed, result2.Seed);
        }

        [Fact]
        public void WithPassphrase_DifferentPassphrases_ProduceDifferentSeeds()
        {
            var result1 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPassphrase("password1")
                .Derive();

            var result2 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPassphrase("password2")
                .Derive();

            Assert.NotEqual(result1.Seed, result2.Seed);
        }
    }

    /// <summary>
    /// Tests for derivation paths.
    /// </summary>
    /// <remarks>
    /// Path derivation uses the portable secp256k1 core on all supported platforms.
    /// </remarks>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DerivationPathTests
    {
        private const string TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        [Fact]
        public void WithPath_ValidPath_DerivesKey()
        {

            var result = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPath("m/44'/0'/0'/0/0")
                .Derive();

            Assert.NotNull(result.Key);
            Assert.Equal("m/44'/0'/0'/0/0", result.Path);
        }

        [Fact]
        public void WithPath_DifferentPaths_ProduceDifferentKeys()
        {

            var result1 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPath("m/44'/0'/0'/0/0")
                .Derive();

            var result2 = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .WithPath("m/44'/0'/0'/0/1")
                .Derive();

            Assert.NotEqual(result1.Key.Key, result2.Key.Key);
        }

        [Fact]
        public void GenerateMasterKey_ReturnsKeyWithoutPath()
        {
            var result = new HdWalletBuilder()
                .FromMnemonic(TestMnemonic)
                .GenerateMasterKey();

            Assert.NotNull(result.Key);
            Assert.Null(result.Path);
        }
    }

    /// <summary>
    /// Tests for using existing seed.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FromSeedTests
    {
        [Fact]
        public void FromSeed_ValidSeed_Succeeds()
        {
            var seed = TestHelpers.RandomBytes(64);

            var result = new HdWalletBuilder()
                .FromSeed(seed)
                .Derive();

            Assert.Null(result.Mnemonic);
            Assert.Equal(seed, result.Seed);
            Assert.NotNull(result.Key);
        }

        [Fact]
        public void FromSeed_SameSeed_ProducesSameKey()
        {
            var seed = TestHelpers.RandomBytes(64);

            var result1 = new HdWalletBuilder().FromSeed(seed).Derive();
            var result2 = new HdWalletBuilder().FromSeed(seed).Derive();

            Assert.Equal(result1.Key.Key, result2.Key.Key);
        }
    }

    /// <summary>
    /// Tests for fluent API chaining.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FluentApiTests
    {
        [Fact]
        public void FluentChaining_Works()
        {

            var result = new HdWalletBuilder()
                .GenerateMnemonic(12)
                .WithPassphrase("test")
                .WithPath("m/44'/60'/0'/0/0")
                .Derive();

            Assert.NotNull(result.Mnemonic);
            Assert.Equal(12, result.Mnemonic.Split(' ').Length);
            Assert.Equal("m/44'/60'/0'/0/0", result.Path);
        }
    }

    /// <summary>
    /// Tests for key structure.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyStructureTests
    {
        [Fact]
        public void DerivedKey_HasPrivateKey()
        {
            var result = new HdWalletBuilder()
                .GenerateMnemonic()
                .Derive();

            Assert.NotNull(result.Key.Key);
            Assert.Equal(32, result.Key.Key.Length);
        }

        [Fact]
        public void DerivedKey_HasChainCode()
        {
            var result = new HdWalletBuilder()
                .GenerateMnemonic()
                .Derive();

            Assert.NotNull(result.Key.ChainCode);
            Assert.Equal(32, result.Key.ChainCode.Length);
        }
    }
}

#endif
