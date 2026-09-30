using HeroCrypt.Protocols.HdWallet;

namespace HeroCrypt.Tests.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// Tests for BIP39 Mnemonic Codes - Standard for generating deterministic keys from mnemonic phrases.
/// </summary>
public class Bip39MnemonicTests
{
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AuditRegressions
    {
        private const string Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        private readonly Bip39Mnemonic bip39 = new();

        // Independently published BIP39 reference vectors: trezor/python-mnemonic vectors.json.
        [Theory]
        [InlineData("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]
        [InlineData("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow")]
        [InlineData("80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above")]
        [InlineData("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")]
        [InlineData("000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent")]
        [InlineData("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will")]
        [InlineData("808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always")]
        [InlineData("ffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when")]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")]
        [InlineData("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")]
        [InlineData("8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless")]
        [InlineData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote")]
        [InlineData("9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic")]
        [InlineData("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b", "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog")]
        [InlineData("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length")]
        [InlineData("c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow")]
        [InlineData("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave")]
        [InlineData("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside")]
        [InlineData("23db8160a31d3e0dca3688ed941adbf3", "cat swing flag economy stadium alone churn speed unique patch report train")]
        [InlineData("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access")]
        [InlineData("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform")]
        [InlineData("f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture")]
        [InlineData("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump")]
        [InlineData("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold")]
        public void OfficialEnglishVectors_MatchEntropyMnemonicAndChecksum(string entropyHex, string mnemonic)
        {
            var entropy = Convert.FromHexString(entropyHex);
            Assert.Equal(mnemonic, bip39.GenerateMnemonic(entropy));
            Assert.True(bip39.ValidateMnemonic(mnemonic));
            var recovered = bip39.MnemonicToEntropy(mnemonic);
            try { Assert.Equal(entropy, recovered); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(recovered); }
        }

        [Theory]
        [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")]
        [InlineData("legal winner thank year wave sausage worth useful legal winner thank yellow", "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607")]
        [InlineData("letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8")]
        [InlineData("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069")]
        [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent", "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa")]
        [InlineData("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will", "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd")]
        [InlineData("letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always", "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65")]
        [InlineData("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when", "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528")]
        [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8")]
        [InlineData("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87")]
        [InlineData("letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless", "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f")]
        [InlineData("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad")]
        [InlineData("ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic", "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028")]
        [InlineData("gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog", "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac")]
        [InlineData("hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length", "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440")]
        [InlineData("scheme spot photo card baby mountain device kick cradle pact join borrow", "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612")]
        [InlineData("horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave", "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d")]
        [InlineData("panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside", "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d")]
        [InlineData("cat swing flag economy stadium alone churn speed unique patch report train", "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5")]
        [InlineData("light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access", "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02")]
        [InlineData("all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform", "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d")]
        [InlineData("vessel ladder alter error federal sibling chat ability sun glass valve picture", "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f")]
        [InlineData("scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump", "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88")]
        [InlineData("void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold", "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998")]
        public void OfficialEnglishVectors_MatchSeed(string mnemonic, string seedHex)
        {
            var seed = bip39.MnemonicToSeed(mnemonic, "TREZOR");
            try { Assert.Equal(Convert.FromHexString(seedHex), seed); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(seed); }
        }

        // Raw seed conversion supports Unicode text without a Japanese wordlist parser.
        [Theory]
        [InlineData("あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら", "5a6c23b5abdd5c3e1f7d77ad25ecd715647bdafb44dab324c730a76a45d7421daccee1a4ff0739715a2c56a8a9f1e527a5e3496224d91293bfcd9b5393bfff83")]
        [InlineData("そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ", "9d269b22155b3c915b09abfefd4e1104573c528f6977cde89c6a68152c3c714dc6c7e0e62f221c322f3f76e4d0bcca66c06e3d2f6a8d70d612c87dd6dee63976")]
        [InlineData("そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あかちゃん", "17914bd3fe4b9e1224c968ec6b967fc6144a5795adbb2636a17f77da9b6b118200ad788672fd06096ca62683940523f5178f6ce3845c967cbd4ad2b3643cc660")]
        public void OfficialJapaneseSeeds_NormalizeIdeographicSpaces(string mnemonic, string seedHex)
        {
            var seed = bip39.MnemonicToSeed(mnemonic, "TREZOR");
            try { Assert.Equal(Convert.FromHexString(seedHex), seed); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(seed); }
        }

        [Fact]
        public void CompleteEnglishWordlist_MatchesOfficialDigest()
        {
            var field = typeof(Bip39Mnemonic).GetField("Wordlist", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
            var words = (string[])field.GetValue(null)!;
            Assert.Equal(2048, words.Length);
            Assert.Equal(2048, words.Distinct(StringComparer.Ordinal).Count());
            var data = System.Text.Encoding.UTF8.GetBytes(string.Join("\n", words) + "\n");
            var digest = System.Security.Cryptography.SHA256.HashData(data);
            Assert.Equal("2F5EED53A4727B4BF8880D8F3F199EFC90E58503646D9FF8EFF3A2ED3B24DBDA", Convert.ToHexString(digest));
        }

        [Theory]
        [InlineData("caf\u00e9")]
        [InlineData("\u338d\u30ac\u30d0\u30f4\u30a1\u3071\u3070\u3050\u309e\u3061\u3062\u5341\u4eba\u5341\u8272")]
        [InlineData("\uff34\uff32\uff25\uff3a\uff2f\uff32")]
        [InlineData(" secret\t ")]
        public void Passphrase_UsesNfkdWithoutTrimmingOrCaseFolding(string passphrase)
        {
            var expected = ReferenceSeed(Mnemonic, passphrase);
            var actual = bip39.MnemonicToSeed(Mnemonic, passphrase);
            try { Assert.Equal(expected, actual); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(expected); HeroCrypt.Security.SecureMemoryOperations.SecureClear(actual); }
        }

        [Theory]
        [InlineData("ABANDON")]
        [InlineData("  abandon")]
        [InlineData("abandon  ")]
        public void RawSeedDerivation_PreservesMnemonicTextExceptNfkd(string firstWord)
        {
            var mnemonic = firstWord + Mnemonic[7..];
            var expected = ReferenceSeed(mnemonic, "TREZOR");
            var actual = bip39.MnemonicToSeed(mnemonic, "TREZOR");
            try { Assert.Equal(expected, actual); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(expected); HeroCrypt.Security.SecureMemoryOperations.SecureClear(actual); }
        }

        [Fact]
        public void MnemonicToEntropy_InvalidChecksum_Rejects()
        {
            var mnemonic = string.Join(" ", Enumerable.Repeat("abandon", 12));
            Assert.False(bip39.ValidateMnemonic(mnemonic));
            Assert.Throws<ArgumentException>(() => bip39.MnemonicToEntropy(mnemonic));
        }

        [Fact]
        public void MnemonicToEntropy_Null_RejectsAtBoundary()
        {
            Assert.Throws<ArgumentNullException>(() => bip39.MnemonicToEntropy(null!));
        }

        [Theory]
        [InlineData(536870928)]
        [InlineData(-536870896)]
        public void EntropySize_OverflowCannotSelectSupportedLength(int bytes)
        {
            Assert.Throws<ArgumentException>(() => bip39.GetWordCountFromEntropyBytes(bytes));
        }

        [Theory]
        [InlineData("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")]
        [InlineData("word0012 word0012 word0012 word0012 word0012 word0012 word0012 word0012 word0012 word0012 word0012 word0012")]
        [InlineData("notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword")]
        public void Builder_InvalidMnemonic_CannotProduceWallet(string mnemonic)
        {
            Assert.Throws<ArgumentException>(() => new HdWalletBuilder().FromMnemonic(mnemonic).Derive());
        }

        [Fact]
        public void Builder_RecognizedFormatting_ReturnsCanonicalMnemonicAndSeed()
        {
            var input = "  " + Mnemonic.ToUpperInvariant().Replace(" ", "  ") + "  ";
            var result = new HdWalletBuilder().FromMnemonic(input).WithPassphrase("TREZOR").Derive();
            var expected = ReferenceSeed(Mnemonic, "TREZOR");
            try
            {
                Assert.Equal(Mnemonic, result.Mnemonic);
                Assert.Equal(expected, result.Seed);
            }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(expected); HeroCrypt.Security.SecureMemoryOperations.SecureClear(result.Seed); result.Key.Clear(); }
        }

        [Fact]
        public void RawSeedDerivation_DoesNotRequireEnglishWordlist()
        {
            const string mnemonic = "a sentence outside the English wordlist";
            var expected = ReferenceSeed(mnemonic, "");
            var actual = bip39.MnemonicToSeed(mnemonic);
            try { Assert.Equal(expected, actual); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(expected); HeroCrypt.Security.SecureMemoryOperations.SecureClear(actual); }
        }

        [Theory]
        [InlineData(16)]
        [InlineData(20)]
        [InlineData(24)]
        [InlineData(28)]
        [InlineData(32)]
        public void InvalidChecksum_AllWordCounts_RejectWithoutReturningEntropy(int bytes)
        {
            var mnemonic = bip39.GenerateMnemonic(new byte[bytes]);
            var words = mnemonic.Split(' ');
            words[^1] = words[^1] == "abandon" ? "ability" : "abandon";
            var invalid = string.Join(" ", words);
            Assert.False(bip39.ValidateMnemonic(invalid));
            Assert.Throws<ArgumentException>(() => bip39.MnemonicToEntropy(invalid));
        }

        [Fact]
        public void Builder_CompliancePolicy_CannotBypassBip32Rejection()
        {
            using var scope = HeroCrypt.Security.SecurityPolicy.ComplianceScope();
            Assert.Throws<HeroCrypt.Security.SecurityPolicyException>(() =>
                new HdWalletBuilder().FromMnemonic(Mnemonic).Derive());
        }

        private static byte[] ReferenceSeed(string mnemonic, string passphrase)
        {
            var password = System.Text.Encoding.UTF8.GetBytes(mnemonic.Normalize(System.Text.NormalizationForm.FormKD));
            var salt = System.Text.Encoding.UTF8.GetBytes(("mnemonic" + passphrase).Normalize(System.Text.NormalizationForm.FormKD));
            try { return System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(password, salt, 2048, System.Security.Cryptography.HashAlgorithmName.SHA512, 64); }
            finally { HeroCrypt.Security.SecureMemoryOperations.SecureClear(password); HeroCrypt.Security.SecureMemoryOperations.SecureClear(salt); }
        }
    }

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
