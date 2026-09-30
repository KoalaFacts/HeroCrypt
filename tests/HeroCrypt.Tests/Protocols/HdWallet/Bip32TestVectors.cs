using HeroCrypt.Protocols.HdWallet;

namespace HeroCrypt.Tests.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// BIP-0032 test vectors for Hierarchical Deterministic Wallets.
/// Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
/// </summary>
/// <remarks>
/// Private derivation uses the portable secp256k1 core; the same tests run on
/// Windows, Linux and macOS without platform exclusions.
/// </remarks>
public class Bip32TestVectors
{
    private readonly Bip32HdWallet bip32 = new();

    /// <summary>
    /// BIP32 Test Vector 1 - Master key generation
    /// </summary>
    [Fact]
    public void BIP32_TestVector1_MasterKey()
    {
        // Arrange - Seed from BIP32 spec
        var seed = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

        // Act
        var masterKey = bip32.GenerateMasterKey(seed);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act - Derive m/0'
        var childKey = bip32.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset + 0);

        // Assert
        Assert.NotNull(childKey);
        Assert.Equal(1, childKey.Depth);
        Assert.Equal(Bip32HdWallet.HardenedOffset, childKey.ChildIndex);
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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act - Derive m/0'/1
        var child0H = bip32.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset + 0);
        var child1 = bip32.DeriveChild(child0H, 1);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act
        var derivedKey = bip32.DerivePath(masterKey, "m/0'/1/2'");

        // Assert
        Assert.NotNull(derivedKey);
        Assert.Equal(3, derivedKey.Depth);
        Assert.Equal(Bip32HdWallet.HardenedOffset + 2, derivedKey.ChildIndex);

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
        var masterKey = bip32.GenerateMasterKey(seed);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act - Normal (non-hardened) derivation
        var childKey = bip32.DeriveChild(masterKey, 0);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act
        var child1 = bip32.DeriveChild(masterKey, 0);
        var child2 = bip32.DeriveChild(masterKey, 0);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act
        var child0 = bip32.DeriveChild(masterKey, 0);
        var child1 = bip32.DeriveChild(masterKey, 1);
        var child2 = bip32.DeriveChild(masterKey, 2);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act
        var normalChild = bip32.DeriveChild(masterKey, 0);
        var hardenedChild = bip32.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset + 0);

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act - BIP44 path for first Bitcoin receiving address
        var addressKey = bip32.DerivePath(masterKey, "m/44'/0'/0'/0/0");

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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act - Manual derivation
        var child0 = bip32.DeriveChild(masterKey, Bip32HdWallet.HardenedOffset + 44);
        var child1 = bip32.DeriveChild(child0, Bip32HdWallet.HardenedOffset + 0);
        var child2 = bip32.DeriveChild(child1, Bip32HdWallet.HardenedOffset + 0);
        var child3 = bip32.DeriveChild(child2, 0);
        var manualFinal = bip32.DeriveChild(child3, 0);

        // Path-based derivation
        var pathFinal = bip32.DerivePath(masterKey, "m/44'/0'/0'/0/0");

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
        var privateKey = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000001");
        var publicKey = Convert.FromHexString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
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
        var masterKey = bip32.GenerateMasterKey(seed);

        // Act - Derive a child key
        var childKey = bip32.DeriveChild(masterKey, 0);

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
        var path1 = bip32.ParsePath("m/0'/1/2'");
        Assert.Equal(3, path1.Length);
        Assert.Equal(Bip32HdWallet.HardenedOffset + 0, path1[0]);
        Assert.Equal(1u, path1[1]);
        Assert.Equal(Bip32HdWallet.HardenedOffset + 2, path1[2]);

        var path2 = bip32.ParsePath("m/44H/0H/0H");
        Assert.Equal(3, path2.Length);
        Assert.All(path2, index => Assert.True(index >= Bip32HdWallet.HardenedOffset));
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
            Bip32HdWallet.HardenedOffset + 44,
            Bip32HdWallet.HardenedOffset + 0,
            Bip32HdWallet.HardenedOffset + 0,
            0,
            5
        };

        // Act
        var formatted = bip32.FormatPath(originalIndices);
        var parsed = bip32.ParsePath(formatted);

        // Assert
        Assert.Equal(originalIndices, parsed);
        Assert.Equal("m/44'/0'/0'/0/5", formatted);
    }
    public class AuditRegressions
    {
        private const string Generator = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        private const string Order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

        // Decoded from the official BIP-0032 xprv/xpub vectors 1-4, including
        // checksum verification. Expected bytes are independent of this implementation.
        [Theory]
        [InlineData("000102030405060708090a0b0c0d0e0f", "m", "E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35", "873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508", "00000000", "0339A36013301597DAEF41FBE593A02CC513D0B55527EC2DF1050E2E8FF49C85C2", (byte)0, 0u)]
        [InlineData("000102030405060708090a0b0c0d0e0f", "m/0'", "EDB2E14F9EE77D26DD93B4ECEDE8D16ED408CE149B6CD80B0715A2D911A0AFEA", "47FDACBD0F1097043B78C63C20C34EF4ED9A111D980047AD16282C7AE6236141", "3442193E", "035A784662A4A20A65BF6AAB9AE98A6C068A81C52E4B032C0FB5400C706CFCCC56", (byte)1, 2147483648u)]
        [InlineData("000102030405060708090a0b0c0d0e0f", "m/0'/1", "3C6CB8D0F6A264C91EA8B5030FADAA8E538B020F0A387421A12DE9319DC93368", "2A7857631386BA23DACAC34180DD1983734E444FDBF774041578E9B6ADB37C19", "5C1BD648", "03501E454BF00751F24B1B489AA925215D66AF2234E3891C3B21A52BEDB3CD711C", (byte)2, 1u)]
        [InlineData("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'", "CBCE0D719ECF7431D88E6A89FA1483E02E35092AF60C042B1DF2FF59FA424DCA", "04466B9CC8E161E966409CA52986C584F07E9DC81F735DB683C3FF6EC7B1503F", "BEF5A2F9", "0357BFE1E341D01C69FE5654309956CBEA516822FBA8A601743A012A7896EE8DC2", (byte)3, 2147483650u)]
        [InlineData("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2", "0F479245FB19A38A1954C5C7C0EBAB2F9BDFD96A17563EF28A6A4B1A2A764EF4", "CFB71883F01676F587D023CC53A35BC7F88F724B1F8C2892AC1275AC822A3EDD", "EE7AB90C", "02E8445082A72F29B75CA48748A914DF60622A609CACFCE8ED0E35804560741D29", (byte)4, 2u)]
        [InlineData("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", "471B76E389E528D6DE6D816857E012C5455051CAD6660850E58372A6C3E6E7C8", "C783E67B921D2BEB8F6B389CC646D7263B4145701DADD2161548A8B078E65E9E", "D880D7D8", "022A471424DA5E657499D1FF51CB43C47481A03B1E77F951FE64CEC9F5A48F7011", (byte)5, 1000000000u)]
        [InlineData("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m", "4B03D6FC340455B363F51020AD3ECCA4F0850280CF436C70C727923F6DB46C3E", "60499F801B896D83179A4374AEB7822AAEACEAA0DB1F85EE3E904C4DEFBD9689", "00000000", "03CBCAA9C98C877A26977D00825C956A238E8DDDFBD322CCE4F74B0B5BD6ACE4A7", (byte)0, 0u)]
        [InlineData("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0", "ABE74A98F6C7EABEE0428F53798F0AB8AA1BD37873999041703C742F15AC7E1E", "F0909AFFAA7EE7ABE5DD4E100598D4DC53CD709D5A5C2CAC40E7412F232F7C9C", "BD16BEE5", "02FC9E5AF0AC8D9B3CECFE2A888E2117BA3D089D8585886C9C826B6B22A98D12EA", (byte)1, 0u)]
        [InlineData("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'", "877C779AD9687164E9C2F4F0F4FF0340814392330693CE95A58FE18FD52E6E93", "BE17A268474A6BB9C61E1D720CF6215E2A88C5406C4AEE7B38547F585C9A37D9", "5A61FF8E", "03C01E7425647BDEFA82B12D9BAD5E3E6865BEE0502694B94CA58B666ABC0A5C3B", (byte)2, 4294967295u)]
        [InlineData("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1", "704ADDF544A06E5EE4BEA37098463C23613DA32020D604506DA8C0518E1DA4B7", "F366F48F1EA9F2D1D3FE958C95CA84EA18E4C4DDB9366C336C927EB246FB38CB", "D8AB4937", "03A7D1D856DEB74C508E05031F9895DAB54626251B3806E16B4BD12E781A7DF5B9", (byte)3, 1u)]
        [InlineData("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1/2147483646'", "F1C7C871A54A804AFE328B4C83A1C33B8E5FF48F5087273F04EFA83B247D6A2D", "637807030D55D01F9A0CB3A7839515D796BD07706386A6EDDF06CC29A65A0E29", "78412E3A", "02D2B36900396C9282FA14628566582F206A5DD0BCC8D5E892611806CAFB0301F0", (byte)4, 4294967294u)]
        [InlineData("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "m/0/2147483647'/1/2147483646'/2", "BB7D39BDB83ECF58F2FD82B6D918341CBEF428661EF01AB97C28A4842125AC23", "9452B549BE8CEA3ECB7A84BEC10DCFD94AFE4D129EBFD3B3CB58EEDF394ED271", "31A507B8", "024D902E1A2FC7A8755AB5B694C575FCE742C48D9FF192E63DF5193E4C7AFE1F9C", (byte)5, 2u)]
        [InlineData("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "m", "00DDB80B067E0D4993197FE10F2657A844A384589847602D56F0C629C81AAE32", "01D28A3E53CFFA419EC122C968B3259E16B65076495494D97CAE10BBFEC3C36F", "00000000", "03683AF1BA5743BDFC798CF814EFEEAB2735EC52D95ECED528E692B8E34C4E5669", (byte)0, 0u)]
        [InlineData("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "m/0'", "491F7A2EEBC7B57028E0D3FAA0ACDA02E75C33B03C48FB288C41E2EA44E1DAEF", "E5FEA12A97B927FC9DC3D2CB0D1EA1CF50AA5A1FDC1F933E8906BB38DF3377BD", "41D63B50", "026557FDDA1D5D43D79611F784780471F086D58E8126B8C40ACB82272A7712E7F2", (byte)1, 2147483648u)]
        [InlineData("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", "m", "12C0D59C7AA3A10973DBD3F478B65F2516627E3FE61E00C345BE9A477AD2E215", "D0C8A1F6EDF2500798C3E0B54F1B56E45F6D03E6076ABD36E5E2F54101E44CE6", "00000000", "026F6FEDC9240F61DAA9C7144B682A430A3A1366576F840BF2D070101FCBC9A02D", (byte)0, 0u)]
        [InlineData("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", "m/0'", "00D948E9261E41362A688B916F297121BA6BFB2274A3575AC0E456551DFD7F7E", "CDC0F06456A14876C898790E0B3B1A41C531170AEC69DA44FF7B7265BFE7743B", "AD85D955", "039382D2B6003446792D2917F7AC4B3EDF079A1A94DD4EB010DC25109DDA680A9D", (byte)1, 2147483648u)]
        [InlineData("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", "m/0'/1'", "3A2086EDD7D9DF86C3487A5905A1712A9AA664BCE8CC268141E07549EAA8661D", "A48EE6674C5264A237703FD383BCCD9FAD4D9378AC98AB05E6E7029B06360C0D", "CFA61281", "032EDAF9E591EE27F3C69C36221E3C54C38088EF34E93FBB9BB2D4D9B92364CBBD", (byte)2, 2147483649u)]
        public void OfficialVectors_ValidateAllKeyFields(string seed, string path,
            string privateKey, string chainCode, string fingerprint, string publicKey, byte depth, uint childIndex)
        {
            var wallet = new Bip32HdWallet();
            var master = wallet.GenerateMasterKey(Convert.FromHexString(seed));
            var derived = wallet.DerivePath(master, path);
            try
            {
                Assert.Equal(Convert.FromHexString(privateKey), derived.Key);
                Assert.Equal(Convert.FromHexString(chainCode), derived.ChainCode);
                Assert.Equal(Convert.FromHexString(fingerprint), derived.ParentFingerprint);
                Assert.Equal(depth, derived.Depth);
                Assert.Equal(childIndex, derived.ChildIndex);

                var method = typeof(Bip32HdWallet).GetMethod("DerivePublicKeyFromPrivate",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Instance)!;
                var actualPublicKey = (byte[])method.Invoke(method.IsStatic ? null : wallet, [derived.Key])!;
                Assert.Equal(Convert.FromHexString(publicKey), actualPublicKey);
            }
            finally
            {
                derived.Clear();
                master.Clear();
            }
        }

        [Fact]
        public void ExtendedKey_NullBuffers_ReportArgumentErrors()
        {
            Assert.Throws<ArgumentNullException>(() => new Bip32HdWallet.ExtendedKey(null!, new byte[32]));
            Assert.Throws<ArgumentNullException>(() => new Bip32HdWallet.ExtendedKey(ScalarOne(), null!));
        }

        [Theory]
        [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
        [InlineData(Order)]
        [InlineData("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
        public void ExtendedKey_InvalidPrivateScalar_IsRejected(string scalar)
        {
            Assert.Throws<ArgumentException>(() =>
                new Bip32HdWallet.ExtendedKey(Convert.FromHexString(scalar), new byte[32]));
        }

        [Theory]
        [InlineData("000000000000000000000000000000000000000000000000000000000000000000")]
        [InlineData("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")]
        [InlineData("020000000000000000000000000000000000000000000000000000000000000007")]
        public void ExtendedKey_InvalidPublicPoint_IsRejected(string point)
        {
            Assert.Throws<ArgumentException>(() =>
                new Bip32HdWallet.ExtendedKey(Convert.FromHexString(point), new byte[32]));
        }

        [Theory]
        [InlineData(3)]
        [InlineData(5)]
        public void ExtendedKey_FingerprintMustBeFourBytes(int length)
        {
            Assert.Throws<ArgumentException>(() =>
                new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32], 1, new byte[length]));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void ExtendedKey_MasterMetadataMustBeZero(bool fingerprint)
        {
            Assert.Throws<ArgumentException>(() =>
                new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32], 0,
                    fingerprint ? [1, 0, 0, 0] : [0, 0, 0, 0], fingerprint ? 0u : 1u));
        }

        [Fact]
        public void ExtendedKey_OwnsBuffers_ClearDoesNotEraseCallerInputs()
        {
            var key = ScalarOne();
            var chain = Enumerable.Repeat((byte)0x42, 32).ToArray();
            byte[] fingerprint = [1, 2, 3, 4];
            var extended = new Bip32HdWallet.ExtendedKey(key, chain, 1, fingerprint);
            fingerprint[0] = 99;
            extended.Clear();

            Assert.Equal((byte)1, key[31]);
            Assert.All(chain, value => Assert.Equal((byte)0x42, value));
            Assert.Equal((byte)1, extended.ParentFingerprint[0]);
            Assert.All(extended.Key, value => Assert.Equal((byte)0, value));
            Assert.All(extended.ChainCode, value => Assert.Equal((byte)0, value));
        }

        [Fact]
        public void DeriveChild_Depth255_IsRejectedBeforeWrapping()
        {
            var parent = new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32], byte.MaxValue);
            Assert.Throws<InvalidOperationException>(() => new Bip32HdWallet().DeriveChild(parent, 0));
        }

        [Fact]
        public void DeriveChild_Depth254_RetainsMaximumValidDepth()
        {
            var parent = new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32], 254);
            var child = new Bip32HdWallet().DeriveChild(parent, uint.MaxValue);
            try
            {
                Assert.Equal(byte.MaxValue, child.Depth);
                Assert.Equal(uint.MaxValue, child.ChildIndex);
                Assert.Equal((byte)1, parent.Key[31]);
            }
            finally
            {
                child.Clear();
                parent.Clear();
            }
        }

        [Fact]
        public void ParsePath_MaximumIndices_RequireExplicitHardenedMarkerAndRoundtrip()
        {
            var wallet = new Bip32HdWallet();
            var indices = wallet.ParsePath("m/2147483647/2147483647'");

            Assert.Equal(new uint[] { 2147483647, uint.MaxValue }, indices);
            Assert.Equal(indices, wallet.ParsePath(wallet.FormatPath(indices)));
        }

        [Fact]
        public void NonHardenedChildPrivateAndParentPublicMaterial_CanRecoverParentPrivate()
        {
            // BIP32 explicitly excludes secrecy of a parent private key when the
            // parent's extended public material and a non-hardened child private key leak.
            var wallet = new Bip32HdWallet();
            var parent = wallet.GenerateMasterKey(Convert.FromHexString("000102030405060708090a0b0c0d0e0f"));
            var child = wallet.DeriveChild(parent, 0);
            var method = typeof(Bip32HdWallet).GetMethod("DerivePublicKeyFromPrivate",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
            var publicKey = (byte[])method.Invoke(wallet, [parent.Key])!;
            var data = new byte[37];
            publicKey.CopyTo(data, 0); // Last four bytes encode index 0.
            byte[]? hmacResult = null;
            try
            {
                using var hmac = new System.Security.Cryptography.HMACSHA512(parent.ChainCode);
                hmacResult = hmac.ComputeHash(data);
                var left = new System.Numerics.BigInteger(hmacResult.AsSpan(0, 32), isUnsigned: true, isBigEndian: true);
                var childScalar = new System.Numerics.BigInteger(child.Key, isUnsigned: true, isBigEndian: true);
                var order = new System.Numerics.BigInteger(Convert.FromHexString(Order), isUnsigned: true, isBigEndian: true);
                var recovered = (childScalar - left + order) % order;

                Assert.Equal(parent.Key, EncodeScalar(recovered));
            }
            finally
            {
                if (hmacResult != null) HeroCrypt.Security.SecureMemoryOperations.SecureClear(hmacResult);
                child.Clear();
                parent.Clear();
            }
        }

        [Fact]
        public void DeriveChild_MutatedInvalidParent_IsRejected()
        {
            var parent = new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32]);
            Array.Clear(parent.Key);
            Assert.Throws<ArgumentException>(() => new Bip32HdWallet().DeriveChild(parent, Bip32HdWallet.HardenedOffset));
        }

        [Theory]
        [InlineData("m/2147483648")]
        [InlineData("m/4294967295")]
        [InlineData("m/+1")]
        [InlineData("m/ 1")]
        [InlineData("m/1 ")]
        public void ParsePath_AmbiguousOrNonCanonicalIndices_AreRejected(string path)
        {
            var wallet = new Bip32HdWallet();
            Assert.Throws<ArgumentException>(() => wallet.ParsePath(path));
            Assert.False(wallet.IsValidPath(path));
        }

        [Fact]
        public void NullArguments_DoNotEscapeAsNullReferenceOrNullResult()
        {
            var wallet = new Bip32HdWallet();
            Assert.Throws<ArgumentNullException>(() => wallet.DerivePath(null!, "m"));
            Assert.Throws<ArgumentNullException>(() => wallet.FormatPath(null!));
        }

        [Fact]
        public void DerivePath_TooDeep_IsRejectedWithoutClearingCallerRoot()
        {
            var parent = new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32], 254);
            Assert.Throws<ArgumentException>(() => new Bip32HdWallet().DerivePath(parent, "0/1"));
            Assert.Equal((byte)1, parent.Key[31]);
        }

        [Fact]
        public void PublicChildDerivation_ReportsUnsupportedOperation()
        {
            var parent = new Bip32HdWallet.ExtendedKey(Convert.FromHexString(Generator), new byte[32]);
            Assert.Throws<NotSupportedException>(() => new Bip32HdWallet().DeriveChild(parent, 0));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void CompliancePolicy_BlocksSecp256k1WalletOperations(bool master)
        {
            var wallet = new Bip32HdWallet(new HeroCrypt.Security.SecurityPolicyOptions(HeroCrypt.Security.SecurityLevel.Compliance));
            Assert.Throws<HeroCrypt.Security.SecurityPolicyException>(() =>
            {
                if (master)
                    wallet.GenerateMasterKey(new byte[16]);
                else
                    wallet.DeriveChild(new Bip32HdWallet.ExtendedKey(ScalarOne(), new byte[32]), 0);
            });
        }

        [Fact]
        public void Builder_ResultSeedIsIndependentOfCallerBuffer()
        {
            var seed = Enumerable.Repeat((byte)0x42, 32).ToArray();
            var result = new HdWalletBuilder().FromSeed(seed).Derive();
            Array.Clear(result.Seed);
            result.Key.Clear();

            Assert.All(seed, value => Assert.Equal((byte)0x42, value));
        }

        private delegate void AddModulo(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result);

        [Fact]
        public void ScalarAddition_CarryAndReduction_MatchIntegerReference()
        {
            var method = typeof(Bip32HdWallet).GetMethod("AddModN",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
            var add = method.CreateDelegate<AddModulo>();
            var n = new System.Numerics.BigInteger(Convert.FromHexString(Order), isUnsigned: true, isBigEndian: true);
            System.Numerics.BigInteger[] values = [0, 1, n / 2, n / 2 + 1, n - 2, n - 1];
            foreach (var a in values)
            {
                foreach (var b in values)
                {
                    var result = new byte[32];
                    add(EncodeScalar(a), EncodeScalar(b), result);
                    Assert.Equal(EncodeScalar((a + b) % n), result);
                }
            }
        }

        private static byte[] EncodeScalar(System.Numerics.BigInteger scalar)
        {
            var bytes = scalar.ToByteArray(isUnsigned: true, isBigEndian: true);
            var encoded = new byte[32];
            bytes.CopyTo(encoded, encoded.Length - bytes.Length);
            return encoded;
        }

        private static byte[] ScalarOne()
        {
            var key = new byte[32];
            key[31] = 1;
            return key;
        }
    }
}
#endif
