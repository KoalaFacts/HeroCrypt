using HeroCrypt.Cryptography.Primitives.Mac;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Mac;

/// <summary>
/// Comprehensive tests for AES-CMAC implementation (RFC 4493).
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class AesCmacCoreTests
{
    private const int BLOCK_SIZE = 16;
    private const int KEY_SIZE_128 = 16;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void ComputeTag_ValidInput_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var data = TestHelpers.RandomBytes(32);
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, key);

            Assert.NotEqual(new byte[BLOCK_SIZE], tag); // Should not be all zeros
        }

        [Fact]
        public void VerifyTag_ValidTag_ReturnsTrue()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var data = TestHelpers.RandomBytes(32);
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, key);
            var isValid = AesCmacCore.VerifyTag(tag, data, key);

            Assert.True(isValid);
        }

        [Fact]
        public void VerifyTag_InvalidTag_ReturnsFalse()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var data = TestHelpers.RandomBytes(32);
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, key);
            tag[0] ^= 0xFF; // Corrupt tag

            var isValid = AesCmacCore.VerifyTag(tag, data, key);

            Assert.False(isValid);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        [Fact]
        public void ComputeTag_InvalidKeySize_ThrowsArgumentException()
        {
            var key = new byte[15]; // Invalid
            var data = new byte[16];
            var tag = new byte[BLOCK_SIZE];

            Assert.Throws<ArgumentException>(() => AesCmacCore.ComputeTag(tag, data, key));
        }

        [Fact]
        public void ComputeTag_InvalidTagSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE_128];
            var data = new byte[16];
            var tag = new byte[BLOCK_SIZE - 1]; // Too small

            Assert.Throws<ArgumentException>(() => AesCmacCore.ComputeTag(tag, data, key));
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 4493 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        private static readonly byte[] Key = TestHelpers.HexToBytes("2b7e151628aed2a6abf7158809cf4f3c");

        [Fact]
        public void Rfc4493_Example1_EmptyString()
        {
            var data = Array.Empty<byte>();
            var expectedTag = TestHelpers.HexToBytes("bb1d6929e95937287fa37d129b756746");
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, Key);

            CryptoAssertions.AssertBytesEqual(expectedTag, tag);
        }

        [Fact]
        public void Rfc4493_Example2_16Bytes()
        {
            var data = TestHelpers.HexToBytes("6bc1bee22e409f96e93d7e117393172a");
            var expectedTag = TestHelpers.HexToBytes("070a16b46b4d4144f79bdd9dd04a287c");
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, Key);

            CryptoAssertions.AssertBytesEqual(expectedTag, tag);
        }

        [Fact]
        public void Rfc4493_Example3_40Bytes()
        {
            var data = TestHelpers.HexToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
            var expectedTag = TestHelpers.HexToBytes("dfa66747de9ae63030ca32611497c827");
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, Key);

            CryptoAssertions.AssertBytesEqual(expectedTag, tag);
        }

        [Fact]
        public void Rfc4493_Example4_64Bytes()
        {
            var data = TestHelpers.HexToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
            var expectedTag = TestHelpers.HexToBytes("51f0bebf7e3b9d92fc49741779363cfe");
            var tag = new byte[BLOCK_SIZE];

            AesCmacCore.ComputeTag(tag, data, Key);

            CryptoAssertions.AssertBytesEqual(expectedTag, tag);
        }
    }
}
