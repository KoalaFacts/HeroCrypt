using System.Security.Cryptography;
using HeroCrypt.Primitives.AesOcb;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.AesOcb;

/// <summary>
/// Comprehensive tests for AES-OCB (Offset Codebook Mode) implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class AesOcbCoreTests
{
    // OCB uses 16, 24, or 32 byte keys (AES-128/192/256)
    // Nonce size 1-15 bytes
    private const int KEY_SIZE_128 = 16;
    private const int KEY_SIZE_192 = 24;
    private const int KEY_SIZE_256 = 32;
    private const int DEFAULT_NONCE_SIZE = 12;
    private const int TAG_SIZE = 16;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        private readonly AesOcbCore core = new();

        [Fact]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_WithAssociatedData_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            // Act
            var result = core.Encrypt(plaintext, key, nonce, associatedData);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce, associatedData);

            // Assert
            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_VariableKeySizes_Success()
        {
            var keySizes = new[] { KEY_SIZE_128, KEY_SIZE_192, KEY_SIZE_256 };
            foreach (var size in keySizes)
            {
                var key = TestHelpers.RandomBytes(size);
                var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
                var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);

                var result = core.Encrypt(plaintext, key, nonce);
                var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

                CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
            }
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly AesOcbCore core = new();

        [Fact]
        public void Encrypt_EmptyPlaintext_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = Array.Empty<byte>();

            // Act
            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void Encrypt_PartialBlock_Success()
        {
            // Arrange - length not multiple of block size (16)
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(17);

            // Act
            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_VariableNonceSizes_Success()
        {
            // RFC 7253 allows 1-15 bytes
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);

            for (int i = 1; i <= 15; i++)
            {
                var nonce = TestHelpers.RandomBytes(i);

                var result = core.Encrypt(plaintext, key, nonce);
                var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

                CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
            }
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        private readonly AesOcbCore core = new();

        [Fact]
        public void Decrypt_ModifiedCiphertext_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            // Act - Tamper with ciphertext
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[0] ^= 0xFF;

            // Assert
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedTag_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            // Act - Tamper with tag
            var tamperedCiphertext = (byte[])result.Ciphertext.Clone();
            tamperedCiphertext[^1] ^= 0xFF;

            // Assert
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedAssociatedData_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE_128);
            var nonce = TestHelpers.RandomBytes(DEFAULT_NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            var result = core.Encrypt(plaintext, key, nonce, associatedData);

            // Act - Tamper with AD
            var tamperedAD = TestHelpers.TamperFirst(associatedData);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAD));
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        private readonly AesOcbCore core = new();

        [Fact]
        public void Encrypt_InvalidKeySize_ThrowsArgumentException()
        {
            var invalidKey = new byte[15]; // Not 16, 24, 32
            var nonce = new byte[DEFAULT_NONCE_SIZE];
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => core.Encrypt(plaintext, invalidKey, nonce),
                "16, 24, or 32 bytes");
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE_128];
            var invalidNonce = new byte[16]; // Max is 15
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => core.Encrypt(plaintext, key, invalidNonce),
                "between 1 and 15");
        }
    }

    /// <summary>
    /// Known Answer Tests for AES-OCB AEAD cipher.
    /// Implementation is verified via round-trip tests; these tests verify determinism and correctness.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        private readonly AesOcbCore core = new();

        /// <summary>
        /// Independent published ciphertext fixtures, not implementation-derived
        /// round trips. RFC 7253 Appendix A, 128-bit tag, AES-128, all 16 cases.
        /// These are mandatory interoperability checks for the corrected wire format.
        /// </summary>
        [Theory]
        [InlineData("00", "", "", "785407BFFFC8AD9EDCC5520AC9111EE6")]
        [InlineData("01", "0001020304050607", "0001020304050607", "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009")]
        [InlineData("02", "0001020304050607", "", "81017F8203F081277152FADE694A0A00")]
        [InlineData("03", "", "0001020304050607", "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9")]
        [InlineData("04", "000102030405060708090A0B0C0D0E0F", "000102030405060708090A0B0C0D0E0F", "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358")]
        [InlineData("05", "000102030405060708090A0B0C0D0E0F", "", "8CF761B6902EF764462AD86498CA6B97")]
        [InlineData("06", "", "000102030405060708090A0B0C0D0E0F", "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D")]
        [InlineData("07", "000102030405060708090A0B0C0D0E0F1011121314151617", "000102030405060708090A0B0C0D0E0F1011121314151617", "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F")]
        [InlineData("08", "000102030405060708090A0B0C0D0E0F1011121314151617", "", "6DC225A071FC1B9F7C69F93B0F1E10DE")]
        [InlineData("09", "", "000102030405060708090A0B0C0D0E0F1011121314151617", "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF")]
        [InlineData("0A", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240")]
        [InlineData("0B", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "", "FE80690BEE8A485D11F32965BC9D2A32")]
        [InlineData("0C", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF")]
        [InlineData("0D", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60")]
        [InlineData("0E", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "", "C5CD9D1850C141E358649994EE701B68")]
        [InlineData("0F", "", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479")]
        public void Rfc7253AppendixA_EncryptAndDecrypt_MatchOfficialVectors(
            string nonceSuffix, string associatedDataHex, string plaintextHex, string expectedCiphertextHex)
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA998877665544332211" + nonceSuffix);
            var associatedData = associatedDataHex.Length == 0
                ? Array.Empty<byte>()
                : TestHelpers.HexToBytes(associatedDataHex);
            var plaintext = plaintextHex.Length == 0
                ? Array.Empty<byte>()
                : TestHelpers.HexToBytes(plaintextHex);
            var expectedCiphertext = TestHelpers.HexToBytes(expectedCiphertextHex);

            var result = core.Encrypt(plaintext, key, nonce, associatedData);
            CryptoAssertions.AssertBytesEqual(expectedCiphertext, result.Ciphertext);

            // Decrypt the independent RFC bytes, not our own generated output.
            CryptoAssertions.AssertBytesEqual(
                plaintext, core.Decrypt(expectedCiphertext, key, nonce, associatedData));
        }

        [Fact]
        public void AesOcb_EmptyMessage_ProducesTagOnly()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221100");
            var plaintext = Array.Empty<byte>();
            var ad = Array.Empty<byte>();

            var result = core.Encrypt(plaintext, key, nonce, ad);

            // For empty plaintext, ciphertext is just the tag (16 bytes)
            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = core.Decrypt(result.Ciphertext, key, nonce, ad);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void AesOcb_WithMessage_IsDeterministic()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221101");
            var plaintext = TestHelpers.HexToBytes("0001020304050607");
            var ad = Array.Empty<byte>();

            var result1 = core.Encrypt(plaintext, key, nonce, ad);
            var result2 = core.Encrypt(plaintext, key, nonce, ad);

            CryptoAssertions.AssertBytesEqual(result1.Ciphertext, result2.Ciphertext);

            // Verify decryption
            var decrypted = core.Decrypt(result1.Ciphertext, key, nonce, ad);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void AesOcb_EmptyPlaintextWithAD_ProducesTagOnly()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221102");
            var plaintext = Array.Empty<byte>();
            var ad = TestHelpers.HexToBytes("0001020304050607");

            var result = core.Encrypt(plaintext, key, nonce, ad);

            Assert.Equal(TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = core.Decrypt(result.Ciphertext, key, nonce, ad);
            Assert.Empty(decrypted);
        }

        [Fact]
        public void AesOcb_WithMessageAndAD_RoundTrip()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221103");
            var plaintext = TestHelpers.HexToBytes("0001020304050607");
            var ad = TestHelpers.HexToBytes("0001020304050607");

            var result = core.Encrypt(plaintext, key, nonce, ad);

            // Ciphertext should be plaintext length + tag
            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = core.Decrypt(result.Ciphertext, key, nonce, ad);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void AesOcb_16ByteBlockMessage_RoundTrip()
        {
            var key = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var nonce = TestHelpers.HexToBytes("BBAA99887766554433221106");
            var plaintext = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");
            var ad = TestHelpers.HexToBytes("000102030405060708090A0B0C0D0E0F");

            var result = core.Encrypt(plaintext, key, nonce, ad);

            Assert.Equal(plaintext.Length + TAG_SIZE, result.Ciphertext.Length);

            // Verify decryption
            var decrypted = core.Decrypt(result.Ciphertext, key, nonce, ad);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }
}
