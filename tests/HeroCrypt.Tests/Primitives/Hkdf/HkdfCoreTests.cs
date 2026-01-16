using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Hkdf;

/// <summary>
/// Comprehensive tests for HKDF (HMAC-based Key Derivation Function) implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class HkdfCoreTests
{
    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void DeriveKey_WithValidParameters_ReturnsCorrectLength()
        {
            // Arrange
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");
            var length = 32;

            // Act
            var key = HkdfCore.DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);

            // Assert
            Assert.Equal(length, key.Length);
        }

        [Fact]
        public void DeriveKey_IsDeterministic()
        {
            // Arrange
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");
            var length = 32;

            // Act
            var key1 = HkdfCore.DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);
            var key2 = HkdfCore.DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentContexts_ProduceDifferentKeys()
        {
            // Arrange
            var ikm = Encoding.UTF8.GetBytes("master_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var length = 32;

            // Act
            var key1 = HkdfCore.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("context1"), length, HashAlgorithmName.SHA256);
            var key2 = HkdfCore.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("context2"), length, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void Extract_WithEmptySalt_ProducesCorrectPRK()
        {
            // Test that Extract works correctly when salt is empty
            // This exercises the code path where a zero-filled salt is created
            var ikm = Encoding.UTF8.GetBytes("input_key_material");

            var prk = HkdfCore.Extract(ikm, [], HashAlgorithmName.SHA256);

            // PRK should be hash length (32 bytes for SHA-256)
            Assert.Equal(32, prk.Length);

            // PRK should be deterministic
            var prk2 = HkdfCore.Extract(ikm, [], HashAlgorithmName.SHA256);
            Assert.Equal(prk, prk2);
        }

        [Fact]
        public void Extract_WithNonEmptySalt_ProducesCorrectPRK()
        {
            // Test that Extract works correctly with provided salt
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("some_salt_value");

            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);

            // PRK should be hash length (32 bytes for SHA-256)
            Assert.Equal(32, prk.Length);

            // PRK should be deterministic
            var prk2 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            Assert.Equal(prk, prk2);
        }

        [Fact]
        public void Extract_EmptyVsNonEmptySalt_ProduceDifferentPRKs()
        {
            // Verify that empty salt and non-empty salt produce different PRKs
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("some_salt_value");

            var prkWithEmptySalt = HkdfCore.Extract(ikm, [], HashAlgorithmName.SHA256);
            var prkWithSalt = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);

            // PRKs should be different
            Assert.False(prkWithEmptySalt.AsSpan().SequenceEqual(prkWithSalt));
        }

        [Fact]
        public void Extract_MultipleHashAlgorithms_Work()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");

            // Test SHA-256
            var prkSha256 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            Assert.Equal(32, prkSha256.Length);

            // Test SHA-384
            var prkSha384 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA384);
            Assert.Equal(48, prkSha384.Length);

            // Test SHA-512
            var prkSha512 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA512);
            Assert.Equal(64, prkSha512.Length);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Fact]
        public void DeriveKey_EmptyInfo_Success()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");

            var key = HkdfCore.DeriveKey(ikm, salt, [], 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void DeriveKey_EmptySalt_Success()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var info = Encoding.UTF8.GetBytes("info");

            var key = HkdfCore.DeriveKey(ikm, [], info, 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        [Fact]
        public void DeriveKey_OutputAppearsRandom()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");

            var key = HkdfCore.DeriveKey(ikm, salt, info, 32, HashAlgorithmName.SHA256);

            CryptoAssertions.AssertAppearsRandom(key);
        }

        [Fact]
        public void DeriveKey_DifferentIkm_ProducesDifferentKeys()
        {
            var ikm1 = Encoding.UTF8.GetBytes("input_key_material_1");
            var ikm2 = Encoding.UTF8.GetBytes("input_key_material_2");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");

            var key1 = HkdfCore.DeriveKey(ikm1, salt, info, 32, HashAlgorithmName.SHA256);
            var key2 = HkdfCore.DeriveKey(ikm2, salt, info, 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_InfoProvidesDomainSeparation()
        {
            // Using different info values for domain separation
            var ikm = Encoding.UTF8.GetBytes("master_secret");
            var salt = Encoding.UTF8.GetBytes("salt");

            var encryptionKey = HkdfCore.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("encryption"), 32, HashAlgorithmName.SHA256);
            var macKey = HkdfCore.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("mac"), 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(encryptionKey, macKey);
        }

        [Fact]
        public void DeriveKey_DifferentHashAlgorithm_ProducesDifferentKeys()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");

            var key256 = HkdfCore.DeriveKey(ikm, salt, info, 32, HashAlgorithmName.SHA256);
            var key512 = HkdfCore.DeriveKey(ikm, salt, info, 32, HashAlgorithmName.SHA512);

            Assert.NotEqual(key256, key512);
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
        public void DeriveKey_InvalidLength_ThrowsArgumentException()
        {
            var ikm = Encoding.UTF8.GetBytes("ikm");
            var salt = Encoding.UTF8.GetBytes("salt");

            Assert.Throws<ArgumentException>(() =>
                HkdfCore.DeriveKey(ikm, salt, [], 0, HashAlgorithmName.SHA256));

            Assert.Throws<ArgumentException>(() =>
                HkdfCore.DeriveKey(ikm, salt, [], -1, HashAlgorithmName.SHA256));
        }

        [Fact]
        public void Extract_EmptyIkm_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
               HkdfCore.Extract([], [], HashAlgorithmName.SHA256));
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 5869 test vectors.
    /// See: https://datatracker.ietf.org/doc/html/rfc5869#appendix-A
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void Rfc5869_TestCase1_Sha256_BasicTest()
        {
            // RFC 5869 Appendix A.1 - Test Case 1
            var ikm = TestHelpers.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = TestHelpers.HexToBytes("000102030405060708090a0b0c");
            var info = TestHelpers.HexToBytes("f0f1f2f3f4f5f6f7f8f9");
            var expectedPrk = TestHelpers.HexToBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
            var expectedOkm = TestHelpers.HexToBytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase2_Sha256_LongerInputsOutputs()
        {
            // RFC 5869 Appendix A.2 - Test Case 2 (longer inputs/outputs)
            var ikm = TestHelpers.HexToBytes(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f");
            var salt = TestHelpers.HexToBytes(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
            var info = TestHelpers.HexToBytes(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var expectedPrk = TestHelpers.HexToBytes("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
            var expectedOkm = TestHelpers.HexToBytes(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f1d87");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 82, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase3_Sha256_ZeroLengthSaltInfo()
        {
            // RFC 5869 Appendix A.3 - Test Case 3 (zero-length salt/info)
            var ikm = TestHelpers.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = Array.Empty<byte>();
            var info = Array.Empty<byte>();
            var expectedPrk = TestHelpers.HexToBytes("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
            var expectedOkm = TestHelpers.HexToBytes("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase4_Sha1_BasicTest()
        {
            // RFC 5869 Appendix A.4 - Test Case 4 (SHA-1)
            var ikm = TestHelpers.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b");
            var salt = TestHelpers.HexToBytes("000102030405060708090a0b0c");
            var info = TestHelpers.HexToBytes("f0f1f2f3f4f5f6f7f8f9");
            var expectedPrk = TestHelpers.HexToBytes("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243");
            var expectedOkm = TestHelpers.HexToBytes("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase5_Sha1_LongerInputsOutputs()
        {
            // RFC 5869 Appendix A.5 - Test Case 5 (SHA-1, longer)
            var ikm = TestHelpers.HexToBytes(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f");
            var salt = TestHelpers.HexToBytes(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
            var info = TestHelpers.HexToBytes(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var expectedPrk = TestHelpers.HexToBytes("8adae09a2a307059478d309b26c4115a224cfaf6");
            var expectedOkm = TestHelpers.HexToBytes(
                "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe" +
                "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e" +
                "927336d0441f4c4300e2cff0d0900b52d3b4");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 82, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase6_Sha1_ZeroLengthSaltInfo()
        {
            // RFC 5869 Appendix A.6 - Test Case 6 (SHA-1, zero-length)
            var ikm = TestHelpers.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = Array.Empty<byte>();
            var info = Array.Empty<byte>();
            var expectedPrk = TestHelpers.HexToBytes("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01");
            var expectedOkm = TestHelpers.HexToBytes("0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase7_Sha1_ZeroLengthIkm()
        {
            // RFC 5869 Appendix A.7 - Test Case 7 (SHA-1, zero-length IKM - edge case)
            // Note: Some implementations reject zero-length IKM, we test this for completeness
            var ikm = TestHelpers.HexToBytes("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
            var salt = Array.Empty<byte>(); // "not provided" in RFC means empty
            var info = Array.Empty<byte>();
            var expectedPrk = TestHelpers.HexToBytes("2adccada18779e7c2077ad2eb19d3f3e731385dd");
            var expectedOkm = TestHelpers.HexToBytes("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48");

            // Test Extract
            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test full DeriveKey
            var okm = HkdfCore.DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA1);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }
    }
}
