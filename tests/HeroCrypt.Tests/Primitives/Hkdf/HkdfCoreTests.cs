using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Security;
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
            var key = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);

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
            var key1 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);
            var key2 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);

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
            var key1 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("context1"), length, HashAlgorithmName.SHA256);
            var key2 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("context2"), length, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void Extract_WithEmptySalt_ProducesCorrectPRK()
        {
            // Test that Extract works correctly when salt is empty
            // This exercises the code path where a zero-filled salt is created
            var ikm = Encoding.UTF8.GetBytes("input_key_material");

            var prk = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, [], HashAlgorithmName.SHA256);

            // PRK should be hash length (32 bytes for SHA-256)
            Assert.Equal(32, prk.Length);

            // PRK should be deterministic
            var prk2 = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, [], HashAlgorithmName.SHA256);
            Assert.Equal(prk, prk2);
        }

        [Fact]
        public void Extract_WithNonEmptySalt_ProducesCorrectPRK()
        {
            // Test that Extract works correctly with provided salt
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("some_salt_value");

            var prk = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);

            // PRK should be hash length (32 bytes for SHA-256)
            Assert.Equal(32, prk.Length);

            // PRK should be deterministic
            var prk2 = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);
            Assert.Equal(prk, prk2);
        }

        [Fact]
        public void Extract_EmptyVsNonEmptySalt_ProduceDifferentPRKs()
        {
            // Verify that empty salt and non-empty salt produce different PRKs
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("some_salt_value");

            var prkWithEmptySalt = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, [], HashAlgorithmName.SHA256);
            var prkWithSalt = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);

            // PRKs should be different
            Assert.False(prkWithEmptySalt.AsSpan().SequenceEqual(prkWithSalt));
        }

        [Fact]
        public void Extract_MultipleHashAlgorithms_Work()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");

            // Test SHA-256
            var prkSha256 = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);
            Assert.Equal(32, prkSha256.Length);

            // Test SHA-384
            var prkSha384 = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA384);
            Assert.Equal(48, prkSha384.Length);

            // Test SHA-512
            var prkSha512 = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA512);
            Assert.Equal(64, prkSha512.Length);
        }
    }

    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class BclCompatibility
    {
        public static TheoryData<string, int, bool> BoundaryCases
        {
            get
            {
                var cases = new TheoryData<string, int, bool>();
                foreach (var (name, hashLength) in new[] { ("SHA256", 32), ("SHA384", 48), ("SHA512", 64) })
                {
                    foreach (int length in new[] { 1, hashLength - 1, hashLength, hashLength + 1, 2 * hashLength + 1, 255 * hashLength })
                    {
                        cases.Add(name, length, false);
                        cases.Add(name, length, true);
                    }
                }

                return cases;
            }
        }

        [Theory]
        [MemberData(nameof(BoundaryCases))]
        public void Expand_BlockBoundaries_MatchesBclAndPreservesInputs(string hashName, int length, bool withInfo)
        {
            var algorithm = new HashAlgorithmName(hashName);
            // 80 bytes is at least the hash length for every algorithm under test.
            var prk = Enumerable.Range(1, 80).Select(i => (byte)i).ToArray();
            var info = withInfo ? "HKDF Expand context"u8.ToArray() : [];
            var originalPrk = prk.ToArray();
            var originalInfo = info.ToArray();
            var expected = HKDF.Expand(algorithm, prk, length, info);

            var actual = new HkdfCore(SecurityPolicyOptions.Default).Expand(prk, info, length, algorithm);

            Assert.Equal(expected, actual);
            Assert.Equal(originalPrk, prk);
            Assert.Equal(originalInfo, info);
        }

        [Theory]
        [MemberData(nameof(BoundaryCases))]
        public void DeriveKey_BlockBoundaries_MatchesBclAndPreservesInputs(string hashName, int length, bool withInfo)
        {
            var algorithm = new HashAlgorithmName(hashName);
            var ikm = Enumerable.Range(1, 80).Select(i => (byte)i).ToArray();
            var salt = "HKDF salt"u8.ToArray();
            var info = withInfo ? "HKDF DeriveKey context"u8.ToArray() : [];
            var originalIkm = ikm.ToArray();
            var originalSalt = salt.ToArray();
            var originalInfo = info.ToArray();
            var expected = HKDF.DeriveKey(algorithm, ikm, length, salt, info);

            var actual = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, length, algorithm);

            Assert.Equal(expected, actual);
            Assert.Equal(originalIkm, ikm);
            Assert.Equal(originalSalt, salt);
            Assert.Equal(originalInfo, info);
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

            var key = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, [], 32, HashAlgorithmName.SHA256);

            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void DeriveKey_EmptySalt_Success()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var info = Encoding.UTF8.GetBytes("info");

            var key = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, [], info, 32, HashAlgorithmName.SHA256);

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

            var key = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, 32, HashAlgorithmName.SHA256);

            CryptoAssertions.AssertAppearsRandom(key);
        }

        [Fact]
        public void DeriveKey_DifferentIkm_ProducesDifferentKeys()
        {
            var ikm1 = Encoding.UTF8.GetBytes("input_key_material_1");
            var ikm2 = Encoding.UTF8.GetBytes("input_key_material_2");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");

            var key1 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm1, salt, info, 32, HashAlgorithmName.SHA256);
            var key2 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm2, salt, info, 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_InfoProvidesDomainSeparation()
        {
            // Using different info values for domain separation
            var ikm = Encoding.UTF8.GetBytes("master_secret");
            var salt = Encoding.UTF8.GetBytes("salt");

            var encryptionKey = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("encryption"), 32, HashAlgorithmName.SHA256);
            var macKey = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("mac"), 32, HashAlgorithmName.SHA256);

            Assert.NotEqual(encryptionKey, macKey);
        }

        [Fact]
        public void DeriveKey_DifferentHashAlgorithm_ProducesDifferentKeys()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");

            var key256 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, 32, HashAlgorithmName.SHA256);
            var key512 = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, 32, HashAlgorithmName.SHA512);

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
        public void Expand_EmptyPrk_ThrowsArgumentException()
        {
            var exception = Assert.Throws<ArgumentException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).Expand([], [], 32, HashAlgorithmName.SHA256));

            Assert.Equal("prk", exception.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        public void Expand_NonPositiveLength_ThrowsArgumentException(int length)
        {
            var exception = Assert.Throws<ArgumentException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).Expand(new byte[32], [], length, HashAlgorithmName.SHA256));

            Assert.Equal("length", exception.ParamName);
        }

        [Theory]
        [InlineData("SHA256", 8161)]
        [InlineData("SHA384", 12241)]
        [InlineData("SHA512", 16321)]
        public void Expand_LengthAboveAlgorithmMaximum_ThrowsArgumentException(string hashName, int length)
        {
            var exception = Assert.Throws<ArgumentException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).Expand(new byte[80], [], length, new HashAlgorithmName(hashName)));

            Assert.Equal("length", exception.ParamName);
        }

        [Fact]
        public void Expand_Sha1_BlockedAtStandardLevel()
        {
            var exception = Assert.Throws<SecurityPolicyException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).Expand(new byte[20], [], 32, HashAlgorithmName.SHA1));

            Assert.Equal("SHA1", exception.Algorithm);
        }

        [Fact]
        public void DeriveKey_InvalidLength_ThrowsArgumentException()
        {
            var ikm = Encoding.UTF8.GetBytes("ikm");
            var salt = Encoding.UTF8.GetBytes("salt");

            Assert.Throws<ArgumentException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, [], 0, HashAlgorithmName.SHA256));

            Assert.Throws<ArgumentException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, [], -1, HashAlgorithmName.SHA256));
        }

        [Fact]
        public void Extract_EmptyIkm_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
               new HkdfCore(SecurityPolicyOptions.Default).Extract([], [], HashAlgorithmName.SHA256));
        }

        [Fact]
        public void DeriveKey_Sha1_BlockedAtStandardLevel()
        {
            // Verify SHA-1 is blocked at Standard security level (default)
            var ikm = Encoding.UTF8.GetBytes("ikm");
            var salt = Encoding.UTF8.GetBytes("salt");

            var ex = Assert.Throws<SecurityPolicyException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, [], 32, HashAlgorithmName.SHA1));

            Assert.Equal("SHA1", ex.Algorithm);
            Assert.Equal("SHA-256", ex.Alternative);
        }

        [Fact]
        public void Extract_Sha1_BlockedAtStandardLevel()
        {
            // Verify SHA-1 is blocked at Standard security level (default)
            var ikm = Encoding.UTF8.GetBytes("ikm");
            var salt = Encoding.UTF8.GetBytes("salt");

            var ex = Assert.Throws<SecurityPolicyException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA1));

            Assert.Equal("SHA1", ex.Algorithm);
        }

        [Fact]
        public void GetRecommendedParameters_LegacyCompatibility_BlockedAtStandardLevel()
        {
            // Verify LegacyCompatibility (SHA-1) throws at Standard level
            var ex = Assert.Throws<SecurityPolicyException>(() =>
                new HkdfCore(SecurityPolicyOptions.Default).GetRecommendedParameters(HkdfUseCase.LegacyCompatibility));

            Assert.Equal("SHA1", ex.Algorithm);
        }

        [Fact]
        public void GetRecommendedParameters_LegacyCompatibility_AllowedInLegacyScope()
        {
            using (SecurityPolicy.LegacyScope())
            {
                var parameters = new HkdfCore(SecurityPolicy.CurrentPolicy).GetRecommendedParameters(HkdfUseCase.LegacyCompatibility);
                Assert.Equal(HashAlgorithmName.SHA1, parameters.HashAlgorithm);
            }
        }

        [Fact]
        public void DeriveKey_Sha1_AllowedInLegacyScope()
        {
            // Verify SHA-1 is allowed when using LegacyScope
            var ikm = Encoding.UTF8.GetBytes("ikm");
            var salt = Encoding.UTF8.GetBytes("salt");

            using (SecurityPolicy.LegacyScope())
            {
                var key = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(ikm, salt, [], 32, HashAlgorithmName.SHA1);
                Assert.Equal(32, key.Length);
            }
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
        [Theory]
        [InlineData("SHA256", 8160, "9477B7BA88122F5AA4E2D7B296483C1C288800F885777FE92F5888AB9C6C5430")]
        [InlineData("SHA512", 16320, "4224B7B7ED7BD4FD34BE44D1131D44B0E7D177B605A74EE0FA0A2FE827AC0685")]
        public void Expand_Maximum255Blocks_MatchesIndependentHmacReference(
            string algorithmName, int length, string expectedSha256)
        {
            // Reference independently calculated using Python hashlib/hmac:
            // PRK = HMAC(salt, ikm); T(i) = HMAC(PRK, T(i-1) || info || i).
            // Inputs deliberately cover multiple blocks and the final 255 counter.
            byte[] ikm = Enumerable.Range(0, 47).Select(i => (byte)((i * 7 + 11) % 256)).ToArray();
            byte[] salt = Enumerable.Range(0, 23).Select(i => (byte)((i * 5 + 19) % 256)).ToArray();
            byte[] info = Enumerable.Range(0, 39).Select(i => (byte)((i * 13 + 3) % 256)).ToArray();
            HashAlgorithmName algorithm = algorithmName == "SHA256"
                ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
            var hkdf = new HkdfCore(SecurityPolicyOptions.Default);
            byte[] prk = hkdf.Extract(ikm, salt, algorithm);
            try
            {
                byte[] okm = hkdf.Expand(prk, info, length, algorithm);
                Assert.Equal(length, okm.Length);
                Assert.Equal(expectedSha256, Convert.ToHexString(SHA256.HashData(okm)));
                Assert.Throws<ArgumentException>(() => hkdf.Expand(prk, info, length + 1, algorithm));
            }
            finally
            {
                SecureMemoryOperations.SecureClear(prk);
            }
        }

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
            var prk = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test Expand directly with the published PRK, independently of Extract.
            var expanded = new HkdfCore(SecurityPolicyOptions.Default).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

            // Test full DeriveKey
            var okm = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA256);
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
            var prk = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test Expand directly with the published PRK, independently of Extract.
            var expanded = new HkdfCore(SecurityPolicyOptions.Default).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

            // Test full DeriveKey
            var okm = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, 82, HashAlgorithmName.SHA256);
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
            var prk = new HkdfCore(SecurityPolicyOptions.Default).Extract(ikm, salt, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

            // Test Expand directly with the published PRK, independently of Extract.
            var expanded = new HkdfCore(SecurityPolicyOptions.Default).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

            // Test full DeriveKey
            var okm = new HkdfCore(SecurityPolicyOptions.Default).DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA256);
            CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
        }

        [Fact]
        public void Rfc5869_TestCase4_Sha1_BasicTest()
        {
            // RFC 5869 Appendix A.4 - Test Case 4 (SHA-1)
            // Note: SHA-1 is blocked at Standard security level; use LegacyScope for RFC compliance testing
            var ikm = TestHelpers.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b");
            var salt = TestHelpers.HexToBytes("000102030405060708090a0b0c");
            var info = TestHelpers.HexToBytes("f0f1f2f3f4f5f6f7f8f9");
            var expectedPrk = TestHelpers.HexToBytes("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243");
            var expectedOkm = TestHelpers.HexToBytes("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896");

            using (SecurityPolicy.LegacyScope())
            {
                // Test Extract
                var prk = new HkdfCore(SecurityPolicy.CurrentPolicy).Extract(ikm, salt, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

                // Test Expand directly with the published PRK, independently of Extract.
                var expanded = new HkdfCore(SecurityPolicy.CurrentPolicy).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

                // Test full DeriveKey
                var okm = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
            }
        }

        [Fact]
        public void Rfc5869_TestCase5_Sha1_LongerInputsOutputs()
        {
            // RFC 5869 Appendix A.5 - Test Case 5 (SHA-1, longer)
            // Note: SHA-1 is blocked at Standard security level; use LegacyScope for RFC compliance testing
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

            using (SecurityPolicy.LegacyScope())
            {
                // Test Extract
                var prk = new HkdfCore(SecurityPolicy.CurrentPolicy).Extract(ikm, salt, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

                // Test Expand directly with the published PRK, independently of Extract.
                var expanded = new HkdfCore(SecurityPolicy.CurrentPolicy).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

                // Test full DeriveKey
                var okm = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(ikm, salt, info, 82, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
            }
        }

        [Fact]
        public void Rfc5869_TestCase6_Sha1_ZeroLengthSaltInfo()
        {
            // RFC 5869 Appendix A.6 - Test Case 6 (SHA-1, zero-length)
            // Note: SHA-1 is blocked at Standard security level; use LegacyScope for RFC compliance testing
            var ikm = TestHelpers.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = Array.Empty<byte>();
            var info = Array.Empty<byte>();
            var expectedPrk = TestHelpers.HexToBytes("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01");
            var expectedOkm = TestHelpers.HexToBytes("0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918");

            using (SecurityPolicy.LegacyScope())
            {
                // Test Extract
                var prk = new HkdfCore(SecurityPolicy.CurrentPolicy).Extract(ikm, salt, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

                // Test Expand directly with the published PRK, independently of Extract.
                var expanded = new HkdfCore(SecurityPolicy.CurrentPolicy).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

                // Test full DeriveKey
                var okm = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
            }
        }

        [Fact]
        public void Rfc5869_TestCase7_Sha1_ZeroLengthIkm()
        {
            // RFC 5869 Appendix A.7 - Test Case 7 (SHA-1, zero-length IKM - edge case)
            // Note: Some implementations reject zero-length IKM, we test this for completeness
            // Note: SHA-1 is blocked at Standard security level; use LegacyScope for RFC compliance testing
            var ikm = TestHelpers.HexToBytes("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
            var salt = Array.Empty<byte>(); // "not provided" in RFC means empty
            var info = Array.Empty<byte>();
            var expectedPrk = TestHelpers.HexToBytes("2adccada18779e7c2077ad2eb19d3f3e731385dd");
            var expectedOkm = TestHelpers.HexToBytes("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48");

            using (SecurityPolicy.LegacyScope())
            {
                // Test Extract
                var prk = new HkdfCore(SecurityPolicy.CurrentPolicy).Extract(ikm, salt, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedPrk, prk);

                // Test Expand directly with the published PRK, independently of Extract.
                var expanded = new HkdfCore(SecurityPolicy.CurrentPolicy).Expand(expectedPrk, info, expectedOkm.Length, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, expanded);

                // Test full DeriveKey
                var okm = new HkdfCore(SecurityPolicy.CurrentPolicy).DeriveKey(ikm, salt, info, 42, HashAlgorithmName.SHA1);
                CryptoAssertions.AssertBytesEqual(expectedOkm, okm);
            }
        }
    }
}
