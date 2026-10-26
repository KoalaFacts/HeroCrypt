using System.Security.Cryptography;
using HeroCrypt.Primitives.AesCcm;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.AesCcm;

/// <summary>
/// Comprehensive tests for AES-CCM implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class AesCcmCoreTests
{
    private const int KEY_SIZE = 16;
    private const int NONCE_SIZE = 13; // Standard nonce size for CCM
    private const int DEFAULT_TAG_SIZE = 16;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        private readonly AesCcmCore core = new();

        [Fact]
        public void EncryptDecrypt_RoundTrip_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            // Act
            var result = core.Encrypt(plaintext, key, nonce, associatedData, DEFAULT_TAG_SIZE);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce, associatedData, DEFAULT_TAG_SIZE);

            // Assert
            Assert.Equal(plaintext.Length + DEFAULT_TAG_SIZE, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Encrypt_WithoutAssociatedData_Success()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var result = core.Encrypt(plaintext, key, nonce);
            var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly AesCcmCore core = new();

        [Fact]
        public void Encrypt_EmptyPlaintext_ReturnsTagOnly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = Array.Empty<byte>();

            // Act
            var result = core.Encrypt(plaintext, key, nonce);

            // Assert
            Assert.Equal(DEFAULT_TAG_SIZE, result.Ciphertext.Length);
            Assert.False(TestHelpers.AllZeros(result.Ciphertext));
        }

        [Fact]
        public void Encrypt_VariableTagSizes_Supported()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Small);
            var tagSizes = new[] { 4, 6, 8, 10, 12, 14, 16 };

            foreach (var tagSize in tagSizes)
            {
                var result = core.Encrypt(plaintext, key, nonce, default, tagSize);
                var decrypted = core.Decrypt(result.Ciphertext, key, result.Nonce, default, tagSize);

                Assert.Equal(plaintext.Length + tagSize, result.Ciphertext.Length);
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
        private readonly AesCcmCore core = new();

        [Fact]
        public void Encrypt_DeterministicMode_RejectsDefaultPolicyEvenWithExplicitNonce()
        {
            var key = new byte[KEY_SIZE];
            var plaintext = new byte[] { 0x42 };
            var secureCore = new AesCcmCore(HeroCrypt.Security.SecurityPolicyOptions.Default);

            Assert.Throws<InvalidOperationException>(
                () => secureCore.Encrypt(plaintext, key, deterministicMode: true));
            Assert.Throws<InvalidOperationException>(
                () => secureCore.Encrypt(plaintext, key, new byte[NONCE_SIZE], deterministicMode: true));
        }

        [Fact]
        public void Encrypt_DeterministicMode_RequiresExplicitOptInAndRoundTripsInTesting()
        {
            var key = new byte[KEY_SIZE];
            var plaintext = new byte[] { 0x42, 0x43, 0x44 };
            var optedInPolicy = HeroCrypt.Security.SecurityPolicyOptions.Default with { AllowDeterministicNonSiv = true };
            var optedInCore = new AesCcmCore(optedInPolicy);

            var first = optedInCore.Encrypt(plaintext, key, deterministicMode: true);
            var second = optedInCore.Encrypt(plaintext, key, deterministicMode: true);

            Assert.Equal(new byte[NONCE_SIZE], first.Nonce);
            CryptoAssertions.AssertBytesEqual(first.Ciphertext, second.Ciphertext);
            CryptoAssertions.AssertBytesEqual(plaintext,
                optedInCore.Decrypt(first.Ciphertext, key, first.Nonce));

            // A testing policy has the same explicit opt-in; never rely on it
            // for production nonces.
            var testingCore = new AesCcmCore(HeroCrypt.Security.SecurityPolicyOptions.Testing);
            var testResult = testingCore.Encrypt(plaintext, key, deterministicMode: true);
            Assert.Equal(new byte[NONCE_SIZE], testResult.Nonce);
            CryptoAssertions.AssertBytesEqual(plaintext,
                testingCore.Decrypt(testResult.Ciphertext, key, testResult.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedCiphertext_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            // Act - Tamper with ciphertext (part of the encrypted message)
            var tamperedCiphertext = TestHelpers.TamperFirst(result.Ciphertext);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedTag_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var result = core.Encrypt(plaintext, key, nonce);

            // Act - Tamper with tag (at the end)
            var tamperedCiphertext = TestHelpers.TamperLast(result.Ciphertext);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(tamperedCiphertext, key, result.Nonce));
        }

        [Fact]
        public void Decrypt_ModifiedAssociatedData_ThrowsCryptographicException()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var associatedData = TestHelpers.RandomBytes(TestDataSizes.Small);

            var result = core.Encrypt(plaintext, key, nonce, associatedData, DEFAULT_TAG_SIZE);

            // Act - Tamper with AD
            var tamperedAD = TestHelpers.TamperFirst(associatedData);

            // Assert
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(result.Ciphertext, key, result.Nonce, tamperedAD, DEFAULT_TAG_SIZE));
        }
    }

    /// <summary>
    /// Tampering must not return unauthenticated plaintext or poison later calls.
    /// The source additionally scrubs partial plaintext/tags on exceptions;
    /// managed-buffer erasure is a best-effort property, not asserted here.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class AuthenticationFailureRecovery
    {
        private readonly AesCcmCore core = new();

        [Fact]
        public void Decrypt_RejectsTampering_ThenAcceptsAuthenticCiphertext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(33);
            var associatedData = TestHelpers.RandomBytes(17);
            var result = core.Encrypt(plaintext, key, nonce, associatedData);

            var alteredCiphertext = (byte[])result.Ciphertext.Clone();
            alteredCiphertext[0] ^= 0x80;
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(alteredCiphertext, key, nonce, associatedData));

            var alteredTag = (byte[])result.Ciphertext.Clone();
            alteredTag[^1] ^= 0x01;
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(alteredTag, key, nonce, associatedData));

            var alteredAad = (byte[])associatedData.Clone();
            alteredAad[0] ^= 0x01;
            Assert.Throws<CryptographicException>(() =>
                core.Decrypt(result.Ciphertext, key, nonce, alteredAad));

            CryptoAssertions.AssertBytesEqual(plaintext,
                core.Decrypt(result.Ciphertext, key, nonce, associatedData));
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        private readonly AesCcmCore core = new();

        [Fact]
        public void Encrypt_InvalidKeySize_ThrowsArgumentException()
        {
            var invalidKey = new byte[12];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => core.Encrypt(plaintext, invalidKey, nonce),
                "Key must be");
        }

        [Fact]
        public void Encrypt_InvalidNonceSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var invalidNonce = new byte[6]; // Too short
            var plaintext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => core.Encrypt(plaintext, key, invalidNonce),
                "Nonce");
        }

        [Fact]
        public void Encrypt_InvalidTagSize_ThrowsArgumentException()
        {
            var key = new byte[KEY_SIZE];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];

            // Odd sizes validation
            Assert.Throws<ArgumentException>(() =>
                core.Encrypt(plaintext, key, nonce, default, tagSize: 7));

            // Too small validation
            Assert.Throws<ArgumentException>(() =>
                core.Encrypt(plaintext, key, nonce, default, tagSize: 2));

            // Too large validation
            Assert.Throws<ArgumentException>(() =>
                core.Encrypt(plaintext, key, nonce, default, tagSize: 18));
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 3610 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        private readonly AesCcmCore core = new();

        [Fact]
        public void Rfc3610_TestVector1()
        {
            var key = TestHelpers.HexToBytes("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
            var nonce = TestHelpers.HexToBytes("00000003020100A0A1A2A3A4A5");
            var plaintext = TestHelpers.HexToBytes("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
            var associatedData = TestHelpers.HexToBytes("0001020304050607");
            var expectedCiphertext = TestHelpers.HexToBytes("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0");

            var result = core.Encrypt(plaintext, key, nonce, associatedData, tagSize: 8);

            Assert.Equal(plaintext.Length + 8, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(expectedCiphertext, result.Ciphertext);
        }

        [Fact]
        public void IndependentAesCcm_SevenByteNonceShortAad_MatchesReferenceVector()
        {
            // Independent AES-CCM reference output generated using the PyCA
            // cryptography AESCCM implementation (AES-128, tag length 8).
            // This runs even where the platform's .NET AesCcm is unsupported.
            var key = TestHelpers.HexToBytes("000102030405060708090a0b0c0d0e0f");
            var nonce = TestHelpers.HexToBytes("00010203040506");
            var plaintext = TestHelpers.HexToBytes("42");
            var associatedData = TestHelpers.HexToBytes("010203");
            var expectedCiphertextAndTag = TestHelpers.HexToBytes("150d713f03056422e8");

            var actual = core.Encrypt(plaintext, key, nonce, associatedData, tagSize: 8);
            CryptoAssertions.AssertBytesEqual(expectedCiphertextAndTag, actual.Ciphertext);
            CryptoAssertions.AssertBytesEqual(plaintext,
                core.Decrypt(expectedCiphertextAndTag, key, nonce, associatedData, tagSize: 8));
        }


        [Theory]
        [InlineData(14, "157e0f1772e35d0dff")]
        [InlineData(15, "150155db61e7f09333")]
        [InlineData(0xFEFF, "15013f00b2ff339738")]
        [InlineData(0xFF00, "151d14dfa7e2401fbd")]
        public void IndependentAesCcm_AadEncodingBoundaries_MatchReferenceAndRejectTampering(
            int associatedDataLength, string expectedCiphertextAndTagHex)
        {
            // Fixed independent PyCA cryptography 46.0.4 AESCCM/AES-128 vectors:
            // nonce=00010203040506, plaintext=42, tag length=8; AAD bytes
            // follow (13 * index + 5) modulo 256. These always execute,
            // including where the platform BCL AesCcm provider is unsupported.
            // Length 14 exactly fills the short-form first block after the
            // two-byte length prefix; 15 crosses it. 0xFEFF/0xFF00 straddle
            // the RFC 3610 short/extended AAD length encoding boundary.
            var key = TestHelpers.HexToBytes("000102030405060708090a0b0c0d0e0f");
            var nonce = TestHelpers.HexToBytes("00010203040506");
            var plaintext = TestHelpers.HexToBytes("42");
            var associatedData = new byte[associatedDataLength];
            for (var i = 0; i < associatedData.Length; i++)
                associatedData[i] = (byte)(i * 13 + 5);
            var expected = TestHelpers.HexToBytes(expectedCiphertextAndTagHex);

            var actual = core.Encrypt(plaintext, key, nonce, associatedData, tagSize: 8);
            CryptoAssertions.AssertBytesEqual(expected, actual.Ciphertext);
            CryptoAssertions.AssertBytesEqual(plaintext,
                core.Decrypt(expected, key, nonce, associatedData, tagSize: 8));

            var alteredAad = (byte[])associatedData.Clone();
            alteredAad[0] ^= 1;
            Assert.Throws<CryptographicException>(
                () => core.Decrypt(expected, key, nonce, alteredAad, tagSize: 8));
        }

        [Theory]
        [InlineData(13, 0xFFFF, "6bc40f63f19555f5f62abc056b53737700e9ec95eedb1da2bc69a2f3a5240c0a")]
        [InlineData(12, 0x10000, "4d36b4cd7f9dd2379a384bab3e8938c621a030a100a6b32cfce311a24ffd0242")]
        public void IndependentAesCcm_CounterLengthBoundary_MatchesReferenceAndEnforcesNonceLimit(
            int nonceSize, int plaintextLength, string expectedCiphertextSha256)
        {
            // Independent PyCA cryptography 46.0.4 AES-128-CCM reference output.
            // Digest covers ALL ciphertext bytes plus the 16-byte tag. It catches
            // CBC-MAC length-encoding and CTR counter errors at the L=2 limit.
            // Always runs on all hosts, including those without BCL AES-CCM.
            var key = TestHelpers.HexToBytes("000102030405060708090a0b0c0d0e0f");
            var nonce = new byte[nonceSize];
            for (var i = 0; i < nonce.Length; i++)
                nonce[i] = (byte)i;
            var associatedData = new byte[14];
            for (var i = 0; i < associatedData.Length; i++)
                associatedData[i] = (byte)(i * 13 + 5);
            var plaintext = new byte[plaintextLength];
            for (var i = 0; i < plaintext.Length; i++)
                plaintext[i] = (byte)(i * 17 + 3);

            var result = core.Encrypt(plaintext, key, nonce, associatedData, tagSize: 16);
            Assert.Equal(plaintextLength + 16, result.Ciphertext.Length);
            CryptoAssertions.AssertBytesEqual(
                TestHelpers.HexToBytes(expectedCiphertextSha256),
                SHA256.HashData(result.Ciphertext));
            CryptoAssertions.AssertBytesEqual(plaintext,
                core.Decrypt(result.Ciphertext, key, nonce, associatedData, tagSize: 16));

            if (nonceSize == 13)
            {
                // L=2 can encode at most 65535 message bytes; preflight must
                // reject 65536 BEFORE attempting CBC-MAC/CTR.
                var overlongPlaintext = new byte[0x10000];
                var overlongCiphertextAndTag = new byte[0x10000 + 16];
                Assert.Throws<ArgumentException>(() =>
                    core.Encrypt(overlongPlaintext, key, nonce, associatedData, tagSize: 16));
                Assert.Throws<ArgumentException>(() =>
                    core.Decrypt(overlongCiphertextAndTag, key, nonce, associatedData, tagSize: 16));
            }
        }

        [Theory]
        [InlineData(7, 0, 0, 8)]
        [InlineData(7, 1, 3, 8)]
        [InlineData(7, 17, 14, 8)]
        [InlineData(7, 17, 15, 8)]
        [InlineData(13, 1, 1, 16)]
        [InlineData(13, 31, 13, 16)]
        [InlineData(13, 31, 14, 16)]
        [InlineData(13, 31, 15, 16)]
        [InlineData(13, 1, 0xFEFF, 16)]
        [InlineData(13, 1, 0xFF00, 16)]
        public void DotNetAesCcm_EncryptDecrypt_MatchesAcrossAadAndNonceBoundaries(
            int nonceLength, int plaintextLength, int associatedDataLength, int tagSize)
        {
            // RFC 3610 known-answer and the independent seven-byte-nonce
            // vector above remain unconditional, even on unsupported platforms.
            Assert.SkipUnless(
                System.Security.Cryptography.AesCcm.IsSupported,
                "The platform BCL has no AES-CCM provider; independent vectors still run.");

            var key = new byte[KEY_SIZE];
            for (var i = 0; i < key.Length; i++) key[i] = (byte)i;
            var nonce = new byte[nonceLength];
            for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i + 1);
            var plaintext = new byte[plaintextLength];
            for (var i = 0; i < plaintext.Length; i++) plaintext[i] = (byte)(i * 17 + 3);
            var associatedData = new byte[associatedDataLength];
            for (var i = 0; i < associatedData.Length; i++)
                associatedData[i] = (byte)(i * 13 + 5);

            var referenceCiphertext = new byte[plaintextLength];
            var referenceTag = new byte[tagSize];
            using var bcl = new System.Security.Cryptography.AesCcm(key);
            bcl.Encrypt(nonce, plaintext, referenceCiphertext, referenceTag, associatedData);

            var result = core.Encrypt(plaintext, key, nonce, associatedData, tagSize);
            CryptoAssertions.AssertBytesEqual(referenceCiphertext,
                result.Ciphertext.AsSpan(0, plaintextLength).ToArray());
            CryptoAssertions.AssertBytesEqual(referenceTag,
                result.Ciphertext.AsSpan(plaintextLength, tagSize).ToArray());

            // Verify HeroCrypt accepts independent BCL output.
            var referenceCombined = new byte[plaintextLength + tagSize];
            referenceCiphertext.CopyTo(referenceCombined, 0);
            referenceTag.CopyTo(referenceCombined, plaintextLength);
            CryptoAssertions.AssertBytesEqual(plaintext,
                core.Decrypt(referenceCombined, key, nonce, associatedData, tagSize));

            // Verify the reverse interoperability direction.
            var bclPlaintext = new byte[plaintextLength];
            bcl.Decrypt(nonce,
                result.Ciphertext.AsSpan(0, plaintextLength),
                result.Ciphertext.AsSpan(plaintextLength, tagSize),
                bclPlaintext, associatedData);
            CryptoAssertions.AssertBytesEqual(plaintext, bclPlaintext);

            if (associatedDataLength > 0 && associatedDataLength < 16)
            {
                var alteredAad = (byte[])associatedData.Clone();
                alteredAad[0] ^= 1;
                Assert.Throws<CryptographicException>(
                    () => core.Decrypt(referenceCombined, key, nonce, alteredAad, tagSize));
            }
        }
    }
}
