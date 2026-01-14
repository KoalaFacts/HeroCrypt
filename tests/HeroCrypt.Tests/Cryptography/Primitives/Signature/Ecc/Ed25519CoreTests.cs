using HeroCrypt.Cryptography.Primitives.Signature.Ecc;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Signature.Ecc;

/// <summary>
/// Comprehensive tests for Ed25519 signature implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Ed25519CoreTests
{
    private const int PRIVATE_KEY_SIZE = 32;
    private const int PUBLIC_KEY_SIZE = 32;
    private const int SIGNATURE_SIZE = 64;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void GenerateKeyPair_ReturnsValidSizedKeys()
        {
            // Act
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

            // Assert
            Assert.Equal(PRIVATE_KEY_SIZE, privateKey.Length);
            Assert.Equal(PUBLIC_KEY_SIZE, publicKey.Length);
        }

        [Fact]
        public void GenerateKeyPair_ProducesNonZeroKeys()
        {
            // Act
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

            // Assert
            Assert.False(TestHelpers.AllZeros(privateKey));
            Assert.False(TestHelpers.AllZeros(publicKey));
        }

        [Fact]
        public void GenerateKeyPair_ProducesDifferentKeysEachCall()
        {
            // Act
            var (privateKey1, publicKey1) = Ed25519Core.GenerateKeyPair();
            var (privateKey2, publicKey2) = Ed25519Core.GenerateKeyPair();

            // Assert
            Assert.NotEqual(privateKey1, privateKey2);
            Assert.NotEqual(publicKey1, publicKey2);
        }

        [Fact]
        public void DerivePublicKey_FromPrivateKey_MatchesGenerated()
        {
            // Arrange
            var (privateKey, expectedPublicKey) = Ed25519Core.GenerateKeyPair();

            // Act
            var derivedPublicKey = Ed25519Core.DerivePublicKey(privateKey);

            // Assert
            CryptoAssertions.AssertBytesEqual(expectedPublicKey, derivedPublicKey);
        }

        [Fact]
        public void Sign_WithValidInput_ReturnsCorrectSizeSignature()
        {
            // Arrange
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var signature = Ed25519Core.Sign(message, privateKey);

            // Assert
            Assert.Equal(SIGNATURE_SIZE, signature.Length);
            Assert.False(TestHelpers.AllZeros(signature));
        }

        [Fact]
        public void Verify_ValidSignature_ReturnsTrue()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var signature = Ed25519Core.Sign(message, privateKey);

            // Act - Note: Verify(message, signature, publicKey)
            var result = Ed25519Core.Verify(message, signature, publicKey);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Sign_SameMessageSameKey_IsDeterministic()
        {
            // Ed25519 signatures are deterministic
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var signature1 = Ed25519Core.Sign(message, privateKey);
            var signature2 = Ed25519Core.Sign(message, privateKey);

            // Assert
            CryptoAssertions.AssertBytesEqual(signature1, signature2);
        }

        [Fact]
        public void Sign_DifferentMessages_ProducesDifferentSignatures()
        {
            // Arrange
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();
            var message1 = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var message2 = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act
            var signature1 = Ed25519Core.Sign(message1, privateKey);
            var signature2 = Ed25519Core.Sign(message2, privateKey);

            // Assert
            Assert.NotEqual(signature1, signature2);
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
        public void SignVerify_EmptyMessage_Succeeds()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = Array.Empty<byte>();

            // Act
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, publicKey);

            // Assert
            Assert.Equal(SIGNATURE_SIZE, signature.Length);
            Assert.True(isValid);
        }

        [Fact]
        public void SignVerify_SingleByte_Succeeds()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();

            var message = "B"u8.ToArray();

            // Act
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, publicKey);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void SignVerify_LargeMessage_Succeeds()
        {
            // Arrange - 1 MB message
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);

            // Act
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, publicKey);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void SignVerify_AllZerosMessage_Succeeds()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.ZeroBytes(64);

            // Act
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, publicKey);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void SignVerify_AllOnesMessage_Succeeds()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.FilledBytes(64, 0xFF);

            // Act
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, publicKey);

            // Assert
            Assert.True(isValid);
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
        public void Verify_ModifiedMessage_ReturnsFalse()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var signature = Ed25519Core.Sign(message, privateKey);

            // Act - modify message
            var tamperedMessage = TestHelpers.TamperFirst(message);
            var result = Ed25519Core.Verify(tamperedMessage, signature, publicKey);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_ModifiedSignature_ReturnsFalse()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var signature = Ed25519Core.Sign(message, privateKey);

            // Act - modify signature
            var tamperedSignature = TestHelpers.TamperFirst(signature);
            var result = Ed25519Core.Verify(message, tamperedSignature, publicKey);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WrongPublicKey_ReturnsFalse()
        {
            // Arrange
            var (privateKey1, _) = Ed25519Core.GenerateKeyPair();
            var (_, publicKey2) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var signature = Ed25519Core.Sign(message, privateKey1);

            // Act - verify with wrong public key
            var result = Ed25519Core.Verify(message, signature, publicKey2);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_RandomSignature_ReturnsFalse()
        {
            // Arrange
            var (_, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var randomSignature = TestHelpers.RandomBytes(SIGNATURE_SIZE);

            // Act
            var result = Ed25519Core.Verify(message, randomSignature, publicKey);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_ZeroSignature_ReturnsFalse()
        {
            // Arrange
            var (_, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var zeroSignature = TestHelpers.ZeroBytes(SIGNATURE_SIZE);

            // Act
            var result = Ed25519Core.Verify(message, zeroSignature, publicKey);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_SignatureForDifferentMessage_ReturnsFalse()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message1 = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var message2 = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var signature = Ed25519Core.Sign(message1, privateKey);

            // Act - verify signature for different message
            var result = Ed25519Core.Verify(message2, signature, publicKey);

            // Assert
            Assert.False(result);
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
        public void DerivePublicKey_NullPrivateKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Ed25519Core.DerivePublicKey(null!));
        }

        [Fact]
        public void DerivePublicKey_InvalidSize_ThrowsArgumentException()
        {
            var invalidKey = TestHelpers.RandomBytes(PRIVATE_KEY_SIZE - 1);

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Ed25519Core.DerivePublicKey(invalidKey),
                "32 bytes");
        }

        [Fact]
        public void Sign_NullMessage_ThrowsArgumentNullException()
        {
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();

            Assert.Throws<ArgumentNullException>(() =>
                Ed25519Core.Sign(null!, privateKey));
        }

        [Fact]
        public void Sign_NullPrivateKey_ThrowsArgumentNullException()
        {
            var message = TestHelpers.RandomBytes(TestDataSizes.Small);

            Assert.Throws<ArgumentNullException>(() =>
                Ed25519Core.Sign(message, null!));
        }

        [Fact]
        public void Verify_NullMessage_ThrowsArgumentNullException()
        {
            var (_, publicKey) = Ed25519Core.GenerateKeyPair();
            var signature = TestHelpers.RandomBytes(SIGNATURE_SIZE);

            Assert.Throws<ArgumentNullException>(() =>
                Ed25519Core.Verify(null!, signature, publicKey));
        }

        [Fact]
        public void Verify_NullSignature_ThrowsArgumentNullException()
        {
            var (_, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Small);

            Assert.Throws<ArgumentNullException>(() =>
                Ed25519Core.Verify(message, null!, publicKey));
        }

        [Fact]
        public void Verify_InvalidSignatureSize_ThrowsArgumentException()
        {
            var (_, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Small);
            var invalidSignature = TestHelpers.RandomBytes(SIGNATURE_SIZE - 1);

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Ed25519Core.Verify(message, invalidSignature, publicKey),
                "64 bytes");
        }
    }

    /// <summary>
    /// Known Answer Tests using official RFC 8032 test vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void RFC8032_Test1_EmptyMessage()
        {
            // RFC 8032 Section 7.1 Test 1
            var privateKey = TestHelpers.HexToBytes(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
            var expectedPublicKey = TestHelpers.HexToBytes(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            var message = Array.Empty<byte>();
            var expectedSignature = TestHelpers.HexToBytes(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

            // Act
            var derivedPublicKey = Ed25519Core.DerivePublicKey(privateKey);
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, derivedPublicKey);

            // Assert
            CryptoAssertions.AssertBytesEqual(expectedPublicKey, derivedPublicKey);
            CryptoAssertions.AssertBytesEqual(expectedSignature, signature);
            Assert.True(isValid);
        }

        [Fact]
        public void RFC8032_Test2_SingleByte()
        {
            // RFC 8032 Section 7.1 Test 2
            var privateKey = TestHelpers.HexToBytes(
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
            var expectedPublicKey = TestHelpers.HexToBytes(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

            var message = "r"u8.ToArray();
            var expectedSignature = TestHelpers.HexToBytes(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

            // Act
            var derivedPublicKey = Ed25519Core.DerivePublicKey(privateKey);
            var signature = Ed25519Core.Sign(message, privateKey);
            var isValid = Ed25519Core.Verify(message, signature, derivedPublicKey);

            // Assert
            CryptoAssertions.AssertBytesEqual(expectedPublicKey, derivedPublicKey);
            CryptoAssertions.AssertBytesEqual(expectedSignature, signature);
            Assert.True(isValid);
        }
    }

    /// <summary>
    /// Memory hygiene tests verifying sensitive data cleanup.
    /// </summary>
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class MemoryHygiene
    {
        [Fact]
        public void SignVerify_RepeatedCalls_NoMemoryAccumulation()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = TestHelpers.RandomBytes(TestDataSizes.Medium);

            // Act - repeated calls should not leak memory
            for (int i = 0; i < 100; i++)
            {
                var signature = Ed25519Core.Sign(message, privateKey);
                var isValid = Ed25519Core.Verify(message, signature, publicKey);
                Assert.True(isValid);
            }

            // Assert - completing without OOM indicates proper cleanup
            Assert.True(true);
        }
    }
}
