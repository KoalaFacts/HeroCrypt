using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Comprehensive tests for encryption/decryption operations using HeroCryptBuilder.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
/// <remarks>
/// <para><b>Platform Support Notes:</b></para>
/// <list type="bullet">
///   <item>
///     <term>AES-CCM on macOS</term>
///     <description>
///       AES-CCM is not supported on macOS. The macOS Security framework does not implement
///       the CCM (Counter with CBC-MAC) mode. Tests using AES-CCM are automatically skipped
///       on macOS using <c>Assert.Skip()</c>. Use AES-GCM as an alternative on macOS.
///     </description>
///   </item>
///   <item>
///     <term>ChaCha20-Poly1305</term>
///     <description>Supported on all platforms (.NET 6+).</description>
///   </item>
///   <item>
///     <term>XChaCha20-Poly1305</term>
///     <description>Custom implementation, supported on all platforms.</description>
///   </item>
///   <item>
///     <term>AES-GCM</term>
///     <description>Supported on all platforms.</description>
///   </item>
/// </list>
/// </remarks>
public class EncryptionBuilderTests
{
    public static IEnumerable<object[]> AeadCases =>
    [
        [EncryptionAlgorithm.ChaCha20Poly1305, 32],
        [EncryptionAlgorithm.XChaCha20Poly1305, 32],
        [EncryptionAlgorithm.AesGcm, 16],
        [EncryptionAlgorithm.AesGcm, 32],
        [EncryptionAlgorithm.AesCcm, 16],
        [EncryptionAlgorithm.AesCcm, 32],
        [EncryptionAlgorithm.AesOcb, 16],
        [EncryptionAlgorithm.AesOcb, 32],
        [EncryptionAlgorithm.AesSiv, 32],  // AES-SIV-128 uses 32-byte key (split into two 16-byte keys)
        [EncryptionAlgorithm.AesSiv, 64]   // AES-SIV-256 uses 64-byte key (split into two 32-byte keys)
    ];

    /// <summary>
    /// Basic functionality tests for AEAD encryption/decryption.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void EncryptDecrypt_RoundTrip_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Hello, AEAD World!"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);
            var associatedData = "metadata"u8.ToArray();

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithAssociatedData(associatedData)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(associatedData)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
            Assert.NotEqual(plaintext, result.Ciphertext);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void EncryptDecrypt_WithoutAssociatedData_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Hello, AEAD World!"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void EncryptDecrypt_EmptyPlaintext_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            // Empty plaintext is valid for AEAD - produces tag-only output for authentication.
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = Array.Empty<byte>();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
            Assert.NotEmpty(result.Ciphertext); // tag present
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void EncryptDecrypt_SingleByte_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = new byte[] { 0x42 };
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void EncryptDecrypt_AllZeros_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = new byte[256]; // 256 bytes of zeros
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
            Assert.NotEqual(plaintext, result.Ciphertext); // ciphertext should differ
        }

        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm, 32)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305, 32)]
        public void EncryptDecrypt_LargeData_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            // Test with 64KB of data
            var plaintext = TestHelpers.RandomBytes(64 * 1024);
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_EmptyString_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(string.Empty);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(string.Empty, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_SingleCharacterString_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "X";

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_UnicodeEmoji_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "\U0001F680\U0001F4BB\U0001F512"; // rocket, laptop, lock emojis

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_MultiByteUnicode_Succeeds()
        {
            var key = TestHelpers.RandomBytes(32);
            // Mix of 1-byte, 2-byte, 3-byte, and 4-byte UTF-8 sequences
            var plaintext = "A\u00e9\u4e2d\U0001F600"; // A, é (2-byte), 中 (3-byte), 😀 (4-byte)

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void EncryptDecrypt_RepeatingPattern_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            // Create a repeating pattern (tests that encryption doesn't produce patterns)
            var pattern = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
            var plaintext = new byte[256];
            for (int i = 0; i < plaintext.Length; i++)
            {
                plaintext[i] = pattern[i % pattern.Length];
            }

            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .Decrypt(result.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void Decrypt_TamperedCiphertext_Fails(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Hello, AEAD World!"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var tampered = TestHelpers.TamperFirst(result.Ciphertext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithNonce(result.Nonce)
                    .Decrypt(tampered));
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void Decrypt_WrongKey_Fails(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Hello, AEAD World!"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);
            var wrongKey = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(wrongKey)
                    .WithNonce(result.Nonce)
                    .Decrypt(result.Ciphertext));
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void Decrypt_WrongNonce_Fails(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Hello, AEAD World!"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var wrongNonce = TestHelpers.RandomBytes(result.Nonce.Length);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithNonce(wrongNonce)
                    .Decrypt(result.Ciphertext));
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void Decrypt_WrongAssociatedData_Fails(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Hello, AEAD World!"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);
            var aad = "metadata"u8.ToArray();
            var wrongAad = "wrong"u8.ToArray();

            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithAssociatedData(aad)
                .Encrypt(plaintext);

            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAlgorithm(algorithm)
                    .WithKey(key)
                    .WithNonce(result.Nonce)
                    .WithAssociatedData(wrongAad)
                    .Decrypt(result.Ciphertext));
        }

        [Theory]
        [MemberData(nameof(AeadCases), MemberType = typeof(EncryptionBuilderTests))]
        public void Encrypt_SamePlaintextDifferentNonce_ProducesDifferentCiphertext(EncryptionAlgorithm algorithm, int keySize)
        {
            if (algorithm == EncryptionAlgorithm.AesCcm && OperatingSystem.IsMacOS())
            {
                Assert.Skip("AES-CCM not supported on macOS");
                return;
            }

            var plaintext = "Same plaintext, different nonce"u8.ToArray();
            var key = TestHelpers.RandomBytes(keySize);

            var result1 = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            var result2 = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            Assert.NotEqual(result1.Ciphertext, result2.Ciphertext);
            Assert.NotEqual(result1.Nonce, result2.Nonce);
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
        public void Encrypt_WithoutKey_ThrowsInvalidOperationException()
        {
            var plaintext = "test"u8.ToArray();

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .Encrypt(plaintext));
        }

        [Fact]
        public void Decrypt_WithoutKey_ThrowsInvalidOperationException()
        {
            var ciphertext = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithNonce(nonce)
                    .Decrypt(ciphertext));
        }

        [Fact]
        public void Decrypt_WithoutNonce_ThrowsInvalidOperationException()
        {
            var ciphertext = TestHelpers.RandomBytes(32);
            var key = TestHelpers.RandomBytes(16);

            Assert.Throws<InvalidOperationException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .Decrypt(ciphertext));
        }
    }

    /// <summary>
    /// Tests for string convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class StringConvenienceMethods
    {
        [Theory]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.AesGcm, 32)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305, 32)]
        public void EncryptString_DecryptToString_RoundTrip_Succeeds(EncryptionAlgorithm algorithm, int keySize)
        {
            // Arrange
            var originalMessage = "Hello, World! This is a test message with UTF-8: \u00e9\u00e8\u00ea";
            var key = TestHelpers.RandomBytes(keySize);

            // Act - Encrypt string directly
            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(originalMessage);

            // Act - Decrypt to string directly
            var decryptedMessage = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(originalMessage, decryptedMessage);
        }

        [Fact]
        public void EncryptString_ProducesSameResultAsEncryptBytes()
        {
            // Arrange
            var message = "Test message";
            var key = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(12);

            // Act - Encrypt as string
            var resultFromString = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonce)
                .WithDeterministicMode()
                .Encrypt(message);

            // Act - Encrypt as bytes
            var resultFromBytes = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonce)
                .WithDeterministicMode()
                .Encrypt(System.Text.Encoding.UTF8.GetBytes(message));

            // Assert - Both should produce identical ciphertext
            Assert.Equal(resultFromBytes.Ciphertext, resultFromString.Ciphertext);
        }

        [Fact]
        public void DecryptToString_ReturnsUtf8String()
        {
            // Arrange
            var originalMessage = "Test with special chars: \u4e2d\u6587"; // Chinese characters
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithChaCha20Poly1305()
                .WithKey(key)
                .Encrypt(originalMessage);

            // Act
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithChaCha20Poly1305()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(originalMessage, decrypted);
        }

        [Fact]
        public void EncryptString_EmptyString_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);

            // Act - AES-SIV handles empty plaintext
            var result = HeroCryptBuilder.Encrypt()
                .WithAesSiv()
                .WithKey(key)
                .Encrypt(string.Empty);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesSiv()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(string.Empty, decrypted);
        }
    }

    /// <summary>
    /// Tests for associated data string convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AssociatedDataStringMethods
    {
        [Fact]
        public void WithAssociatedDataString_EncryptDecrypt_RoundTrip_Succeeds()
        {
            // Arrange
            var plaintext = "Secret message";
            var key = TestHelpers.RandomBytes(32);
            var associatedData = "user-id:12345";

            // Act - Encrypt with string AAD
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithAssociatedData(associatedData)
                .Encrypt(plaintext);

            // Act - Decrypt with matching string AAD
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(associatedData)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithAssociatedDataString_MatchesByteOverload()
        {
            // Arrange
            var plaintext = "Test message"u8.ToArray();
            var key = TestHelpers.RandomBytes(32);
            var aadString = "context-info";
            var aadBytes = System.Text.Encoding.UTF8.GetBytes(aadString);
            var nonce = TestHelpers.RandomBytes(12);

            // Act - Encrypt with string AAD
            var resultFromString = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonce)
                .WithDeterministicMode()
                .WithAssociatedData(aadString)
                .Encrypt(plaintext);

            // Act - Encrypt with bytes AAD
            var resultFromBytes = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonce)
                .WithDeterministicMode()
                .WithAssociatedData(aadBytes)
                .Encrypt(plaintext);

            // Assert - Both should produce identical ciphertext
            Assert.Equal(resultFromBytes.Ciphertext, resultFromString.Ciphertext);
        }

        [Fact]
        public void WithAssociatedDataString_DifferentAad_FailsDecryption()
        {
            // Arrange
            var plaintext = "Secret message";
            var key = TestHelpers.RandomBytes(32);

            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithAssociatedData("correct-aad")
                .Encrypt(plaintext);

            // Act & Assert - Different AAD should fail
            Assert.ThrowsAny<CryptographicException>(() =>
                HeroCryptBuilder.Decrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(result.Nonce)
                    .WithAssociatedData("wrong-aad")
                    .Decrypt(result.Ciphertext));
        }

        [Fact]
        public void WithAssociatedDataString_EmptyString_Succeeds()
        {
            // Arrange
            var plaintext = "Secret message";
            var key = TestHelpers.RandomBytes(32);

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithAssociatedData(string.Empty)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(string.Empty)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithAssociatedDataString_UnicodeCharacters_Succeeds()
        {
            // Arrange
            var plaintext = "Secret message";
            var key = TestHelpers.RandomBytes(32);
            var aad = "Unicode AAD: \u4e2d\u6587 \u00e9\u00e8\u00ea";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithAssociatedData(aad)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .WithAssociatedData(aad)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for key management convenience methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyManagementMethods
    {
        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm, 32)]
        [InlineData(EncryptionAlgorithm.AesCcm, 32)]
        [InlineData(EncryptionAlgorithm.AesOcb, 32)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.AesSiv, 64)]
        public void WithRandomKey_GeneratesCorrectSizeKey(EncryptionAlgorithm algorithm, int expectedKeySize)
        {
            // Arrange & Act
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithRandomKey();

            var key = builder.GetKey();

            // Assert
            Assert.Equal(expectedKeySize, key.Length);
        }

        [Fact]
        public void WithRandomKey_GeneratesDifferentKeysEachTime()
        {
            // Arrange & Act
            using var builder1 = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            using var builder2 = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var key1 = builder1.GetKey();
            var key2 = builder2.GetKey();

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void WithRandomKey_ExplicitSize_GeneratesCorrectSizeKey(int keySize)
        {
            // Arrange & Act
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey(keySize);

            var key = builder.GetKey();

            // Assert
            Assert.Equal(keySize, key.Length);
        }

        [Fact]
        public void WithRandomKey_EncryptDecrypt_RoundTrip_Succeeds()
        {
            // Arrange
            var plaintext = "Secret message encrypted with random key";

            // Act - Encrypt with random key
            using var encryptBuilder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var key = encryptBuilder.GetKey();
            var result = encryptBuilder.Encrypt(plaintext);

            // Act - Decrypt with retrieved key
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void GetKey_WithoutSettingKey_ThrowsInvalidOperationException()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(builder.GetKey);
        }

        [Fact]
        public void GetKey_AfterWithKey_ReturnsSameKey()
        {
            // Arrange
            var originalKey = TestHelpers.RandomBytes(32);

            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(originalKey);

            // Act
            var retrievedKey = builder.GetKey();

            // Assert
            Assert.Equal(originalKey, retrievedKey);
        }

        [Fact]
        public void GetKeyAsHex_ReturnsLowercaseHexString()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            // Act
            var hexKey = builder.GetKeyAsHex();

            // Assert
            Assert.Equal(64, hexKey.Length); // 32 bytes = 64 hex chars
            Assert.Equal(hexKey, hexKey.ToLowerInvariant());
            Assert.True(hexKey.All(char.IsLetterOrDigit));
        }

        [Fact]
        public void GetKeyAsHex_MatchesGetKey()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            // Act
            var key = builder.GetKey();
            var hexKey = builder.GetKeyAsHex();

            // Assert
            Assert.Equal(Convert.ToHexString(key).ToLowerInvariant(), hexKey);
        }

        [Fact]
        public void GetKeyAsBase64_ReturnsValidBase64()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            // Act
            var base64Key = builder.GetKeyAsBase64();

            // Assert
            var decoded = Convert.FromBase64String(base64Key);
            Assert.Equal(32, decoded.Length);
        }

        [Fact]
        public void GetKeyAsBase64_MatchesGetKey()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            // Act
            var key = builder.GetKey();
            var base64Key = builder.GetKeyAsBase64();

            // Assert
            Assert.Equal(Convert.ToBase64String(key), base64Key);
        }

        [Fact]
        public void GetKeyAsBase64Url_ReturnsUrlSafeString()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            // Act
            var base64UrlKey = builder.GetKeyAsBase64Url();

            // Assert
            Assert.DoesNotContain("+", base64UrlKey);
            Assert.DoesNotContain("/", base64UrlKey);
            Assert.DoesNotContain("=", base64UrlKey);
        }

        [Fact]
        public void GetKeyAsBase64Url_CanBeDecodedBack()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var originalKey = builder.GetKey();

            // Act
            var base64UrlKey = builder.GetKeyAsBase64Url();

            // Decode URL-safe Base64
            var base64 = base64UrlKey
                .Replace('-', '+')
                .Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 0: break;
                case 1: break;
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
                default: break;
            }
            var decodedKey = Convert.FromBase64String(base64);

            // Assert
            Assert.Equal(originalKey, decodedKey);
        }

        [Fact]
        public void WithRandomKey_ZeroSize_ThrowsArgumentOutOfRangeException()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm();

            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() => builder.WithRandomKey(0));
        }

        [Fact]
        public void WithRandomKey_NegativeSize_ThrowsArgumentOutOfRangeException()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm();

            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() => builder.WithRandomKey(-1));
        }

        [Fact]
        public void WithRandomKey_RsaAlgorithm_ThrowsNotSupportedException()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithRsaOaep();

            // Act & Assert
            Assert.Throws<NotSupportedException>(builder.WithRandomKey);
        }

        [Fact]
        public void WithRandomKey_X25519Algorithm_ThrowsNotSupportedException()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(EncryptionAlgorithm.X25519ChaCha20Poly1305);

            // Act & Assert
            Assert.Throws<NotSupportedException>(builder.WithRandomKey);
        }
    }

    /// <summary>
    /// Tests for key input format convenience methods (WithKeyFromHex, WithKeyFromBase64, WithKeyFromBase64Url).
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyInputFormatTests
    {
        [Fact]
        public void WithKeyFromHex_EncryptsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key);
            var plaintext = "Test message for encryption";

            // Act
            var resultFromBytes = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithDeterministicMode()
                .Encrypt(plaintext);

            var resultFromHex = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .WithDeterministicMode()
                .Encrypt(plaintext);

            // Assert - both should produce the same ciphertext with deterministic mode
            Assert.Equal(resultFromBytes.Ciphertext, resultFromHex.Ciphertext);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsLowercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .Encrypt(plaintext);

            // Assert
            Assert.NotNull(result.Ciphertext);
            Assert.NotEmpty(result.Ciphertext);
        }

        [Fact]
        public void WithKeyFromHex_AcceptsUppercaseHex()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToUpperInvariant();
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .Encrypt(plaintext);

            // Assert
            Assert.NotNull(result.Ciphertext);
            Assert.NotEmpty(result.Ciphertext);
        }

        [Fact]
        public void WithKeyFromHex_WithInvalidHex_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKeyFromHex("not-valid-hex!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64_EncryptsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64Key = Convert.ToBase64String(key);
            var plaintext = "Test message for encryption";

            // Act
            var resultFromBytes = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithDeterministicMode()
                .Encrypt(plaintext);

            var resultFromBase64 = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromBase64(base64Key)
                .WithDeterministicMode()
                .Encrypt(plaintext);

            // Assert
            Assert.Equal(resultFromBytes.Ciphertext, resultFromBase64.Ciphertext);
        }

        [Fact]
        public void WithKeyFromBase64_WithInvalidBase64_ThrowsFormatException()
        {
            // Act & Assert
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKeyFromBase64("not-valid-base64!@#$"));
        }

        [Fact]
        public void WithKeyFromBase64Url_EncryptsCorrectly()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var plaintext = "Test message for encryption";

            // Act
            var resultFromBytes = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithDeterministicMode()
                .Encrypt(plaintext);

            var resultFromBase64Url = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithDeterministicMode()
                .Encrypt(plaintext);

            // Assert
            Assert.Equal(resultFromBytes.Ciphertext, resultFromBase64Url.Ciphertext);
        }

        [Fact]
        public void WithKeyFromBase64Url_AcceptsPaddedInput()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .Replace('+', '-')
                .Replace('/', '_');
            // Keep padding
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .Encrypt(plaintext);

            // Assert
            Assert.NotNull(result.Ciphertext);
        }

        [Fact]
        public void WithKeyFromHex_EncryptAndDecrypt_RoundTrip()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var hexKey = Convert.ToHexString(key).ToLowerInvariant();
            var plaintext = "Secret message encrypted with hex key";

            // Act - Encrypt with hex key
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .Encrypt(plaintext);

            // Act - Decrypt with same hex key
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void WithKeyFromBase64Url_EncryptAndDecrypt_RoundTrip()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var base64UrlKey = Convert.ToBase64String(key)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var plaintext = "Secret message encrypted with URL-safe base64 key";

            // Act - Encrypt with base64url key
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .Encrypt(plaintext);

            // Act - Decrypt with same base64url key
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm, 32)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305, 32)]
        [InlineData(EncryptionAlgorithm.AesOcb, 32)]
        [InlineData(EncryptionAlgorithm.AesSiv, 64)]
        public void WithKeyFromHex_WorksWithAllSymmetricAlgorithms(EncryptionAlgorithm algorithm, int keySize)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(keySize);
            var hexKey = Convert.ToHexString(key);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKeyFromHex(hexKey)
                .Encrypt(plaintext);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAlgorithm(algorithm)
                .WithKeyFromHex(hexKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void GetKeyAsHex_And_WithKeyFromHex_RoundTrip()
        {
            // Arrange
            var plaintext = "Message to encrypt and decrypt";

            // Act - Generate random key and get as hex
            using var encryptBuilder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var hexKey = encryptBuilder.GetKeyAsHex();
            var result = encryptBuilder.Encrypt(plaintext);

            // Act - Use hex key for decryption
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromHex(hexKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void GetKeyAsBase64Url_And_WithKeyFromBase64Url_RoundTrip()
        {
            // Arrange
            var plaintext = "Message to encrypt and decrypt";

            // Act - Generate random key and get as Base64Url
            using var encryptBuilder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var base64UrlKey = encryptBuilder.GetKeyAsBase64Url();
            var result = encryptBuilder.Encrypt(plaintext);

            // Act - Use Base64Url key for decryption
            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKeyFromBase64Url(base64UrlKey)
                .WithNonce(result.Nonce)
                .DecryptToString(result.Ciphertext);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Tests for EncryptionResult text format output properties.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncryptionResultOutputFormatTests
    {
        [Fact]
        public void CiphertextAsHex_ReturnsLowercaseHexString()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.NotNull(result.CiphertextAsHex);
            Assert.Equal(result.CiphertextAsHex, result.CiphertextAsHex.ToLowerInvariant());
            Assert.True(result.CiphertextAsHex.All(char.IsLetterOrDigit));
        }

        [Fact]
        public void CiphertextAsHex_MatchesCiphertext()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.Equal(Convert.ToHexString(result.Ciphertext).ToLowerInvariant(), result.CiphertextAsHex);
        }

        [Fact]
        public void CiphertextAsBase64_ReturnsValidBase64()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            var decoded = Convert.FromBase64String(result.CiphertextAsBase64);
            Assert.Equal(result.Ciphertext, decoded);
        }

        [Fact]
        public void CiphertextAsBase64Url_ReturnsUrlSafeString()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.DoesNotContain("+", result.CiphertextAsBase64Url);
            Assert.DoesNotContain("/", result.CiphertextAsBase64Url);
            Assert.DoesNotContain("=", result.CiphertextAsBase64Url);
        }

        [Fact]
        public void NonceAsHex_ReturnsLowercaseHexString()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.NotNull(result.NonceAsHex);
            Assert.Equal(result.NonceAsHex, result.NonceAsHex.ToLowerInvariant());
        }

        [Fact]
        public void NonceAsHex_MatchesNonce()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.Equal(Convert.ToHexString(result.Nonce).ToLowerInvariant(), result.NonceAsHex);
        }

        [Fact]
        public void NonceAsBase64_ReturnsValidBase64()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            var decoded = Convert.FromBase64String(result.NonceAsBase64);
            Assert.Equal(result.Nonce, decoded);
        }

        [Fact]
        public void NonceAsBase64Url_ReturnsUrlSafeString()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.DoesNotContain("+", result.NonceAsBase64Url);
            Assert.DoesNotContain("/", result.NonceAsBase64Url);
            Assert.DoesNotContain("=", result.NonceAsBase64Url);
        }

        [Fact]
        public void EncapsulatedKeyProperties_ReturnNullWhenNotPresent()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Test message";

            // Act - AES-GCM doesn't produce encapsulated keys
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert
            Assert.Null(result.EncapsulatedKey);
            Assert.Null(result.EncapsulatedKeyAsHex);
            Assert.Null(result.EncapsulatedKeyAsBase64);
            Assert.Null(result.EncapsulatedKeyAsBase64Url);
        }

        [Fact]
        public void CiphertextAsHex_CanBeUsedForDecryption()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Secret message to encrypt and decrypt";

            // Act - Encrypt and get text format outputs
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var ciphertextHex = result.CiphertextAsHex;
            var nonceHex = result.NonceAsHex;

            // Decrypt using the hex values
            var ciphertextBytes = Convert.FromHexString(ciphertextHex);
            var nonceBytes = Convert.FromHexString(nonceHex);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonceBytes)
                .DecryptToString(ciphertextBytes);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void CiphertextAsBase64Url_CanBeUsedForDecryption()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintext = "Secret message to encrypt and decrypt";

            // Act - Encrypt and get text format outputs
            var result = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key)
                .Encrypt(plaintext);

            var ciphertextBase64Url = result.CiphertextAsBase64Url;
            var nonceBase64Url = result.NonceAsBase64Url;

            // Decrypt using WithCiphertextFromBase64Url would be nice, but for now convert manually
            var ciphertextBytes = FromBase64Url(ciphertextBase64Url);
            var nonceBytes = FromBase64Url(nonceBase64Url);

            var decrypted = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(nonceBytes)
                .DecryptToString(ciphertextBytes);

            // Assert
            Assert.Equal(plaintext, decrypted);
        }

        [Theory]
        [InlineData(EncryptionAlgorithm.AesGcm)]
        [InlineData(EncryptionAlgorithm.ChaCha20Poly1305)]
        [InlineData(EncryptionAlgorithm.XChaCha20Poly1305)]
        [InlineData(EncryptionAlgorithm.AesOcb)]
        [InlineData(EncryptionAlgorithm.AesSiv)]
        public void TextFormatProperties_WorkWithAllSymmetricAlgorithms(EncryptionAlgorithm algorithm)
        {
            // Arrange
            var keySize = algorithm == EncryptionAlgorithm.AesSiv ? 64 : 32;
            var key = TestHelpers.RandomBytes(keySize);
            var plaintext = "Test message";

            // Act
            var result = HeroCryptBuilder.Encrypt()
                .WithAlgorithm(algorithm)
                .WithKey(key)
                .Encrypt(plaintext);

            // Assert - All text format properties should work
            Assert.NotNull(result.CiphertextAsHex);
            Assert.NotNull(result.CiphertextAsBase64);
            Assert.NotNull(result.CiphertextAsBase64Url);
            Assert.NotNull(result.NonceAsHex);
            Assert.NotNull(result.NonceAsBase64);
            Assert.NotNull(result.NonceAsBase64Url);
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            var base64 = base64Url
                .Replace('-', '+')
                .Replace('_', '/');

            switch (base64.Length % 4)
            {
                case 0: break;
                case 1: break;
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
                default: break;
            }

            return Convert.FromBase64String(base64);
        }
    }

    /// <summary>
    /// Tests for malformed input handling in EncryptionBuilder.
    /// </summary>
    [Trait("Category", TestCategories.INPUT_VALIDATION)]
    [Trait("Category", TestCategories.FAST)]
    public class InputValidation
    {
        public static TheoryData<string> InvalidHexStrings => new()
        {
            "not-valid-hex",
            "GHIJKL",
            "123",
            "0x1234",
            "!@#$%^&*()",
        };

        public static TheoryData<string> InvalidBase64Strings => new()
        {
            "not valid base64!",
            "!!!",
            "====",
            "a===",
        };

        [Theory]
        [MemberData(nameof(InvalidHexStrings))]
        public void WithKeyFromHex_InvalidHex_ThrowsFormatException(string invalidHex)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKeyFromHex(invalidHex));
        }

        [Theory]
        [MemberData(nameof(InvalidBase64Strings))]
        public void WithKeyFromBase64_InvalidBase64_ThrowsFormatException(string invalidBase64)
        {
            Assert.Throws<FormatException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKeyFromBase64(invalidBase64));
        }

        [Theory]
        [InlineData(15)]
        [InlineData(17)]
        [InlineData(31)]
        [InlineData(33)]
        public void AesGcm_WithWrongKeySize_ThrowsException(int keySize)
        {
            var key = TestHelpers.RandomBytes(keySize);

            Assert.ThrowsAny<Exception>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .Encrypt("test"));
        }

        [Theory]
        [InlineData(15)]
        [InlineData(31)]
        [InlineData(33)]
        public void ChaCha20Poly1305_WithWrongKeySize_ThrowsException(int keySize)
        {
            var key = TestHelpers.RandomBytes(keySize);

            Assert.ThrowsAny<Exception>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithChaCha20Poly1305()
                    .WithKey(key)
                    .Encrypt("test"));
        }

        [Theory]
        [InlineData(11)]
        [InlineData(13)]
        public void AesGcm_WithWrongNonceSize_ThrowsException(int nonceSize)
        {
            var key = TestHelpers.RandomBytes(32);
            var nonce = TestHelpers.RandomBytes(nonceSize);

            Assert.ThrowsAny<Exception>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(nonce)
                    .Encrypt("test"));
        }

        [Fact]
        public void WithNullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKey(null!));
        }

        [Fact]
        public void WithNullNonce_ThrowsArgumentNullException()
        {
            var key = TestHelpers.RandomBytes(32);
            Assert.Throws<ArgumentNullException>(() =>
                HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .WithNonce(null!));
        }

        [Fact]
        public void TamperedCiphertext_ThrowsCryptographicException()
        {
            var key = TestHelpers.RandomBytes(32);

            using var encryptor = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(key);

            var result = encryptor.Encrypt("Secret message");

            var tampered = result.Ciphertext.ToArray();
            tampered[0] ^= 0xFF;

            using var decryptor = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(key)
                .WithNonce(result.Nonce);

            Assert.ThrowsAny<CryptographicException>(() =>
                decryptor.Decrypt(tampered));
        }

        [Fact]
        public void DecryptWithWrongKey_ThrowsCryptographicException()
        {
            var correctKey = TestHelpers.RandomBytes(32);
            var wrongKey = TestHelpers.RandomBytes(32);

            using var encryptor = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithKey(correctKey);

            var result = encryptor.Encrypt("Secret message");

            using var decryptor = HeroCryptBuilder.Decrypt()
                .WithAesGcm()
                .WithKey(wrongKey)
                .WithNonce(result.Nonce);

            Assert.ThrowsAny<CryptographicException>(() =>
                decryptor.Decrypt(result.Ciphertext.ToArray()));
        }
    }
}
