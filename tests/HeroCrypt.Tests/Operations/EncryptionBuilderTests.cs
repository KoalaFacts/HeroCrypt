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
}
