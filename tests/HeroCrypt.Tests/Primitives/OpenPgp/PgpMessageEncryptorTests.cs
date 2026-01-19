using System.Numerics;
using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PgpMessageEncryptor and PgpMessageDecryptor.
/// Tests cover encryption, decryption, round-trip verification, and error handling.
/// </summary>
public class PgpMessageEncryptorTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // Test Utilities
    // ─────────────────────────────────────────────────────────────────────────────

    // Fixed timestamp for deterministic key creation in tests
    private static readonly DateTimeOffset FixedTestTimestamp = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Creates an RSA key pair for testing.
    /// Each call creates a fresh key pair to ensure test isolation.
    /// </summary>
    private static (PgpPublicKeyPacket PublicKey, PgpSecretKeyPacket SecretKey) CreateRsaKeyPair(int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        var parameters = rsa.ExportParameters(includePrivateParameters: true);

        var n = new BigInteger(parameters.Modulus!, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(parameters.Exponent!, isUnsigned: true, isBigEndian: true);
        var d = new BigInteger(parameters.D!, isUnsigned: true, isBigEndian: true);
        var p = new BigInteger(parameters.P!, isUnsigned: true, isBigEndian: true);
        var q = new BigInteger(parameters.Q!, isUnsigned: true, isBigEndian: true);

        var publicKey = PgpPublicKeyPacket.CreateRsa(
            version: 4,
            creationTime: FixedTestTimestamp,
            modulus: n,
            exponent: e,
            isSubkey: false);

        // Build secret key material: d || p || q || u (where u = p^-1 mod q)
        var u = BigInteger.ModPow(p, q - 2, q); // u = p^-1 mod q
        var secretMaterial = BuildRsaSecretMaterial(d, p, q, u);

        var secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);

        return (publicKey, secretKey);
    }

    /// <summary>
    /// Builds the secret key material in OpenPGP MPI format.
    /// </summary>
    private static byte[] BuildRsaSecretMaterial(BigInteger d, BigInteger p, BigInteger q, BigInteger u)
    {
        using var ms = new MemoryStream();

        WriteMpi(ms, d);
        WriteMpi(ms, p);
        WriteMpi(ms, q);
        WriteMpi(ms, u);

        return ms.ToArray();
    }

    /// <summary>
    /// Writes a BigInteger as an OpenPGP MPI.
    /// </summary>
    private static void WriteMpi(MemoryStream ms, BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

        // Skip leading zeros
        int start = 0;
        while (start < bytes.Length && bytes[start] == 0)
        {
            start++;
        }

        if (start == bytes.Length)
        {
            ms.WriteByte(0);
            ms.WriteByte(0);
            return;
        }

        int dataLen = bytes.Length - start;
        int bitLen = (dataLen - 1) * 8;
        byte msb = bytes[start];
        while (msb != 0)
        {
            bitLen++;
            msb >>= 1;
        }

        ms.WriteByte((byte)(bitLen >> 8));
        ms.WriteByte((byte)bitLen);
        ms.Write(bytes, start, dataLen);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Basic Factory Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FactoryTests
    {
        [Fact]
        public void Create_ReturnsNewInstance()
        {
            using var encryptor = PgpMessageEncryptor.Create();
            Assert.NotNull(encryptor);
        }

        [Fact]
        public void Create_Decryptor_ReturnsNewInstance()
        {
            using var decryptor = PgpMessageDecryptor.Create();
            Assert.NotNull(decryptor);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Encryption Validation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncryptionValidationTests
    {
        [Fact]
        public void Encrypt_WithoutRecipients_ThrowsInvalidOperationException()
        {
            using var encryptor = PgpMessageEncryptor.Create();
            var plaintext = "Hello, World!"u8.ToArray();

            var ex = Assert.Throws<InvalidOperationException>(() => encryptor.Encrypt(plaintext));
            Assert.Contains("recipient", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void EncryptText_WithNullText_ThrowsArgumentNullException()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            Assert.Throws<ArgumentNullException>(() => encryptor.EncryptText(null!));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Decryption Validation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DecryptionValidationTests
    {
        [Fact]
        public void Decrypt_WithoutSecretKeys_ThrowsInvalidOperationException()
        {
            using var decryptor = PgpMessageDecryptor.Create();
            var data = TestHelpers.RandomBytes(100);

            var ex = Assert.Throws<InvalidOperationException>(() => decryptor.Decrypt(data));
            Assert.Contains("secret key", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // RSA Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class RsaRoundTripTests
    {
        [Fact]
        public void RoundTrip_WithRsaKey_DecryptsSuccessfully()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Hello, OpenPGP World!"u8.ToArray();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithAes256();

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.True(encrypted.Data.Length > 0);
            Assert.Equal(1, encrypted.RecipientCount);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void RoundTrip_WithText_DecryptsSuccessfully()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var originalText = "Hello, OpenPGP World! 🔐";

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.EncryptText(originalText);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(originalText, decrypted.GetDataAsString());
            Assert.Equal(PgpLiteralDataFormat.Utf8, decrypted.Format);
        }

        [Fact]
        public void RoundTrip_WithFileName_PreservesMetadata()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Test content"u8.ToArray();
            var fileName = "document.txt";
            var fileDate = new DateTimeOffset(2025, 1, 15, 10, 30, 0, TimeSpan.Zero);

            // Encrypt with metadata
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithFileName(fileName)
                .WithFileDate(fileDate);

            var encrypted = encryptor.Encrypt(plaintext);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
            Assert.Equal(fileName, decrypted.FileName);
            Assert.Equal(fileDate.ToUnixTimeSeconds(), decrypted.Date.ToUnixTimeSeconds());
        }

        [Fact]
        public void RoundTrip_WithEmptyData_DecryptsSuccessfully()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = Array.Empty<byte>();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Empty(decrypted.Data.ToArray());
        }

        [Fact]
        public void RoundTrip_WithLargeData_DecryptsSuccessfully()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = TestHelpers.RandomBytes(64 * 1024); // 64 KB

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Theory]
        [InlineData(PgpLiteralDataFormat.Binary)]
        [InlineData(PgpLiteralDataFormat.Text)]
        [InlineData(PgpLiteralDataFormat.Utf8)]
        public void RoundTrip_WithDataFormat_PreservesFormat(PgpLiteralDataFormat format)
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Test content"u8.ToArray();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithFormat(format);

            var encrypted = encryptor.Encrypt(plaintext);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(format, decrypted.Format);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Compression Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class CompressionTests
    {
        [Theory]
        [InlineData(PgpCompressionAlgorithm.Zip)]
        [InlineData(PgpCompressionAlgorithm.Zlib)]
        public void RoundTrip_WithCompression_DecryptsSuccessfully(PgpCompressionAlgorithm compression)
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            // Use repetitive data that compresses well
            var plaintext = new byte[1024];
            for (int i = 0; i < plaintext.Length; i++)
            {
                plaintext[i] = (byte)(i % 10);
            }

            // Encrypt with compression
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithCompression(compression);

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.True(encrypted.IsCompressed);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
            Assert.True(decrypted.WasCompressed);
            Assert.Equal(compression, decrypted.CompressionAlgorithm);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Symmetric Algorithm Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class SymmetricAlgorithmTests
    {
        [Theory]
        [InlineData(SymmetricCipherAlgorithm.Aes128)]
        [InlineData(SymmetricCipherAlgorithm.Aes192)]
        [InlineData(SymmetricCipherAlgorithm.Aes256)]
        public void RoundTrip_WithDifferentAesSizes_DecryptsSuccessfully(SymmetricCipherAlgorithm algorithm)
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Test with different AES key sizes"u8.ToArray();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithSymmetricAlgorithm(algorithm);

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.Equal(algorithm, encrypted.SymmetricAlgorithm);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void WithAes128_SetsCorrectAlgorithm()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithAes128();

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.Equal(SymmetricCipherAlgorithm.Aes128, encrypted.SymmetricAlgorithm);
        }

        [Fact]
        public void WithAes192_SetsCorrectAlgorithm()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithAes192();

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.Equal(SymmetricCipherAlgorithm.Aes192, encrypted.SymmetricAlgorithm);
        }

        [Fact]
        public void DefaultAlgorithm_IsAes256()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.Equal(SymmetricCipherAlgorithm.Aes256, encrypted.SymmetricAlgorithm);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Multiple Recipients Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class MultipleRecipientsTests
    {
        [Fact]
        public void RoundTrip_WithMultipleRecipients_AnyCanDecrypt()
        {
            var (publicKey1, secretKey1) = CreateRsaKeyPair();
            var (publicKey2, secretKey2) = CreateRsaKeyPair();
            var plaintext = "Message for multiple recipients"u8.ToArray();

            // Encrypt for both recipients
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey1)
                .AddRecipient(publicKey2);

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.Equal(2, encrypted.RecipientCount);

            // Decrypt with first key
            using var decryptor1 = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey1);

            var decrypted1 = decryptor1.Decrypt(encrypted);
            Assert.Equal(plaintext, decrypted1.Data.ToArray());

            // Decrypt with second key
            using var decryptor2 = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey2);

            var decrypted2 = decryptor2.Decrypt(encrypted);
            Assert.Equal(plaintext, decrypted2.Data.ToArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Ring Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyRingTests
    {
        [Fact]
        public void RoundTrip_WithKeyRing_DecryptsSuccessfully()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var publicKeyRing = new PgpPublicKeyRing(publicKey);
            var secretKeyRing = new PgpSecretKeyRing(secretKey);
            var plaintext = "Test with key rings"u8.ToArray();

            // Encrypt using key ring
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKeyRing);

            var encrypted = encryptor.Encrypt(plaintext);

            // Decrypt using key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(secretKeyRing);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Error Handling Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class ErrorHandlingTests
    {
        [Fact]
        public void Decrypt_WithWrongKey_ThrowsCryptographicException()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var (_, wrongSecretKey) = CreateRsaKeyPair(); // Different key pair
            var plaintext = "Secret message"u8.ToArray();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            // Attempt decryption with wrong key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(wrongSecretKey);

            Assert.Throws<CryptographicException>(() => decryptor.Decrypt(encrypted));
        }

        [Fact]
        public void TryDecrypt_WithWrongKey_ReturnsFalse()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var (_, wrongSecretKey) = CreateRsaKeyPair(); // Different key pair
            var plaintext = "Secret message"u8.ToArray();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            // Attempt decryption with wrong key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(wrongSecretKey);

            var result = decryptor.TryDecrypt(encrypted.Data.Span, out var message, out var error);

            Assert.False(result);
            Assert.NotNull(error);
            Assert.Contains("key", error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Decrypt_WithInvalidData_ThrowsException()
        {
            var (_, secretKey) = CreateRsaKeyPair();
            var invalidData = TestHelpers.RandomBytes(100);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            // Invalid random data throws an exception (could be InvalidDataException for bad packet
            // format or CryptographicException for decryption failures)
            Assert.ThrowsAny<Exception>(() => decryptor.Decrypt(invalidData));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Disposal Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DisposalTests
    {
        [Fact]
        public void Encryptor_AfterDispose_ThrowsObjectDisposedException()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            encryptor.Dispose();

            Assert.Throws<ObjectDisposedException>(() => encryptor.Encrypt("test"u8.ToArray()));
        }

        [Fact]
        public void Decryptor_AfterDispose_ThrowsObjectDisposedException()
        {
            var (_, secretKey) = CreateRsaKeyPair();
            var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            decryptor.Dispose();

            Assert.Throws<ObjectDisposedException>(() => decryptor.Decrypt(TestHelpers.RandomBytes(100)));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpEncryptedMessage Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class EncryptedMessageTests
    {
        [Fact]
        public void ToArray_ReturnsCopyOfData()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            var array1 = encrypted.ToArray();
            var array2 = encrypted.ToArray();

            Assert.Equal(array1, array2);
            Assert.NotSame(array1, array2);
        }

        [Fact]
        public void WriteTo_WritesDataToStream()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            using var ms = new MemoryStream();
            encrypted.WriteTo(ms);

            Assert.Equal(encrypted.ToArray(), ms.ToArray());
        }

        [Fact]
        public void ToString_ContainsRelevantInfo()
        {
            var (publicKey, _) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            var str = encrypted.ToString();

            Assert.Contains("PgpEncryptedMessage", str);
            Assert.Contains("bytes", str);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpDecryptedMessage Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class DecryptedMessageTests
    {
        [Fact]
        public void GetDataAsString_ReturnsUtf8String()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var originalText = "Hello, World! 你好世界 🌍";

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.EncryptText(originalText);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(originalText, decrypted.GetDataAsString());
        }

        [Fact]
        public void TryGetDataAsString_WithValidUtf8_ReturnsTrue()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var originalText = "Valid UTF-8";

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.EncryptText(originalText);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var success = decrypted.TryGetDataAsString(out var result);

            Assert.True(success);
            Assert.Equal(originalText, result);
        }

        [Fact]
        public void TryGetDataAsString_WithBinaryData_StillSucceeds()
        {
            // Note: .NET's Encoding.UTF8 uses replacement fallback by default,
            // so it won't throw on invalid bytes - it replaces them with U+FFFD.
            // This test verifies that binary data can still be converted to a string
            // (with replacement characters for invalid sequences).
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var binaryData = new byte[] { 0xFF, 0xFE, 0x00, 0x01 };

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithFormat(PgpLiteralDataFormat.Binary);

            var encrypted = encryptor.Encrypt(binaryData);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            // TryGetDataAsString should succeed but produce replacement characters
            var success = decrypted.TryGetDataAsString(out var result);
            Assert.True(success);
            Assert.Contains('\uFFFD', result); // Replacement character for invalid UTF-8
        }

        [Fact]
        public void ToArray_ReturnsCopyOfData()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var array = decrypted.ToArray();

            Assert.Equal(plaintext, array);
        }

        [Fact]
        public void WriteTo_WritesDataToStream()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            using var ms = new MemoryStream();
            decrypted.WriteTo(ms);

            Assert.Equal(plaintext, ms.ToArray());
        }

        [Fact]
        public void ToString_ContainsRelevantInfo()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey);

            var encrypted = encryptor.Encrypt(plaintext);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var str = decrypted.ToString();

            Assert.Contains("PgpDecryptedMessage", str);
            Assert.Contains("bytes", str);
        }
    }

#if !NETSTANDARD2_0
    // ─────────────────────────────────────────────────────────────────────────────
    // AEAD Tests (SEIPD v2) - .NET Core only
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class AeadTests
    {
        [Fact]
        public void RoundTrip_WithAeadGcm_DecryptsSuccessfully()
        {
            var (publicKey, secretKey) = CreateRsaKeyPair();
            var plaintext = "AEAD encrypted message"u8.ToArray();

            // Encrypt with AEAD
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(publicKey)
                .WithAead(AeadAlgorithm.Gcm);

            var encrypted = encryptor.Encrypt(plaintext);

            Assert.Equal(2, encrypted.SeipdVersion);
            Assert.Equal(AeadAlgorithm.Gcm, encrypted.AeadAlgorithm);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(secretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
            Assert.Equal(2, decrypted.SeipdVersion);
        }
    }
#endif
}
