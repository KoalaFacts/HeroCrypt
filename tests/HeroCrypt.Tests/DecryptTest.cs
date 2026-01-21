using System.Text;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests;

/// <summary>
/// Basic tests for PGP message encryption and decryption using generated keys.
/// For comprehensive algorithm coverage, see PgpEndToEndAlgorithmTests.
/// </summary>
public class DecryptTest
{
    private const string TestPlaintext = "Hello, World! This is a test message for encryption/decryption.";

    public class RsaEncryption
    {
        [Fact]
        public void RoundTrip_Succeeds()
        {
            // Generate an RSA key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Encrypt the message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt the message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void WithPassphrase_RoundTrip_Succeeds()
        {
            const string passphrase = "test-passphrase-123";

            // Generate an RSA key pair with passphrase protection
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Verify key is encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);

            // Decrypt the secret key
            var decryptedKey = keyResult.MasterSecretKey.Decrypt(passphrase);
            Assert.False(decryptedKey.IsEncrypted);

            // Encrypt the message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt the message using decrypted key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }
    }

    public class Ed25519X25519Encryption
    {
        [Fact]
        public void RoundTrip_Succeeds()
        {
            // Generate Ed25519/X25519 key pair (master key for signing, subkey for encryption)
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .GenerateEd25519WithX25519Subkey();

            // Get encryption subkey (X25519)
            var encryptionSubkey = keyResult.SecretKeyRing.Subkeys[0];
            var encryptionPublicKey = encryptionSubkey.PublicKey;

            // Encrypt the message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(encryptionPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt the message using the subkey
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(encryptionSubkey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }
    }

    public class MessageVariations
    {
        [Fact]
        public void LargeMessage_Succeeds()
        {
            // Generate a large message (100KB)
            var largeMessage = new string('A', 100 * 1024);
            var plainBytes = Encoding.UTF8.GetBytes(largeMessage);

            // Generate key
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(largeMessage, decryptedText);
        }

        [Fact]
        public void BinaryData_Succeeds()
        {
            // Generate random binary data
            var binaryData = new byte[1024];
            new Random(42).NextBytes(binaryData);

            // Generate key
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(binaryData);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(binaryData, decrypted.Data.ToArray());
        }
    }

    public class ErrorCases
    {
        [Fact]
        public void WithWrongKey_Fails()
        {
            // Generate two different key pairs
            var keyResult1 = PgpKeyGenerator.Create()
                .WithUserId("user1@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            var keyResult2 = PgpKeyGenerator.Create()
                .WithUserId("user2@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Encrypt with key 1
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult1.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Try to decrypt with key 2 - should fail
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult2.MasterSecretKey);

            var success = decryptor.TryDecrypt(encrypted.ToArray(), out _, out var error);

            Assert.False(success);
            Assert.NotNull(error);
        }
    }
}
