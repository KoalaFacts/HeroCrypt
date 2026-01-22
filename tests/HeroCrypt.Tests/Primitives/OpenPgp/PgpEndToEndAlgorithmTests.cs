using System.Text;
using HeroCrypt.Primitives.Armor;
using HeroCrypt.Primitives.OpenPgp;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive end-to-end tests for PGP encryption/decryption
/// covering all supported algorithms with both known test vectors
/// and round-trip verification.
/// </summary>
public class PgpEndToEndAlgorithmTests
{
    private const string TestPlaintext = "Hello, World! This is a test message for encryption/decryption.";

    public class KnownTestVectors
    {
        // Test vectors from OpenPGP.js - Night user keys for encryption target
        // Source: https://github.com/openpgpjs/openpgpjs/blob/main/test/general/x25519.js
        // Note: Light user keys removed as they use EdDSA legacy format (algorithm 22)
        private const string NightUserPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEWkN/RRYJKwYBBAHaRw8BAQdAM359sYg+LtcQo9G+mzMwxiu6wgY7UTVyip+V
y8CWMhz+BwMCxwCG2X+GJp7uQHSoj4fmvArR8d9hzyKBKDX84QsC1nCqMNRARz1v
aSqXfCt4gLzR3sZh4yS0cDUB0UdDfFhh3XiG2j8zRJ3cKkXdV3GcSbQSTmlnaHQg
PG5pZ2h0QG1vb24+iJAEExYIADgWIQR2tpyb3fzwT+cjQN/yXl8kuzcs+gUCWkN/
RQIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRDyXl8kuzcs+qgUAP4iQRLX
Q1Uugidh/qsxzEpjb82f4ODhpi12+mFjyFjRvQD+OXfhgR5xkBC8Za54ZrlfawIm
9HVZkQxRaNb1x9HRMgeciwRaQ39FEgorBgEEAZdVAQUBAQdAJ64RN2MWwSiuu5gd
eYBIqjtU1WCbb0Rl4DhuBtfWCxUDAQgH/gcDAoeG6mA2BitC7sbt5erYFzAndJx3
fOBDIo9MF2xo/JX1OrL5Z9Fro1UP+A3P+YyZQ3W/PMMVFArfnyiEoJAmQOkashgd
CocKYaKUNrgbYl2IeAQYFggAIBYhBHa2nJvd/PBP5yNA3/JeXyS7Nyz6BQJaQ39F
AhsMAAoJEPJeXyS7Nyz6I04BAKcoNxne0e+84QvJpEgyLLHoKxQqC6g4DWDkiEoI
sVHYAP4+7SAxheOQvSQuC0LI3ymPVk3dCPe4VkX7m/bWKND/Cg==
=NDSU
-----END PGP PRIVATE KEY BLOCK-----";

        private const string NightUserPassphrase = "moon";

        // Encrypted message from Light to Night
        private const string LightToNightEncryptedMessage = @"-----BEGIN PGP MESSAGE-----

hF4DzfwiGcVT05ISAQdAetSWotgG0+MTEfyKvagrHAeGw0Denjph+Mu2KcpAajIw
kE398hrqnc6qYFdf3p761kzvgjX0auua8L2WFlhAzGh1ULodxHVLmvxwiId4JwHq
0sAzAaM+Vn5hfDM5799p2DpPK8635LN0UvtlOqGIdaNfu5DgfoherMSb3zlBa4YF
WJG1Fa9glfWTOlMNKKoFl4LUh1BUF4TbqUv3a0BR6GcDy6zSp4KRl3NIq22fUD/F
BZWuhPRhnsvDAoBTbvlgjyuActYhtXU5srMAEh4UeVvKyU8xImDfLgJReU4500JU
VjZkMXTileVhAprvE5KCCDWi6YWzV+SSpn+VhtnShAfoF870GI+DOnvFwEnhQlol
JRZdfjq5haoEjWTuqSIS+O40AgmQYPIjnO5ALehFuWTHKLDFVv4EDqx7MatXZidz
drpAMWGi
=erKa
-----END PGP MESSAGE-----";

        private const string ExpectedLightToNightMessage = "Oh hi, this is a private message from Light to Night!\n";

        // V6 NIST P-256 test vector from OpenPGP.js
        private const string NistP256V6PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xXkGZoVjGhMAAABMCCqGSM49AwEHAgMEUqR9vqdSZv8I+DGuSOYUSf4cNVlE
H16loiqRcAsDY9SHSTVHQkEWbc63HyEvV3jGSbSk2dNF64faN3nbhlZ0PgAB
APcoOjqcdJ9/LHRgxWvSbrKAmKNm0yJE9U9DY9hwshqhwqEGHxMIAAAAPgWC
ZoVjGgMLCQcFFQgKDA4EFgACAQKbAwIeASKhBk+e6Xq0rbnjKzVy/3Qitc2h
eW/w/IuxgPXjJW3nfTRxAAAAABQOEKxf0tyJS3Pbs1xApVxWKP4BAM8Bkygn
ddtiBifou11xgxOjT0y0CsbjIKyOnPTvIh/4AQCfyLJIAmQUN36mSInEepvy
NVk8jmweVYOCT8RluvFtG80OPHRlc3RAdGVzdC5pdD7CjwYTEwgAAAAsBYJm
hWMaAhkBIqEGT57perStueMrNXL/dCK1zaF5b/D8i7GA9eMlbed9NHEAAAAA
g9UQJqaRsvniF1WYuuRLpqMpOAEAvAhGhNpom/L2iIZLCpeyFCfGe5VDUBQB
1cjGpTbnrJoBAIjy1tgUH1gjixchymNf5LfUqwdXwEiLfv2f/Iq+KEX/x30G
ZoVjGhIAAABQCCqGSM49AwEHAgMESZrMsc0UrXB5/C8FHXAepykqAyueem7p
cjVvWFP9V59w/O/VXVyJBrZqleN0w/KexznRyzvQjH36HRlwVFwJ5QMBCAcA
AQDiiISRsjcPcaGXSAEYmvd80nH1oP8CJ/TQsi8od5nhqMKPBhgTCAAAACwF
gmaFYxoCmwwioQZPnul6tK254ys1cv90IrXNoXlv8PyLsYD14yVt5300cQAA
AAC2GhBn4S5eLyGPjccfUkFRKKWmAP4iHESir/KDsmsfhE5m/RwQcy7feCl7
2bny7QRNGY8dFQD8CwmHJ0EvMDQcvVWPrj8WdgPblJEEgWd9AUItEFcDee0=
-----END PGP PRIVATE KEY BLOCK-----";

        private const string NistP256V6EncryptedMessage = @"-----BEGIN PGP MESSAGE-----

wX4DYKEfntV7jkcSAgMEXplJPwjsvhh7xNeBeZtgepG1f0hUaW4eoeFCDpYH
IOr2RZFgRd6KbtmNsI1saqDwDg7EjFk+AWOe7av2xcFStTDfz+9mus03A6tk
7mPFWGsDUrxP2b+tyO6ofr9I4gyj5tI2X7R94AfRWgQxy+O2PvLSNAFXcx4o
SsrtSQmZUKpxuBROy+bZNheNgmN966vqnFBiM1vXikv5OVyprUV0EzzQ3Hnt
69s=
=0Agg
-----END PGP MESSAGE-----";

        private const string ExpectedNistP256DecryptedMessage = "abc";

        [Fact]
        public void DecryptKnownVector_X25519_LightToNight_Succeeds()
        {
            // Parse and decrypt Night's private key
            var dearmored = ArmorCore.Decode(NightUserPrivateKey);
            var secretKeyRing = PgpSecretKeyRing.Read(dearmored.Data);

            // Find and decrypt the encryption subkey
            var encryptionSubkey = secretKeyRing.Subkeys[0];
            Assert.True(encryptionSubkey.IsEncrypted);

            var decryptedSubkey = encryptionSubkey.Decrypt(NightUserPassphrase);
            Assert.False(decryptedSubkey.IsEncrypted);

            // Parse the encrypted message
            var messageDearmored = ArmorCore.Decode(LightToNightEncryptedMessage);

            // Decrypt the message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedSubkey);

            var success = decryptor.TryDecrypt(messageDearmored.Data, out var decryptedMessage, out var error);

            Assert.True(success, $"Decryption failed: {error}");
            var text = Encoding.UTF8.GetString(decryptedMessage!.Data.ToArray());
            Assert.Equal(ExpectedLightToNightMessage, text);
        }

        [Fact]
        public void DecryptKnownVector_NistP256V6_Succeeds()
        {
            // Parse the private key (V6 format, no passphrase)
            var dearmored = ArmorCore.Decode(NistP256V6PrivateKey);
            var secretKeyRing = PgpSecretKeyRing.Read(dearmored.Data);

            // Find the encryption subkey
            var encryptionSubkey = secretKeyRing.Subkeys[0];

            // Parse the encrypted message
            var messageDearmored = ArmorCore.Decode(NistP256V6EncryptedMessage);

            // Decrypt the message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(encryptionSubkey);

            var success = decryptor.TryDecrypt(messageDearmored.Data, out var decryptedMessage, out var error);

            Assert.True(success, $"Decryption failed: {error}");
            var text = Encoding.UTF8.GetString(decryptedMessage!.Data.ToArray());
            Assert.Equal(ExpectedNistP256DecryptedMessage, text);
        }
    }

    public class RsaAlgorithm
    {
        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void EncryptDecrypt_VariousKeySizes_RoundTrip_Succeeds(int keySize)
        {
            // Generate RSA key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId($"test-rsa-{keySize}@example.com")
                .WithKeySize(keySize)
                .GenerateRsa();

            // Encrypt
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Theory]
        [InlineData(2048, "simple-pass")]
        [InlineData(3072, "complex-p@ss!123")]
        [InlineData(4096, "unicode-密码-пароль")]
        public void EncryptDecrypt_WithPassphrase_VariousKeySizes_Succeeds(int keySize, string passphrase)
        {
            // Generate RSA key pair with passphrase
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId($"test-rsa-{keySize}-protected@example.com")
                .WithKeySize(keySize)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Verify key is encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);

            // Decrypt the secret key
            var decryptedKey = keyResult.MasterSecretKey.Decrypt(passphrase);
            Assert.False(decryptedKey.IsEncrypted);

            // Encrypt message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void EncryptDecrypt_WithEncryptionSubkey_Succeeds()
        {
            // Generate RSA key with encryption subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-rsa-subkey@example.com")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Get encryption subkey
            var encryptionSubkey = keyResult.SecretKeyRing.Subkeys[0];
            var encryptionPublicKey = encryptionSubkey.PublicKey;

            // Encrypt with subkey
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(encryptionPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt with subkey
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(encryptionSubkey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void EncryptDecrypt_WithArgon2Passphrase_Succeeds()
        {
            const string passphrase = "argon2-rsa-test-pass";

            // Generate RSA key with Argon2 passphrase protection
            // Using lower memory for faster tests (2^16 KB = 64MB)
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-rsa-argon2@example.com")
                .WithKeySize(2048)
                .WithArgon2Passphrase(passphrase, 1, 1, 16)
                .GenerateRsa();

            // Verify key is encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);

            // Decrypt the secret key
            var decryptedKey = keyResult.MasterSecretKey.Decrypt(passphrase);
            Assert.False(decryptedKey.IsEncrypted);

            // Encrypt message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void EncryptDecrypt_WithEncryptionSubkey_AndArgon2Passphrase_Succeeds()
        {
            const string passphrase = "argon2-subkey-pass";

            // Generate RSA key with encryption subkey and Argon2 passphrase protection
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-rsa-subkey-argon2@example.com")
                .WithKeySize(2048)
                .WithArgon2Passphrase(passphrase, 1, 1, 16)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Get encryption subkey
            var encryptionSubkey = keyResult.SecretKeyRing.Subkeys[0];
            Assert.True(encryptionSubkey.IsEncrypted);

            // Decrypt the subkey
            var decryptedSubkey = encryptionSubkey.Decrypt(passphrase);
            Assert.False(decryptedSubkey.IsEncrypted);

            // Encrypt with subkey's public key
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(encryptionSubkey.PublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt with decrypted subkey
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedSubkey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }
    }

    public class Ed25519X25519Algorithm
    {
        [Fact]
        public void EncryptDecrypt_RoundTrip_Succeeds()
        {
            // Generate Ed25519/X25519 key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-ed25519@example.com")
                .GenerateEd25519WithX25519Subkey();

            // Get encryption subkey (X25519)
            var encryptionSubkey = keyResult.SecretKeyRing.Subkeys[0];
            var encryptionPublicKey = encryptionSubkey.PublicKey;

            // Encrypt
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(encryptionPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(encryptionSubkey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Theory]
        [InlineData("simple")]
        [InlineData("complex-p@ss!123")]
        [InlineData("unicode-密码")]
        public void EncryptDecrypt_WithPassphrase_Succeeds(string passphrase)
        {
            // Generate Ed25519/X25519 key pair with passphrase
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-ed25519-protected@example.com")
                .WithPassphrase(passphrase)
                .GenerateEd25519WithX25519Subkey();

            // Verify keys are encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);
            var encryptionSubkey = keyResult.SecretKeyRing.Subkeys[0];
            Assert.True(encryptionSubkey.IsEncrypted);

            // Decrypt the encryption subkey
            var decryptedSubkey = encryptionSubkey.Decrypt(passphrase);
            Assert.False(decryptedSubkey.IsEncrypted);

            // Encrypt message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(encryptionSubkey.PublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedSubkey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void EncryptDecrypt_WithArgon2Passphrase_Succeeds()
        {
            const string passphrase = "argon2-test-pass";

            // Generate Ed25519/X25519 key pair with Argon2 passphrase protection
            // Using lower memory for faster tests (2^16 KB = 64MB)
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-ed25519-argon2@example.com")
                .WithArgon2Passphrase(passphrase, 1, 1, 16)
                .GenerateEd25519WithX25519Subkey();

            // Verify keys are encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);
            var encryptionSubkey = keyResult.SecretKeyRing.Subkeys[0];
            Assert.True(encryptionSubkey.IsEncrypted);

            // Decrypt the encryption subkey
            var decryptedSubkey = encryptionSubkey.Decrypt(passphrase);
            Assert.False(decryptedSubkey.IsEncrypted);

            // Encrypt message
            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(encryptionSubkey.PublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedSubkey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }
    }

    public class SymmetricAlgorithms
    {
        [Fact]
        public void EncryptDecrypt_WithAes128_Succeeds()
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-aes128@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);

            // Encrypt with AES-128
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey)
                .WithAes128();

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void EncryptDecrypt_WithAes192_Succeeds()
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-aes192@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);

            // Encrypt with AES-192
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey)
                .WithAes192();

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }

        [Fact]
        public void EncryptDecrypt_WithAes256_Succeeds()
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-aes256@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);

            // Encrypt with AES-256 (default)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey)
                .WithAes256();

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }
    }

    public class DataVariations
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(100)]
        [InlineData(1000)]
        [InlineData(10000)]
        [InlineData(100000)]
        public void EncryptDecrypt_VariousMessageSizes_Succeeds(int messageSize)
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-size@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Generate message of specified size
            var plainBytes = new byte[messageSize];
            if (messageSize > 0)
            {
                new Random(42).NextBytes(plainBytes);
            }

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plainBytes, decrypted.Data.ToArray());
        }

        [Fact]
        public void EncryptDecrypt_BinaryData_Succeeds()
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-binary@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Generate binary data with all byte values
            var plainBytes = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                plainBytes[i] = (byte)i;
            }

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plainBytes, decrypted.Data.ToArray());
        }

        [Theory]
        [InlineData("ASCII text")]
        [InlineData("UTF-8: αβγδ")]
        [InlineData("Chinese: 中文测试")]
        [InlineData("Japanese: 日本語テスト")]
        [InlineData("Korean: 한국어 테스트")]
        [InlineData("Emoji: 😀🎉🔐")]
        [InlineData("Mixed: Hello 世界 🌍")]
        public void EncryptDecrypt_UnicodeText_Succeeds(string text)
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test-unicode@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            var plainBytes = Encoding.UTF8.GetBytes(text);

            // Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(text, decryptedText);
        }
    }

    public class ErrorHandling
    {
        [Fact]
        public void Decrypt_WithWrongKey_Fails()
        {
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

            // Try to decrypt with key 2
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult2.MasterSecretKey);

            var success = decryptor.TryDecrypt(encrypted.ToArray(), out _, out var error);

            Assert.False(success);
            Assert.NotNull(error);
        }

        [Fact]
        public void Decrypt_WithWrongPassphrase_Fails()
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .WithKeySize(2048)
                .WithPassphrase("correct-password")
                .GenerateRsa();

            Assert.True(keyResult.MasterSecretKey.IsEncrypted);

            // Try to decrypt with wrong passphrase - should throw CryptographicException
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
                keyResult.MasterSecretKey.Decrypt("wrong-password"));
        }

        [Fact]
        public void Decrypt_CorruptedMessage_Fails()
        {
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("test@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes).ToArray();

            // Corrupt the message
            if (encrypted.Length > 50)
            {
                encrypted[50] ^= 0xFF;
            }

            // Try to decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);

            var success = decryptor.TryDecrypt(encrypted, out _, out _);

            Assert.False(success);
        }
    }

    public class CrossAlgorithmCompatibility
    {
        [Fact]
        public void EncryptDecrypt_RsaToRsa_DifferentKeySizes_Succeeds()
        {
            // Generate different sized keys for recipient
            var recipientKey = PgpKeyGenerator.Create()
                .WithUserId("recipient@example.com")
                .WithKeySize(4096)
                .GenerateRsa();

            var plainBytes = Encoding.UTF8.GetBytes(TestPlaintext);

            // Encrypt to recipient
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(recipientKey.MasterPublicKey);

            var encrypted = encryptor.Encrypt(plainBytes);

            // Recipient decrypts
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(recipientKey.MasterSecretKey);

            var decrypted = decryptor.Decrypt(encrypted);

            var decryptedText = Encoding.UTF8.GetString(decrypted.Data.ToArray());
            Assert.Equal(TestPlaintext, decryptedText);
        }
    }
}
