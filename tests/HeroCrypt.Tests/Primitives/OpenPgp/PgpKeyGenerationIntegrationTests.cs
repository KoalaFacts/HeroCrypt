using HeroCrypt.Primitives.Armor;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Integration tests for PGP key generation with end-to-end workflows.
/// These tests verify that generated keys work correctly for signing,
/// verification, encryption, and decryption operations.
/// </summary>
public class PgpKeyGenerationIntegrationTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // RSA Key Generation + Encryption Workflow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class RsaEncryptionWorkflowTests
    {
        [Fact]
        public void GenerateRsaKey_EncryptAndDecrypt_RoundTripSucceeds()
        {
            // Arrange - Generate RSA key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Hello, World! This is a secret message."u8.ToArray();

            // Act - Encrypt with public key
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt with secret key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateRsaKey_WithEncryptionSubkey_EncryptAndDecrypt_RoundTripSucceeds()
        {
            // Arrange - Generate RSA key pair with encryption subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            var plaintext = "Message encrypted to subkey."u8.ToArray();

            // Act - Encrypt using key ring (should select encryption subkey)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt using secret key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(keyResult.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateRsaKey_MultipleRecipients_AllCanDecrypt()
        {
            // Arrange - Generate two RSA key pairs
            var aliceKey = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var bobKey = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Message for both Alice and Bob."u8.ToArray();

            // Act - Encrypt for both recipients
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(aliceKey.MasterPublicKey)
                .AddRecipient(bobKey.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Alice decrypts
            using var aliceDecryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(aliceKey.MasterSecretKey);
            var aliceDecrypted = aliceDecryptor.Decrypt(encrypted);

            // Act - Bob decrypts (using a fresh copy of encrypted data)
            using var bobDecryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(bobKey.MasterSecretKey);
            var bobDecrypted = bobDecryptor.Decrypt(encrypted.ToArray());

            // Assert
            Assert.Equal(plaintext, aliceDecrypted.Data.ToArray());
            Assert.Equal(plaintext, bobDecrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateRsaKey_SignAndEncrypt_VerifyAndDecrypt_Succeeds()
        {
            // Arrange - Generate sender and recipient keys
            var senderKey = PgpKeyGenerator.Create()
                .WithUserId("Sender <sender@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var recipientKey = PgpKeyGenerator.Create()
                .WithUserId("Recipient <recipient@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Signed and encrypted message."u8.ToArray();

            // Act - Sign with sender's key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(senderKey.MasterSecretKey);
            var signedMessage = signer.Sign(plaintext);

            // Act - Encrypt signed message for recipient
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(recipientKey.MasterPublicKey);
            var encrypted = encryptor.Encrypt(signedMessage.ToArray());

            // Act - Decrypt with recipient's key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(recipientKey.MasterSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Act - Parse and verify signature
            var reimportedSigned = PgpSignedMessage.Read(decrypted.Data.Span);
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(senderKey.MasterPublicKey);
            var verifyResult = verifier.Verify(reimportedSigned);

            // Assert
            Assert.True(verifyResult.IsValid);
            Assert.Equal(plaintext, reimportedSigned.Data.ToArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Ed25519 + X25519 Key Generation + Encryption Workflow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class Ed25519X25519EncryptionWorkflowTests
    {
        [Fact]
        public void GenerateEd25519WithX25519Subkey_EncryptAndDecrypt_RoundTripSucceeds()
        {
            // Arrange - Generate Ed25519 + X25519 key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Charlie <charlie@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var plaintext = "Message encrypted with X25519."u8.ToArray();

            // Act - Encrypt using key ring (should select X25519 subkey)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt using secret key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(keyResult.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateEd25519_SignAndVerify_RoundTripSucceeds()
        {
            // Arrange - Generate Ed25519 signing key
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Dave <dave@example.com>")
                .GenerateEd25519();

            var message = "Message to be signed with Ed25519."u8.ToArray();

            // Act - Sign
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var signedMessage = signer.Sign(message);

            // Act - Verify
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(keyResult.MasterPublicKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
            Assert.Equal(message, signedMessage.Data.ToArray());
        }

        [Fact]
        public void GenerateEd25519WithX25519_SignAndEncrypt_VerifyAndDecrypt_Succeeds()
        {
            // Arrange - Generate sender (Ed25519+X25519) and recipient (Ed25519+X25519) keys
            var senderKey = PgpKeyGenerator.Create()
                .WithUserId("Sender <sender@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var recipientKey = PgpKeyGenerator.Create()
                .WithUserId("Recipient <recipient@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var plaintext = "Signed with Ed25519, encrypted with X25519."u8.ToArray();

            // Act - Sign with sender's Ed25519 master key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(senderKey.MasterSecretKey);
            var signedMessage = signer.Sign(plaintext);

            // Act - Encrypt for recipient's X25519 subkey
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(recipientKey.PublicKeyRing);
            var encrypted = encryptor.Encrypt(signedMessage.ToArray());

            // Act - Decrypt with recipient's secret key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(recipientKey.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Act - Parse and verify signature
            var reimportedSigned = PgpSignedMessage.Read(decrypted.Data.Span);
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(senderKey.MasterPublicKey);
            var verifyResult = verifier.Verify(reimportedSigned);

            // Assert
            Assert.True(verifyResult.IsValid);
            Assert.Equal(plaintext, reimportedSigned.Data.ToArray());
        }

        [Fact]
        public void CrossAlgorithm_RsaSenderToX25519Recipient_Succeeds()
        {
            // Arrange - RSA sender, Ed25519+X25519 recipient
            var senderKey = PgpKeyGenerator.Create()
                .WithUserId("RSA Sender <rsa@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var recipientKey = PgpKeyGenerator.Create()
                .WithUserId("X25519 Recipient <x25519@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var plaintext = "From RSA to X25519."u8.ToArray();

            // Act - Sign with RSA
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(senderKey.MasterSecretKey);
            var signedMessage = signer.Sign(plaintext);

            // Act - Encrypt for X25519
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(recipientKey.PublicKeyRing);
            var encrypted = encryptor.Encrypt(signedMessage.ToArray());

            // Act - Decrypt with X25519
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(recipientKey.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Act - Verify RSA signature
            var reimportedSigned = PgpSignedMessage.Read(decrypted.Data.Span);
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(senderKey.MasterPublicKey);
            var verifyResult = verifier.Verify(reimportedSigned);

            // Assert
            Assert.True(verifyResult.IsValid);
        }

        [Fact]
        public void CrossAlgorithm_Ed25519SenderToRsaRecipient_Succeeds()
        {
            // Arrange - Ed25519 sender, RSA recipient
            var senderKey = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 Sender <ed25519@example.com>")
                .GenerateEd25519();

            var recipientKey = PgpKeyGenerator.Create()
                .WithUserId("RSA Recipient <rsa@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "From Ed25519 to RSA."u8.ToArray();

            // Act - Sign with Ed25519
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(senderKey.MasterSecretKey);
            var signedMessage = signer.Sign(plaintext);

            // Act - Encrypt for RSA
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(recipientKey.MasterPublicKey);
            var encrypted = encryptor.Encrypt(signedMessage.ToArray());

            // Act - Decrypt with RSA
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(recipientKey.MasterSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Act - Verify Ed25519 signature
            var reimportedSigned = PgpSignedMessage.Read(decrypted.Data.Span);
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(senderKey.MasterPublicKey);
            var verifyResult = verifier.Verify(reimportedSigned);

            // Assert
            Assert.True(verifyResult.IsValid);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Armor Export/Import Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class ArmorRoundTripWorkflowTests
    {
        [Fact]
        public void GenerateRsaKey_ArmorExport_Reimport_EncryptDecrypt_Succeeds()
        {
            // Arrange - Generate key and export to armor
            var originalKey = PgpKeyGenerator.Create()
                .WithUserId("Armor Test <armor@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Export to ASCII armor
            var armoredPublic = originalKey.GetArmoredPublicKey();
            var armoredSecret = originalKey.GetArmoredSecretKey();

            // Act - Reimport from armor
            var decodedPublic = ArmorBuilder.Create().Decode(armoredPublic);
            var decodedSecret = ArmorBuilder.Create().Decode(armoredSecret);

            var reimportedPublicRing = PgpPublicKeyRing.Read(decodedPublic.Data);
            var reimportedSecretRing = PgpSecretKeyRing.Read(decodedSecret.Data);

            // Act - Use reimported keys for encryption/decryption
            var plaintext = "Armor round-trip test message."u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(reimportedPublicRing.MasterKey);
            var encrypted = encryptor.Encrypt(plaintext);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(reimportedSecretRing.MasterKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(originalKey.Fingerprint, reimportedPublicRing.MasterFingerprint);
            Assert.Equal(originalKey.Fingerprint, reimportedSecretRing.MasterFingerprint);
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateEd25519WithX25519_ArmorExport_Reimport_EncryptDecrypt_Succeeds()
        {
            // Arrange - Generate key and export to armor
            var originalKey = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 Armor Test <ed25519-armor@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Act - Export to ASCII armor
            var armoredPublic = originalKey.GetArmoredPublicKey();
            var armoredSecret = originalKey.GetArmoredSecretKey();

            // Act - Reimport from armor
            var decodedPublic = ArmorBuilder.Create().Decode(armoredPublic);
            var decodedSecret = ArmorBuilder.Create().Decode(armoredSecret);

            var reimportedPublicRing = PgpPublicKeyRing.Read(decodedPublic.Data);
            var reimportedSecretRing = PgpSecretKeyRing.Read(decodedSecret.Data);

            // Act - Use reimported keys for encryption/decryption
            var plaintext = "Ed25519/X25519 armor round-trip test."u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(reimportedPublicRing);
            var encrypted = encryptor.Encrypt(plaintext);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(reimportedSecretRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(originalKey.Fingerprint, reimportedPublicRing.MasterFingerprint);
            Assert.Equal(2, reimportedPublicRing.KeyCount);
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateKey_ArmorExport_SignAndVerify_Reimported_Succeeds()
        {
            // Arrange - Generate key and export to armor
            var originalKey = PgpKeyGenerator.Create()
                .WithUserId("Signature Armor Test <sig-armor@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Export and reimport
            var armoredPublic = originalKey.GetArmoredPublicKey();
            var armoredSecret = originalKey.GetArmoredSecretKey();

            var reimportedPublicRing = PgpPublicKeyRing.Read(
                ArmorBuilder.Create().Decode(armoredPublic).Data);
            var reimportedSecretRing = PgpSecretKeyRing.Read(
                ArmorBuilder.Create().Decode(armoredSecret).Data);

            var message = "Sign this with reimported key."u8.ToArray();

            // Act - Sign with reimported secret key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(reimportedSecretRing.MasterKey);
            var signedMessage = signer.Sign(message);

            // Act - Verify with reimported public key
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(reimportedPublicRing.MasterKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Passphrase-Protected Key Workflow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class PassphraseProtectedKeyWorkflowTests
    {
        [Fact]
        public void GenerateRsaKey_WithPassphrase_DecryptKey_ThenEncryptMessage_Succeeds()
        {
            // Arrange - Generate passphrase-protected RSA key
            var passphrase = "secure-passphrase-123";
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Protected User <protected@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            var plaintext = "Message for passphrase-protected key."u8.ToArray();

            // Verify key is encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);

            // Act - Encrypt with public key (no passphrase needed)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt secret key with passphrase
            var decryptedSecretKey = keyResult.MasterSecretKey.Decrypt(passphrase);
            Assert.False(decryptedSecretKey.IsEncrypted);

            // Act - Decrypt message with decrypted secret key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(decryptedSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void GenerateRsaKey_WithPassphrase_ExportReimport_DecryptKey_Succeeds()
        {
            // Arrange - Generate passphrase-protected RSA key
            var passphrase = "export-test-pass";
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Export Test <export@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Act - Export to armor
            var armoredSecret = keyResult.GetArmoredSecretKey();

            // Act - Reimport
            var reimportedRing = PgpSecretKeyRing.Read(
                ArmorBuilder.Create().Decode(armoredSecret).Data);

            // Verify reimported key is still encrypted
            Assert.True(reimportedRing.MasterKey.IsEncrypted);

            // Act - Decrypt reimported key
            var decryptedKey = reimportedRing.MasterKey.Decrypt(passphrase);

            // Assert
            Assert.False(decryptedKey.IsEncrypted);
            Assert.Equal(keyResult.Fingerprint, decryptedKey.ComputeFingerprint());
        }

        [Fact]
        public void GenerateRsaKey_WithPassphrase_Sign_ThenVerify_Succeeds()
        {
            // Arrange - Generate passphrase-protected RSA key
            var passphrase = "sign-test-pass";
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Sign Test <sign@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            var message = "Message to sign with protected key."u8.ToArray();

            // Act - Decrypt secret key
            var decryptedSecretKey = keyResult.MasterSecretKey.Decrypt(passphrase);

            // Act - Sign with decrypted key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(decryptedSecretKey);
            var signedMessage = signer.Sign(message);

            // Act - Verify with public key
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(keyResult.MasterPublicKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }

        [Fact]
        public void GenerateEd25519WithX25519_WithPassphrase_FullWorkflow_Succeeds()
        {
            // Arrange - Generate passphrase-protected Ed25519+X25519 key
            var passphrase = "ed25519-x25519-pass";
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 Protected <ed-protected@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519WithX25519Subkey();

            var plaintext = "Signed and encrypted with protected Ed25519/X25519."u8.ToArray();

            // Verify both keys are encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);
            Assert.True(keyResult.SecretKeyRing.Subkeys[0].IsEncrypted);

            // Act - Decrypt master key for signing
            var decryptedMaster = keyResult.MasterSecretKey.Decrypt(passphrase);

            // Act - Sign with Ed25519
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(decryptedMaster);
            var signedMessage = signer.Sign(plaintext);

            // Act - Encrypt using public key ring (X25519 subkey)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(signedMessage.ToArray());

            // Act - Decrypt X25519 subkey
            var decryptedSubkey = keyResult.SecretKeyRing.Subkeys[0].Decrypt(passphrase);

            // Build decrypted secret key ring for decryption
            var decryptedSecretRing = new PgpSecretKeyRing(
                decryptedMaster,
                [decryptedSubkey],
                keyResult.SecretKeyRing.UserIds,
                keyResult.SecretKeyRing.UserAttributes,
                keyResult.SecretKeyRing.Signatures);

            // Act - Decrypt message
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(decryptedSecretRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Act - Verify signature
            var reimportedSigned = PgpSignedMessage.Read(decrypted.Data.Span);
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(keyResult.MasterPublicKey);
            var verifyResult = verifier.Verify(reimportedSigned);

            // Assert
            Assert.True(verifyResult.IsValid);
            Assert.Equal(plaintext, reimportedSigned.Data.ToArray());
        }

        [Fact]
        public void GenerateRsaKey_WithSubkeyAndPassphrase_BothSubkeysDecrypt_Succeeds()
        {
            // Arrange - Generate RSA key with encryption subkey, both passphrase-protected
            var passphrase = "subkey-test-pass";
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Subkey Test <subkey@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Verify both keys are encrypted
            Assert.True(keyResult.MasterSecretKey.IsEncrypted);
            Assert.True(keyResult.SecretKeyRing.Subkeys[0].IsEncrypted);

            // Act - Decrypt master key
            var decryptedMaster = keyResult.MasterSecretKey.Decrypt(passphrase);

            // Act - Decrypt subkey
            var decryptedSubkey = keyResult.SecretKeyRing.Subkeys[0].Decrypt(passphrase);

            // Assert
            Assert.False(decryptedMaster.IsEncrypted);
            Assert.False(decryptedSubkey.IsEncrypted);

            // Verify RSA parameters are readable
            var (d, p, q, u) = decryptedMaster.ReadRsaSecretKey();
            Assert.True(d > 0);
            Assert.True(p > 0);
            Assert.True(q > 0);
            Assert.True(u > 0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Large Data Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class LargeDataWorkflowTests
    {
        [Theory]
        [InlineData(1024)]           // 1 KB
        [InlineData(64 * 1024)]      // 64 KB
        [InlineData(256 * 1024)]     // 256 KB
        public void GenerateRsaKey_EncryptDecrypt_LargeData_Succeeds(int dataSize)
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Large Data Test <large@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = TestHelpers.RandomBytes(dataSize);

            // Act - Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Theory]
        [InlineData(1024)]           // 1 KB
        [InlineData(64 * 1024)]      // 64 KB
        public void GenerateEd25519WithX25519_EncryptDecrypt_LargeData_Succeeds(int dataSize)
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 Large Data <ed-large@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var plaintext = TestHelpers.RandomBytes(dataSize);

            // Act - Encrypt
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(keyResult.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }
    }
}
