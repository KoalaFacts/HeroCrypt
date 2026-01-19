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

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Ring Serialization Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyRingSerializationTests
    {
        [Fact]
        public void PublicKeyRing_WriteAndRead_RoundTripSucceeds()
        {
            // Arrange - Generate key with subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Serialization Test <serial@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var originalRing = keyResult.PublicKeyRing;

            // Act - Serialize to bytes
            var bytes = originalRing.ToArray();

            // Act - Deserialize back
            var reimportedRing = PgpPublicKeyRing.Read(bytes);

            // Assert - Verify structure preserved
            Assert.Equal(originalRing.MasterFingerprint, reimportedRing.MasterFingerprint);
            Assert.Equal(originalRing.KeyCount, reimportedRing.KeyCount);
            Assert.Equal(originalRing.UserIds.Count, reimportedRing.UserIds.Count);
            Assert.Equal(originalRing.UserIds[0].UserId, reimportedRing.UserIds[0].UserId);
            Assert.Equal(originalRing.Subkeys.Count, reimportedRing.Subkeys.Count);
        }

        [Fact]
        public void SecretKeyRing_WriteAndRead_RoundTripSucceeds()
        {
            // Arrange - Generate key with subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Secret Ring Test <secret-ring@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            var originalRing = keyResult.SecretKeyRing;

            // Act - Serialize to bytes
            var bytes = originalRing.ToArray();

            // Act - Deserialize back
            var reimportedRing = PgpSecretKeyRing.Read(bytes);

            // Assert - Verify structure preserved
            Assert.Equal(originalRing.MasterFingerprint, reimportedRing.MasterFingerprint);
            Assert.Equal(originalRing.KeyCount, reimportedRing.KeyCount);
            Assert.Equal(originalRing.UserIds.Count, reimportedRing.UserIds.Count);
            Assert.Equal(originalRing.Subkeys.Count, reimportedRing.Subkeys.Count);
        }

        [Fact]
        public void PublicKeyRing_ReimportedKey_CanEncrypt()
        {
            // Arrange - Generate, serialize, and reimport
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Reimport Encrypt Test <reimport@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var bytes = keyResult.PublicKeyRing.ToArray();
            var reimportedRing = PgpPublicKeyRing.Read(bytes);

            var plaintext = "Test message for reimported key."u8.ToArray();

            // Act - Encrypt with reimported public key
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(reimportedRing.MasterKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt with original secret key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void SecretKeyRing_ReimportedKey_CanDecrypt()
        {
            // Arrange - Generate, serialize, and reimport
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Reimport Decrypt Test <reimport-dec@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var bytes = keyResult.SecretKeyRing.ToArray();
            var reimportedRing = PgpSecretKeyRing.Read(bytes);

            var plaintext = "Test message for reimported secret key."u8.ToArray();

            // Act - Encrypt with original public key
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt with reimported secret key
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(reimportedRing.MasterKey);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Ring Collection Workflow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyRingCollectionWorkflowTests
    {
        [Fact]
        public void PublicKeyRingCollection_ManageMultipleKeys_LookupSucceeds()
        {
            // Arrange - Generate multiple keys
            var aliceKey = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var bobKey = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var charlieKey = PgpKeyGenerator.Create()
                .WithUserId("Charlie <charlie@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Act - Build collection
            var collection = new PgpPublicKeyRingCollection([
                aliceKey.PublicKeyRing,
                bobKey.PublicKeyRing,
                charlieKey.PublicKeyRing
            ]);

            // Assert - Lookup by key ID
            Assert.Equal(3, collection.Count);
            Assert.NotNull(collection.GetKeyRing(aliceKey.KeyId));
            Assert.NotNull(collection.GetKeyRing(bobKey.KeyId));
            Assert.NotNull(collection.GetKeyRing(charlieKey.KeyId));

            // Assert - Lookup by user ID substring
            var aliceRings = collection.GetKeyRingsByUserId("alice@example.com").ToList();
            Assert.Single(aliceRings);
            Assert.Equal(aliceKey.Fingerprint, aliceRings[0].MasterFingerprint);
        }

        [Fact]
        public void SecretKeyRingCollection_DecryptWithMatchingKey_Succeeds()
        {
            // Arrange - Generate multiple keys
            var key1 = PgpKeyGenerator.Create()
                .WithUserId("Key1 <key1@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var key2 = PgpKeyGenerator.Create()
                .WithUserId("Key2 <key2@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Build secret key ring collection
            var secretCollection = new PgpSecretKeyRingCollection([
                key1.SecretKeyRing,
                key2.SecretKeyRing
            ]);

            var plaintext = "Message encrypted for key2."u8.ToArray();

            // Act - Encrypt for key2 only
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(key2.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt using key2's secret key ring from collection
            var key2Ring = secretCollection.GetKeyRing(key2.KeyId);
            Assert.NotNull(key2Ring);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(key2Ring.Value);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void SecretKeyRingCollection_DecryptWithWrongKey_Fails()
        {
            // Arrange - Generate multiple keys
            var key1 = PgpKeyGenerator.Create()
                .WithUserId("Key1 <key1@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var key2 = PgpKeyGenerator.Create()
                .WithUserId("Key2 <key2@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var plaintext = "Message encrypted for key2 only."u8.ToArray();

            // Act - Encrypt for key2 only
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(key2.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act/Assert - Try to decrypt with key1 (should fail)
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(key1.SecretKeyRing);

            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => decryptor.Decrypt(encrypted));
        }

        [Fact]
        public void KeyRingCollection_AddAndRemove_MaintainsIntegrity()
        {
            // Arrange
            var key1 = PgpKeyGenerator.Create()
                .WithUserId("Key1 <key1@example.com>")
                .GenerateEd25519();

            var key2 = PgpKeyGenerator.Create()
                .WithUserId("Key2 <key2@example.com>")
                .GenerateEd25519();

            var key3 = PgpKeyGenerator.Create()
                .WithUserId("Key3 <key3@example.com>")
                .GenerateEd25519();

            // Act - Build and modify collection
            var collection = new PgpPublicKeyRingCollection(key1.PublicKeyRing);
            Assert.Equal(1, collection.Count);

            collection = collection.Add(key2.PublicKeyRing);
            Assert.Equal(2, collection.Count);

            collection = collection.Add(key3.PublicKeyRing);
            Assert.Equal(3, collection.Count);

            // Remove key2
            collection = collection.Remove(key2.KeyId);
            Assert.Equal(2, collection.Count);

            // Assert - key2 is gone, others remain
            Assert.Null(collection.GetKeyRing(key2.KeyId));
            Assert.NotNull(collection.GetKeyRing(key1.KeyId));
            Assert.NotNull(collection.GetKeyRing(key3.KeyId));
        }

        [Fact]
        public void SecretKeyRingCollection_ExtractPublicKeys_ProducesMatchingCollection()
        {
            // Arrange
            var key1 = PgpKeyGenerator.Create()
                .WithUserId("Extract1 <extract1@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var key2 = PgpKeyGenerator.Create()
                .WithUserId("Extract2 <extract2@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var secretCollection = new PgpSecretKeyRingCollection([
                key1.SecretKeyRing,
                key2.SecretKeyRing
            ]);

            // Act - Extract public keys
            var publicCollection = secretCollection.ExtractPublicKeyRingCollection();

            // Assert
            Assert.Equal(secretCollection.Count, publicCollection.Count);
            Assert.NotNull(publicCollection.GetKeyRing(key1.KeyId));
            Assert.NotNull(publicCollection.GetKeyRing(key2.KeyId));

            // Verify fingerprints match
            var publicRing1 = publicCollection.GetKeyRing(key1.KeyId)!.Value;
            Assert.Equal(key1.Fingerprint, publicRing1.MasterFingerprint);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Ring Subkey Selection Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyRingSubkeySelectionTests
    {
        [Fact]
        public void EncryptionSubkey_CanDecrypt_WhenUsedWithKeyRing()
        {
            // Arrange - Generate RSA key with encryption subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Subkey Selection Test <subkey@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Verify we have a subkey
            Assert.Single(keyResult.PublicKeyRing.Subkeys);

            var plaintext = "Test message for encryption subkey."u8.ToArray();

            // Act - Encrypt using key ring (implementation selects encryption-capable key)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt with secret key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(keyResult.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void Ed25519WithX25519_EncryptsAndDecrypts_UsingSubkey()
        {
            // Arrange - Ed25519 master (signing only) + X25519 subkey (encryption)
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Ed25519/X25519 Selection <ed-x@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Verify key structure
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, keyResult.MasterPublicKey.Algorithm);
            Assert.Single(keyResult.PublicKeyRing.Subkeys);
            Assert.Equal(PgpPublicKeyAlgorithm.X25519, keyResult.PublicKeyRing.Subkeys[0].Algorithm);

            var plaintext = "Ed25519 can't encrypt, must use X25519 subkey."u8.ToArray();

            // Act - Encrypt using key ring (must use X25519 subkey since Ed25519 can't encrypt)
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt with secret key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(keyResult.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void KeyRing_WithMultipleSubkeys_EncryptsAndDecrypts()
        {
            // Arrange - Generate RSA key with both signing and encryption subkeys
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Multi-Subkey Test <multi@example.com>")
                .WithKeySize(2048)
                .WithSigningSubkey()
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Verify we have 2 subkeys
            Assert.Equal(2, keyResult.PublicKeyRing.Subkeys.Count);

            var plaintext = "Message for key ring with multiple subkeys."u8.ToArray();

            // Act - Encrypt using key ring
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Decrypt with secret key ring
            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKeyRing(keyResult.SecretKeyRing);
            var decrypted = decryptor.Decrypt(encrypted);

            // Assert
            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void SigningSubkey_CanSign_WhenUsedFromKeyRing()
        {
            // Arrange - Generate RSA key with signing subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Signing Subkey Test <sign-subkey@example.com>")
                .WithKeySize(2048)
                .WithSigningSubkey()
                .GenerateRsa();

            // Get the signing subkey
            var signingSubkey = keyResult.SecretKeyRing.Subkeys[0];
            var signingPublicSubkey = keyResult.PublicKeyRing.Subkeys[0];

            var message = "Message to sign with signing subkey."u8.ToArray();

            // Act - Sign with signing subkey
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(signingSubkey);
            var signedMessage = signer.Sign(message);

            // Act - Verify with signing subkey's public key
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(signingPublicSubkey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Ring Modification Workflow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyRingModificationWorkflowTests
    {
        [Fact]
        public void AddUserId_CreatesNewRingWithBothUserIds()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Primary <primary@example.com>")
                .GenerateEd25519();

            var originalRing = keyResult.PublicKeyRing;
            Assert.Single(originalRing.UserIds);

            // Act - Add second user ID
            var newUserId = new PgpUserIdPacket("Secondary <secondary@example.com>");
            var modifiedRing = originalRing.AddUserId(newUserId);

            // Assert
            Assert.Single(originalRing.UserIds); // Original unchanged
            Assert.Equal(2, modifiedRing.UserIds.Count);
            Assert.Equal("Primary <primary@example.com>", modifiedRing.UserIds[0].UserId);
            Assert.Equal("Secondary <secondary@example.com>", modifiedRing.UserIds[1].UserId);

            // Verify fingerprint unchanged
            Assert.Equal(originalRing.MasterFingerprint, modifiedRing.MasterFingerprint);
        }

        [Fact]
        public void SecretKeyRing_ExtractPublicKeyRing_ProducesUsablePublicKey()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Extract Test <extract@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Extract public key ring from secret key ring
            var extractedPublicRing = keyResult.SecretKeyRing.ExtractPublicKeyRing();

            // Assert - Verify it's usable for encryption
            var plaintext = "Message encrypted with extracted public key."u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(extractedPublicRing.MasterKey);
            var encrypted = encryptor.Encrypt(plaintext);

            using var decryptor = PgpMessageDecryptor.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var decrypted = decryptor.Decrypt(encrypted);

            Assert.Equal(plaintext, decrypted.Data.ToArray());
        }

        [Fact]
        public void KeyRing_GetPrimaryUserId_ReturnsFirstUserId()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Primary User <primary@example.com>")
                .GenerateEd25519();

            // Add additional user ID
            var modifiedRing = keyResult.PublicKeyRing
                .AddUserId(new PgpUserIdPacket("Secondary User <secondary@example.com>"));

            // Act
            var primaryUserId = modifiedRing.GetPrimaryUserId();

            // Assert
            Assert.NotNull(primaryUserId);
            Assert.Equal("Primary User <primary@example.com>", primaryUserId.Value.UserId);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Recipient Info / PKESK Exposure Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    public class RecipientInfoTests
    {
        [Fact]
        public void EncryptedMessage_Recipients_ContainsKeyInfo()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Test message"u8.ToArray();

            // Act
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Assert
            Assert.Equal(1, encrypted.RecipientCount);
            Assert.Single(encrypted.Recipients.ToArray());

            var recipient = encrypted.Recipients[0];
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, recipient.Algorithm);
            Assert.Equal(8, recipient.KeyId.Length);
            Assert.NotEmpty(recipient.KeyIdHex);
        }

        [Fact]
        public void EncryptedMessage_Recipients_MatchesPublicKey_V4()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Test"u8.ToArray();

            // Act
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Assert
            var recipient = encrypted.Recipients[0];
            Assert.True(recipient.MatchesKey(keyResult.MasterPublicKey));
        }

        [Fact]
        public void EncryptedMessage_Recipients_MultipleRecipients_AllExposed()
        {
            // Arrange
            var aliceKey = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var bobKey = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Multi-recipient message"u8.ToArray();

            // Act
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(aliceKey.MasterPublicKey)
                .AddRecipient(bobKey.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Assert
            Assert.Equal(2, encrypted.RecipientCount);
            Assert.Equal(2, encrypted.Recipients.Length);

            var recipients = encrypted.Recipients.ToArray();
            Assert.True(recipients[0].MatchesKey(aliceKey.MasterPublicKey));
            Assert.True(recipients[1].MatchesKey(bobKey.MasterPublicKey));
        }

        [Fact]
        public void EncryptedMessage_Recipients_Ed25519X25519_V6Format()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 User <ed@example.com>")
                .GenerateEd25519WithX25519Subkey();

            var plaintext = "V6 encrypted message"u8.ToArray();

            // Act
            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.PublicKeyRing);
            var encrypted = encryptor.Encrypt(plaintext);

            // Assert
            Assert.Equal(1, encrypted.RecipientCount);

            var recipient = encrypted.Recipients[0];
            Assert.Equal(PgpPublicKeyAlgorithm.X25519, recipient.Algorithm);
            // V6 PKESK exposes full fingerprint
            Assert.True(recipient.Version == 6 || recipient.Fingerprint.Length > 0 || recipient.KeyId.Length == 8);
        }

        [Fact]
        public void EncryptedMessage_Read_ParsesRecipientInfo()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Parse test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act - Re-read the encrypted message from bytes
            var reRead = PgpEncryptedMessage.Read(encrypted.Data.Span);

            // Assert
            Assert.Equal(encrypted.RecipientCount, reRead.RecipientCount);
            Assert.Equal(1, reRead.Recipients.Length);

            var recipient = reRead.Recipients[0];
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, recipient.Algorithm);
            Assert.True(recipient.MatchesKey(keyResult.MasterPublicKey));
        }

        [Fact]
        public void RecipientInfo_KeyIdHex_ReturnsCorrectFormat()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(keyResult.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act
            var recipient = encrypted.Recipients[0];
            var keyIdHex = recipient.KeyIdHex;

            // Assert
            Assert.Equal(16, keyIdHex.Length); // 8 bytes = 16 hex chars
            Assert.True(keyIdHex.All(c => char.IsLetterOrDigit(c)));
        }

        [Fact]
        public void RecipientInfo_MatchesKey_ReturnsFalseForWrongKey()
        {
            // Arrange
            var aliceKey = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var bobKey = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var plaintext = "Test"u8.ToArray();

            using var encryptor = PgpMessageEncryptor.Create()
                .AddRecipient(aliceKey.MasterPublicKey);
            var encrypted = encryptor.Encrypt(plaintext);

            // Act
            var recipient = encrypted.Recipients[0];

            // Assert
            Assert.True(recipient.MatchesKey(aliceKey.MasterPublicKey));
            Assert.False(recipient.MatchesKey(bobKey.MasterPublicKey));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Revocation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyRevocationTests
    {
        [Fact]
        public void RevokeKey_RSA_CreatesValidRevocationSignature()
        {
            // Arrange - Generate RSA key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Create revocation signature
            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeyCompromised, "Key was compromised");
            var revocation = revoker.RevokeKey();

            // Assert
            Assert.Equal(PgpSignatureType.KeyRevocation, revocation.SignatureType);
            Assert.Equal(4, revocation.Version); // RSA keys are V4
        }

        [Fact]
        public void RevokeKey_Ed25519_CreatesValidRevocationSignature()
        {
            // Arrange - Generate Ed25519 key pair
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519();

            // Act - Create revocation signature
            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeyRetired, "Key is no longer used");
            var revocation = revoker.RevokeKey();

            // Assert
            Assert.Equal(PgpSignatureType.KeyRevocation, revocation.SignatureType);
            Assert.Equal(6, revocation.Version); // Ed25519 keys are V6
        }

        [Fact]
        public void RevokeSubkey_RSA_CreatesValidSubkeyRevocationSignature()
        {
            // Arrange - Generate RSA key pair with subkey
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            var subkeyPublicKey = keyResult.PublicKeyRing.Subkeys[0];

            // Act - Create subkey revocation signature
            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithSubkey(subkeyPublicKey)
                .WithReason(PgpRevocationReason.KeySuperseded);
            var revocation = revoker.RevokeSubkey();

            // Assert
            Assert.Equal(PgpSignatureType.SubkeyRevocation, revocation.SignatureType);
        }

        [Fact]
        public void AddRevocationSignature_ToPublicKeyRing_SetsIsRevoked()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeyCompromised);
            var revocation = revoker.RevokeKey();

            // Act
            var revokedKeyRing = keyResult.PublicKeyRing.AddRevocationSignature(revocation);

            // Assert
            Assert.False(keyResult.PublicKeyRing.IsRevoked);
            Assert.True(revokedKeyRing.IsRevoked);
        }

        [Fact]
        public void AddRevocationSignature_ToSecretKeyRing_SetsIsKeyRevoked()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeyRetired, "No longer in use");
            var revocation = revoker.RevokeKey();

            // Act
            var revokedKeyRing = keyResult.SecretKeyRing.AddRevocationSignature(revocation);

            // Assert
            Assert.False(keyResult.SecretKeyRing.IsKeyRevoked);
            Assert.True(revokedKeyRing.IsKeyRevoked);
        }

        [Fact]
        public void GetRevocationReason_ReturnsCorrectReasonAndText()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var reasonText = "This key was compromised in a security breach";
            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeyCompromised, reasonText);
            var revocation = revoker.RevokeKey();
            var revokedKeyRing = keyResult.PublicKeyRing.AddRevocationSignature(revocation);

            // Act
            var result = revokedKeyRing.GetRevocationReason();

            // Assert
            Assert.NotNull(result);
            Assert.Equal(PgpRevocationReason.KeyCompromised, result.Value.Reason);
            Assert.Equal(reasonText, result.Value.ReasonText);
        }

        [Fact]
        public void GetRevocationReason_NoRevocation_ReturnsNull()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var result = keyResult.PublicKeyRing.GetRevocationReason();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void RevokeKey_WithCustomTime_UsesSpecifiedTime()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var customTime = new DateTimeOffset(2025, 6, 15, 12, 0, 0, TimeSpan.Zero);

            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.NoReason)
                .WithRevocationTime(customTime);
            var revocation = revoker.RevokeKey();

            // Act - Get signature creation time from subpackets
            var creationTimeSubpacket = revocation.HashedSubpackets
                .First(sp => sp.Type == PgpSignatureSubpacketType.SignatureCreationTime);

            // Assert
            var creationTime = creationTimeSubpacket.GetSignatureCreationTime();
            Assert.Equal(customTime, creationTime);
        }

        [Fact]
        public void RevokeKey_WithoutSecretKey_ThrowsInvalidOperationException()
        {
            // Arrange
            using var revoker = PgpKeyRevoker.Create()
                .WithReason(PgpRevocationReason.KeyCompromised);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => revoker.RevokeKey());
        }

        [Fact]
        public void RevokeSubkey_WithoutSubkey_ThrowsInvalidOperationException()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeySuperseded);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => revoker.RevokeSubkey());
        }

        [Fact]
        public void AddRevocationSignature_WrongSignatureType_ThrowsArgumentException()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Get a subkey binding signature (wrong type)
            var bindingSignature = keyResult.PublicKeyRing.Signatures
                .First(s => s.SignatureType == PgpSignatureType.SubkeyBinding);

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                keyResult.PublicKeyRing.AddRevocationSignature(bindingSignature));
        }

        [Fact]
        public void RevocationReason_IsHardRevocation_ReturnsTrueForKeyCompromised()
        {
            // Assert
            Assert.True(PgpRevocationReason.KeyCompromised.IsHardRevocation());
            Assert.False(PgpRevocationReason.KeyRetired.IsHardRevocation());
            Assert.False(PgpRevocationReason.KeySuperseded.IsHardRevocation());
            Assert.False(PgpRevocationReason.NoReason.IsHardRevocation());
        }

        [Fact]
        public void RevocationReason_GetDescription_ReturnsAppropriateText()
        {
            // Assert
            Assert.Contains("compromised", PgpRevocationReason.KeyCompromised.GetDescription(), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("superseded", PgpRevocationReason.KeySuperseded.GetDescription(), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("retired", PgpRevocationReason.KeyRetired.GetDescription(), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void RevokedKeyRing_Serialization_PreservesRevocation()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            using var revoker = PgpKeyRevoker.Create()
                .WithSecretKey(keyResult.MasterSecretKey)
                .WithReason(PgpRevocationReason.KeyCompromised, "Serialization test");
            var revocation = revoker.RevokeKey();
            var revokedKeyRing = keyResult.PublicKeyRing.AddRevocationSignature(revocation);

            // Act - Serialize and deserialize
            var serialized = revokedKeyRing.ToArray();
            var deserialized = PgpPublicKeyRing.Read(serialized);

            // Assert
            Assert.True(deserialized.IsRevoked);
            var reason = deserialized.GetRevocationReason();
            Assert.NotNull(reason);
            Assert.Equal(PgpRevocationReason.KeyCompromised, reason.Value.Reason);
            Assert.Equal("Serialization test", reason.Value.ReasonText);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Rotation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyRotationTests
    {
        [Fact]
        public void RotateRsaKey_CreatesTransitionSignature()
        {
            // Arrange - Generate old and new keys
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Alice <alice-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Assert
            Assert.Equal(PgpSignatureType.DirectKey, result.TransitionSignature.SignatureType);
            Assert.False(result.OldKeyWasRevoked);
            Assert.Null(result.OldKeyRevocation);
        }

        [Fact]
        public void RotateRsaKey_WithRevocation_CreatesRevocationSignature()
        {
            // Arrange - Generate old and new keys
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate with revocation
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing)
                .WithRevocation(PgpRevocationReason.KeySuperseded, "Rotating to new key");
            var result = rotator.Rotate();

            // Assert
            Assert.True(result.OldKeyWasRevoked);
            Assert.NotNull(result.OldKeyRevocation);
            Assert.Equal(PgpSignatureType.KeyRevocation, result.OldKeyRevocation.Value.SignatureType);
        }

        [Fact]
        public void RotateEd25519Key_CreatesTransitionSignature()
        {
            // Arrange - Generate old and new Ed25519 keys
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Charlie <charlie@example.com>")
                .GenerateEd25519();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Charlie <charlie-new@example.com>")
                .GenerateEd25519();

            // Act - Rotate
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Assert
            Assert.Equal(PgpSignatureType.DirectKey, result.TransitionSignature.SignatureType);
            Assert.Equal(6, result.TransitionSignature.Version);
        }

        [Fact]
        public void RotateKey_TransitionSignatureAddedToNewKeyRing()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Dave <dave@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Dave <dave-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            int originalSignatureCount = newKey.PublicKeyRing.Signatures.Count;

            // Act - Rotate
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Assert - Certified key ring should have one more signature
            Assert.Equal(originalSignatureCount + 1, result.CertifiedNewKeyRing.Signatures.Count);

            // The transition signature should be in the certified key ring
            Assert.Contains(result.CertifiedNewKeyRing.Signatures,
                sig => sig.SignatureType == PgpSignatureType.DirectKey);
        }

        [Fact]
        public void RotateKey_IssuerFingerprintMatchesOldKey()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Eve <eve@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Eve <eve-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Assert - Issuer fingerprint in transition signature should match old key
            // GetIssuerFingerprint returns [version byte] + [fingerprint]
            var issuerData = result.TransitionSignature.GetIssuerFingerprint();

            Assert.NotNull(issuerData);
            Assert.True(issuerData.Length > 1);
            var fingerprint = issuerData[1..]; // Skip version byte
            Assert.Equal(oldKey.MasterPublicKey.ComputeFingerprint(), fingerprint);
        }

        [Fact]
        public void RotateKey_WithCustomTime_UsesSpecifiedTime()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Frank <frank@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Frank <frank-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var customTime = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);

            // Act - Rotate with custom time
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing)
                .WithRotationTime(customTime);
            var result = rotator.Rotate();

            // Assert
            var creationTimeSubpacket = result.TransitionSignature.HashedSubpackets
                .First(sp => sp.Type == PgpSignatureSubpacketType.SignatureCreationTime);
            var creationTime = creationTimeSubpacket.GetSignatureCreationTime();
            Assert.Equal(customTime, creationTime);
        }

        [Fact]
        public void RotateKey_FromKeyRing_UsesSecretKeyRingMasterKey()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Grace <grace@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Grace <grace-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate using key ring
            using var rotator = PgpKeyRotator.Create()
                .FromOldKeyRing(oldKey.SecretKeyRing)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Assert
            Assert.Equal(PgpSignatureType.DirectKey, result.TransitionSignature.SignatureType);
        }

        [Fact]
        public void RotateKey_ToKeyGeneratorResult_WorksCorrectly()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Henry <henry@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Henry <henry-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate using generator result directly
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey);  // Pass generator result directly
            var result = rotator.Rotate();

            // Assert
            Assert.Equal(PgpSignatureType.DirectKey, result.TransitionSignature.SignatureType);
        }

        [Fact]
        public void RotateKey_OldAndNewKeyFingerprints_AreAvailable()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Ivy <ivy@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Ivy <ivy-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Assert
            Assert.Equal(oldKey.MasterPublicKey.ComputeFingerprint(), result.OldKeyFingerprint);
            Assert.Equal(newKey.MasterPublicKey.ComputeFingerprint(), result.NewKeyFingerprint);
            Assert.NotEqual(result.OldKeyFingerprint, result.NewKeyFingerprint);
        }

        [Fact]
        public void RotateKey_WithoutOldKey_ThrowsInvalidOperationException()
        {
            // Arrange
            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Jack <jack@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            using var rotator = PgpKeyRotator.Create()
                .ToNewKey(newKey.PublicKeyRing);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => rotator.Rotate());
        }

        [Fact]
        public void RotateKey_WithoutNewKey_ThrowsInvalidOperationException()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Kate <kate@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => rotator.Rotate());
        }

        [Fact]
        public void RotateKey_WithEncryptedOldKey_ThrowsArgumentException()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Larry <larry@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("test123")
                .GenerateRsa();

            // Act & Assert - Encrypted key should throw
            Assert.Throws<ArgumentException>(() =>
                PgpKeyRotator.Create().FromOldKey(oldKey.MasterSecretKey));
        }

        [Fact]
        public void RotateKey_CertifiedKeyRing_CanBeSerializedAndDeserialized()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Mike <mike@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Mike <mike-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing);
            var result = rotator.Rotate();

            // Serialize and deserialize
            var serialized = result.CertifiedNewKeyRing.ToArray();
            var deserialized = PgpPublicKeyRing.Read(serialized);

            // Assert - Direct key signature should be preserved
            Assert.Contains(deserialized.Signatures,
                sig => sig.SignatureType == PgpSignatureType.DirectKey);
        }

        [Fact]
        public void RotateKey_RevocationSignature_CanBeAddedToOldKeyRing()
        {
            // Arrange
            var oldKey = PgpKeyGenerator.Create()
                .WithUserId("Nancy <nancy@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var newKey = PgpKeyGenerator.Create()
                .WithUserId("Nancy <nancy-new@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act - Rotate with revocation
            using var rotator = PgpKeyRotator.Create()
                .FromOldKey(oldKey.MasterSecretKey)
                .ToNewKey(newKey.PublicKeyRing)
                .WithRevocation(PgpRevocationReason.KeySuperseded);
            var result = rotator.Rotate();

            // Add revocation to old key ring
            var revokedOldKeyRing = oldKey.PublicKeyRing.AddRevocationSignature(result.OldKeyRevocation!.Value);

            // Assert
            Assert.True(revokedOldKeyRing.IsRevoked);
            var reason = revokedOldKeyRing.GetRevocationReason();
            Assert.NotNull(reason);
            Assert.Equal(PgpRevocationReason.KeySuperseded, reason.Value.Reason);
        }
    }
}
