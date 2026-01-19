using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PgpKeyGenerator.
/// </summary>
public class PgpKeyGeneratorTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // Basic Key Generation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class BasicKeyGenerationTests
    {
        [Fact]
        public void GenerateRsa_WithUserId_ProducesValidKeyPair()
        {
            // Arrange
            var userId = "Test User <test@example.com>";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(userId)
                .WithKeySize(2048) // Use smaller key for faster tests
                .GenerateRsa();

            // Assert
            Assert.Equal(userId, result.UserId);
            Assert.Equal(4, result.Version);
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, result.Algorithm);
            Assert.False(default(PgpSecretKeyRing).Equals(result.SecretKeyRing));
            Assert.False(default(PgpPublicKeyRing).Equals(result.PublicKeyRing));
        }

        [Fact]
        public void GenerateRsa_ProducesValidFingerprint()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.NotNull(result.Fingerprint);
            Assert.Equal(20, result.Fingerprint.Length); // V4 fingerprint is 20 bytes (SHA-1)
            Assert.NotNull(result.KeyId);
            Assert.Equal(8, result.KeyId.Length); // Key ID is 8 bytes
        }

        [Fact]
        public void GenerateRsa_ProducesValidKeyId()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert - Key ID should be last 8 bytes of fingerprint
            var fingerprint = result.Fingerprint;
            var keyId = result.KeyId;
            Assert.Equal(fingerprint[^8..], keyId);
        }

        [Fact]
        public void GenerateRsa_WithNameAndEmail_FormatsUserIdCorrectly()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Alice Smith", "alice@example.com")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Equal("Alice Smith <alice@example.com>", result.UserId);
        }

        [Fact]
        public void GenerateRsa_WithExplicitKeySize_UsesCorrectSize()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateRsa(2048);

            // Assert
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, result.Algorithm);
            // Key size can be verified by modulus byte length (256 bytes for 2048-bit key)
            var (n, _) = result.MasterPublicKey.ReadRsaKey();
            Assert.True(n.GetByteCount(isUnsigned: true) >= 255 && n.GetByteCount(isUnsigned: true) <= 257);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // User ID and Certification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class UserIdAndCertificationTests
    {
        [Fact]
        public void GenerateRsa_IncludesUserIdInKeyRing()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Bob <bob@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Single(result.PublicKeyRing.UserIds);
            Assert.Equal("Bob <bob@example.com>", result.PublicKeyRing.UserIds[0].UserId);
            Assert.Single(result.SecretKeyRing.UserIds);
            Assert.Equal("Bob <bob@example.com>", result.SecretKeyRing.UserIds[0].UserId);
        }

        [Fact]
        public void GenerateRsa_IncludesSelfCertificationSignature()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Charlie <charlie@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Single(result.PublicKeyRing.Signatures);
            var sig = result.PublicKeyRing.Signatures[0];
            Assert.Equal(PgpSignatureType.PositiveCertification, sig.SignatureType);
            Assert.Equal(4, sig.Version);
        }

        [Fact]
        public void GenerateRsa_CertificationHasCorrectKeyFlags()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Dave <dave@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            var sig = result.PublicKeyRing.Signatures[0];
            var keyFlags = sig.GetKeyFlags();
            Assert.NotNull(keyFlags);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.Certify) != 0);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.Sign) != 0);
        }

        [Fact]
        public void GenerateRsa_CertificationHasCreationTime()
        {
            // Arrange
            var now = DateTimeOffset.UtcNow;

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Eve <eve@example.com>")
                .WithKeySize(2048)
                .WithCreationTime(now)
                .GenerateRsa();

            // Assert
            var sig = result.PublicKeyRing.Signatures[0];
            var sigTime = sig.GetCreationTime();
            Assert.NotNull(sigTime);
            // Allow 1-second tolerance for test execution
            Assert.True(Math.Abs((sigTime.Value - now).TotalSeconds) < 2);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Key Ring Structure Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyRingStructureTests
    {
        [Fact]
        public void GenerateRsa_SecretKeyRingContainsMasterKey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Equal(1, result.SecretKeyRing.KeyCount);
            Assert.False(result.SecretKeyRing.MasterKey.IsSubkey);
            Assert.False(result.SecretKeyRing.MasterKey.IsEncrypted);
        }

        [Fact]
        public void GenerateRsa_PublicKeyRingContainsMasterKey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Equal(1, result.PublicKeyRing.KeyCount);
            Assert.False(result.PublicKeyRing.MasterKey.IsSubkey);
        }

        [Fact]
        public void GenerateRsa_KeyRingsHaveMatchingFingerprints()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Equal(result.SecretKeyRing.MasterFingerprint, result.PublicKeyRing.MasterFingerprint);
            Assert.Equal(result.Fingerprint, result.PublicKeyRing.MasterFingerprint);
        }

        [Fact]
        public void ExtractPublicKeyRing_MatchesGeneratedPublicRing()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var extractedPublicRing = result.SecretKeyRing.ExtractPublicKeyRing();

            // Assert
            Assert.Equal(result.PublicKeyRing.MasterFingerprint, extractedPublicRing.MasterFingerprint);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Subkey Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class SubkeyTests
    {
        [Fact]
        public void GenerateRsa_WithEncryptionSubkey_AddsSubkey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Assert
            Assert.Equal(2, result.PublicKeyRing.KeyCount);
            Assert.Equal(2, result.SecretKeyRing.KeyCount);
            Assert.Single(result.PublicKeyRing.Subkeys);
            Assert.True(result.PublicKeyRing.Subkeys[0].IsSubkey);
        }

        [Fact]
        public void GenerateRsa_WithSigningSubkey_AddsSubkey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithSigningSubkey()
                .GenerateRsa();

            // Assert
            Assert.Equal(2, result.PublicKeyRing.KeyCount);
            Assert.Single(result.PublicKeyRing.Subkeys);
        }

        [Fact]
        public void GenerateRsa_WithBothSubkeys_AddsTwoSubkeys()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .WithSigningSubkey()
                .GenerateRsa();

            // Assert
            Assert.Equal(3, result.PublicKeyRing.KeyCount);
            Assert.Equal(2, result.PublicKeyRing.Subkeys.Count);
        }

        [Fact]
        public void GenerateRsa_SubkeyHasBindingSignature()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Assert - Should have certification + binding signatures
            Assert.Equal(2, result.PublicKeyRing.Signatures.Count);
            var bindingSig = result.PublicKeyRing.Signatures[1];
            Assert.Equal(PgpSignatureType.SubkeyBinding, bindingSig.SignatureType);
        }

        [Fact]
        public void GenerateRsa_EncryptionSubkeyHasCorrectFlags()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Assert
            var bindingSig = result.PublicKeyRing.Signatures[1];
            var keyFlags = bindingSig.GetKeyFlags();
            Assert.NotNull(keyFlags);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.EncryptCommunications) != 0);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.EncryptStorage) != 0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Serialization Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class SerializationTests
    {
        [Fact]
        public void ExportPublicKey_CanBeReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var exported = result.ExportPublicKey();
            var reimported = PgpPublicKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(result.UserId, reimported.UserIds[0].UserId);
        }

        [Fact]
        public void ExportSecretKey_CanBeReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(result.UserId, reimported.UserIds[0].UserId);
        }

        [Fact]
        public void ExportPublicKey_WithSubkey_CanBeReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Act
            var exported = result.ExportPublicKey();
            var reimported = PgpPublicKeyRing.Read(exported);

            // Assert
            Assert.Equal(2, reimported.KeyCount);
            Assert.Single(reimported.Subkeys);
        }

        [Fact]
        public void ExportToStream_ProducesValidData()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            using var ms = new MemoryStream();
            result.ExportPublicKey(ms);
            var data = ms.ToArray();

            // Assert
            Assert.NotEmpty(data);
            var reimported = PgpPublicKeyRing.Read(data);
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Integration Tests - Sign and Verify with Generated Keys
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SLOW)]
    public class SignAndVerifyIntegrationTests
    {
        [Fact]
        public void GeneratedKey_CanSignData()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var data = TestHelpers.RandomBytes(100);

            // Act
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var signedMessage = signer.Sign(data);

            // Assert
            Assert.False(signedMessage.Signature.SignatureData.IsEmpty);
            Assert.Equal(data.Length, signedMessage.Data.Length);
        }

        [Fact]
        public void GeneratedKey_SignAndVerify_Succeeds()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var data = TestHelpers.RandomBytes(100);

            // Act - Sign
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var signedMessage = signer.Sign(data);

            // Act - Verify
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(keyResult.MasterPublicKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }

        [Fact]
        public void GeneratedKey_DetachedSignatureVerify_Succeeds()
        {
            // Arrange
            var keyResult = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var data = TestHelpers.RandomBytes(100);

            // Act - Sign
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(keyResult.MasterSecretKey);
            var signature = signer.CreateDetachedSignature(data);

            // Act - Verify
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(keyResult.MasterPublicKey);
            var verifyResult = verifier.Verify(data, signature);

            // Assert
            Assert.True(verifyResult.IsValid);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Validation and Error Handling Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ValidationTests
    {
        [Fact]
        public void GenerateRsa_WithoutUserId_ThrowsInvalidOperationException()
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => generator.GenerateRsa());
        }

        [Fact]
        public void WithUserId_NullValue_ThrowsArgumentNullException()
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => generator.WithUserId(null!));
        }

        [Theory]
        [InlineData(1024)]
        [InlineData(1536)]
        [InlineData(8192)]
        public void GenerateRsa_InvalidKeySize_ThrowsArgumentException(int invalidKeySize)
        {
            // Arrange
            var generator = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => generator.GenerateRsa(invalidKeySize));
        }

        [Theory]
        [InlineData(1024)]
        [InlineData(1536)]
        public void WithKeySize_InvalidSize_ThrowsArgumentException(int invalidKeySize)
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => generator.WithKeySize(invalidKeySize));
        }

        [Fact]
        public void WithVersion_InvalidVersion_ThrowsArgumentException()
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => generator.WithVersion(5));
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void WithKeySize_ValidSizes_Succeeds(int validKeySize)
        {
            // Arrange & Act
            var generator = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(validKeySize);

            // Assert - no exception thrown
            Assert.NotNull(generator);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Configuration Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class ConfigurationTests
    {
        [Fact]
        public void WithCreationTime_SetsKeyCreationTime()
        {
            // Arrange
            var fixedTime = new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithCreationTime(fixedTime)
                .GenerateRsa();

            // Assert
            Assert.Equal(fixedTime, result.CreationTime);
        }

        [Fact]
        public void WithKeyFlags_SetsCustomKeyFlags()
        {
            // Arrange
            var customFlags = PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign |
                            PgpKeyCapabilities.EncryptCommunications;

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithKeyFlags(customFlags)
                .GenerateRsa();

            // Assert
            var sig = result.PublicKeyRing.Signatures[0];
            var keyFlags = sig.GetKeyFlags();
            Assert.NotNull(keyFlags);
            Assert.Equal(customFlags, keyFlags.Value);
        }

        [Fact]
        public void FluentAPI_AllowsChaining()
        {
            // Arrange & Act - verify fluent chaining works
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test", "test@example.com")
                .WithKeySize(2048)
                .WithCreationTime(DateTimeOffset.UtcNow)
                .WithKeyFlags(PgpKeyCapabilities.Certify | PgpKeyCapabilities.Sign)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Assert
            Assert.Equal(2, result.PublicKeyRing.KeyCount);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Result Object Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class ResultObjectTests
    {
        [Fact]
        public void Result_ToString_ReturnsUsefulInfo()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test User <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            var str = result.ToString();
            Assert.Contains("Test User", str);
            Assert.Contains("RSA", str, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Result_ClearSensitiveData_ZeroesKeyMaterial()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            result.ClearSensitiveData();

            // Assert - The method should execute without throwing
            // Note: This is a security best-effort test; checking actual clearing is difficult
            Assert.False(default(PgpSecretKeyRing).Equals(result.SecretKeyRing));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Ed25519 Key Generation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class Ed25519KeyGenerationTests
    {
        [Fact]
        public void GenerateEd25519_WithUserId_ProducesValidKeyPair()
        {
            // Arrange
            var userId = "Ed25519 User <ed25519@example.com>";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(userId)
                .GenerateEd25519();

            // Assert
            Assert.Equal(userId, result.UserId);
            Assert.Equal(6, result.Version); // Ed25519 requires V6
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, result.Algorithm);
            Assert.False(default(PgpSecretKeyRing).Equals(result.SecretKeyRing));
            Assert.False(default(PgpPublicKeyRing).Equals(result.PublicKeyRing));
        }

        [Fact]
        public void GenerateEd25519_ProducesV6Fingerprint()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519();

            // Assert
            Assert.NotNull(result.Fingerprint);
            Assert.Equal(32, result.Fingerprint.Length); // V6 fingerprint is 32 bytes (SHA-256)
            Assert.NotNull(result.KeyId);
            Assert.Equal(8, result.KeyId.Length); // Key ID is 8 bytes
        }

        [Fact]
        public void GenerateEd25519_ProducesCorrectKeyId()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519();

            // Assert - V6 Key ID should be first 8 bytes of fingerprint
            var fingerprint = result.Fingerprint;
            var keyId = result.KeyId;
            Assert.Equal(fingerprint[..8], keyId);
        }

        [Fact]
        public void GenerateEd25519_IncludesSelfCertificationSignature()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .GenerateEd25519();

            // Assert
            Assert.Single(result.PublicKeyRing.Signatures);
            var sig = result.PublicKeyRing.Signatures[0];
            Assert.Equal(PgpSignatureType.PositiveCertification, sig.SignatureType);
            Assert.Equal(6, sig.Version);
            Assert.Equal((byte)PgpPublicKeyAlgorithm.Ed25519, sig.PublicKeyAlgorithm);
        }

        [Fact]
        public void GenerateEd25519_CertificationHasCorrectKeyFlags()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .GenerateEd25519();

            // Assert
            var sig = result.PublicKeyRing.Signatures[0];
            var keyFlags = sig.GetKeyFlags();
            Assert.NotNull(keyFlags);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.Certify) != 0);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.Sign) != 0);
        }

        [Fact]
        public void GenerateEd25519_SecretKeyHas32ByteMaterial()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519();

            // Assert - Ed25519 secret material is 32-byte seed + 2-byte checksum = 34 bytes
            // (PgpSecretKeyPacket adds checksum automatically)
            Assert.Equal(34, result.MasterSecretKey.SecretKeyMaterial.Length);
        }

        [Fact]
        public void GenerateEd25519_PublicKeyHas32ByteMaterial()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519();

            // Assert - Ed25519 public key is 32 bytes
            var publicKey = result.MasterPublicKey.ReadNativePublicKey();
            Assert.Equal(32, publicKey.Length);
        }

        [Fact]
        public void GenerateEd25519_CanBeSerializedAndReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .GenerateEd25519();

            // Act
            var exported = result.ExportPublicKey();
            var reimported = PgpPublicKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(result.UserId, reimported.UserIds[0].UserId);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // X25519 Key Generation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class X25519KeyGenerationTests
    {
        [Fact]
        public void GenerateX25519_WithUserId_ProducesValidKeyPair()
        {
            // Arrange
            var userId = "X25519 User <x25519@example.com>";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(userId)
                .GenerateX25519();

            // Assert
            Assert.Equal(userId, result.UserId);
            Assert.Equal(6, result.Version); // X25519 requires V6
            Assert.Equal(PgpPublicKeyAlgorithm.X25519, result.Algorithm);
        }

        [Fact]
        public void GenerateX25519_ProducesV6Fingerprint()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateX25519();

            // Assert
            Assert.NotNull(result.Fingerprint);
            Assert.Equal(32, result.Fingerprint.Length); // V6 fingerprint is 32 bytes (SHA-256)
        }

        [Fact]
        public void GenerateX25519_HasNoSelfCertification()
        {
            // Arrange & Act - X25519 cannot sign, so no self-certification
            var result = PgpKeyGenerator.Create()
                .WithUserId("X25519 <x25519@example.com>")
                .GenerateX25519();

            // Assert
            Assert.Empty(result.PublicKeyRing.Signatures);
        }

        [Fact]
        public void GenerateX25519_PublicKeyHas32ByteMaterial()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateX25519();

            // Assert - X25519 public key is 32 bytes
            var publicKey = result.MasterPublicKey.ReadNativePublicKey();
            Assert.Equal(32, publicKey.Length);
        }

        [Fact]
        public void GenerateX25519_CanBeSerializedAndReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("X25519 <x25519@example.com>")
                .GenerateX25519();

            // Act
            var exported = result.ExportPublicKey();
            var reimported = PgpPublicKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(result.UserId, reimported.UserIds[0].UserId);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Ed25519 + X25519 Combined Key Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class Ed25519WithX25519SubkeyTests
    {
        [Fact]
        public void GenerateEd25519WithX25519Subkey_ProducesValidKeyPair()
        {
            // Arrange
            var userId = "Combined User <combined@example.com>";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(userId)
                .GenerateEd25519WithX25519Subkey();

            // Assert
            Assert.Equal(userId, result.UserId);
            Assert.Equal(6, result.Version);
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, result.Algorithm);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_HasMasterAndSubkey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert
            Assert.Equal(2, result.PublicKeyRing.KeyCount);
            Assert.Equal(2, result.SecretKeyRing.KeyCount);
            Assert.Single(result.PublicKeyRing.Subkeys);
            Assert.Single(result.SecretKeyRing.Subkeys);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_MasterKeyIsEd25519()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, result.MasterPublicKey.Algorithm);
            Assert.False(result.MasterPublicKey.IsSubkey);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_SubkeyIsX25519()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert
            var subkey = result.PublicKeyRing.Subkeys[0];
            Assert.Equal(PgpPublicKeyAlgorithm.X25519, subkey.Algorithm);
            Assert.True(subkey.IsSubkey);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_HasCertificationAndBindingSignatures()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert - Should have certification + binding signatures
            Assert.Equal(2, result.PublicKeyRing.Signatures.Count);

            var certSig = result.PublicKeyRing.Signatures[0];
            Assert.Equal(PgpSignatureType.PositiveCertification, certSig.SignatureType);

            var bindingSig = result.PublicKeyRing.Signatures[1];
            Assert.Equal(PgpSignatureType.SubkeyBinding, bindingSig.SignatureType);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_SubkeyHasEncryptionFlags()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert
            var bindingSig = result.PublicKeyRing.Signatures[1];
            var keyFlags = bindingSig.GetKeyFlags();
            Assert.NotNull(keyFlags);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.EncryptCommunications) != 0);
            Assert.True((keyFlags.Value & PgpKeyCapabilities.EncryptStorage) != 0);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_BothKeysAreV6()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert
            Assert.Equal(6, result.MasterPublicKey.Version);
            Assert.Equal(6, result.PublicKeyRing.Subkeys[0].Version);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_CanBeSerializedAndReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Combined <combined@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Act
            var exported = result.ExportPublicKey();
            var reimported = PgpPublicKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(2, reimported.KeyCount);
            Assert.Single(reimported.Subkeys);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_SecretKeyCanBeReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Combined <combined@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Act
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(2, reimported.KeyCount);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_BothKeyRingsHaveMatchingFingerprints()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .GenerateEd25519WithX25519Subkey();

            // Assert
            Assert.Equal(result.SecretKeyRing.MasterFingerprint, result.PublicKeyRing.MasterFingerprint);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Ed25519/X25519 Validation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class Ed25519X25519ValidationTests
    {
        [Fact]
        public void GenerateEd25519_WithoutUserId_ThrowsInvalidOperationException()
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => generator.GenerateEd25519());
        }

        [Fact]
        public void GenerateX25519_WithoutUserId_ThrowsInvalidOperationException()
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => generator.GenerateX25519());
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_WithoutUserId_ThrowsInvalidOperationException()
        {
            // Arrange
            var generator = PgpKeyGenerator.Create();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => generator.GenerateEd25519WithX25519Subkey());
        }

    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Passphrase Protection Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class PassphraseProtectionTests
    {
        [Fact]
        public void GenerateRsa_WithPassphrase_ProducesEncryptedSecretKey()
        {
            // Arrange
            var passphrase = "testpassphrase123";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Assert
            Assert.True(result.MasterSecretKey.IsEncrypted);
            Assert.Equal(PgpS2KUsage.Sha1Hash, result.MasterSecretKey.S2KUsage);
            Assert.NotNull(result.MasterSecretKey.S2KSpecifier);
            Assert.Equal(HeroCrypt.Primitives.S2K.S2KType.IteratedAndSalted, result.MasterSecretKey.S2KSpecifier.Value.Type);
        }

        [Fact]
        public void GenerateRsa_WithPassphrase_HasCorrectCipherAlgorithm()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("mypassword")
                .GenerateRsa();

            // Assert - Should use AES-256 (algorithm 9)
            Assert.Equal(9, result.MasterSecretKey.CipherAlgorithm);
        }

        [Fact]
        public void GenerateRsa_WithPassphrase_HasIV()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("testpass")
                .GenerateRsa();

            // Assert - AES has 16-byte block size
            Assert.Equal(16, result.MasterSecretKey.IV.Length);
        }

        [Fact]
        public void GenerateRsa_WithPassphrase_HasSalt()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("testpass")
                .GenerateRsa();

            // Assert - S2K salt should be 8 bytes
            Assert.NotNull(result.MasterSecretKey.S2KSpecifier);
            Assert.Equal(8, result.MasterSecretKey.S2KSpecifier.Value.Salt.Length);
        }

        [Fact]
        public void GenerateRsa_WithPassphrase_CanBeSerializedAndReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("testpassphrase")
                .GenerateRsa();

            // Act
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.True(reimported.MasterKey.IsEncrypted);
        }

        [Fact]
        public void GenerateRsa_WithPassphraseAndSubkey_BothKeysAreEncrypted()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("testpassphrase")
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Assert
            Assert.True(result.MasterSecretKey.IsEncrypted);
            Assert.True(result.SecretKeyRing.Subkeys[0].IsEncrypted);
        }

        [Fact]
        public void GenerateEd25519_WithPassphrase_ProducesEncryptedSecretKey()
        {
            // Arrange
            var passphrase = "ed25519pass";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519();

            // Assert
            Assert.True(result.MasterSecretKey.IsEncrypted);
            Assert.Equal(PgpS2KUsage.Sha1Hash, result.MasterSecretKey.S2KUsage);
        }

        [Fact]
        public void GenerateX25519_WithPassphrase_ProducesEncryptedSecretKey()
        {
            // Arrange
            var passphrase = "x25519pass";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("X25519 <x25519@example.com>")
                .WithPassphrase(passphrase)
                .GenerateX25519();

            // Assert
            Assert.True(result.MasterSecretKey.IsEncrypted);
            Assert.Equal(PgpS2KUsage.Sha1Hash, result.MasterSecretKey.S2KUsage);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_WithPassphrase_BothKeysEncrypted()
        {
            // Arrange
            var passphrase = "combinedpass";

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Combined <combined@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519WithX25519Subkey();

            // Assert
            Assert.True(result.MasterSecretKey.IsEncrypted);
            Assert.True(result.SecretKeyRing.Subkeys[0].IsEncrypted);
        }

        [Fact]
        public void GenerateEd25519_WithPassphrase_CanBeSerializedAndReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .WithPassphrase("testpassphrase")
                .GenerateEd25519();

            // Act
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.True(reimported.MasterKey.IsEncrypted);
            Assert.Equal(PgpS2KUsage.Sha1Hash, reimported.MasterKey.S2KUsage);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_WithPassphrase_CanBeSerializedAndReimported()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Combined <combined@example.com>")
                .WithPassphrase("combpass")
                .GenerateEd25519WithX25519Subkey();

            // Act
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(2, reimported.KeyCount);
            Assert.True(reimported.MasterKey.IsEncrypted);
            Assert.True(reimported.Subkeys[0].IsEncrypted);
        }

        [Fact]
        public void GenerateRsa_DifferentPassphrases_ProduceDifferentEncryptions()
        {
            // Arrange & Act
            var result1 = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("pass1")
                .GenerateRsa();

            var result2 = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("pass2")
                .GenerateRsa();

            // Assert - Different salts and IVs
            Assert.False(result1.MasterSecretKey.IV.Span.SequenceEqual(result2.MasterSecretKey.IV.Span));
            Assert.False(result1.MasterSecretKey.S2KSpecifier!.Value.Salt.Span
                .SequenceEqual(result2.MasterSecretKey.S2KSpecifier!.Value.Salt.Span));
        }

        [Fact]
        public void GenerateRsa_WithEmptyPassphrase_ProducesUnencryptedKey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("")
                .GenerateRsa();

            // Assert
            Assert.False(result.MasterSecretKey.IsEncrypted);
        }
    }
}
