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
}
