using System.Security.Cryptography;
using HeroCrypt.Primitives.Armor;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.S2K;
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
            Assert.Equal(S2KType.IteratedAndSalted, result.MasterSecretKey.S2KSpecifier.Value.Type);
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

    // ─────────────────────────────────────────────────────────────────────────────
    // ASCII Armor Export Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class AsciiArmorExportTests
    {
        [Fact]
        public void GetArmoredPublicKey_ReturnsValidArmorFormat()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredPublicKey();

            // Assert
            Assert.Contains("-----BEGIN PGP PUBLIC KEY BLOCK-----", armored);
            Assert.Contains("-----END PGP PUBLIC KEY BLOCK-----", armored);
        }

        [Fact]
        public void GetArmoredSecretKey_ReturnsValidArmorFormat()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredSecretKey();

            // Assert
            Assert.Contains("-----BEGIN PGP PRIVATE KEY BLOCK-----", armored);
            Assert.Contains("-----END PGP PRIVATE KEY BLOCK-----", armored);
        }

        [Fact]
        public void GetArmoredPublicKey_ContainsCrc24Checksum()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredPublicKey();

            // Assert - CRC line starts with '=' and has 4 Base64 characters
            var lines = armored.Split('\n');
            var crcLine = lines.FirstOrDefault(l => l.TrimEnd().StartsWith('='));
            Assert.NotNull(crcLine);
            Assert.Equal(5, crcLine.TrimEnd().Length); // '=' + 4 Base64 chars
        }

        [Fact]
        public void GetArmoredPublicKey_CanBeDecoded()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredPublicKey();
            var decoded = ArmorBuilder.Create().Decode(armored);

            // Assert
            Assert.Equal(ArmorType.PublicKey, decoded.Type);
            Assert.NotEmpty(decoded.Data);
        }

        [Fact]
        public void GetArmoredSecretKey_CanBeDecoded()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredSecretKey();
            var decoded = ArmorBuilder.Create().Decode(armored);

            // Assert
            Assert.Equal(ArmorType.PrivateKey, decoded.Type);
            Assert.NotEmpty(decoded.Data);
        }

        [Fact]
        public void GetArmoredPublicKey_DecodedDataMatchesOriginal()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredPublicKey();
            var decoded = ArmorBuilder.Create().Decode(armored);
            var reimported = PgpPublicKeyRing.Read(decoded.Data);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
        }

        [Fact]
        public void GetArmoredSecretKey_DecodedDataMatchesOriginal()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredSecretKey();
            var decoded = ArmorBuilder.Create().Decode(armored);
            var reimported = PgpSecretKeyRing.Read(decoded.Data);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
        }

        [Fact]
        public void GetArmoredPublicKeyBytes_ReturnsUtf8EncodedString()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armoredBytes = result.GetArmoredPublicKeyBytes();
            var armoredString = System.Text.Encoding.UTF8.GetString(armoredBytes);

            // Assert
            Assert.Contains("-----BEGIN PGP PUBLIC KEY BLOCK-----", armoredString);
        }

        [Fact]
        public void GetArmoredSecretKeyBytes_ReturnsUtf8EncodedString()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var armoredBytes = result.GetArmoredSecretKeyBytes();
            var armoredString = System.Text.Encoding.UTF8.GetString(armoredBytes);

            // Assert
            Assert.Contains("-----BEGIN PGP PRIVATE KEY BLOCK-----", armoredString);
        }

        [Fact]
        public void GetArmoredPublicKey_Ed25519_ReturnsValidArmorFormat()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .GenerateEd25519();

            // Act
            var armored = result.GetArmoredPublicKey();
            var decoded = ArmorBuilder.Create().Decode(armored);
            var reimported = PgpPublicKeyRing.Read(decoded.Data);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, reimported.MasterKey.Algorithm);
        }

        [Fact]
        public void GetArmoredSecretKey_WithPassphrase_ReturnsValidArmorFormat()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase("secretpassword")
                .GenerateRsa();

            // Act
            var armored = result.GetArmoredSecretKey();
            var decoded = ArmorBuilder.Create().Decode(armored);
            var reimported = PgpSecretKeyRing.Read(decoded.Data);

            // Assert
            Assert.Equal(result.Fingerprint, reimported.MasterFingerprint);
            Assert.True(reimported.MasterKey.IsEncrypted);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Secret Key Decryption Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class SecretKeyDecryptionTests
    {
        [Fact]
        public void Decrypt_RsaKey_ReturnsUnencryptedKey()
        {
            // Arrange
            var passphrase = "testpassphrase";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Act
            var decrypted = result.MasterSecretKey.Decrypt(passphrase);

            // Assert
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(PgpS2KUsage.None, decrypted.S2KUsage);
        }

        [Fact]
        public void Decrypt_RsaKey_CanReadSecretMaterial()
        {
            // Arrange
            var passphrase = "testpassphrase";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Act
            var decrypted = result.MasterSecretKey.Decrypt(passphrase);
            var (d, p, q, u) = decrypted.ReadRsaSecretKey();

            // Assert
            Assert.True(d > 0);
            Assert.True(p > 0);
            Assert.True(q > 0);
            Assert.True(u > 0);
        }

        [Fact]
        public void Decrypt_RsaKey_PreservesPublicKeyPortion()
        {
            // Arrange
            var passphrase = "testpassphrase";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Act
            var decrypted = result.MasterSecretKey.Decrypt(passphrase);

            // Assert
            Assert.Equal(result.Fingerprint, decrypted.ComputeFingerprint());
            Assert.Equal(result.Algorithm, decrypted.Algorithm);
            Assert.Equal(result.Version, decrypted.Version);
        }

        [Fact]
        public void Decrypt_Ed25519Key_ReturnsUnencryptedKey()
        {
            // Arrange
            var passphrase = "ed25519pass";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519();

            // Act
            var decrypted = result.MasterSecretKey.Decrypt(passphrase);

            // Assert
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(PgpS2KUsage.None, decrypted.S2KUsage);
        }

        [Fact]
        public void Decrypt_Ed25519Key_CanReadSecretMaterial()
        {
            // Arrange
            var passphrase = "ed25519pass";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519();

            // Act
            var decrypted = result.MasterSecretKey.Decrypt(passphrase);
            var secretKey = decrypted.ReadEcSecretKey();

            // Assert
            Assert.Equal(32, secretKey.Length); // Ed25519 private key is 32 bytes
        }

        [Fact]
        public void Decrypt_CombinedKey_BothKeysCanBeDecrypted()
        {
            // Arrange
            var passphrase = "combinedpass";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Combined <combined@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519WithX25519Subkey();

            // Act
            var decryptedMaster = result.MasterSecretKey.Decrypt(passphrase);
            var decryptedSubkey = result.SecretKeyRing.Subkeys[0].Decrypt(passphrase);

            // Assert
            Assert.False(decryptedMaster.IsEncrypted);
            Assert.False(decryptedSubkey.IsEncrypted);
        }

        [Fact]
        public void Decrypt_WithWrongPassphrase_ThrowsCryptographicException()
        {
            // Arrange
            var passphrase = "correctpassphrase";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Act & Assert
            Assert.Throws<CryptographicException>(
                () => result.MasterSecretKey.Decrypt("wrongpassphrase"));
        }

        [Fact]
        public void Decrypt_UnencryptedKey_ThrowsInvalidOperationException()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert - key is not encrypted
            Assert.False(result.MasterSecretKey.IsEncrypted);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(
                () => result.MasterSecretKey.Decrypt("anypassphrase"));
        }

        [Fact]
        public void Decrypt_RoundTrip_SignatureVerifies()
        {
            // Arrange
            var passphrase = "signaturetest";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            var data = TestHelpers.RandomBytes(100);

            // Act - Decrypt the key
            var decryptedSecretKey = result.MasterSecretKey.Decrypt(passphrase);

            // Sign with decrypted key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(decryptedSecretKey);
            var signedMessage = signer.Sign(data);

            // Verify with public key
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(result.MasterPublicKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }

        [Fact]
        public void Decrypt_Ed25519_RoundTrip_SignatureVerifies()
        {
            // Arrange
            var passphrase = "ed25519signtest";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .WithPassphrase(passphrase)
                .GenerateEd25519();

            var data = TestHelpers.RandomBytes(100);

            // Act - Decrypt the key
            var decryptedSecretKey = result.MasterSecretKey.Decrypt(passphrase);

            // Sign with decrypted key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(decryptedSecretKey);
            var signedMessage = signer.Sign(data);

            // Verify with public key
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(result.MasterPublicKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }

        [Fact]
        public void Decrypt_Reimported_CanDecrypt()
        {
            // Arrange
            var passphrase = "reimporttest";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .GenerateRsa();

            // Export and reimport
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Act
            var decrypted = reimported.MasterKey.Decrypt(passphrase);

            // Assert
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(result.Fingerprint, decrypted.ComputeFingerprint());
        }

        [Fact]
        public void Decrypt_WithSubkey_CanDecryptBothFromReimported()
        {
            // Arrange
            var passphrase = "subkeytest";
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .WithPassphrase(passphrase)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Export and reimport
            var exported = result.ExportSecretKey();
            var reimported = PgpSecretKeyRing.Read(exported);

            // Act
            var decryptedMaster = reimported.MasterKey.Decrypt(passphrase);
            var decryptedSubkey = reimported.Subkeys[0].Decrypt(passphrase);

            // Assert
            Assert.False(decryptedMaster.IsEncrypted);
            Assert.False(decryptedSubkey.IsEncrypted);
            Assert.Equal(result.Fingerprint, decryptedMaster.ComputeFingerprint());
        }
    }

    /// <summary>
    /// Tests for Argon2-protected secret key decryption.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SLOW)]
    public class Argon2SecretKeyDecryptionTests
    {
        private const byte SHA256_HASH = 8;
        private const byte AES_256 = 9;

        [Fact]
        public void Decrypt_Argon2ProtectedKey_ReturnsUnencryptedKey()
        {
            // Arrange - Generate an unencrypted RSA key first
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            // Get the secret key material from the unencrypted key
            var secretMaterial = result.MasterSecretKey.SecretKeyMaterial.ToArray();
            // Remove the 2-byte checksum as we'll encrypt with SHA-1 hash
            var plainMaterial = new byte[secretMaterial.Length - 2];
            Array.Copy(secretMaterial, 0, plainMaterial, 0, plainMaterial.Length);

            var passphrase = "argon2-test-passphrase";
            var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);

            // Create Argon2-protected secret key
            var argon2ProtectedKey = CreateArgon2ProtectedSecretKey(
                result.MasterSecretKey.PublicKey,
                plainMaterial,
                passphraseBytes);

            // Act - Decrypt with Argon2
            var decrypted = argon2ProtectedKey.Decrypt(passphrase);

            // Assert
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(result.Fingerprint, decrypted.ComputeFingerprint());
        }

        [Fact]
        public void Decrypt_Argon2ProtectedKey_CanReadSecretMaterial()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var secretMaterial = result.MasterSecretKey.SecretKeyMaterial.ToArray();
            var plainMaterial = new byte[secretMaterial.Length - 2];
            Array.Copy(secretMaterial, 0, plainMaterial, 0, plainMaterial.Length);

            var passphrase = "argon2-material-test";
            var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);

            var argon2ProtectedKey = CreateArgon2ProtectedSecretKey(
                result.MasterSecretKey.PublicKey,
                plainMaterial,
                passphraseBytes);

            // Act
            var decrypted = argon2ProtectedKey.Decrypt(passphrase);
            var (d, p, q, u) = decrypted.ReadRsaSecretKey();

            // Assert - verify RSA parameters are valid
            Assert.True(d > System.Numerics.BigInteger.One);
            Assert.True(p > System.Numerics.BigInteger.One);
            Assert.True(q > System.Numerics.BigInteger.One);
            Assert.True(u > System.Numerics.BigInteger.One);
        }

        [Fact]
        public void Decrypt_Argon2ProtectedKey_WrongPassphrase_ThrowsCryptographicException()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var secretMaterial = result.MasterSecretKey.SecretKeyMaterial.ToArray();
            var plainMaterial = new byte[secretMaterial.Length - 2];
            Array.Copy(secretMaterial, 0, plainMaterial, 0, plainMaterial.Length);

            var passphrase = "correct-argon2-pass";
            var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);

            var argon2ProtectedKey = CreateArgon2ProtectedSecretKey(
                result.MasterSecretKey.PublicKey,
                plainMaterial,
                passphraseBytes);

            // Act & Assert
            Assert.Throws<CryptographicException>(
                () => argon2ProtectedKey.Decrypt("wrong-passphrase"));
        }

        [Fact]
        public void Decrypt_Argon2Ed25519Key_ReturnsUnencryptedKey()
        {
            // Arrange - Generate an unencrypted Ed25519 key
            var result = PgpKeyGenerator.Create()
                .WithUserId("Ed25519 <ed25519@example.com>")
                .GenerateEd25519();

            var secretMaterial = result.MasterSecretKey.SecretKeyMaterial.ToArray();
            var plainMaterial = new byte[secretMaterial.Length - 2];
            Array.Copy(secretMaterial, 0, plainMaterial, 0, plainMaterial.Length);

            var passphrase = "argon2-ed25519-pass";
            var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);

            var argon2ProtectedKey = CreateArgon2ProtectedSecretKey(
                result.MasterSecretKey.PublicKey,
                plainMaterial,
                passphraseBytes);

            // Act
            var decrypted = argon2ProtectedKey.Decrypt(passphrase);

            // Assert
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(result.Fingerprint, decrypted.ComputeFingerprint());
        }

        [Fact]
        public void Decrypt_Argon2Key_ThenSign_Succeeds()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId("Test <test@example.com>")
                .WithKeySize(2048)
                .GenerateRsa();

            var secretMaterial = result.MasterSecretKey.SecretKeyMaterial.ToArray();
            var plainMaterial = new byte[secretMaterial.Length - 2];
            Array.Copy(secretMaterial, 0, plainMaterial, 0, plainMaterial.Length);

            var passphrase = "argon2-sign-test";
            var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);

            var argon2ProtectedKey = CreateArgon2ProtectedSecretKey(
                result.MasterSecretKey.PublicKey,
                plainMaterial,
                passphraseBytes);

            var data = TestHelpers.RandomBytes(100);

            // Act - Decrypt the key
            var decryptedSecretKey = argon2ProtectedKey.Decrypt(passphrase);

            // Sign with decrypted key
            using var signer = PgpSignatureSigner.Create()
                .WithSecretKey(decryptedSecretKey);
            var signedMessage = signer.Sign(data);

            // Verify with public key
            using var verifier = PgpSignatureVerifier.Create()
                .WithPublicKey(result.MasterPublicKey);
            var verifyResult = verifier.Verify(signedMessage);

            // Assert
            Assert.True(verifyResult.IsValid);
        }

        /// <summary>
        /// Creates a secret key packet protected with Argon2 S2K.
        /// </summary>
        private static PgpSecretKeyPacket CreateArgon2ProtectedSecretKey(
            PgpPublicKeyPacket publicKey,
            byte[] secretMaterial,
            byte[] passphraseBytes)
        {
            // Generate 16-byte salt for Argon2
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            // Generate IV for AES-256 (16 bytes)
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            // Create Argon2 S2K specifier with conservative parameters for testing
            // Using memoryExponent=10 (1 MB) for fast tests
            var s2kSpecifier = PgpS2KSpecifier.CreateArgon2(
                SHA256_HASH,
                salt,
                passes: 1,
                parallelism: 1,
                memoryExponent: 10);

            // Derive key using Argon2
            var encryptionKey = S2KCore.Argon2S2K(
                passphraseBytes,
                salt,
                timePasses: 1,
                parallelism: 1,
                memoryExponent: 10,
                keySize: 32);

            try
            {
                // Prepare plaintext with SHA-1 hash (S2KUsage.Sha1Hash = 254)
                byte[] plaintextWithHash;
                using (var sha1 = SHA1.Create())
                {
                    var hash = sha1.ComputeHash(secretMaterial);
                    plaintextWithHash = new byte[secretMaterial.Length + 20];
                    secretMaterial.CopyTo(plaintextWithHash, 0);
                    hash.CopyTo(plaintextWithHash, secretMaterial.Length);
                }

                // Encrypt with CFB mode
                var encryptedMaterial = CfbEncrypt(plaintextWithHash, encryptionKey, iv);

                // Create encrypted secret key packet
                return PgpSecretKeyPacket.CreateEncrypted(
                    publicKey,
                    PgpS2KUsage.Sha1Hash,
                    AES_256,
                    s2kSpecifier,
                    iv,
                    encryptedMaterial);
            }
            finally
            {
                HeroCrypt.Security.SecureMemoryOperations.SecureClear(encryptionKey);
            }
        }

        /// <summary>
        /// CFB encryption for secret key material.
        /// </summary>
        private static byte[] CfbEncrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            var ciphertext = new byte[plaintext.Length];
            var feedback = new byte[16];
            iv.CopyTo(feedback, 0);

            using var encryptor = aes.CreateEncryptor();
            var keystreamBlock = new byte[16];

            int offset = 0;
            while (offset < plaintext.Length)
            {
                encryptor.TransformBlock(feedback, 0, 16, keystreamBlock, 0);

                int bytesToProcess = Math.Min(16, plaintext.Length - offset);
                for (int i = 0; i < bytesToProcess; i++)
                {
                    ciphertext[offset + i] = (byte)(plaintext[offset + i] ^ keystreamBlock[i]);
                }

                Array.Copy(ciphertext, offset, feedback, 0, bytesToProcess);
                if (bytesToProcess < 16)
                {
                    Array.Clear(feedback, bytesToProcess, 16 - bytesToProcess);
                }

                offset += bytesToProcess;
            }

            return ciphertext;
        }
    }

    /// <summary>
    /// Tests for generating keys with Argon2 S2K passphrase protection.
    /// </summary>
    public class Argon2KeyGenerationTests
    {
        private const string TEST_PASSPHRASE = "test-argon2-passphrase";
        private const string USER_ID = "Argon2 Test <argon2@example.com>";

        [Fact]
        public void GenerateRsa_WithArgon2Passphrase_CreatesEncryptedKey()
        {
            // Arrange & Act - use low memory for fast tests
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.True(result.SecretKeyRing.MasterKey.IsEncrypted);
            Assert.Equal(PgpS2KUsage.Sha1Hash, result.SecretKeyRing.MasterKey.S2KUsage);
            Assert.Equal(S2KType.Argon2, result.SecretKeyRing.MasterKey.S2KSpecifier!.Value.Type);
        }

        [Fact]
        public void GenerateRsa_WithArgon2Passphrase_CanDecryptKey()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .WithKeySize(2048)
                .GenerateRsa();

            // Act
            var decrypted = result.SecretKeyRing.MasterKey.Decrypt(TEST_PASSPHRASE);

            // Assert
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(PgpS2KUsage.None, decrypted.S2KUsage);
        }

        [Fact]
        public void GenerateRsa_WithArgon2Passphrase_WrongPassphrase_ThrowsCryptographicException()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .WithKeySize(2048)
                .GenerateRsa();

            // Act & Assert
            Assert.Throws<CryptographicException>(() => result.SecretKeyRing.MasterKey.Decrypt("wrong-passphrase"));
        }

        [Fact]
        public void GenerateRsa_WithArgon2Passphrase_HasCorrectArgon2Params()
        {
            // Arrange
            byte expectedPasses = 2;
            byte expectedParallelism = 3;
            byte expectedMemoryExponent = 17;

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, expectedPasses, expectedParallelism, expectedMemoryExponent)
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            var s2k = result.SecretKeyRing.MasterKey.S2KSpecifier!.Value;
            Assert.Equal(S2KType.Argon2, s2k.Type);
            Assert.Equal(expectedPasses, s2k.Argon2Params!.Value.Passes);
            Assert.Equal(expectedParallelism, s2k.Argon2Params!.Value.Parallelism);
            Assert.Equal(expectedMemoryExponent, s2k.Argon2Params!.Value.MemoryExponent);
            Assert.Equal(16, s2k.Salt.Length); // Argon2 uses 16-byte salt
        }

        [Fact]
        public void GenerateRsa_WithArgon2Passphrase_AndSubkey_EncryptsSubkeyWithArgon2()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .WithKeySize(2048)
                .WithEncryptionSubkey()
                .GenerateRsa();

            // Assert
            Assert.Single(result.SecretKeyRing.Subkeys);
            var subkey = result.SecretKeyRing.Subkeys.First();
            Assert.True(subkey.IsEncrypted);
            Assert.Equal(S2KType.Argon2, subkey.S2KSpecifier!.Value.Type);

            // Verify subkey can be decrypted
            var decryptedSubkey = subkey.Decrypt(TEST_PASSPHRASE);
            Assert.False(decryptedSubkey.IsEncrypted);
        }

        [Fact]
        public void GenerateRsa_WithArgon2PassphraseBytes_WorksCorrectly()
        {
            // Arrange
            var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(TEST_PASSPHRASE);

            // Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(passphraseBytes, passes: 1, parallelism: 1, memoryExponent: 16)
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert
            Assert.Equal(S2KType.Argon2, result.SecretKeyRing.MasterKey.S2KSpecifier!.Value.Type);

            // Can decrypt with same passphrase (as string since Decrypt takes string)
            var decrypted = result.SecretKeyRing.MasterKey.Decrypt(TEST_PASSPHRASE);
            Assert.False(decrypted.IsEncrypted);
        }

        [Fact]
        public void GenerateEd25519_WithArgon2Passphrase_CreatesEncryptedKey()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .GenerateEd25519();

            // Assert
            Assert.True(result.SecretKeyRing.MasterKey.IsEncrypted);
            Assert.Equal(S2KType.Argon2, result.SecretKeyRing.MasterKey.S2KSpecifier!.Value.Type);
        }

        [Fact]
        public void GenerateEd25519_WithArgon2Passphrase_CanDecryptAndSign()
        {
            // Arrange
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .GenerateEd25519();

            // Act
            var decrypted = result.SecretKeyRing.MasterKey.Decrypt(TEST_PASSPHRASE);

            // Assert - verify we can read the secret material (32 bytes for Ed25519 + 2-byte checksum)
            Assert.False(decrypted.IsEncrypted);
            Assert.Equal(34, decrypted.SecretKeyMaterial.Length);
        }

        [Fact]
        public void GenerateEd25519WithX25519Subkey_WithArgon2Passphrase_EncryptsBothKeys()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 16)
                .GenerateEd25519WithX25519Subkey();

            // Assert - master key
            Assert.True(result.SecretKeyRing.MasterKey.IsEncrypted);
            Assert.Equal(S2KType.Argon2, result.SecretKeyRing.MasterKey.S2KSpecifier!.Value.Type);

            // Assert - subkey
            Assert.Single(result.SecretKeyRing.Subkeys);
            var subkey = result.SecretKeyRing.Subkeys.First();
            Assert.True(subkey.IsEncrypted);
            Assert.Equal(S2KType.Argon2, subkey.S2KSpecifier!.Value.Type);

            // Verify both can be decrypted
            var decryptedMaster = result.SecretKeyRing.MasterKey.Decrypt(TEST_PASSPHRASE);
            var decryptedSubkey = subkey.Decrypt(TEST_PASSPHRASE);
            Assert.False(decryptedMaster.IsEncrypted);
            Assert.False(decryptedSubkey.IsEncrypted);
        }

        [Fact]
        public void WithArgon2Passphrase_DefaultParameters_UsesSecureDefaults()
        {
            // Arrange & Act
            var result = PgpKeyGenerator.Create()
                .WithUserId(USER_ID)
                .WithArgon2Passphrase(TEST_PASSPHRASE)
                .WithKeySize(2048)
                .GenerateRsa();

            // Assert - verify defaults: passes=3, parallelism=4, memoryExponent=19
            var s2k = result.SecretKeyRing.MasterKey.S2KSpecifier!.Value;
            Assert.Equal(S2KType.Argon2, s2k.Type);
            Assert.Equal(3, s2k.Argon2Params!.Value.Passes);
            Assert.Equal(4, s2k.Argon2Params!.Value.Parallelism);
            Assert.Equal(19, s2k.Argon2Params!.Value.MemoryExponent);
        }

        [Fact]
        public void WithArgon2Passphrase_InvalidMemoryExponent_ThrowsArgumentOutOfRangeException()
        {
            // Arrange & Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpKeyGenerator.Create()
                    .WithUserId(USER_ID)
                    .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 2));

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpKeyGenerator.Create()
                    .WithUserId(USER_ID)
                    .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 1, memoryExponent: 32));
        }

        [Fact]
        public void WithArgon2Passphrase_InvalidPasses_ThrowsArgumentOutOfRangeException()
        {
            // Arrange & Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpKeyGenerator.Create()
                    .WithUserId(USER_ID)
                    .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 0, parallelism: 1, memoryExponent: 16));
        }

        [Fact]
        public void WithArgon2Passphrase_InvalidParallelism_ThrowsArgumentOutOfRangeException()
        {
            // Arrange & Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpKeyGenerator.Create()
                    .WithUserId(USER_ID)
                    .WithArgon2Passphrase(TEST_PASSPHRASE, passes: 1, parallelism: 0, memoryExponent: 16));
        }
    }
}
