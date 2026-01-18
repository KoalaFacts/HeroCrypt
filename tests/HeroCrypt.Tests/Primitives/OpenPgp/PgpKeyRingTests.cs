using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Key Ring classes per RFC 4880 Section 11.
/// </summary>
public class PgpKeyRingTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyRing Factory Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyRingFactoryTests
    {
        [Fact]
        public void Constructor_WithValidMasterKey_CreateKeyRing()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);

            var keyRing = new PgpPublicKeyRing(masterKey);

            Assert.Equal(masterKey.Algorithm, keyRing.MasterKey.Algorithm);
            Assert.Equal(1, keyRing.KeyCount);
            Assert.Empty(keyRing.Subkeys);
            Assert.Empty(keyRing.UserIds);
        }

        [Fact]
        public void Constructor_WithSubkeyAsMaster_ThrowsException()
        {
            var subkey = CreateTestPublicKey(isSubkey: true);

            Assert.Throws<ArgumentException>(() => new PgpPublicKeyRing(subkey));
        }

        [Fact]
        public void Create_WithUserIds_IncludesUserIds()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var userIds = new[] { new PgpUserIdPacket("Test User <test@example.com>") };

            var keyRing = PgpPublicKeyRing.Create(masterKey, userIds);

            Assert.Single(keyRing.UserIds);
            Assert.Equal("Test User <test@example.com>", keyRing.UserIds[0].UserId);
        }

        [Fact]
        public void MasterKeyId_ReturnsCorrectKeyId()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);

            var keyRing = new PgpPublicKeyRing(masterKey);

            Assert.Equal(masterKey.GetKeyId(), keyRing.MasterKeyId);
        }

        [Fact]
        public void MasterFingerprint_ReturnsCorrectFingerprint()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);

            var keyRing = new PgpPublicKeyRing(masterKey);

            Assert.Equal(masterKey.ComputeFingerprint(), keyRing.MasterFingerprint);
        }

        [Fact]
        public void KeyCount_ReturnsOnePluSubkeys()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var subkey = CreateTestPublicKey(isSubkey: true);

            var keyRing = new PgpPublicKeyRing(masterKey, [subkey]);

            Assert.Equal(2, keyRing.KeyCount);
        }

        private static PgpPublicKeyPacket CreateTestPublicKey(bool isSubkey)
        {
            return PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: isSubkey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyRing Lookup Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyRingLookupTests
    {
        [Fact]
        public void GetPublicKey_ByMasterKeyId_ReturnsMasterKey()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var keyId = masterKey.GetKeyId();

            var result = keyRing.GetPublicKey(keyId);

            Assert.NotNull(result);
            Assert.Equal(masterKey.Algorithm, result.Value.Algorithm);
        }

        [Fact]
        public void GetPublicKey_BySubkeyId_ReturnsSubkey()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var subkey = CreateTestPublicKey(isSubkey: true);
            var keyRing = new PgpPublicKeyRing(masterKey, [subkey]);
            var subkeyId = subkey.GetKeyId();

            var result = keyRing.GetPublicKey(subkeyId);

            Assert.NotNull(result);
            Assert.True(result.Value.IsSubkey);
        }

        [Fact]
        public void GetPublicKey_WithNonExistentId_ReturnsNull()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var fakeKeyId = new byte[8];

            var result = keyRing.GetPublicKey(fakeKeyId);

            Assert.Null(result);
        }

        [Fact]
        public void GetPublicKeyByFingerprint_ByMasterFingerprint_ReturnsMasterKey()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var fingerprint = masterKey.ComputeFingerprint();

            var result = keyRing.GetPublicKeyByFingerprint(fingerprint);

            Assert.NotNull(result);
        }

        [Fact]
        public void ContainsKey_WithExistingKey_ReturnsTrue()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var keyId = masterKey.GetKeyId();

            Assert.True(keyRing.ContainsKey(keyId));
        }

        [Fact]
        public void ContainsKey_WithNonExistingKey_ReturnsFalse()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var fakeKeyId = new byte[8];

            Assert.False(keyRing.ContainsKey(fakeKeyId));
        }

        [Fact]
        public void GetPrimaryUserId_WhenNoUserIds_ReturnsNull()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);

            Assert.Null(keyRing.GetPrimaryUserId());
        }

        [Fact]
        public void GetPrimaryUserId_WithUserIds_ReturnsFirst()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var userIds = new[] { new PgpUserIdPacket("First User"), new PgpUserIdPacket("Second User") };
            var keyRing = new PgpPublicKeyRing(masterKey, userIds: userIds);

            var primary = keyRing.GetPrimaryUserId();

            Assert.NotNull(primary);
            Assert.Equal("First User", primary.Value.UserId);
        }

        private static PgpPublicKeyPacket CreateTestPublicKey(bool isSubkey)
        {
            return PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: isSubkey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyRing Modification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyRingModificationTests
    {
        [Fact]
        public void AddUserId_ReturnsNewInstanceWithUserId()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var userId = new PgpUserIdPacket("New User");

            var newKeyRing = keyRing.AddUserId(userId);

            Assert.Empty(keyRing.UserIds);
            Assert.Single(newKeyRing.UserIds);
            Assert.Equal("New User", newKeyRing.UserIds[0].UserId);
        }

        [Fact]
        public void RemoveSubkey_ReturnsNewInstanceWithoutSubkey()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var subkey = CreateTestPublicKey(isSubkey: true);
            var keyRing = new PgpPublicKeyRing(masterKey, [subkey]);
            var subkeyId = subkey.GetKeyId();

            var newKeyRing = keyRing.RemoveSubkey(subkeyId);

            Assert.Single(keyRing.Subkeys);
            Assert.Empty(newKeyRing.Subkeys);
        }

        [Fact]
        public void RemoveSubkey_WithNonExistingKey_ReturnsSameInstance()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);
            var fakeKeyId = new byte[8];

            var newKeyRing = keyRing.RemoveSubkey(fakeKeyId);

            Assert.Equal(keyRing, newKeyRing);
        }

        private static PgpPublicKeyPacket CreateTestPublicKey(bool isSubkey)
        {
            return PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: isSubkey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyRing Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyRingSerializationTests
    {
        [Fact]
        public void ToArray_ProducesValidBytes()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);

            var bytes = keyRing.ToArray();

            Assert.NotEmpty(bytes);
        }

        [Fact]
        public void GetEncodedLength_ReturnsPositiveValue()
        {
            var masterKey = CreateTestPublicKey(isSubkey: false);
            var keyRing = new PgpPublicKeyRing(masterKey);

            var length = keyRing.GetEncodedLength();

            Assert.True(length > 0);
        }

        private static PgpPublicKeyPacket CreateTestPublicKey(bool isSubkey)
        {
            return PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: isSubkey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyRingCollection Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyRingCollectionTests
    {
        [Fact]
        public void Empty_ReturnsEmptyCollection()
        {
            var collection = PgpPublicKeyRingCollection.Empty;

            Assert.Equal(0, collection.Count);
            Assert.Empty(collection.KeyRings);
        }

        [Fact]
        public void Constructor_WithSingleKeyRing_CreatesCollection()
        {
            var keyRing = CreateTestKeyRing();

            var collection = new PgpPublicKeyRingCollection(keyRing);

            Assert.Single(collection.KeyRings);
        }

        [Fact]
        public void Constructor_WithMultipleKeyRings_CreatesCollection()
        {
            var keyRing1 = CreateTestKeyRing();
            var keyRing2 = CreateTestKeyRing();

            var collection = new PgpPublicKeyRingCollection([keyRing1, keyRing2]);

            Assert.Equal(2, collection.Count);
        }

        [Fact]
        public void GetKeyRing_ByKeyId_ReturnsKeyRing()
        {
            var keyRing = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection(keyRing);
            var keyId = keyRing.MasterKeyId;

            var result = collection.GetKeyRing(keyId);

            Assert.NotNull(result);
        }

        [Fact]
        public void GetKeyRing_WithNonExistentKeyId_ReturnsNull()
        {
            var keyRing = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection(keyRing);
            var fakeKeyId = new byte[8];

            var result = collection.GetKeyRing(fakeKeyId);

            Assert.Null(result);
        }

        [Fact]
        public void GetPublicKey_SearchesAcrossKeyRings()
        {
            var keyRing1 = CreateTestKeyRing();
            var keyRing2 = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection([keyRing1, keyRing2]);
            var keyId = keyRing2.MasterKeyId;

            var result = collection.GetPublicKey(keyId);

            Assert.NotNull(result);
        }

        [Fact]
        public void ContainsKey_WithExistingKey_ReturnsTrue()
        {
            var keyRing = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection(keyRing);
            var keyId = keyRing.MasterKeyId;

            Assert.True(collection.ContainsKey(keyId));
        }

        [Fact]
        public void Add_ReturnsNewCollectionWithKeyRing()
        {
            var keyRing1 = CreateTestKeyRing();
            var keyRing2 = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection(keyRing1);

            var newCollection = collection.Add(keyRing2);

            Assert.Single(collection.KeyRings);
            Assert.Equal(2, newCollection.Count);
        }

        [Fact]
        public void Remove_ReturnsNewCollectionWithoutKeyRing()
        {
            var keyRing1 = CreateTestKeyRing();
            var keyRing2 = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection([keyRing1, keyRing2]);

            var newCollection = collection.Remove(keyRing1.MasterKeyId);

            Assert.Equal(2, collection.Count);
            Assert.Single(newCollection.KeyRings);
        }

        [Fact]
        public void GetKeyRingsByUserId_MatchesSubstring()
        {
            var keyRing = CreateTestKeyRingWithUserId("Test User <test@example.com>");
            var collection = new PgpPublicKeyRingCollection(keyRing);

            var results = collection.GetKeyRingsByUserId("test@example.com").ToList();

            Assert.Single(results);
        }

        [Fact]
        public void GetKeyRingsByUserId_CaseInsensitive()
        {
            var keyRing = CreateTestKeyRingWithUserId("Test User <test@example.com>");
            var collection = new PgpPublicKeyRingCollection(keyRing);

            var results = collection.GetKeyRingsByUserId("TEST@EXAMPLE.COM").ToList();

            Assert.Single(results);
        }

        [Fact]
        public void Enumeration_IteratesAllKeyRings()
        {
            var keyRing1 = CreateTestKeyRing();
            var keyRing2 = CreateTestKeyRing();
            var collection = new PgpPublicKeyRingCollection([keyRing1, keyRing2]);

            var count = 0;
            foreach (var _ in collection)
            {
                count++;
            }

            Assert.Equal(2, count);
        }

        private static PgpPublicKeyRing CreateTestKeyRing()
        {
            var masterKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: false);

            return new PgpPublicKeyRing(masterKey);
        }

        private static PgpPublicKeyRing CreateTestKeyRingWithUserId(string userId)
        {
            var masterKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: false);

            return new PgpPublicKeyRing(masterKey, userIds: [new PgpUserIdPacket(userId)]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSecretKeyRing Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecretKeyRingTests
    {
        [Fact]
        public void Constructor_WithValidMasterKey_CreateKeyRing()
        {
            var masterKey = CreateTestSecretKey(isSubkey: false);

            var keyRing = new PgpSecretKeyRing(masterKey);

            Assert.Equal(masterKey.Algorithm, keyRing.MasterKey.Algorithm);
            Assert.Empty(keyRing.Subkeys);
        }

        [Fact]
        public void Constructor_WithSubkeyAsMaster_ThrowsException()
        {
            var subkey = CreateTestSecretKey(isSubkey: true);

            Assert.Throws<ArgumentException>(() => new PgpSecretKeyRing(subkey));
        }

        [Fact]
        public void IsEncrypted_ReflectsMasterKeyState()
        {
            var masterKey = CreateTestSecretKey(isSubkey: false);
            var keyRing = new PgpSecretKeyRing(masterKey);

            Assert.Equal(masterKey.IsEncrypted, keyRing.IsEncrypted);
        }

        [Fact]
        public void ExtractPublicKeyRing_ReturnsPublicKeyRing()
        {
            var masterKey = CreateTestSecretKey(isSubkey: false);
            var keyRing = new PgpSecretKeyRing(masterKey);

            var publicKeyRing = keyRing.ExtractPublicKeyRing();

            Assert.Equal(keyRing.MasterKeyId, publicKeyRing.MasterKeyId);
        }

        [Fact]
        public void GetSecretKey_ByKeyId_ReturnsKey()
        {
            var masterKey = CreateTestSecretKey(isSubkey: false);
            var keyRing = new PgpSecretKeyRing(masterKey);
            var keyId = masterKey.GetKeyId();

            var result = keyRing.GetSecretKey(keyId);

            Assert.NotNull(result);
        }

        private static PgpSecretKeyPacket CreateTestSecretKey(bool isSubkey)
        {
            var publicKeyMaterial = TestHelpers.RandomBytes(32);
            var secretKeyMaterial = TestHelpers.RandomBytes(32);

            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                publicKeyMaterial,
                isSubkey: isSubkey);

            return PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretKeyMaterial);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSecretKeyRingCollection Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecretKeyRingCollectionTests
    {
        [Fact]
        public void Empty_ReturnsEmptyCollection()
        {
            var collection = PgpSecretKeyRingCollection.Empty;

            Assert.Equal(0, collection.Count);
        }

        [Fact]
        public void Constructor_WithSingleKeyRing_CreatesCollection()
        {
            var keyRing = CreateTestSecretKeyRing();

            var collection = new PgpSecretKeyRingCollection(keyRing);

            Assert.Single(collection.KeyRings);
        }

        [Fact]
        public void GetKeyRing_ByKeyId_ReturnsKeyRing()
        {
            var keyRing = CreateTestSecretKeyRing();
            var collection = new PgpSecretKeyRingCollection(keyRing);
            var keyId = keyRing.MasterKeyId;

            var result = collection.GetKeyRing(keyId);

            Assert.NotNull(result);
        }

        [Fact]
        public void GetSecretKey_SearchesAcrossKeyRings()
        {
            var keyRing1 = CreateTestSecretKeyRing();
            var keyRing2 = CreateTestSecretKeyRing();
            var collection = new PgpSecretKeyRingCollection([keyRing1, keyRing2]);
            var keyId = keyRing2.MasterKeyId;

            var result = collection.GetSecretKey(keyId);

            Assert.NotNull(result);
        }

        [Fact]
        public void ExtractPublicKeyRingCollection_ReturnsPublicCollection()
        {
            var keyRing = CreateTestSecretKeyRing();
            var collection = new PgpSecretKeyRingCollection(keyRing);

            var publicCollection = collection.ExtractPublicKeyRingCollection();

            Assert.Equal(collection.Count, publicCollection.Count);
        }

        [Fact]
        public void Add_ReturnsNewCollectionWithKeyRing()
        {
            var keyRing1 = CreateTestSecretKeyRing();
            var keyRing2 = CreateTestSecretKeyRing();
            var collection = new PgpSecretKeyRingCollection(keyRing1);

            var newCollection = collection.Add(keyRing2);

            Assert.Single(collection.KeyRings);
            Assert.Equal(2, newCollection.Count);
        }

        [Fact]
        public void Remove_ReturnsNewCollectionWithoutKeyRing()
        {
            var keyRing1 = CreateTestSecretKeyRing();
            var keyRing2 = CreateTestSecretKeyRing();
            var collection = new PgpSecretKeyRingCollection([keyRing1, keyRing2]);

            var newCollection = collection.Remove(keyRing1.MasterKeyId);

            Assert.Equal(2, collection.Count);
            Assert.Single(newCollection.KeyRings);
        }

        private static PgpSecretKeyRing CreateTestSecretKeyRing()
        {
            var publicKeyMaterial = TestHelpers.RandomBytes(32);
            var secretKeyMaterial = TestHelpers.RandomBytes(32);

            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                publicKeyMaterial,
                isSubkey: false);

            var masterKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretKeyMaterial);

            return new PgpSecretKeyRing(masterKey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Equality and ToString Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EqualityTests
    {
        [Fact]
        public void PublicKeyRing_Equals_SameFingerprint_ReturnsTrue()
        {
            var masterKey = CreateTestPublicKey();
            var keyRing1 = new PgpPublicKeyRing(masterKey);
            var keyRing2 = new PgpPublicKeyRing(masterKey);

            Assert.Equal(keyRing1, keyRing2);
            Assert.True(keyRing1 == keyRing2);
        }

        [Fact]
        public void PublicKeyRing_Equals_DifferentFingerprint_ReturnsFalse()
        {
            var keyRing1 = new PgpPublicKeyRing(CreateTestPublicKey());
            var keyRing2 = new PgpPublicKeyRing(CreateTestPublicKey());

            Assert.NotEqual(keyRing1, keyRing2);
            Assert.True(keyRing1 != keyRing2);
        }

        [Fact]
        public void PublicKeyRing_ToString_ContainsKeyInfo()
        {
            var masterKey = CreateTestPublicKey();
            var keyRing = new PgpPublicKeyRing(masterKey);

            var str = keyRing.ToString();

            Assert.Contains("PublicKeyRing", str);
            Assert.Contains("v4", str);
        }

        [Fact]
        public void SecretKeyRing_ToString_ContainsKeyInfo()
        {
            var keyRing = CreateTestSecretKeyRing();

            var str = keyRing.ToString();

            Assert.Contains("SecretKeyRing", str);
        }

        [Fact]
        public void PublicKeyRingCollection_ToString_ContainsCount()
        {
            var keyRing = new PgpPublicKeyRing(CreateTestPublicKey());
            var collection = new PgpPublicKeyRingCollection(keyRing);

            var str = collection.ToString();

            Assert.Contains("1", str);
            Assert.Contains("key rings", str);
        }

        private static PgpPublicKeyPacket CreateTestPublicKey()
        {
            return PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: false);
        }

        private static PgpSecretKeyRing CreateTestSecretKeyRing()
        {
            var publicKeyMaterial = TestHelpers.RandomBytes(32);
            var secretKeyMaterial = TestHelpers.RandomBytes(32);

            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                publicKeyMaterial,
                isSubkey: false);

            var masterKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretKeyMaterial);

            return new PgpSecretKeyRing(masterKey);
        }
    }
}
